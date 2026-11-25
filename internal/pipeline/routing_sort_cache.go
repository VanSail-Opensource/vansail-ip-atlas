package pipeline

import (
	"context"
	"errors"
	"io"
	"os"

	"vansail-ip-atlas/internal/intelligence"
)

const sortedPathsDomain = "sorted-paths"
const sortedPrefixesDomain = "sorted-prefixes"
const sortedRoutingBytes = 256 << 20

// Only the canonical input ordering is independent of clock and relationship
// data. Each consumer still reads the sorted rows, computes current rankings
// or rebuilds the prefix index, and performs its ordinary publication gates.
func (s *bulkSpool) sortRoutingRows(ctx context.Context, domain string, parts []intelligence.RecordPartition, produce func(func(bulkPathRow) error) error) (string, error) {
	if s.reuse == nil {
		return s.sortKeyedRows(ctx, produce)
	}
	key, err := spatialReuseKey(domain, parts)
	if err != nil {
		return "", err
	}
	entry, hit, err := s.reuse.Lookup(ctx, domain, key)
	if err != nil {
		return "", err
	}
	if hit {
		if err := s.verifyParts(ctx, parts); err != nil {
			return "", err
		}
		path, err := s.restoreRoutingSort(ctx, entry.Leaf.Stream)
		if err != nil {
			return "", err
		}
		_, err = s.reuse.Retain(ctx, entry, nil)
		return path, err
	}
	path, err := s.sortKeyedRows(ctx, produce)
	if err != nil || path == "" {
		return path, err
	}
	return path, s.retainRoutingSort(ctx, path, domain, key)
}

func (s *bulkSpool) retainRoutingSort(ctx context.Context, path, domain string, key [32]byte) (returnErr error) {
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.Join(errSpatialCache, err)
	}
	if info.Size() > sortedRoutingBytes {
		return nil
	}
	writer, err := s.newSpatialStream(ctx)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, writer.abort()) }()
	if writer.disabled {
		return nil
	}
	n, err := io.Copy(writer.writer, io.LimitReader(&cacheContextReader{ctx, source}, info.Size()+1))
	if errors.Is(err, errSpatialStreamCapacity) {
		return nil
	}
	if err != nil || n != info.Size() {
		return errors.Join(errSpatialCache, err)
	}
	// One compressed object contains one complete sorted file.
	writer.records, writer.decoded = 1, uint64(n)
	stream, retained, err := writer.finish()
	if err != nil || !retained {
		return err
	}
	entry := spatialCacheEntry{Domain: domain, Key: key, Leaf: &spatialCacheLeaf{Stream: stream}}
	_, err = s.reuse.Retain(ctx, entry, map[[32]byte]string{stream.SHA256: writer.path})
	return err
}

func (s *bulkSpool) restoreRoutingSort(ctx context.Context, stream spatialCacheStream) (string, error) {
	used := s.external() + s.store.DiskBytes() + s.pathBytes
	if used > s.maximum || stream.DecodedBytes > s.maximum-used {
		return "", errors.New("restored routing sort exceeds scratch budget")
	}
	input, err := s.openSpatialStream(ctx, stream)
	if err != nil {
		return "", err
	}
	defer input.Close()
	file, err := os.CreateTemp(s.root, "restored-routing-*.partial")
	if err != nil {
		return "", err
	}
	// Reserve the exact decoded length before writing. On failure the owned
	// spool is discarded, including any partial bytes and their reservation.
	s.pathBytes += stream.DecodedBytes
	n, err := io.Copy(file, io.LimitReader(input.reader, int64(stream.DecodedBytes)))
	closeErr := file.Close()
	if err != nil || closeErr != nil || uint64(n) != stream.DecodedBytes {
		return "", errors.Join(errSpatialCache, err, closeErr)
	}
	var extra [1]byte
	if n, err := input.reader.Read(extra[:]); n != 0 || err != io.EOF {
		return "", errors.Join(errSpatialCache, err)
	}
	if err = input.verify(); err != nil {
		return "", err
	}
	return file.Name(), ctx.Err()
}
