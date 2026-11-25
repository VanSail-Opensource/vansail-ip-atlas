package intelligence

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// ImportPartition copies or links a verified immutable object into this store.
// The destination stays subject to the same integrity, byte, file-count and
// free-space checks as locally written objects. Imports never mint a
// CanonicalPartition capability.
func (s *RecordStore) ImportPartition(ctx context.Context, from string, part RecordPartition) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validPartition(part) || part.Records > s.limits.PartitionRecords || max(part.Bytes, part.DecodedBytes) > s.limits.PartitionBytes {
		return errors.New("invalid import descriptor")
	}
	root, err := recordDirectory(filepath.Dir(filepath.Dir(s.root)), false)
	if err != nil || root != s.root {
		return errors.New("private import directory changed")
	}
	resolved, err := filepath.EvalSymlinks(from)
	if err != nil || resolved != from {
		return errors.New("invalid private import source")
	}
	info, err := os.Lstat(from)
	if err != nil || !info.Mode().IsRegular() || info.Size() != part.Bytes {
		return errors.New("private import source length invalid")
	}
	to := filepath.Join(root, partitionName(part))
	s.mu.Lock()
	defer s.mu.Unlock()
	free, err := recordFreeSpace(root)
	if err != nil {
		return err
	}
	if free < 1<<30 {
		return errors.New("private state free-space floor reached")
	}
	if _, err = os.Lstat(to); err == nil {
		return s.verifyImport(ctx, part)
	} else if !os.IsNotExist(err) {
		return err
	}
	if s.objects >= maxRecordPartitions || part.Bytes >= s.limits.DiskBytes-s.disk {
		return errors.New("private import inventory or disk budget exceeded")
	}
	// Reserve before linking or writing. Release a failed reservation only if
	// no destination was created or its owned entry was successfully removed.
	s.disk += part.Bytes
	s.objects++
	var owned os.FileInfo
	if err = os.Link(from, to); err == nil {
		owned = info
	} else if free-(1<<30) < uint64(part.Bytes) {
		err = errors.New("private import would cross free-space floor")
	} else {
		owned, err = copyImport(ctx, from, to, info, part.Bytes)
	}
	if err == nil {
		err = s.verifyImport(ctx, part)
	}
	if err != nil {
		if owned == nil {
			if _, statErr := os.Lstat(to); !os.IsNotExist(statErr) {
				return err
			}
		} else {
			actual, statErr := os.Lstat(to)
			if statErr != nil || !os.SameFile(actual, owned) {
				return err
			}
			if removeErr := os.Remove(to); removeErr != nil {
				return errors.Join(err, removeErr)
			}
		}
		s.disk -= part.Bytes
		s.objects--
	}
	return err
}

func (s *RecordStore) verifyImport(ctx context.Context, part RecordPartition) error {
	if s.limits.RecordBytes == DefaultRecordStoreLimits().RecordBytes {
		return walkPartition(ctx, s.root, part, nil)
	}
	return walkPartitionFrames(ctx, s.root, part, func(_ NormalizedRecord, data []byte) error {
		if len(data) > s.limits.RecordBytes {
			return errors.New("private import record exceeds store limit")
		}
		return nil
	})
}

func copyImport(ctx context.Context, from, to string, original os.FileInfo, size int64) (owned os.FileInfo, returnErr error) {
	input, err := os.Open(from)
	if err != nil {
		return nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, input.Close()) }()
	info, err := input.Stat()
	if err != nil || !os.SameFile(info, original) {
		return nil, errors.New("private import source changed")
	}
	output, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, output.Close()) }()
	owned, err = output.Stat()
	if err != nil {
		return nil, err
	}
	reader := &recordContextReader{ctx: ctx, reader: input}
	if _, err = io.CopyN(output, reader, size); err != nil {
		return owned, err
	}
	var extra [1]byte
	if n, err := reader.Read(extra[:]); n != 0 || err != io.EOF {
		return owned, errors.New("private import source length changed")
	}
	return owned, nil
}
