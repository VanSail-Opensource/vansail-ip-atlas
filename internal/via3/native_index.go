package via3

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"runtime"
)

// The private index contains the validated typed vectors and prefix ancestry for
// this one release. The immutable public bytes still determine the release ID.
// The row-page cache remains within the native deployment envelope. Each
// request also pays the complete logical public object admission charge.
type nativeIndex struct {
	facts                   nativeComponents
	fenceBudget, fenceBytes int
	resource                *nativeIndexFile
	cleanup                 runtime.Cleanup
	size                    int64
	pages                   *nativePages
}

type nativeIndexFile struct {
	file *os.File
	path string
}

type indexSpan struct{ offset, size int }

type indexedShard struct {
	slot                      uint16
	scopes                    [2][]*componentEntry
	pages                     *nativePages
	base                      int64
	length, decoded           int
	shard                     Shard
	sections                  [13]indexSpan
	prefixFences              [2][2][][16]byte
	rpkiFences                [2][][20]byte
	asnFences                 []uint32
	prefixOffsets, prefixText indexSpan
}

func closeNativeIndex(f *nativeIndexFile) error {
	err := f.file.Close()
	// Windows needs write permission to unlink a read-only file.
	if runtime.GOOS == "windows" {
		_ = os.Chmod(f.path, 0600)
	}
	return errors.Join(err, os.Remove(f.path))
}
func cleanupNativeIndex(f *nativeIndexFile) { _ = closeNativeIndex(f) }

// NativeIndexBytes is the size of the private, release-specific native index.
// No native scratch is created by NewRelease with an arbitrary object loader.
func (r *Release) NativeIndexBytes() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.native == nil {
		return 0
	}
	return r.native.size
}

// NativePageReads counts actual reads of private 4 KiB component pages. Reads
// continues to count original immutable VIA3 object reads.
func (r *Release) NativePageReads() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.native == nil {
		return 0
	}
	return r.native.pages.reads
}

// Close releases the private file and its page cache. A release cannot be queried
// after Close. The automatic cleanup also handles existing short-lived callers.
func (r *Release) Close() error {
	var err error
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.native != nil {
		r.native.cleanup.Stop()
		err = closeNativeIndex(r.native.resource)
		r.native = nil
	}
	r.references = nil
	r.usedReferences = nil
	r.cacheHead, r.cacheTail = nil, nil
	r.router = nil
	r.load = nil
	return err
}

// PrepareNativeIndex verifies every immutable public object once and builds an
// index of its typed components in the caller's private scratch directory.
// Ordinary OpenRelease remains lazy. Preparing is optional and idempotent.
// A cancellation or failure leaves the ordinary release reader usable.
func (r *Release) PrepareNativeIndex(ctx context.Context, directory string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.current(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.native != nil {
		return nil
	}
	writer, err := os.CreateTemp(directory, ".vansail-native-index-*")
	if err != nil {
		return err
	}
	path := writer.Name()
	reader, err := os.Open(path)
	if err != nil {
		writer.Close()
		os.Remove(path)
		return err
	}
	resource := &nativeIndexFile{file: reader, path: path}
	index := &nativeIndex{resource: resource, fenceBudget: max(0, PublicCacheDecoded-r.routerBytes-rowPageSize)}
	stream := &nativeIndexWriter{file: writer}
	type objectIndex struct {
		ref       *objectReference
		component *indexedShard
	}
	staged := make([]objectIndex, 0, len(r.Manifest.Objects)-1)
	r.preparing = true
	complete := false
	defer func() {
		r.preparing = false
		r.endQuery()
		writer.Close()
		if !complete {
			closeNativeIndex(resource)
		}
	}()
	for _, obj := range r.Manifest.Objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		reference := r.references[obj.SHA256]
		if reference.router {
			continue
		}
		shard, err := r.objectReference(ctx, reference)
		if err != nil {
			return err
		}
		onsite, err := index.append(stream, shard)
		if err != nil {
			return err
		}
		r.endQuery()
		r.evictReference(reference)
		staged = append(staged, objectIndex{reference, onsite})
	}
	if err := stream.flush(); err != nil {
		return err
	}
	if err := writer.Chmod(0400); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.current(); err != nil {
		return err
	}
	stat, err := reader.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() != index.size {
		return fail("integrity")
	}
	index.pages = &nativePages{owner: r, file: reader, total: index.size, dir: stream.pages, routerBytes: r.routerBytes}
	index.pages.setMetadata(index.fenceBytes)
	index.facts.pages = index.pages
	for i, entry := range staged {
		entry.component.slot = uint16(i)
		entry.ref.onsite = entry.component
		entry.component.pages = index.pages
		entry.component.shard.disk = entry.component
	}
	r.native = index
	index.cleanup = runtime.AddCleanup(index, cleanupNativeIndex, resource)
	complete = true
	return nil
}

// Hash each page from the same verified bytes being written. A modified private
// index cannot become authoritative for a later lookup, even with file access.
type nativeIndexWriter struct {
	file  *os.File
	buf   [rowPageSize]byte
	n     int
	pages []nativePageEntry
}

func (w *nativeIndexWriter) write(data []byte) error {
	for len(data) > 0 {
		k := copy(w.buf[w.n:], data)
		w.n += k
		data = data[k:]
		if w.n == len(w.buf) {
			if err := w.flush(); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w *nativeIndexWriter) flush() error {
	if w.n == 0 {
		return nil
	}
	block := w.buf[:w.n]
	n, err := w.file.Write(block)
	if err != nil {
		return err
	}
	if n != len(block) {
		return io.ErrShortWrite
	}
	w.pages = append(w.pages, nativePageEntry{digest: sha256.Sum256(block)})
	w.n = 0
	return nil
}

func (index *nativeIndex) append(writer *nativeIndexWriter, s *Shard) (*indexedShard, error) {
	base := index.size
	derived := &shardLookup{depths: s.lookup.depths, widths: s.lookup.widths, references: s.lookup.references, owner: s.lookup.owner}
	onsite := &indexedShard{base: base, decoded: decodedSize(s), shard: Shard{Kind: s.Kind, lookup: derived}}

	reserve := func(n int) indexSpan {
		span := indexSpan{onsite.length, n}
		onsite.length += n
		return span
	}
	for _, section := range s.Sections {
		rowStart := base + int64(onsite.length) + 8
		if section.ID == 1 || section.ID == 2 || section.ID == 8 {
			// Large searchable vectors begin on a page boundary. A smaller
			// searchable vector needs padding only if it would straddle two.
			n := len(section.Data) - 8
			if n >= rowPageSize || int(rowStart%rowPageSize)+n > rowPageSize {
				reserve(int((-rowStart) & (rowPageSize - 1)))
			}
		}
		onsite.sections[section.ID] = reserve(len(section.Data))
	}
	for i, parents := range s.lookup.prefixes {
		derived.prefixes[i].families = parents.families

	}
	prefixes, _ := s.Rows(11)
	if len(prefixes) > 0 {
		onsite.prefixOffsets = reserve((len(prefixes)/24 + 1) * 4)
		onsite.prefixText = reserve(prefixTextSize(prefixes))
	}
	// The native index shares the hosted 10 GiB scratch ceiling. Reserve the
	// full object before writing its first byte, including all typed vector and ancestry bytes.
	end := base + int64(onsite.length)
	if end >= 10<<30 {
		return nil, fail("resource_limit")
	}
	if err := checkIndexSpace(writer.file, end-index.size); err != nil {
		return nil, err
	}
	onsite.buildFences(s, index)
	var zeros [rowPageSize]byte
	pos := 0
	for _, section := range s.Sections {
		span := onsite.sections[section.ID]
		if err := writer.write(zeros[:span.offset-pos]); err != nil {
			return nil, err
		}
		if (section.ID == 1 || section.ID == 8) && s.Kind != 9 {
			// Private search rows store their parent next to the address. Keep the
			// original authenticated public vector untouched throughout preparation.
			k := 0
			if section.ID == 8 {
				k = 1
			}
			if err := writer.write(section.Data[:8]); err != nil {
				return nil, err
			}
			rows := section.Data[8:]
			parents := s.lookup.prefixes[k].parents
			var buffer [rowPageSize]byte
			for i := 0; i < len(parents); {
				count := min(prefixBlockRows, len(parents)-i)
				part := buffer[:count*32]
				copy(part, rows[i*32:(i+count)*32])
				for j, parent := range parents[i : i+count] {
					p32(part, j*32+24, parent)
				}
				if err := writer.write(part); err != nil {
					return nil, err
				}
				i += count
			}
		} else if err := writer.write(section.Data); err != nil {
			return nil, err
		}
		pos = span.offset + span.size
	}
	if len(prefixes) > 0 {
		if err := writePrefixText(writer, prefixes); err != nil {
			return nil, err
		}
	}
	index.size = end
	return onsite, nil
}

func (index *nativeIndex) release(onsite *indexedShard) {
	onsite.shard.lookup.prefixSpans = nil
	onsite.shard.lookup.graphIndex = nil
}
