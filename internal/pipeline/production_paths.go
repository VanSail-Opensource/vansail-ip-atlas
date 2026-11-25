package pipeline

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"

	"vansail-ip-atlas/internal/intelligence"
)

type bulkPathRow struct {
	group, family string
	data          []byte
}

func pathRowLess(a, b bulkPathRow) bool {
	if a.group != b.group {
		return a.group < b.group
	}
	if a.family != b.family {
		return a.family < b.family
	}
	return bytes.Compare(a.data, b.data) < 0
}
func (s *bulkSpool) writePathRow(ctx context.Context, w io.Writer, row bulkPathRow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n := uint64(12 + len(row.group) + len(row.family) + len(row.data))
	used := s.external() + s.store.DiskBytes() + s.pathBytes
	if used > s.maximum || n > s.maximum-used {
		return errors.New("path sort scratch budget exceeded")
	}
	s.pathBytes += n
	var frame [12]byte
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(row.group)))
	binary.LittleEndian.PutUint32(frame[4:8], uint32(len(row.family)))
	binary.LittleEndian.PutUint32(frame[8:], uint32(len(row.data)))
	for _, data := range [][]byte{frame[:], []byte(row.group), []byte(row.family), row.data} {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}
func (s *bulkSpool) removePathFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	s.pathBytes -= uint64(info.Size())
	return nil
}

type bulkPathReader struct {
	file   *os.File
	reader *bufio.Reader
	row    bulkPathRow
}

func openPathRun(path string) (*bulkPathReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &bulkPathReader{file: f, reader: bufio.NewReaderSize(f, 64<<10)}, nil
}
func (r *bulkPathReader) next() error {
	var frame [12]byte
	if _, err := io.ReadFull(r.reader, frame[:]); err != nil {
		return err
	}
	group, family, data := int(binary.LittleEndian.Uint32(frame[:4])), int(binary.LittleEndian.Uint32(frame[4:8])), int(binary.LittleEndian.Uint32(frame[8:]))
	if group < 4 || group > 1<<20 || family < 1 || family > 256 || data < 1 || data > 1<<20 {
		return errors.New("private path sort frame invalid")
	}
	payload := make([]byte, group+family+data)
	if _, err := io.ReadFull(r.reader, payload); err != nil {
		return err
	}
	r.row = bulkPathRow{group: string(payload[:group]), family: string(payload[group : group+family]), data: payload[group+family:]}
	return nil
}

type bulkPathHeap []*bulkPathReader

func (h bulkPathHeap) Len() int           { return len(h) }
func (h bulkPathHeap) Less(i, j int) bool { return pathRowLess(h[i].row, h[j].row) }
func (h bulkPathHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *bulkPathHeap) Push(v any)        { *h = append(*h, v.(*bulkPathReader)) }
func (h *bulkPathHeap) Pop() any          { old := *h; v := old[len(old)-1]; *h = old[:len(old)-1]; return v }
func (s *bulkSpool) mergePathRuns(ctx context.Context, paths []string) (string, error) {
	file, err := os.CreateTemp(s.root, "path-merge-*.partial")
	if err != nil {
		return "", err
	}
	defer file.Close()
	writer := bufio.NewWriterSize(file, 64<<10)
	var readers []*bulkPathReader
	defer func() {
		for _, reader := range readers {
			reader.file.Close()
		}
	}()
	var queue bulkPathHeap
	for _, path := range paths {
		reader, err := openPathRun(path)
		if err != nil {
			return "", err
		}
		readers = append(readers, reader)
		if err = reader.next(); err == nil {
			heap.Push(&queue, reader)
		} else if err != io.EOF {
			return "", err
		}
	}
	var previous bulkPathRow
	hasPrevious := false
	for queue.Len() > 0 {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		reader := heap.Pop(&queue).(*bulkPathReader)
		row := reader.row
		if !hasPrevious || row.group != previous.group || row.family != previous.family {
			if err = s.writePathRow(ctx, writer, row); err != nil {
				return "", err
			}
			previous = row
			hasPrevious = true
		}
		if err = reader.next(); err == nil {
			heap.Push(&queue, reader)
		} else if err != io.EOF {
			return "", err
		}
	}
	if err = writer.Flush(); err != nil {
		return "", err
	}
	if err = file.Close(); err != nil {
		return "", err
	}
	for _, reader := range readers {
		_ = reader.file.Close()
	}
	for _, path := range paths {
		if err = s.removePathFile(path); err != nil {
			return "", err
		}
	}
	return file.Name(), nil
}

// reducePaths external-sorts by canonical observed structure and independent
// family before applying the existing exact top-twelve comparator. One origin
// can have arbitrarily many bounded input records without a giant heap group.
func (s *bulkSpool) reducePaths(ctx context.Context, relations intelligence.RelationResolver, emit func(intelligence.Path, uint16) error) error {
	if len(s.pathParts) == 0 {
		return nil
	}
	path, err := s.sortRoutingRows(ctx, sortedPathsDomain, s.pathParts, func(emit func(bulkPathRow) error) error {
		return s.walk(ctx, s.pathParts, func(record intelligence.NormalizedRecord) error {
			if record.Path == nil || !record.Path.Observation.Current || record.Path.Observation.Family == "" {
				return errors.New("current private path required")
			}
			group, err := intelligence.PathGroupKey(record.Path.Observation)
			if err != nil {
				return err
			}
			data, err := json.Marshal(record)
			if err != nil {
				return err
			}
			return emit(bulkPathRow{group, record.Path.Observation.Family, data})
		})
	})
	if err != nil {
		return err
	}
	reader, err := openPathRun(path)
	if err != nil {
		return err
	}
	defer reader.file.Close()
	selection := intelligence.NewPathSelection(relations)
	var origin uint32
	var group, lastFamily string
	families := 0
	var observation intelligence.PathObservation
	finishOrigin := func() error {
		for rank, path := range selection.Paths() {
			if err := emit(path, uint16(rank)); err != nil {
				return err
			}
		}
		return nil
	}
	finishGroup := func() error {
		if families == 0 {
			return nil
		}
		asn := observation.Origin
		if origin != 0 && origin != asn {
			if err := finishOrigin(); err != nil {
				return err
			}
			selection = intelligence.NewPathSelection(relations)
		}
		origin = asn
		return selection.Consider(observation, families)
	}
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		err = reader.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		row := reader.row
		if row.group != group {
			if err = finishGroup(); err != nil {
				return err
			}
			var record intelligence.NormalizedRecord
			decoder := json.NewDecoder(bytesReader(row.data))
			decoder.DisallowUnknownFields()
			if err = decoder.Decode(&record); err != nil {
				return err
			}
			if err = record.Validate(); err != nil || record.Path == nil {
				return errors.New("private ranked path invalid")
			}
			observation = record.Path.Observation
			group = row.group
			families = 0
			lastFamily = ""
		}
		if row.family != lastFamily {
			families++
			if families > 1000 {
				return errors.New("path family budget exceeded")
			}
			lastFamily = row.family
		}
	}
	if err = finishGroup(); err != nil {
		return err
	}
	if err = finishOrigin(); err != nil {
		return err
	}
	if err = reader.file.Close(); err != nil {
		return err
	}
	if err = s.removePathFile(path); err != nil {
		return err
	}
	s.pathParts = nil
	return s.gc(ctx)
}
func bytesReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }

func (s *bulkSpool) sortKeyedRows(ctx context.Context, produce func(func(bulkPathRow) error) error) (string, error) {
	var batch []bulkPathRow
	size := 0
	var runs []string
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		sort.Slice(batch, func(i, j int) bool { return pathRowLess(batch[i], batch[j]) })
		file, err := os.CreateTemp(s.root, "keyed-run-*.partial")
		if err != nil {
			return err
		}
		defer file.Close()
		writer := bufio.NewWriterSize(file, 64<<10)
		var previous bulkPathRow
		seen := false
		for _, row := range batch {
			if !seen || row.group != previous.group || row.family != previous.family {
				if err = s.writePathRow(ctx, writer, row); err != nil {
					return err
				}
				previous = row
				seen = true
			}
		}
		if err = writer.Flush(); err != nil {
			return err
		}
		if err = file.Close(); err != nil {
			return err
		}
		runs = append(runs, file.Name())
		if len(runs) > 8192 {
			return errors.New("keyed sort-run budget exceeded")
		}
		batch = nil
		size = 0
		return nil
	}
	err := produce(func(row bulkPathRow) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		cost := 3*len(row.data) + len(row.group) + len(row.family) + 512
		if cost > 96<<20 {
			return errors.New("one keyed row exceeds sort buffer")
		}
		if size+cost > 96<<20 {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, row)
		size += cost
		return nil
	})
	if err != nil {
		return "", err
	}
	if err = flush(); err != nil {
		return "", err
	}
	if len(runs) == 0 {
		return "", nil
	}
	for len(runs) > 1 {
		var next []string
		for first := 0; first < len(runs); first += 16 {
			end := min(first+16, len(runs))
			path, err := s.mergePathRuns(ctx, runs[first:end])
			if err != nil {
				return "", err
			}
			next = append(next, path)
		}
		runs = next
	}
	return runs[0], nil
}
