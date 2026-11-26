package intelligence

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
)

// RecordPartition describes one immutable private normalized-record object.
// Its location is derived only from SHA256, never from a source-provided path.
type RecordPartition struct {
	SHA256       [32]byte
	Bytes        int64
	Records      uint64
	Codec        string `json:",omitempty"`
	DecodedBytes int64  `json:",omitempty"`
}

// ErrVerifyRecordPrefix requests a validated early stop from a record callback.
// The walker returns the callback's marked error only after hashing the physical
// suffix on the same read that supplied the decoded prefix.
var ErrVerifyRecordPrefix = errors.New("verify consumed record prefix")

// CanonicalPartition is a process-local capability for frames produced by a
// successful RecordWriter or verified byte-for-byte against its encoder.
// It conveys no source approval or freshness.
type CanonicalPartition struct {
	root string
	part RecordPartition
}

// Descriptor returns an independent copy of the immutable object identity.
func (p CanonicalPartition) Descriptor() RecordPartition { return p.part }

// Walk retains the normal byte, framing, decoding and semantic checks. Only the
// proven writer encoding permits reusing the encoded length and digest.
func (p CanonicalPartition) Walk(ctx context.Context, emit func(CanonicalRecordFrame) error) error {
	if p.root == "" || !validPartition(p.part) || emit == nil {
		return errors.New("canonical partition capability invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := recordDirectory(filepath.Dir(filepath.Dir(p.root)), false)
	if err != nil {
		return err
	}
	if root != p.root {
		return errors.New("canonical partition root changed")
	}
	return walkPartitionFrames(ctx, root, p.part, func(record NormalizedRecord, data []byte) error {
		return emit(CanonicalRecordFrame{record: record, data: data})
	})
}

// CompareCanonicalFrames walks the ordinary strict representation, including
// its final count, hash and decoder checks. The callback receives a fresh frame
// encoded exactly as a RecordWriter would encode the owned record. A capability
// for later reads is returned only if every original frame already matched.
func CompareCanonicalFrames(ctx context.Context, workspace string, part RecordPartition, emit func(CanonicalRecordFrame) error) (CanonicalPartition, error) {
	if ctx == nil || emit == nil {
		return CanonicalPartition{}, errors.New("canonical comparison sink required")
	}
	root, err := recordDirectory(workspace, false)
	if err != nil {
		return CanonicalPartition{}, err
	}
	equal := true
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	err = walkPartitionFrames(ctx, root, part, func(record NormalizedRecord, data []byte) error {
		if record.Geo != nil && canonicalWriterGeo(data, record.Geo) {
			return emit(CanonicalRecordFrame{record: record, data: data})
		}
		buffer.Reset()
		if err := encoder.Encode(record); err != nil {
			return err
		}
		// Encode uses the writer's default JSON encoding plus a trailing newline.
		encoded := buffer.Bytes()[:buffer.Len()-1]
		if !bytes.Equal(data, encoded) {
			equal = false
			data = bytes.Clone(encoded)
		}
		return emit(CanonicalRecordFrame{record: record, data: data})
	})
	if err != nil || !equal {
		return CanonicalPartition{}, err
	}
	return CanonicalPartition{root: root, part: part}, nil
}

// CanonicalRecordFrame owns one strictly decoded canonical frame. Its encoded
// bytes are private and never alias the mutable decoded record returned below.
type CanonicalRecordFrame struct {
	record NormalizedRecord
	data   []byte
}

// Record transfers the decoded value to the caller. Mutating its payload does
// not change the encoded frame used by Digest or AppendTo.
func (f CanonicalRecordFrame) Record() (NormalizedRecord, error) {
	if len(f.data) == 0 {
		return NormalizedRecord{}, errors.New("canonical record frame invalid")
	}
	return f.record, nil
}

func (f CanonicalRecordFrame) EncodedBytes() int { return len(f.data) }
func (f CanonicalRecordFrame) Digest() [32]byte {
	if len(f.data) == 0 {
		return [32]byte{}
	}
	return sha256.Sum256(f.data)
}

// AppendTo copies the original canonical bytes through the destination's usual
// count, logical-byte, physical-byte and cancellation limits. It deliberately
// ignores mutations to the independently decoded record.
func (f CanonicalRecordFrame) AppendTo(w *RecordWriter) error {
	if len(f.data) == 0 || w == nil || w.store == nil || w.ctx == nil {
		return errors.New("canonical record frame or writer invalid")
	}
	return w.appendEncoded(f.data)
}

type RecordStoreLimits struct {
	PartitionBytes   int64
	PartitionRecords uint64
	RecordBytes      int
	DiskBytes        int64
}

func DefaultRecordStoreLimits() RecordStoreLimits {
	return RecordStoreLimits{64 << 20, 100000, 1 << 20, 10 << 30}
}

const recordHeader = "ATNR\x02\x03\x00\x00"
const compressedRecordHeader = "ATNZ\x03\x03\x00\x00"
const maxRecordPartitions = 16384

type RecordStore struct {
	root           string
	limits         RecordStoreLimits
	mu             sync.Mutex
	disk           int64
	lastFreeSample int64
	objects        int
}

// DiskBytes includes existing immutable objects and reserved in-flight bytes.
func (s *RecordStore) DiskBytes() uint64 { s.mu.Lock(); defer s.mu.Unlock(); return uint64(s.disk) }

// RemainingPartitionSlots reports headroom from the latest inventory and
// every object installed since. Writers still enforce the hard limit.
func (s *RecordStore) RemainingPartitionSlots() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maxRecordPartitions - s.objects
}

func recordDirectory(workspace string, create bool) (string, error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	current := root
	for _, name := range []string{".atlas-private", "records-v2"} {
		current = filepath.Join(current, name)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) && create {
			if err = os.Mkdir(current, 0700); err != nil {
				return "", err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return "", err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("record directory is not an owned regular directory")
		}
	}
	return current, nil
}
func NewRecordStore(workspace string, limits RecordStoreLimits) (*RecordStore, error) {
	if limits.PartitionBytes < 16 || limits.PartitionBytes > 64<<20 || limits.PartitionRecords == 0 || limits.PartitionRecords > 100000 || limits.RecordBytes < 1 || limits.RecordBytes > 1<<20 || limits.DiskBytes < limits.PartitionBytes || limits.DiskBytes > 10<<30 {
		return nil, errors.New("invalid private record-store limits")
	}
	root, err := recordDirectory(workspace, true)
	if err != nil {
		return nil, err
	}
	store := &RecordStore{root: root, limits: limits}
	free, err := recordFreeSpace(root)
	if err != nil {
		return nil, err
	}
	if free < 1<<30 {
		return nil, errors.New("private state free-space floor reached")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	if len(entries) > maxRecordPartitions {
		return nil, errors.New("private partition inventory exceeded")
	}
	store.objects = len(entries)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("invalid private partition entry")
		}
		store.disk += info.Size()
		if store.disk > limits.DiskBytes {
			return nil, errors.New("private record disk budget exceeded")
		}
	}
	return store, nil
}
func partitionName(p RecordPartition) string { return hex.EncodeToString(p.SHA256[:]) + ".records" }
func validPartition(p RecordPartition) bool {
	base := p.SHA256 != ([32]byte{}) && p.Bytes >= 8 && p.Bytes <= 64<<20 && p.Records > 0 && p.Records <= 100000
	return base && (p.Codec == "" && p.DecodedBytes == 0 || p.Codec == "zstd-v1" && p.DecodedBytes >= 8 && p.DecodedBytes <= 64<<20)
}
func (s *RecordStore) reserve(n int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n < 0 || n > s.limits.DiskBytes-s.disk {
		return errors.New("private record disk budget exceeded")
	}
	if s.disk-s.lastFreeSample >= 16<<20 {
		free, err := recordFreeSpace(s.root)
		if err != nil {
			return err
		}
		if free < (1<<30)+(16<<20) {
			return errors.New("private state free-space floor reached")
		}
		s.lastFreeSample = s.disk
	}
	s.disk += n
	return nil
}
func (s *RecordStore) release(n int64) { s.mu.Lock(); s.disk -= n; s.mu.Unlock() }

type RecordWriter struct {
	store   *RecordStore
	ctx     context.Context
	file    *os.File
	buffer  *bufio.Writer
	digest  hash.Hash
	size    int64
	decoded int64
	encoder *zstd.Encoder
	count   uint64
	parts   []RecordPartition
	closed  bool
}

func (s *RecordStore) Writer(ctx context.Context) *RecordWriter {
	return &RecordWriter{store: s, ctx: ctx}
}
func (w *RecordWriter) start() error {
	f, err := os.CreateTemp(w.store.root, "record-*.partial")
	if err != nil {
		return err
	}
	w.file = f
	w.digest = sha256.New()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	output := &compressedRecordWriter{owner: w}
	if _, err = output.Write([]byte(compressedRecordHeader)); err != nil {
		return err
	}
	w.encoder, err = zstd.NewWriter(output, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithWindowSize(1<<20), zstd.WithEncoderCRC(true))
	if err != nil {
		return err
	}
	w.buffer = bufio.NewWriterSize(w.encoder, 64<<10)
	w.decoded = int64(len(recordHeader))
	_, err = w.buffer.WriteString(recordHeader)
	return err
}
func (w *RecordWriter) Append(record NormalizedRecord) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.closed {
		return errors.New("record writer closed")
	}
	if err := record.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return w.appendEncoded(data)
}

func (w *RecordWriter) appendEncoded(data []byte) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.closed {
		return errors.New("record writer closed")
	}
	if len(data) > w.store.limits.RecordBytes || int64(len(data)+4+len(recordHeader)) > w.store.limits.PartitionBytes {
		return errors.New("private record byte budget exceeded")
	}
	if w.file != nil && (w.count >= w.store.limits.PartitionRecords || int64(len(data)+4) > w.store.limits.PartitionBytes-w.decoded) {
		if err := w.finishPartition(); err != nil {
			return err
		}
	}
	if w.file == nil {
		if err := w.start(); err != nil {
			return err
		}
	}
	n := int64(len(data) + 4)
	w.decoded += n
	var frame [4]byte
	binary.LittleEndian.PutUint32(frame[:], uint32(len(data)))
	if _, err := w.buffer.Write(frame[:]); err != nil {
		return err
	}
	if _, err := w.buffer.Write(data); err != nil {
		return err
	}
	w.count++
	return nil
}
func (w *RecordWriter) finishPartition() error {
	if w.file == nil {
		return nil
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if len(w.parts) >= maxRecordPartitions {
		return errors.New("private partition inventory exceeded")
	}
	if err := w.buffer.Flush(); err != nil {
		return err
	}
	if err := w.encoder.Close(); err != nil {
		return err
	}
	w.encoder = nil
	if err := w.file.Sync(); err != nil {
		return err
	}
	if err := w.file.Close(); err != nil {
		return err
	}
	part := RecordPartition{Bytes: w.size, Records: w.count, Codec: "zstd-v1", DecodedBytes: w.decoded}
	copy(part.SHA256[:], w.digest.Sum(nil))
	if err := w.installPartition(part); err != nil {
		return err
	}
	w.parts = append(w.parts, part)
	w.file = nil
	w.buffer = nil
	w.size = 0
	w.decoded = 0
	w.count = 0
	return nil
}

// Inspect and install the destination while holding the same lock as imports.
// Two concurrent writers finishing identical bytes charge one file.
func (w *RecordWriter) installPartition(part RecordPartition) error {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	destination := filepath.Join(w.store.root, partitionName(part))
	if info, err := os.Lstat(destination); err == nil {
		if !info.Mode().IsRegular() || info.Size() != part.Bytes {
			return errors.New("private partition collision")
		}
		if err = walkPartition(w.ctx, w.store.root, part, nil); err != nil {
			return err
		}
		if err = os.Remove(w.file.Name()); err != nil {
			return err
		}
		w.store.disk -= w.size
	} else if !os.IsNotExist(err) {
		return err
	} else {
		if w.store.objects >= maxRecordPartitions {
			return errors.New("private partition inventory exceeded")
		}
		err = os.Rename(w.file.Name(), destination)
		if err == nil {
			w.store.objects++
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (w *RecordWriter) Finish() ([]RecordPartition, error) {
	if w.closed {
		return nil, errors.New("record writer closed")
	}
	if err := w.finishPartition(); err != nil {
		return nil, err
	}
	w.closed = true
	return append([]RecordPartition(nil), w.parts...), nil
}

// FinishCanonical mints capabilities only for the exact objects successfully
// finished by this writer. Opening an existing store never adopts its objects.
func (w *RecordWriter) FinishCanonical() ([]CanonicalPartition, error) {
	if w == nil || w.store == nil || w.ctx == nil {
		return nil, errors.New("canonical record writer invalid")
	}
	parts, err := w.Finish()
	if err != nil {
		return nil, err
	}
	out := make([]CanonicalPartition, len(parts))
	for i, part := range parts {
		out[i] = CanonicalPartition{root: w.store.root, part: part}
	}
	return out, nil
}
func (w *RecordWriter) Abort() error {
	w.closed = true
	if w.encoder != nil {
		_ = w.encoder.Close()
		w.encoder = nil
	}
	if w.file == nil {
		return nil
	}
	_ = w.file.Close()
	err := os.Remove(w.file.Name())
	if err == nil || os.IsNotExist(err) {
		w.store.release(w.size)
		err = nil
	}
	w.file = nil
	return err
}

func walkPartition(ctx context.Context, root string, part RecordPartition, emit func(NormalizedRecord) error) error {
	return walkPartitionRecords(ctx, root, part, recordDecodeSink{typed: emit})
}

func walkPartitionFrames(ctx context.Context, root string, part RecordPartition, emit func(NormalizedRecord, []byte) error) error {
	return walkPartitionRecords(ctx, root, part, recordDecodeSink{raw: emit})
}

// Only the typed callback is eligible for recycling. It never receives a raw
// buffer or a view into one, even if it retains the entire decoded record.
type recordDecodeSink struct {
	typed func(NormalizedRecord) error
	raw   func(NormalizedRecord, []byte) error
}

func (s recordDecodeSink) emit(record NormalizedRecord, frame []byte) error {
	if s.typed != nil {
		return s.typed(record)
	}
	return s.raw(record, frame)
}

func walkPartitionRecords(ctx context.Context, root string, part RecordPartition, sink recordDecodeSink) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validPartition(part) {
		return errors.New("private partition descriptor invalid")
	}
	path := filepath.Join(root, partitionName(part))
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != part.Bytes {
		return errors.New("private partition length invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	h := sha256.New()
	reader := &recordContextReader{ctx: ctx, reader: io.LimitReader(file, part.Bytes+1)}
	size, err := io.Copy(h, reader)
	if err != nil {
		return err
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	if size != part.Bytes || digest != part.SHA256 {
		return errors.New("private partition integrity failed")
	}
	if part.Codec == "zstd-v1" {
		if err = validatePrivateFrame(ctx, file, part); err != nil {
			return err
		}
	}
	if sink.typed == nil && sink.raw == nil {
		return nil
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	parsedHash := sha256.New()
	physical := &recordContextReader{ctx, io.TeeReader(io.LimitReader(file, part.Bytes), parsedHash)}
	var logical io.Reader = physical
	finishRead := func(result error) error {
		if result != nil {
			if !errors.Is(result, ErrVerifyRecordPrefix) {
				return result
			}
			// Buffered compressed bytes are already in parsedHash. Drain the
			// unread physical suffix without decoding unused logical frames.
			if _, readErr := io.Copy(io.Discard, physical); readErr != nil {
				return readErr
			}
		}
		var parsedDigest [32]byte
		copy(parsedDigest[:], parsedHash.Sum(nil))
		if parsedDigest != part.SHA256 {
			return errors.New("private partition changed while reading")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return result
	}
	decodedBytes := part.Bytes
	if part.Codec == "zstd-v1" {
		var outer [len(compressedRecordHeader)]byte
		if _, err = io.ReadFull(logical, outer[:]); err != nil || string(outer[:]) != compressedRecordHeader {
			return errors.New("compressed private partition header invalid")
		}
		decoder, err := zstd.NewReader(logical, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(64<<20), zstd.WithDecoderMaxWindow(1<<20))
		if err != nil {
			return err
		}
		defer decoder.Close()
		logical = io.LimitReader(decoder, part.DecodedBytes+1)
		decodedBytes = part.DecodedBytes
	}
	buffer := bufio.NewReaderSize(logical, 64<<10)
	var header [len(recordHeader)]byte
	if _, err = io.ReadFull(buffer, header[:]); err != nil || string(header[:]) != recordHeader {
		return errors.New("private partition version invalid")
	}
	remaining := decodedBytes - int64(len(header))
	var count uint64
	if part.Records > recordDecodeBatchFrames {
		count, err = walkRecordDecodeBatchesWithSink(ctx, buffer, remaining, part.Records, sink)
		if err != nil {
			return finishRead(err)
		}
	} else {
		var scratch []byte
		for remaining > 0 {
			if err = ctx.Err(); err != nil {
				return err
			}
			var frame [4]byte
			if remaining < 4 {
				return errors.New("private record frame truncated")
			}
			if _, err = io.ReadFull(buffer, frame[:]); err != nil {
				return err
			}
			remaining -= 4
			n := binary.LittleEndian.Uint32(frame[:])
			if n == 0 || n > 1<<20 || int64(n) > remaining || count >= part.Records {
				return errors.New("private record frame invalid")
			}
			var data []byte
			if sink.typed == nil {
				data = make([]byte, int(n))
			} else {
				if int(n) > cap(scratch) {
					scratch = make([]byte, min(recordDecodeBatchBytes, max(int(n), 2*cap(scratch))))
				}
				data = scratch[:n:n]
			}
			if _, err = io.ReadFull(buffer, data); err != nil {
				return err
			}
			remaining -= int64(n)
			record, err := decodeRecordFrame(data)
			if err != nil {
				return err
			}
			if err = sink.emit(record, data); err != nil {
				return finishRead(err)
			}
			count++
		}
	}
	if count != part.Records {
		return errors.New("private record count invalid")
	}
	if _, err = buffer.ReadByte(); err != io.EOF {
		return errors.New("private partition decoded length or checksum invalid")
	}
	return finishRead(nil)
}

// Decode only independently owned, complete frames. Both scheduling paths keep
// the existing UTF-8, v1 member/duplicate semantics, trailing-data, unknown-field
// and typed-union checks; concurrency conveys no source or schema approval.
func decodeRecordFrame(data []byte) (NormalizedRecord, error) {
	if !utf8.Valid(data) {
		return NormalizedRecord{}, errors.New("private record UTF-8 invalid")
	}
	if geo, ok := decodeWriterGeo(data); ok {
		record := NormalizedRecord{Version: 3, Kind: RecordGeo, Geo: geo}
		return record, record.Validate()
	}
	if record, ok := decodeWriterRouting(data); ok {
		return record, record.Validate()
	}
	var record NormalizedRecord
	if err := jsonv2.Unmarshal(data, &record, json.DefaultOptionsV1(), jsonv2.RejectUnknownMembers(true)); err != nil {
		return record, err
	}
	return record, record.Validate()
}

const recordDecodeBatchFrames = 64
const recordDecodeBatchBytes = 1 << 20

type recordDecodeBatch struct {
	frames                [recordDecodeBatchFrames][]byte
	buffer                []byte
	ends                  [recordDecodeBatchFrames]int
	records               [recordDecodeBatchFrames]NormalizedRecord
	count, bytes, decoded int
	readErr, decodeErr    error
}

func (b *recordDecodeBatch) reset(recycle bool) {
	var buffer []byte
	if recycle {
		buffer = b.buffer[:0]
	}
	*b = recordDecodeBatch{buffer: buffer}
}

// The caller exclusively owns framing and all underlying reader state. A
// length that would exceed this batch's byte limit is retained without reading
// its payload; even a single one-MiB frame fits without a third live buffer.
type recordBatchReader struct {
	ctx             context.Context
	reader          io.Reader
	remaining       int64
	expected, count uint64
	pending         uint32
}

func (r *recordBatchReader) fill(b *recordDecodeBatch) {
	// The backing memory is immutable once this batch is queued. Give every
	// frame its own extent so a retained frame cannot extend into another.
	defer func() {
		start := 0
		for i := 0; i < b.count; i++ {
			end := b.ends[i]
			b.frames[i] = b.buffer[start:end:end]
			start = end
		}
	}()
	for b.count < recordDecodeBatchFrames && r.remaining > 0 {
		if err := r.ctx.Err(); err != nil {
			b.readErr = err
			return
		}
		if r.pending == 0 {
			var frame [4]byte
			if r.remaining < 4 {
				b.readErr = errors.New("private record frame truncated")
				return
			}
			if _, err := io.ReadFull(r.reader, frame[:]); err != nil {
				b.readErr = err
				return
			}
			r.remaining -= 4
			n := binary.LittleEndian.Uint32(frame[:])
			if n == 0 || n > 1<<20 || int64(n) > r.remaining || r.count >= r.expected {
				b.readErr = errors.New("private record frame invalid")
				return
			}
			r.pending = n
		}
		if int(r.pending) > recordDecodeBatchBytes-b.bytes {
			return
		}
		end := b.bytes + int(r.pending)
		if end > cap(b.buffer) {
			capacity := max(end, 2*cap(b.buffer))
			if cap(b.buffer) == 0 {
				capacity = max(end, min(64<<10, end*recordDecodeBatchFrames))
			}
			expanded := make([]byte, b.bytes, min(recordDecodeBatchBytes, capacity))
			copy(expanded, b.buffer)
			b.buffer = expanded
		}
		data := b.buffer[b.bytes:end]
		if _, err := io.ReadFull(r.reader, data); err != nil {
			b.readErr = err
			return
		}
		r.remaining -= int64(r.pending)
		r.pending = 0
		r.count++
		b.buffer = b.buffer[:end]
		b.ends[b.count] = end
		b.count++
		b.bytes = end
	}
}

func runRecordDecodeWorker(ctx context.Context, jobs <-chan *recordDecodeBatch, done chan<- *recordDecodeBatch, workers *sync.WaitGroup) {
	defer workers.Done()
	for b := range jobs {
		for i := 0; i < b.count; i++ {
			if err := ctx.Err(); err != nil {
				b.decodeErr = err
				break
			}
			record, err := decodeRecordFrame(b.frames[i])
			if err != nil {
				b.decodeErr = err
				break
			}
			b.records[i] = record
			b.decoded++
		}
		done <- b
	}
}

// At most two slots are live: each has <=64 owned frames and <=one MiB of
// encoded bytes. Only workers decode; the caller emits every callback in FIFO
// order. An earlier callback failure wins over later non-context read/decode
// failures. Once cancellation is observed, scheduling and callbacks stop; read
// ahead intentionally does not reproduce a serial reader's wall-clock ordering
// of cancellation side effects.
func walkRecordDecodeBatches(ctx context.Context, reader io.Reader, remaining int64, expected uint64, emit func(NormalizedRecord, []byte) error) (uint64, error) {
	return walkRecordDecodeBatchesWithSink(ctx, reader, remaining, expected, recordDecodeSink{raw: emit})
}

// The worker pair is joined before returning, hence before the caller closes
// its decoder or file. Canonical callers may retain their immutable raw bytes,
// so only the typed-only route can recycle a slot after its worker and all of
// its callbacks have finished. Decoded values own their storage in both modes.
func walkRecordDecodeBatchesWithSink(ctx context.Context, reader io.Reader, remaining int64, expected uint64, sink recordDecodeSink) (uint64, error) {
	var slots [2]recordDecodeBatch
	var jobs [2]chan *recordDecodeBatch
	var done [2]chan *recordDecodeBatch
	var workers sync.WaitGroup
	for i := range jobs {
		jobs[i], done[i] = make(chan *recordDecodeBatch), make(chan *recordDecodeBatch, 1)
		workers.Add(1)
		go runRecordDecodeWorker(ctx, jobs[i], done[i], &workers)
	}
	defer func() {
		for _, ch := range jobs {
			close(ch)
		}
		workers.Wait()
	}()
	input := recordBatchReader{ctx: ctx, reader: reader, remaining: remaining, expected: expected}
	submitted, consumed := 0, 0
	ended := false
	fill := func(slot int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := &slots[slot]
		b.reset(sink.typed != nil)
		input.fill(b)
		ended = b.readErr != nil || input.remaining == 0
		if err := ctx.Err(); err != nil {
			return err
		}
		jobs[slot] <- b
		submitted++
		return nil
	}
	for submitted < 2 && !ended {
		if err := fill(submitted); err != nil {
			return input.count, err
		}
	}
	for consumed < submitted {
		slot := consumed % 2
		b := <-done[slot]
		for i := 0; i < b.decoded; i++ {
			if err := ctx.Err(); err != nil {
				return input.count, err
			}
			if err := sink.emit(b.records[i], b.frames[i]); err != nil {
				return input.count, err
			}
		}
		if b.decodeErr != nil {
			return input.count, b.decodeErr
		}
		if b.readErr != nil {
			return input.count, b.readErr
		}
		consumed++
		if !ended {
			if err := fill(slot); err != nil {
				return input.count, err
			}
		} else {
			*b = recordDecodeBatch{}
		}
	}
	return input.count, ctx.Err()
}

type recordContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *recordContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// VerifyStoredSourceObjects checks exact stored bytes without decoding an
// already validated immutable record stream again. A caller may use this only
// to verify an exact cache input identity; it does not certify source semantics,
// rights, freshness, admission, or an unbound partition descriptor.
func VerifyStoredSourceObjects(ctx context.Context, workspace string, source StoredSource) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(source.Records) > 0 && len(source.RecordPartitions) > 0 || len(source.RecordPartitions) > maxRecordPartitions {
		return errors.New("ambiguous private record storage")
	}
	if len(source.RecordPartitions) == 0 {
		for _, record := range source.Records {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := record.Validate(); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	root, err := recordDirectory(workspace, false)
	if err != nil {
		return err
	}
	for _, part := range source.RecordPartitions {
		if err = walkPartition(ctx, root, part, nil); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// WalkStoredSource emits one owned typed record at a time. V1 inline sources
// remain supported. Every V2 object is hash checked before its first record.
func WalkStoredSource(ctx context.Context, workspace string, source StoredSource, emit func(NormalizedRecord) error) error {
	if emit == nil {
		return errors.New("record sink required")
	}
	if len(source.Records) > 0 && len(source.RecordPartitions) > 0 || len(source.RecordPartitions) > maxRecordPartitions {
		return errors.New("ambiguous private record storage")
	}
	if len(source.RecordPartitions) == 0 {
		for _, record := range source.Records {
			if err := ctx.Err(); err != nil {
				return err
			}
			clone, err := cloneRecord(record)
			if err != nil {
				return err
			}
			if err = emit(clone); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	root, err := recordDirectory(workspace, false)
	if err != nil {
		return err
	}
	for _, part := range source.RecordPartitions {
		if err = walkPartition(ctx, root, part, emit); err != nil {
			return err
		}
	}
	return nil
}
