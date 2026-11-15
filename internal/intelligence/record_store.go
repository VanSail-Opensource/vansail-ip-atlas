package intelligence

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	if len(data) > w.store.limits.RecordBytes || int64(len(data)+4+len(recordHeader)) > w.store.limits.PartitionBytes {
		return errors.New("private record byte budget exceeded")
	}
	if w.file != nil && (w.count >= w.store.limits.PartitionRecords || int64(len(data)+4) > w.store.limits.PartitionBytes-w.decoded) {
		if err = w.finishPartition(); err != nil {
			return err
		}
	}
	if w.file == nil {
		if err = w.start(); err != nil {
			return err
		}
	}
	n := int64(len(data) + 4)
	w.decoded += n
	var frame [4]byte
	binary.LittleEndian.PutUint32(frame[:], uint32(len(data)))
	if _, err = w.buffer.Write(frame[:]); err != nil {
		return err
	}
	if _, err = w.buffer.Write(data); err != nil {
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
		w.store.release(w.size)
	} else if !os.IsNotExist(err) {
		return err
	} else {
		w.store.mu.Lock()
		if w.store.objects >= maxRecordPartitions {
			w.store.mu.Unlock()
			return errors.New("private partition inventory exceeded")
		}
		err = os.Rename(w.file.Name(), destination)
		if err == nil {
			w.store.objects++
		}
		w.store.mu.Unlock()
		if err != nil {
			return err
		}
	}
	w.parts = append(w.parts, part)
	w.file = nil
	w.buffer = nil
	w.size = 0
	w.decoded = 0
	w.count = 0
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
	if emit == nil {
		return nil
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	parsedHash := sha256.New()
	var logical io.Reader = &recordContextReader{ctx, io.TeeReader(io.LimitReader(file, part.Bytes), parsedHash)}
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
		data := make([]byte, int(n))
		if _, err = io.ReadFull(buffer, data); err != nil {
			return err
		}
		remaining -= int64(n)
		if !utf8.Valid(data) {
			return errors.New("private record UTF-8 invalid")
		}
		var record NormalizedRecord
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&record); err != nil {
			return err
		}
		if err = record.Validate(); err != nil {
			return err
		}
		if err = decoder.Decode(new(json.RawMessage)); err != io.EOF {
			return errors.New("private record trailing data")
		}
		if err = emit(record); err != nil {
			return err
		}
		count++
	}
	if count != part.Records {
		return errors.New("private record count invalid")
	}
	if _, err = buffer.ReadByte(); err != io.EOF {
		return errors.New("private partition decoded length or checksum invalid")
	}
	var parsedDigest [32]byte
	copy(parsedDigest[:], parsedHash.Sum(nil))
	if parsedDigest != part.SHA256 {
		return errors.New("private partition changed while reading")
	}
	return ctx.Err()
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
