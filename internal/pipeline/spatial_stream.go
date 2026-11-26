package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"math"
	"net/netip"
	"os"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/via3"
)

const spatialStreamDecodedLimit = 96 << 20
const spatialRiskFrameLimit = 1 << 20

var errSpatialStreamCapacity = errors.New("optional spatial stream capacity reached")

type spatialStreamWriter struct {
	spool            *bulkSpool
	ctx              context.Context
	file             *os.File
	writer           *privateRunWriter
	path             string
	reserved         uint64
	decoded, records uint64
	disabled         bool
}

func (s *bulkSpool) newSpatialStream(ctx context.Context) (*spatialStreamWriter, error) {
	file, err := os.CreateTemp(s.root, "spatial-result-")
	if err != nil {
		return nil, err
	}
	w := &spatialStreamWriter{spool: s, ctx: ctx, file: file, path: file.Name()}
	w.writer, err = newPrivateRunWriterWithBudget(ctx, w.reserve, file)
	if errors.Is(err, errSpatialStreamCapacity) {
		return w, w.disable()
	}
	if err != nil {
		_ = w.abort()
		return nil, err
	}
	return w, nil
}

func (w *spatialStreamWriter) reserve(n uint64) error {
	used := w.spool.external() + w.spool.pathBytes + w.spool.store.DiskBytes()
	if used >= w.spool.maximum || n >= w.spool.maximum-used {
		return errSpatialStreamCapacity
	}
	w.spool.pathBytes += n
	w.reserved += n
	return nil
}

func (w *spatialStreamWriter) disable() error {
	w.disabled = true
	return w.abort()
}

func (w *spatialStreamWriter) appendPublic(row encoded) error {
	if w == nil || w.disabled {
		return nil
	}
	bytes := uint64(row.frameBytes())
	if bytes > spatialStreamDecodedLimit-w.decoded {
		return w.disable()
	}
	err := writeRunFrame(w.writer, row)
	if errors.Is(err, errSpatialStreamCapacity) {
		return w.disable()
	}
	if err != nil {
		return err
	}
	w.decoded += bytes
	w.records++
	return nil
}

// Exact-event replay deliberately preserves individual additions. Grouped
// floating sums could change the public quantized result after rounding.
type spatialRiskEvent struct {
	Address  netip.Addr
	Risk     float64
	Families []string
	Origins  []uint32
}

func (e spatialRiskEvent) validate() error {
	if !e.Address.IsValid() || e.Address.Is4In6() || e.Address.Zone() != "" || math.IsNaN(e.Risk) || math.IsInf(e.Risk, 0) || e.Risk < 0 || e.Risk > 1 || len(e.Families) > 1000 || len(e.Origins) > 4096 {
		return errors.New("cached exact-risk event is invalid")
	}
	for _, family := range e.Families {
		if family == "" || len(family) > 256 {
			return errors.New("cached exact-risk family is invalid")
		}
	}
	for _, asn := range e.Origins {
		if !facts.PublicASN(asn) {
			return errors.New("cached exact-risk origin is invalid")
		}
	}
	return nil
}

func (w *spatialStreamWriter) appendRisk(event spatialRiskEvent) error {
	if w == nil || w.disabled {
		return nil
	}
	if err := event.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(data) > spatialRiskFrameLimit || uint64(len(data)+4) > spatialStreamDecodedLimit-w.decoded || w.records >= 200000 {
		return w.disable()
	}
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(data)))
	for _, part := range [][]byte{size[:], data} {
		if _, err = w.writer.Write(part); err != nil {
			if errors.Is(err, errSpatialStreamCapacity) {
				return w.disable()
			}
			return err
		}
	}
	w.decoded += uint64(len(data) + 4)
	w.records++
	return nil
}

func (w *spatialStreamWriter) finish() (spatialCacheStream, bool, error) {
	if w.disabled {
		return spatialCacheStream{}, false, nil
	}
	if w.records == 0 {
		return spatialCacheStream{}, true, w.abort()
	}
	if err := w.writer.Flush(); err != nil {
		if errors.Is(err, errSpatialStreamCapacity) {
			return spatialCacheStream{}, false, w.disable()
		}
		return spatialCacheStream{}, false, err
	}
	if err := errors.Join(w.file.Sync(), w.file.Close()); err != nil {
		return spatialCacheStream{}, false, err
	}
	w.file = nil
	digest, err := cacheFileHash(w.ctx, w.path, int64(w.reserved))
	if err != nil {
		return spatialCacheStream{}, false, err
	}
	return spatialCacheStream{SHA256: digest, Bytes: w.reserved, DecodedBytes: w.decoded, Records: w.records}, true, nil
}

func (w *spatialStreamWriter) abort() error {
	if w.writer != nil {
		_ = w.writer.Close()
		w.writer = nil
	}
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	err := os.Remove(w.path)
	if err == nil || os.IsNotExist(err) {
		w.spool.pathBytes -= w.reserved
		w.reserved = 0
		return nil
	}
	return err
}

func (s *bulkSpool) replayPublic(ctx context.Context, stream spatialCacheStream, emit func(via3.PublicRecord) error) error {
	if stream == (spatialCacheStream{}) {
		return ctx.Err()
	}
	if stream.DecodedBytes > spatialStreamDecodedLimit {
		return errors.New("cached public stream exceeds replay bound")
	}
	input, err := s.openSpatialStream(ctx, stream)
	if err != nil {
		return err
	}
	defer input.Close()
	limit := DefaultLimits().RecordBytes
	reader := &runReader{reader: input.reader, limit: limit}
	consume := func(data []byte) error {
		_, record, err := decodeRunPayload(data, limit)
		if err != nil {
			return err
		}
		if record.Kind >= 8 && record.Kind != 9 {
			return errSpatialPublicRow
		}
		return emit(record)
	}
	if sink := s.replaySink; sink != nil {
		bodies := spatialReplayBodies{compiler: sink.compiler}
		consume = func(data []byte) error {
			frame, err := bodies.canonical(data, limit)
			if err != nil {
				return err
			}
			return sink.append(frame)
		}
	}
	var records, decoded uint64
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		data := input.reader.takeFrame(limit)
		if data == nil {
			data, err = reader.readPayload()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
		records++
		decoded += uint64(len(data)) + 4
		if records > stream.Records || decoded > stream.DecodedBytes {
			return errSpatialPublicRow
		}
		if err = consume(data); err != nil {
			return err
		}
		// The compiler sink copied all retained bytes into its own frame.
		if s.replaySink != nil {
			input.reader.shared = false
		}
	}
	if records != stream.Records || decoded != stream.DecodedBytes {
		return errors.New("cached public stream count differs")
	}
	return input.verify()
}

func (s *bulkSpool) replayRisk(ctx context.Context, stream spatialCacheStream, emit func(spatialRiskEvent) error) error {
	if stream == (spatialCacheStream{}) {
		return ctx.Err()
	}
	if stream.DecodedBytes > spatialStreamDecodedLimit || stream.Records > 200000 {
		return errors.New("cached risk stream exceeds replay bound")
	}
	input, err := s.openSpatialStream(ctx, stream)
	if err != nil {
		return err
	}
	defer input.Close()
	reader := input.reader
	var records, decoded uint64
	var previous netip.Addr
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		var head [4]byte
		_, err = io.ReadFull(reader, head[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		n := binary.LittleEndian.Uint32(head[:])
		if n == 0 || n > spatialRiskFrameLimit || decoded+uint64(n)+4 > stream.DecodedBytes || records >= stream.Records {
			return errors.New("cached risk frame exceeds bound")
		}
		data := make([]byte, n)
		if _, err = io.ReadFull(reader, data); err != nil {
			return err
		}
		var event spatialRiskEvent
		if err = strictDecodeSpatialRisk(data, &event); err != nil {
			return err
		}
		if previous.IsValid() && previous.Compare(event.Address) >= 0 {
			return errors.New("cached risk event order differs")
		}
		previous = event.Address
		if err = emit(event); err != nil {
			return err
		}
		decoded += uint64(n) + 4
		records++
	}
	if records != stream.Records || decoded != stream.DecodedBytes {
		return errors.New("cached risk stream count differs")
	}
	return input.verify()
}

func strictDecodeSpatialRisk(data []byte, event *spatialRiskEvent) error {
	// Match the authenticated producer's canonical bytes, rejecting duplicate,
	// unknown or reordered members in addition to ordinary typed validation.
	if err := json.Unmarshal(data, event); err != nil {
		return err
	}
	canonical, err := json.Marshal(event)
	if err != nil || !bytes.Equal(canonical, data) {
		return errors.New("cached risk event is noncanonical")
	}
	return event.validate()
}

type spatialCountedHash struct {
	hash.Hash
	bytes uint64
}

func (h *spatialCountedHash) Write(data []byte) (int, error) {
	n, err := h.Hash.Write(data)
	h.bytes += uint64(n)
	return n, err
}

type spatialStreamReader struct {
	file     *os.File
	reader   *privateRunReader
	digest   *spatialCountedHash
	expected spatialCacheStream
}

func (s *bulkSpool) openSpatialStream(ctx context.Context, stream spatialCacheStream) (*spatialStreamReader, error) {
	path, err := s.reuse.ObjectPath(stream.SHA256)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != stream.Bytes {
		_ = file.Close()
		return nil, errors.New("cached stream object shape differs")
	}
	digest := &spatialCountedHash{Hash: sha256.New()}
	raw := &cacheContextReader{ctx: ctx, r: io.TeeReader(io.LimitReader(file, int64(stream.Bytes)+1), digest)}
	var magic [len(privateRunMagic)]byte
	if _, err = io.ReadFull(raw, magic[:]); err != nil || string(magic[:]) != privateRunMagic {
		_ = file.Close()
		return nil, errors.New("cached stream version differs")
	}
	reader, err := newPrivateRunReader(raw)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &spatialStreamReader{file: file, reader: reader, digest: digest, expected: stream}, nil
}

func (r *spatialStreamReader) Close() error {
	r.reader.Close()
	return r.file.Close()
}

func (r *spatialStreamReader) verify() error {
	var digest [32]byte
	copy(digest[:], r.digest.Sum(nil))
	if r.digest.bytes != r.expected.Bytes || digest != r.expected.SHA256 {
		return errors.New("cached stream changed during replay")
	}
	return nil
}
