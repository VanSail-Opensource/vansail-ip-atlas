package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

// Only private temporary runs use this container. Logical record frames and all
// record/sort/partition limits are unchanged. Each independent 1-MiB segment is
// length-bound and authenticated before exposing decoded bytes. A terminator
// makes truncation at a complete segment boundary distinguishable from EOF.
const privateRunMagic = "VPRZ\x01\x00\x00\x00"
const privateRunBlockBytes = 1 << 20
const privateRunStoredMax = privateRunBlockBytes + 1024
const privateRunSegmentHeader = 40

type privateRunWriter struct {
	ctx              context.Context
	reserve          func(uint64) error
	output           io.Writer
	encoder          *zstd.Encoder
	pending, encoded []byte
	finished         bool
	failure          error
}

func newPrivateRunWriter(c *compiler, output io.Writer) (*privateRunWriter, error) {
	return newPrivateRunWriterWithBudget(c.ctx, c.reserve, output)
}

func newPrivateRunWriterWithBudget(ctx context.Context, reserve func(uint64) error, output io.Writer) (*privateRunWriter, error) {
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithWindowSize(privateRunBlockBytes), zstd.WithEncoderCRC(true), zstd.WithSingleSegment(true))
	if err != nil {
		return nil, err
	}
	w := &privateRunWriter{ctx: ctx, reserve: reserve, output: output, encoder: encoder}
	if err := w.store([]byte(privateRunMagic)); err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}

func (w *privateRunWriter) store(p []byte) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if err := w.reserve(uint64(len(p))); err != nil {
		return err
	}
	n, err := w.output.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return err
}

func (w *privateRunWriter) Write(p []byte) (int, error) {
	if w.failure != nil {
		return 0, w.failure
	}
	if w.finished {
		return 0, errors.New("private compressed run closed")
	}
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	original := len(p)
	for len(p) > 0 {
		n := min(len(p), privateRunBlockBytes-len(w.pending))
		w.pending = append(w.pending, p[:n]...)
		p = p[n:]
		if len(w.pending) == privateRunBlockBytes {
			if err := w.segment(); err != nil {
				w.failure = err
				return original - len(p), err
			}
		}
	}
	return original, nil
}

func (w *privateRunWriter) segment() error {
	if len(w.pending) == 0 {
		return nil
	}
	w.encoded = w.encoder.EncodeAll(w.pending, w.encoded[:0])
	if len(w.encoded) > privateRunStoredMax {
		return errors.New("private compressed segment exceeds limit")
	}
	var header [privateRunSegmentHeader]byte
	binary.LittleEndian.PutUint32(header[:4], uint32(len(w.encoded)))
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(w.pending)))
	digest := sha256.Sum256(w.pending)
	copy(header[8:], digest[:])
	// Reserve the entire segment before writing either its header or body.
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if err := w.reserve(uint64(len(header) + len(w.encoded))); err != nil {
		return err
	}
	for _, p := range [][]byte{header[:], w.encoded} {
		n, err := w.output.Write(p)
		if err != nil {
			return err
		}
		if n != len(p) {
			return io.ErrShortWrite
		}
	}
	w.pending = w.pending[:0]
	return nil
}

// Flush finalizes the logical run; no bytes may be appended afterward.
func (w *privateRunWriter) Flush() error {
	if w.failure != nil {
		return w.failure
	}
	if w.finished {
		return nil
	}
	if err := w.segment(); err != nil {
		w.failure = err
		return err
	}
	if err := w.store(make([]byte, privateRunSegmentHeader)); err != nil {
		w.failure = err
		return err
	}
	w.finished = true
	return w.Close()
}

// Close releases codec buffers on both success and failure; it never commits a
// partial run. The owning compiler closes/removes its own file separately.
func (w *privateRunWriter) Close() error {
	w.finished = true
	w.pending = nil
	w.encoded = nil
	if w.encoder != nil {
		err := w.encoder.Close()
		w.encoder = nil
		return err
	}
	return nil
}

// This bound includes even incompressible segments and all framing. It is only
// a conservative preflight; the sink charges the actual physical bytes.
func privateRunStoredBound(logical uint64) uint64 {
	segments := (logical + privateRunBlockBytes - 1) / privateRunBlockBytes
	return uint64(len(privateRunMagic)+privateRunSegmentHeader) + logical + segments*(1024+privateRunSegmentHeader)
}

type privateRunReader struct {
	input            io.Reader
	decoder          *zstd.Decoder
	encoded, decoded []byte
	offset           int
	ended            bool
	failure          error
}

func newPrivateRunReader(input io.Reader) (*privateRunReader, error) {
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(privateRunBlockBytes), zstd.WithDecoderMaxWindow(privateRunBlockBytes), zstd.WithDecodeAllCapLimit(true))
	if err != nil {
		return nil, err
	}
	return &privateRunReader{input: input, decoder: decoder}, nil
}

func (r *privateRunReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.failure != nil {
		return 0, r.failure
	}
	if r.offset == len(r.decoded) {
		if r.ended {
			return 0, io.EOF
		}
		if err := r.segment(); err != nil {
			r.failure = err
			return 0, err
		}
	}
	n := copy(p, r.decoded[r.offset:])
	r.offset += n
	return n, nil
}

func (r *privateRunReader) segment() error {
	var header [privateRunSegmentHeader]byte
	if _, err := io.ReadFull(r.input, header[:]); err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	stored := binary.LittleEndian.Uint32(header[:4])
	decoded := binary.LittleEndian.Uint32(header[4:8])
	if stored == 0 && decoded == 0 {
		if !bytes.Equal(header[8:], make([]byte, 32)) {
			return errors.New("private run terminator invalid")
		}
		var extra [1]byte
		if n, err := io.ReadFull(r.input, extra[:]); n != 0 || err != io.EOF {
			return errors.New("private run trailing bytes")
		}
		r.ended = true
		return io.EOF
	}
	if stored == 0 || stored > privateRunStoredMax || decoded == 0 || decoded > privateRunBlockBytes {
		return errors.New("private run segment size invalid")
	}
	r.encoded = resizePrivateRun(r.encoded, int(stored))
	if _, err := io.ReadFull(r.input, r.encoded); err != nil {
		return err
	}
	if err := validatePrivateRunFrame(r.encoded, uint64(decoded)); err != nil {
		return err
	}
	r.decoded = resizePrivateRun(r.decoded, int(decoded))
	result, err := r.decoder.DecodeAll(r.encoded, r.decoded[:0:int(decoded)])
	if err != nil {
		return err
	}
	if len(result) != int(decoded) {
		return errors.New("private run decoded length mismatch")
	}
	digest := sha256.Sum256(result)
	if !bytes.Equal(digest[:], header[8:]) {
		return errors.New("private run segment digest mismatch")
	}
	r.decoded = result
	r.offset = 0
	return nil
}
func resizePrivateRun(p []byte, n int) []byte {
	if cap(p) < n {
		return make([]byte, n)
	}
	return p[:n]
}
func (r *privateRunReader) Close() {
	if r.decoder != nil {
		r.decoder.Close()
		r.decoder = nil
	}
	r.encoded = nil
	r.decoded = nil
	r.offset = 0
	r.ended = true
}

// Reject concatenated/skippable/dictionary frames and oversized windows before
// decoding. Content size, CRC, exact frame extent and decoded SHA are all bound.
func validatePrivateRunFrame(data []byte, decoded uint64) error {
	var h zstd.Header
	if err := h.Decode(data); err != nil {
		return err
	}
	if len(data) < 5 || data[4]&0x1b != 0 || h.Skippable || h.DictionaryID != 0 || !h.HasFCS || !h.HasCheckSum || h.FrameContentSize != decoded || h.WindowSize > privateRunBlockBytes || h.SingleSegment && h.FrameContentSize > privateRunBlockBytes {
		return errors.New("private run Zstandard profile invalid")
	}
	offset := h.HeaderSize
	for blocks := 0; ; blocks++ {
		if blocks > 1024 || offset+3 > len(data) {
			return errors.New("private run Zstandard blocks invalid")
		}
		raw := uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16
		offset += 3
		kind := (raw >> 1) & 3
		size := int(raw >> 3)
		if kind == 3 || size > 128<<10 {
			return errors.New("private run Zstandard block invalid")
		}
		if kind == 1 {
			size = 1
		}
		if size > len(data)-offset {
			return io.ErrUnexpectedEOF
		}
		offset += size
		if raw&1 != 0 {
			break
		}
	}
	if offset+4 != len(data) {
		return errors.New("private run Zstandard extent invalid")
	}
	return nil
}

type privateRunFile struct {
	*os.File
	compressed *privateRunReader
}

func (f *privateRunFile) Close() error {
	if f.compressed != nil {
		f.compressed.Close()
	}
	return f.File.Close()
}
