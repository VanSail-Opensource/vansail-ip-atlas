// Package via3 implements the frozen, source-free VIA3 schema-3 container.
package via3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/klauspost/compress/zstd"
)

const (
	MaxFile    = 24 << 20
	MaxSection = 64 << 20
	MaxTotal   = 256 << 20
	MaxWindow  = 8 << 20
	None       = ^uint32(0)
)

type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }
func fail(code string) error   { return &Error{Code: code} }
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "internal"
}

type Section struct {
	ID   uint16
	Data []byte
}
type Shard struct {
	Kind     uint16
	Sections []Section
}

func Hash(data []byte) string       { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func u16(b []byte, p int) uint16    { return binary.LittleEndian.Uint16(b[p : p+2]) }
func u32(b []byte, p int) uint32    { return binary.LittleEndian.Uint32(b[p : p+4]) }
func u64(b []byte, p int) uint64    { return binary.LittleEndian.Uint64(b[p : p+8]) }
func p16(b []byte, p int, v uint16) { binary.LittleEndian.PutUint16(b[p:p+2], v) }
func p32(b []byte, p int, v uint32) { binary.LittleEndian.PutUint32(b[p:p+4], v) }
func p64(b []byte, p int, v uint64) { binary.LittleEndian.PutUint64(b[p:p+8], v) }
func zero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func schema(kind uint16) (int, []uint16) {
	switch kind {
	case 1:
		return 16, []uint16{1, 2, 3, 4, 7}
	case 2:
		return 24, []uint16{1, 3, 7, 8}
	case 3:
		return 16, []uint16{1, 3, 8}
	case 4:
		return 40, []uint16{1, 3, 4, 7, 8}
	case 5:
		return 8, []uint16{1, 3, 8}
	case 6:
		return 32, []uint16{1, 3, 8}
	case 7:
		return 24, []uint16{1, 3, 7, 10}
	case 8:
		return 64, []uint16{2, 3, 7, 11, 12}
	case 9:
		return 16, []uint16{1, 3, 8}
	case 10:
		return 16, []uint16{1, 3, 4, 8}
	case 11:
		return 24, []uint16{2, 3, 4, 9}
	case 12:
		return 16, []uint16{2, 3, 4}
	case 13:
		return 16, []uint16{2, 3}
	case 14:
		return 0, []uint16{5, 6}
	default:
		return 0, nil
	}
}

func Vector(width int, rows ...[]byte) []byte {
	b := make([]byte, 8+width*len(rows))
	p32(b, 0, uint32(len(rows)))
	p32(b, 4, uint32(width))
	for i, row := range rows {
		if len(row) != width {
			panic("via3: wrong vector row width")
		}
		copy(b[8+i*width:], row)
	}
	return b
}
func BytesVector(data []byte) []byte {
	b := make([]byte, 8+len(data))
	p32(b, 0, uint32(len(data)))
	p32(b, 4, 1)
	copy(b[8:], data)
	return b
}
func (s *Shard) Section(id uint16) []byte {
	i := sort.Search(len(s.Sections), func(i int) bool { return s.Sections[i].ID >= id })
	if i < len(s.Sections) && s.Sections[i].ID == id {
		return s.Sections[i].Data
	}
	return nil
}
func (s *Shard) Rows(id uint16) ([]byte, int) {
	b := s.Section(id)
	if len(b) < 8 {
		return nil, 0
	}
	return b[8:], int(u32(b, 4))
}
func (s *Shard) Record(index uint32) []byte {
	b, w := s.Rows(3)
	if w == 0 || uint64(index) >= uint64(len(b)/w) {
		return nil
	}
	return b[int(index)*w : (int(index)+1)*w]
}

func Write(ctx context.Context, shard Shard) ([]byte, error) {
	if err := Validate(shard); err != nil {
		return nil, err
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(3)), zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(MaxWindow), zstd.WithEncoderCRC(true), zstd.WithSingleSegment(true))
	if err != nil {
		return nil, err
	}
	defer encoder.Close()
	count := len(shard.Sections)
	offset := 64 + count*64
	b := make([]byte, offset)
	copy(b, "VIA3")
	p16(b, 4, 3)
	p16(b, 6, 3)
	p16(b, 8, 64)
	p16(b, 10, shard.Kind)
	p32(b, 16, uint32(count))
	p64(b, 20, 64)
	b[44] = 1
	var total uint64
	for i, section := range shard.Sections {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var frame []byte
		if len(section.Data) <= MaxWindow {
			frame = encoder.EncodeAll(section.Data, nil)
		} else {
			large, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(3)), zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(MaxWindow), zstd.WithEncoderCRC(true), zstd.WithSingleSegment(false))
			if err != nil {
				return nil, err
			}
			frame = large.EncodeAll(section.Data, nil)
			large.Close()
		}
		if len(b)+len(frame) >= MaxFile {
			return nil, fail("length")
		}
		d := b[64+i*64 : 64+(i+1)*64]
		p16(d, 0, section.ID)
		d[2] = 1
		p64(d, 8, uint64(len(b)))
		p64(d, 16, uint64(len(frame)))
		p64(d, 24, uint64(len(section.Data)))
		sum := sha256.Sum256(section.Data)
		copy(d[32:], sum[:])
		b = append(b, frame...)
		total += uint64(len(section.Data))
	}
	p64(b, 28, uint64(len(b)))
	p64(b, 36, total)
	return b, nil
}

// frameBounds checks the complete single-frame envelope before decoder allocation.
func frameBounds(frame []byte, expected uint64) error {
	var h zstd.Header
	if err := h.Decode(frame); err != nil {
		return fail("codec")
	}
	window := h.WindowSize
	if h.SingleSegment {
		window = h.FrameContentSize
	}
	if h.Skippable || h.DictionaryID != 0 || !h.HasFCS || !h.HasCheckSum || h.FrameContentSize != expected {
		return fail("codec")
	}
	if window > MaxWindow {
		return fail("decompression_limit")
	}
	p := h.HeaderSize
	for {
		if p+3 > len(frame) {
			return fail("codec")
		}
		v := uint32(frame[p]) | uint32(frame[p+1])<<8 | uint32(frame[p+2])<<16
		p += 3
		last, typ, n := v&1, (v>>1)&3, int(v>>3)
		if typ == 3 || n > 128<<10 {
			return fail("codec")
		}
		if typ == 1 {
			n = 1
		}
		if n > len(frame)-p {
			return fail("codec")
		}
		p += n
		if last != 0 {
			break
		}
	}
	if p+4 != len(frame) {
		return fail("codec")
	}
	return nil
}

func Read(ctx context.Context, b []byte) (Shard, error) {
	if len(b) < 64 || len(b) >= MaxFile {
		return Shard{}, fail("length")
	}
	if string(b[:4]) != "VIA3" || u16(b, 4) != 3 || u16(b, 6) != 3 {
		return Shard{}, fail("version")
	}
	if u16(b, 8) != 64 || u32(b, 12) != 0 || b[44] != 1 || !zero(b[45:64]) {
		return Shard{}, fail("header")
	}
	kind := u16(b, 10)
	_, ids := schema(kind)
	if ids == nil {
		return Shard{}, fail("schema")
	}
	count := uint64(u32(b, 16))
	if count == 0 || count > 256 || u64(b, 20) != 64 || u64(b, 28) != uint64(len(b)) || u64(b, 36) > MaxTotal {
		return Shard{}, fail("bounds")
	}
	end := 64 + count*64
	if end > uint64(len(b)) {
		return Shard{}, fail("bounds")
	}
	type descriptor struct {
		id                      uint16
		offset, length, decoded uint64
		hash                    [32]byte
	}
	ds := make([]descriptor, 0, int(count))
	var total uint64
	previous := uint16(0)
	for i := uint64(0); i < count; i++ {
		d := b[64+i*64 : 64+(i+1)*64]
		id := u16(d, 0)
		off, n, out := u64(d, 8), u64(d, 16), u64(d, 24)
		if id <= previous || d[2] != 1 || d[3] != 0 || !zero(d[4:8]) {
			return Shard{}, fail("schema")
		}
		previous = id
		if off != end || n == 0 || n > uint64(len(b))-end || out > MaxSection || total+out > MaxTotal {
			return Shard{}, fail("bounds")
		}
		var hash [32]byte
		copy(hash[:], d[32:])
		ds = append(ds, descriptor{id, off, n, out, hash})
		end += n
		total += out
	}
	if end != uint64(len(b)) || total != u64(b, 36) {
		return Shard{}, fail("bounds")
	}
	if len(ids) != len(ds) {
		return Shard{}, fail("schema")
	}
	for i, id := range ids {
		if ds[i].id != id {
			return Shard{}, fail("schema")
		}
	}
	shard := Shard{Kind: kind, Sections: make([]Section, 0, len(ds))}
	for _, d := range ds {
		if err := ctx.Err(); err != nil {
			return Shard{}, err
		}
		frame := b[d.offset : d.offset+d.length]
		if err := frameBounds(frame, d.decoded); err != nil {
			return Shard{}, err
		}
		decoder, err := zstd.NewReader(bytes.NewReader(frame), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(MaxSection), zstd.WithDecoderMaxWindow(MaxWindow), zstd.WithDecoderLowmem(true))
		if err != nil {
			return Shard{}, fail("codec")
		}
		out := make([]byte, int(d.decoded))
		_, err = io.ReadFull(decoder, out)
		if err == nil {
			var extra [1]byte
			n, e := decoder.Read(extra[:])
			if n != 0 || e != io.EOF {
				err = fmt.Errorf("decode termination: %v", e)
			}
		}
		decoder.Close()
		if err != nil {
			return Shard{}, fail("integrity")
		}
		sum := sha256.Sum256(out)
		if sum != d.hash {
			return Shard{}, fail("integrity")
		}
		shard.Sections = append(shard.Sections, Section{ID: d.id, Data: out})
	}
	if err := Validate(shard); err != nil {
		return Shard{}, err
	}
	return shard, nil
}
