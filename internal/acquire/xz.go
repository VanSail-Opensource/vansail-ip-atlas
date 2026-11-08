package acquire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

// Preflight every block before the decoder can allocate its advertised history.
// xz.ReaderConfig.DictCap is a minimum, not a maximum. The index/footer and
// block layouts follow https://tukaani.org/xz/xz-file-format.txt. The production
// profile accepts one stream, one LZMA2 filter and at most 64 MiB history/block.
// It never accepts the partial first-block reconnaissance decoder as integrity.
func preflightXZ(ctx context.Context, input ArchiveInput, limits ArchiveLimits) (blocks []xzBlock, checkID byte, failure error) {
	if input.ReaderAt == nil || input.Size < 32 || input.Size%4 != 0 || input.Size > limits.CompressedBytes {
		return nil, 0, ErrArchive
	}
	r := &archiveRandomBudget{ctx: ctx, r: input.ReaderAt, remaining: limits.CompressedBytes}
	read := func(offset int64, output []byte) bool {
		if offset < 0 || offset > input.Size-int64(len(output)) {
			return false
		}
		_, err := r.ReadAt(output, offset)
		return err == nil
	}
	var header, footer [12]byte
	if !read(0, header[:]) || !read(input.Size-12, footer[:]) || !bytes.Equal(header[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0}) || header[6] != 0 || footer[10] != 'Y' || footer[11] != 'Z' || !bytes.Equal(header[6:8], footer[8:10]) || crc32.ChecksumIEEE(header[6:8]) != binary.LittleEndian.Uint32(header[8:]) || crc32.ChecksumIEEE(footer[4:10]) != binary.LittleEndian.Uint32(footer[:4]) {
		return nil, 0, ErrArchive
	}
	checkID = header[7]
	var check uint64
	switch header[7] {
	case 0:
		check = 0
	case 1:
		check = 4
	case 4:
		check = 8
	case 10:
		check = 32
	default:
		return nil, 0, ErrArchive
	}
	indexBytes := (uint64(binary.LittleEndian.Uint32(footer[4:8])) + 1) * 4
	if indexBytes < 8 || indexBytes > 1<<20 || indexBytes > uint64(input.Size-24) {
		return nil, 0, ErrArchive
	}
	indexOffset := input.Size - 12 - int64(indexBytes)
	index := make([]byte, int(indexBytes))
	if !read(indexOffset, index) || index[0] != 0 || crc32.ChecksumIEEE(index[:len(index)-4]) != binary.LittleEndian.Uint32(index[len(index)-4:]) {
		return nil, 0, ErrArchive
	}
	body, pos := index[:len(index)-4], 1
	count, ok := xzVLI(body, &pos)
	if !ok || count > 10000 {
		return nil, 0, ErrArchive
	}
	var decoded uint64
	offset := uint64(12)
	for block := uint64(0); block < count; block++ {
		unpadded, ok := xzVLI(body, &pos)
		if !ok {
			return nil, 0, ErrArchive
		}
		outputBytes, ok := xzVLI(body, &pos)
		if !ok || outputBytes > uint64(limits.DecodedBytes)-decoded || unpadded < 8+check || unpadded > uint64(indexOffset)-offset {
			return nil, 0, ErrArchive
		}
		decoded += outputBytes
		padded := (unpadded + 3) &^ uint64(3)
		if padded > uint64(indexOffset)-offset {
			return nil, 0, ErrArchive
		}
		var first [1]byte
		if !read(int64(offset), first[:]) || first[0] == 0 {
			return nil, 0, ErrArchive
		}
		size := (int(first[0]) + 1) * 4
		if uint64(size)+check > unpadded {
			return nil, 0, ErrArchive
		}
		blockHeader := make([]byte, size)
		if !read(int64(offset), blockHeader) || crc32.ChecksumIEEE(blockHeader[:size-4]) != binary.LittleEndian.Uint32(blockHeader[size-4:]) || blockHeader[1]&0x3f != 0 {
			return nil, 0, ErrArchive
		}
		fields, field := blockHeader[:size-4], 2
		if blockHeader[1]&0x40 != 0 {
			v, ok := xzVLI(fields, &field)
			if !ok || v != unpadded-uint64(size)-check {
				return nil, 0, ErrArchive
			}
		}
		if blockHeader[1]&0x80 != 0 {
			v, ok := xzVLI(fields, &field)
			if !ok || v != outputBytes {
				return nil, 0, ErrArchive
			}
		}
		filter, ok := xzVLI(fields, &field)
		if !ok || filter != 0x21 {
			return nil, 0, ErrArchive
		}
		properties, ok := xzVLI(fields, &field)
		if !ok || properties != 1 || field >= len(fields) {
			return nil, 0, ErrArchive
		}
		capacity, err := lzma.DecodeDictCap(fields[field])
		if err != nil || capacity > 64<<20 {
			return nil, 0, ErrArchive
		}
		field++
		for _, b := range fields[field:] {
			if b != 0 {
				return nil, 0, ErrArchive
			}
		}
		blocks = append(blocks, xzBlock{offset: int64(offset) + int64(size), compressed: int64(unpadded) - int64(size) - int64(check), decoded: outputBytes, dictionary: int(capacity), padding: int(padded - unpadded)})
		offset += padded
	}
	if offset != uint64(indexOffset) || len(body)-pos > 3 {
		return nil, 0, ErrArchive
	}
	for _, b := range body[pos:] {
		if b != 0 {
			return nil, 0, ErrArchive
		}
	}
	return blocks, checkID, nil
}

// XZ variable-length integers are canonical and at most 63 bits (nine bytes).
func xzVLI(input []byte, position *int) (uint64, bool) {
	var value uint64
	for i := 0; i < 9 && *position < len(input); i++ {
		b := input[*position]
		*position++
		value |= uint64(b&0x7f) << uint(i*7)
		if b&0x80 == 0 {
			return value, i == 0 || b != 0
		}
	}
	return 0, false
}

type xzBlock struct {
	offset, compressed  int64
	decoded             uint64
	dictionary, padding int
}

// Decode only the preflighted block ranges, rather than letting an untrusted
// index drive a general stream decoder through unexamined hidden block headers.
// Exact compressed/decoded sizes, padding and the block check must all match.
type boundedXZ struct {
	ctx        context.Context
	input      io.ReaderAt
	blocks     []xzBlock
	check      byte
	block      int
	active     *lzma.Reader2
	compressed *io.SectionReader
	digest     hash.Hash
	output     uint64
	failed     bool
}

func newBoundedXZ(ctx context.Context, input ArchiveInput, limits ArchiveLimits) (*boundedXZ, error) {
	blocks, check, err := preflightXZ(ctx, input, limits)
	if err != nil {
		return nil, err
	}
	return &boundedXZ{ctx: ctx, input: input.ReaderAt, blocks: blocks, check: check}, nil
}

func (r *boundedXZ) Read(p []byte) (int, error) {
	if r.failed || r.ctx.Err() != nil {
		return 0, ErrArchive
	}
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if r.active == nil {
			if r.block == len(r.blocks) {
				return 0, io.EOF
			}
			b := r.blocks[r.block]
			r.compressed = io.NewSectionReader(r.input, b.offset, b.compressed)
			var err error
			r.active, err = (lzma.Reader2Config{DictCap: b.dictionary}).NewReader2(&archiveBudget{ctx: r.ctx, r: r.compressed, remaining: b.compressed})
			if err != nil {
				r.failed = true
				return 0, ErrArchive
			}
			switch r.check {
			case 1:
				r.digest = crc32.NewIEEE()
			case 4:
				r.digest = crc64.New(crc64.MakeTable(crc64.ECMA))
			case 10:
				r.digest = sha256.New()
			}
			r.output = 0
		}
		b := r.blocks[r.block]
		if uint64(len(p)) > b.decoded-r.output+1 {
			p = p[:b.decoded-r.output+1]
		}
		n, err := r.active.Read(p)
		r.output += uint64(n)
		if r.digest != nil {
			_, _ = r.digest.Write(p[:n])
		}
		if r.output > b.decoded || r.ctx.Err() != nil || err != nil && err != io.EOF {
			r.failed = true
			return 0, ErrArchive
		}
		if err == io.EOF {
			consumed, seekErr := r.compressed.Seek(0, io.SeekCurrent)
			if seekErr != nil || consumed != b.compressed || r.output != b.decoded || r.verifyBlock(b) != nil {
				r.failed = true
				return 0, ErrArchive
			}
			r.active = nil
			r.compressed = nil
			r.digest = nil
			r.block++
			if n == 0 {
				continue
			}
			return n, nil
		}
		return n, nil
	}
}

func (r *boundedXZ) verifyBlock(b xzBlock) error {
	var expected []byte
	switch r.check {
	case 1:
		expected = make([]byte, 4)
		binary.LittleEndian.PutUint32(expected, r.digest.(hash.Hash32).Sum32())
	case 4:
		expected = make([]byte, 8)
		binary.LittleEndian.PutUint64(expected, r.digest.(hash.Hash64).Sum64())
	case 10:
		expected = r.digest.Sum(nil)
	}
	var stored [35]byte // at most three padding bytes and a 32-byte SHA-256.
	if _, err := r.input.ReadAt(stored[:b.padding+len(expected)], b.offset+b.compressed); err != nil {
		return ErrArchive
	}
	for _, value := range stored[:b.padding] {
		if value != 0 {
			return ErrArchive
		}
	}
	if !bytes.Equal(stored[b.padding:b.padding+len(expected)], expected) {
		return ErrArchive
	}
	return nil
}
