package intelligence

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

type compressedRecordWriter struct{ owner *RecordWriter }

func (w *compressedRecordWriter) Write(p []byte) (int, error) {
	o := w.owner
	if err := o.ctx.Err(); err != nil {
		return 0, err
	}
	if o.closed {
		return 0, errors.New("private record writer closed")
	}
	n := int64(len(p))
	if n > 64<<20-o.size {
		return 0, errors.New("encoded private partition exceeds limit")
	}
	if err := o.store.reserve(n); err != nil {
		return 0, err
	}
	o.size += n
	return io.MultiWriter(o.file, o.digest).Write(p)
}

// Preflight a single ordinary checksummed dictionary-free Zstandard frame.
// Header/block reads are bounded; neither a claimed window nor frame size can
// make the decoder allocate before this profile has been established.
func validatePrivateFrame(ctx context.Context, file *os.File, part RecordPartition) error {
	var outer [len(compressedRecordHeader)]byte
	if _, err := file.ReadAt(outer[:], 0); err != nil || string(outer[:]) != compressedRecordHeader {
		return errors.New("compressed private partition header invalid")
	}
	end := part.Bytes
	offset := int64(len(compressedRecordHeader))
	read := func(n int) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if n < 0 || int64(n) > end-offset {
			return nil, errors.New("private Zstandard frame truncated")
		}
		data := make([]byte, n)
		if _, err := file.ReadAt(data, offset); err != nil {
			return nil, err
		}
		offset += int64(n)
		return data, nil
	}
	magic, err := read(4)
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(magic) != 0xfd2fb528 {
		return errors.New("private Zstandard frame magic invalid")
	}
	flags, err := read(1)
	if err != nil {
		return err
	}
	descriptor := flags[0]
	if descriptor&0x1b != 0 || descriptor&4 == 0 {
		return errors.New("private Zstandard descriptor unsupported")
	}
	single := descriptor&0x20 != 0
	var window uint64
	if !single {
		raw, err := read(1)
		if err != nil {
			return err
		}
		exponent := uint(raw[0]>>3) + 10
		base := uint64(1) << exponent
		window = base + (base/8)*uint64(raw[0]&7)
		if window > 1<<20 {
			return errors.New("private Zstandard window exceeds limit")
		}
	}
	sizeFlag := descriptor >> 6
	length := 0
	switch sizeFlag {
	case 0:
		if single {
			length = 1
		}
	case 1:
		length = 2
	case 2:
		length = 4
	case 3:
		length = 8
	}
	if length > 0 {
		raw, err := read(length)
		if err != nil {
			return err
		}
		var size uint64
		for i, value := range raw {
			size |= uint64(value) << uint(8*i)
		}
		if length == 2 {
			size += 256
		}
		if size != uint64(part.DecodedBytes) {
			return errors.New("private Zstandard content size mismatch")
		}
		if single {
			window = size
			if window > 1<<20 {
				return errors.New("private Zstandard window exceeds limit")
			}
		}
	}
	for blocks := 0; ; blocks++ {
		if blocks >= 65536 {
			return errors.New("private Zstandard block budget exceeded")
		}
		raw, err := read(3)
		if err != nil {
			return err
		}
		header := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16
		kind := (header >> 1) & 3
		size := int64(header >> 3)
		if kind == 3 || size > 128<<10 {
			return errors.New("private Zstandard block invalid")
		}
		stored := size
		if kind == 1 {
			stored = 1
		}
		if stored > end-offset {
			return errors.New("private Zstandard block truncated")
		}
		offset += stored
		if header&1 != 0 {
			break
		}
	}
	if _, err = read(4); err != nil {
		return err
	}
	if offset != end {
		return errors.New("private Zstandard trailing data or concatenated frame")
	}
	return nil
}
