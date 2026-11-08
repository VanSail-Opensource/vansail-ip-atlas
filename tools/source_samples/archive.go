package main

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/ulikunitz/xz/lzma"
)

// Decode only the first LZMA2 block. The xz package's DictCap is a minimum,
// so passing it to xz.NewReader does not impose a memory ceiling. A prefix can
// never reference history longer than its total decoded output: cap the ring
// at maxTransferBytes even when the archive advertises a larger dictionary.
func xzBlockPrefix(data []byte) ([]byte, error) {
	if len(data) < 24 || !bytes.Equal(data[:6], []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0}) ||
		data[6] != 0 || crc32.ChecksumIEEE(data[6:8]) != binary.LittleEndian.Uint32(data[8:12]) {
		return nil, errors.New("invalid XZ stream header")
	}
	size := (int(data[12]) + 1) * 4
	if data[12] == 0 || size < 8 || 12+size > len(data) {
		return nil, errors.New("truncated XZ block header")
	}
	header := data[12 : 12+size]
	if crc32.ChecksumIEEE(header[:size-4]) != binary.LittleEndian.Uint32(header[size-4:]) {
		return nil, errors.New("invalid XZ block header checksum")
	}
	flags := header[1]
	if flags&0x3f != 0 {
		return nil, errors.New("only one XZ LZMA2 filter is supported")
	}
	pos := 2
	readVar := func() (uint64, error) {
		v, n := binary.Uvarint(header[pos : size-4])
		if n <= 0 || v > 1<<63-1 {
			return 0, errors.New("invalid XZ header integer")
		}
		pos += n
		return v, nil
	}
	if flags&0x40 != 0 {
		if _, err := readVar(); err != nil {
			return nil, err
		}
	}
	if flags&0x80 != 0 {
		if _, err := readVar(); err != nil {
			return nil, err
		}
	}
	id, err := readVar()
	if err != nil {
		return nil, err
	}
	props, err := readVar()
	if err != nil || id != 0x21 || props != 1 || pos >= size-4 {
		return nil, errors.New("unsupported XZ filter")
	}
	capacity, err := lzma.DecodeDictCap(header[pos])
	if err != nil {
		return nil, errors.New("invalid XZ dictionary property")
	}
	pos++
	for _, b := range header[pos : size-4] {
		if b != 0 {
			return nil, errors.New("invalid XZ header padding")
		}
	}
	r, err := (lzma.Reader2Config{DictCap: int(min(capacity, int64(maxTransferBytes)))}).NewReader2(bytes.NewReader(data[12+size:]))
	if err != nil {
		return nil, errors.New("invalid XZ LZMA2 stream")
	}
	out, err := io.ReadAll(io.LimitReader(r, maxTransferBytes))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, errors.New("invalid XZ LZMA2 payload")
	}
	return out, nil
}

func safeArchiveName(name string) bool {
	return name != "" && utf8.ValidString(name) && !strings.HasPrefix(name, "/") &&
		!strings.Contains(name, "\\") && !strings.Contains(name, ":") &&
		!strings.Contains("/"+name+"/", "/../") && name != ".." && !strings.HasPrefix(path.Clean(name), "../")
}

// ZIP central directories often lie beyond the bounded transfer. Read the first
// local CSV member only; no paths are extracted and no archive integrity is claimed.
func zipPrefix(data []byte) ([]byte, string, error) {
	for count := 0; count < 64; count++ {
		if len(data) < 30 || !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
			return nil, "", errors.New("no CSV member in ZIP prefix")
		}
		flags := binary.LittleEndian.Uint16(data[6:8])
		method := binary.LittleEndian.Uint16(data[8:10])
		compressed := uint64(binary.LittleEndian.Uint32(data[18:22]))
		n := int(binary.LittleEndian.Uint16(data[26:28]))
		extra := int(binary.LittleEndian.Uint16(data[28:30]))
		start := 30 + n + extra
		if start > len(data) || flags&1 != 0 {
			return nil, "", errors.New("truncated or encrypted ZIP header")
		}
		name := string(data[30 : 30+n])
		if !safeArchiveName(name) {
			return nil, "", errors.New("unsafe ZIP member name")
		}
		if !strings.HasSuffix(strings.ToLower(name), ".csv") {
			if flags&8 != 0 || compressed > uint64(len(data)-start) {
				return nil, "", errors.New("cannot skip incomplete non-CSV ZIP member")
			}
			data = data[start+int(compressed):]
			continue
		}
		payload := data[start:]
		if compressed > 0 && compressed < uint64(len(payload)) {
			payload = payload[:int(compressed)]
		}
		var reader io.Reader = bytes.NewReader(payload)
		switch method {
		case 0:
			if flags&8 != 0 {
				return nil, "", errors.New("unbounded stored ZIP member")
			}
		case 8:
			r := flate.NewReader(reader)
			defer r.Close()
			reader = r
		default:
			return nil, "", errors.New("unsupported ZIP compression method")
		}
		out, err := io.ReadAll(io.LimitReader(reader, maxSampleBytes))
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, "", errors.New("invalid ZIP deflate stream")
		}
		if len(out) == 0 {
			return nil, "", errors.New("empty ZIP CSV prefix")
		}
		return textPrefix(bytes.NewReader(out), maxSampleBytes), name, nil
	}
	return nil, "", errors.New("ZIP entry budget exceeded")
}

func rejectNonData(payload []byte) error {
	p := bytes.TrimSpace(limitBytes(payload, 1024))
	lower := strings.ToLower(string(p))
	if strings.Contains(lower, "<!doctype html") || strings.Contains(lower, "<html") ||
		strings.HasPrefix(lower, "<?xml") || strings.HasPrefix(lower, "version https://git-lfs.github.com/spec/") ||
		strings.HasPrefix(lower, "{\"error\"") || strings.HasPrefix(lower, "{\"message\"") {
		return errors.New("response is a web/error document or Git LFS pointer, not source data")
	}
	return nil
}
