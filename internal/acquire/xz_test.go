package acquire

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"

	"github.com/ulikunitz/xz"
)

func xzFixture(t *testing.T, data []byte, blockSize int64) []byte {
	t.Helper()
	var output bytes.Buffer
	w, err := (xz.WriterConfig{BlockSize: blockSize}).NewWriter(&output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestXZStreamsAndTar(t *testing.T) {
	data := bytes.Repeat([]byte("synthetic\n"), 20)
	for _, blockSize := range []int64{0, 32} {
		input := xzFixture(t, data, blockSize)
		output := map[string]string{}
		if err := WalkArchive(context.Background(), inputArchive(input), "xz", DefaultArchiveLimits(), testConsume(output)); err != nil || output["payload"] != string(data) {
			t.Fatalf("XZ block size %d: %v", blockSize, err)
		}
	}
	raw := archiveFixture(t, "tar", []*tar.Header{{Name: "facts.csv", Mode: 0600, Size: 3, Typeflag: tar.TypeReg}})
	output := map[string]string{}
	if err := WalkArchive(context.Background(), inputArchive(xzFixture(t, raw, 1024)), "tar.xz", DefaultArchiveLimits(), testConsume(output)); err != nil || output["facts.csv"] != "xxx" {
		t.Fatalf("tar.xz: %v", err)
	}
}

func TestXZRejectsOversizedDictionaryBeforeConsumer(t *testing.T) {
	input := xzFixture(t, []byte("synthetic"), 0)
	if input[14] != 0x21 || input[15] != 1 {
		t.Fatal("unexpected fixture header")
	}
	input[16] = 40 // A valid 4 GiB advertised dictionary must never be allocated.
	size := (int(input[12]) + 1) * 4
	binary.LittleEndian.PutUint32(input[12+size-4:], crc32.ChecksumIEEE(input[12:12+size-4]))
	called := false
	err := WalkArchive(context.Background(), inputArchive(input), "xz", DefaultArchiveLimits(), func(string, io.Reader) error { called = true; return nil })
	if err != ErrArchive || called {
		t.Fatal("dictionary bomb reached consumer")
	}
}

func TestXZRejectsCorruptionConcatenationAndBounds(t *testing.T) {
	valid := xzFixture(t, bytes.Repeat([]byte("x"), 2048), 128)
	for _, input := range [][]byte{
		valid[:len(valid)-1], append(append([]byte{}, valid...), valid...), append(append([]byte{}, valid...), 0, 0, 0, 0),
	} {
		if err := WalkArchive(context.Background(), inputArchive(input), "xz", DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
			t.Fatal("corrupt/trailing XZ accepted")
		}
	}
	for _, offset := range []int{8, 17, len(valid) - 12, len(valid) - 1} {
		input := append([]byte{}, valid...)
		input[offset] ^= 1
		if err := WalkArchive(context.Background(), inputArchive(input), "xz", DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
			t.Fatal("corrupt XZ accepted")
		}
	}
	limits := DefaultArchiveLimits()
	limits.DecodedBytes, limits.EntryBytes = 1024, 1024
	called := false
	if err := WalkArchive(context.Background(), inputArchive(valid), "xz", limits, func(string, io.Reader) error { called = true; return nil }); err != ErrArchive || called {
		t.Fatal("decoded bomb passed preflight")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WalkArchive(ctx, inputArchive(valid), "xz", DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
		t.Fatal("cancelled XZ accepted")
	}
}

func TestXZForgedIndexCannotExposeUnexaminedBlockHeader(t *testing.T) {
	input := xzFixture(t, bytes.Repeat([]byte("x"), 64), 32)
	footer := input[len(input)-12:]
	indexSize := (int(binary.LittleEndian.Uint32(footer[4:8])) + 1) * 4
	indexOffset := len(input) - 12 - indexSize
	index := input[indexOffset : len(input)-12]
	position := 1
	count, ok := xzVLI(index, &position)
	if !ok || count != 2 {
		t.Fatal("expected two blocks")
	}
	first, ok := xzVLI(index, &position)
	if !ok {
		t.Fatal("invalid fixture index")
	}
	secondOffset := 12 + int((first+3)&^uint64(3))
	input[secondOffset+4] = 40 // Unexamined header would advertise 4 GiB history.
	headerSize := (int(input[secondOffset]) + 1) * 4
	binary.LittleEndian.PutUint32(input[secondOffset+headerSize-4:], crc32.ChecksumIEEE(input[secondOffset:secondOffset+headerSize-4]))
	// Claim both blocks form one larger block. An ordinary XZ stream decoder
	// follows the actual first end marker before discovering the index mismatch.
	var forged [32]byte
	forged[1] = 1
	n := 2 + binary.PutUvarint(forged[2:], uint64(indexOffset-12))
	n += binary.PutUvarint(forged[n:], 64)
	for n%4 != 0 {
		n++
	}
	binary.LittleEndian.PutUint32(forged[n:], crc32.ChecksumIEEE(forged[:n]))
	n += 4
	newFooter := append([]byte{}, footer...)
	binary.LittleEndian.PutUint32(newFooter[4:], uint32(n/4-1))
	binary.LittleEndian.PutUint32(newFooter, crc32.ChecksumIEEE(newFooter[4:10]))
	data := append(append(append([]byte{}, input[:indexOffset]...), forged[:n]...), newFooter...)
	if err := WalkArchive(context.Background(), inputArchive(data), "xz", DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
		t.Fatal("forged block framing accepted")
	}
}
