package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/klauspost/compress/zstd"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func compressedRunFixture(t *testing.T, data []byte) ([]byte, uint64) {
	t.Helper()
	c := &compiler{ctx: context.Background(), options: Options{Limits: DefaultLimits()}}
	var out bytes.Buffer
	w, err := newPrivateRunWriter(c, &out)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err = w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	if c.used != uint64(out.Len()) {
		t.Fatalf("physical charge %d != %d", c.used, out.Len())
	}
	return out.Bytes(), c.used
}

func TestPrivateRunCompressionRoundTripAndBounds(t *testing.T) {
	for _, n := range []int{0, 1, privateRunBlockBytes - 1, privateRunBlockBytes, privateRunBlockBytes + 1, 3*privateRunBlockBytes + 91} {
		data := bytes.Repeat([]byte("bounded framed public records\n"), n/len("bounded framed public records\n")+1)[:n]
		encoded, _ := compressedRunFixture(t, data)
		r, err := newPrivateRunReader(bytes.NewReader(encoded[len(privateRunMagic):]))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("length %d: %v", n, err)
		}
		if n > privateRunBlockBytes && len(encoded) >= n/4 {
			t.Fatalf("ineffective private compression: %d/%d", len(encoded), n)
		}
	}
}

func TestPrivateRunCompressionRejectsCorruptionAndTruncation(t *testing.T) {
	good, _ := compressedRunFixture(t, bytes.Repeat([]byte("public fact"), 200000))
	for _, end := range []int{4, 7, 8, 9, 47, len(good) - 41, len(good) - 40, len(good) - 1} {
		t.Run("truncated-"+strconv.Itoa(end), func(t *testing.T) { assertBadCompressedRun(t, good[:end]) })
	}
	for _, offset := range []int{4, 8, 12, 16, 48, len(good) - 41} {
		damaged := bytes.Clone(good)
		damaged[offset] ^= 0x80
		assertBadCompressedRun(t, damaged)
	}
	assertBadCompressedRun(t, append(bytes.Clone(good), 0))
	oversized := bytes.Clone(good)
	binary.LittleEndian.PutUint32(oversized[12:16], privateRunBlockBytes+1)
	assertBadCompressedRun(t, oversized)
}

func assertBadCompressedRun(t *testing.T, data []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := openRun(path, DefaultLimits().RecordBytes)
	if err == nil {
		defer r.file.Close()
		_, err = io.ReadAll(r.reader)
	}
	if err == nil {
		t.Fatal("malformed compressed run accepted")
	}
}

func TestPrivateRunCompressionChargesBeforeWriteAndCancels(t *testing.T) {
	c := &compiler{ctx: context.Background(), options: Options{Limits: DefaultLimits()}}
	var out bytes.Buffer
	w, err := newPrivateRunWriter(c, &out)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err = w.Write(bytes.Repeat([]byte("x"), 900)); err != nil {
		t.Fatal(err)
	}
	c.options.Limits.ScratchBytes = c.used + 1
	before := out.Len()
	if err = w.Flush(); err == nil || out.Len() != before {
		t.Fatal("scratch rejection wrote compressed bytes", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.ctx = ctx
	if _, err = w.Write([]byte("x")); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestPrivateRunIncompressibleStorageAndStrictFrameProfile(t *testing.T) {
	data := make([]byte, privateRunBlockBytes*2+123)
	random := rand.New(rand.NewPCG(100, 200))
	for i := range data {
		data[i] = byte(random.Uint32())
	}
	encoded, stored := compressedRunFixture(t, data)
	if stored > privateRunStoredBound(uint64(len(data))) {
		t.Fatal("incompressible preflight underestimated")
	}
	r, err := newPrivateRunReader(bytes.NewReader(encoded[len(privateRunMagic):]))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("incompressible roundtrip", err)
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true), zstd.WithSingleSegment(true))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	frame := encoder.EncodeAll([]byte("one small frame"), nil)
	if err := validatePrivateRunFrame(frame, 15); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(frame), frame...), append(bytes.Clone(frame), 0), frame[:len(frame)-1]} {
		if validatePrivateRunFrame(bad, 15) == nil {
			t.Fatal("invalid frame extent accepted")
		}
	}
	if validatePrivateRunFrame(frame, 16) == nil {
		t.Fatal("incorrect decoded size accepted")
	}
	large := encoder.EncodeAll(make([]byte, privateRunBlockBytes+1), nil)
	if validatePrivateRunFrame(large, privateRunBlockBytes+1) == nil {
		t.Fatal("oversized decoder window accepted")
	}
}
