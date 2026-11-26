package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/klauspost/compress/zstd"
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

func TestPrivateRunFramesStayImmutableAcrossSegments(t *testing.T) {
	payloads := [][]byte{
		[]byte("first"),
		[]byte("second"),
		bytes.Repeat([]byte("x"), privateRunBlockBytes-32),
		bytes.Repeat([]byte("y"), privateRunBlockBytes),
		[]byte("last"),
	}
	var wire bytes.Buffer
	for _, data := range payloads {
		if err := binary.Write(&wire, binary.LittleEndian, uint32(len(data))); err != nil {
			t.Fatal(err)
		}
		wire.Write(data)
	}
	compressed, _ := compressedRunFixture(t, wire.Bytes())
	path := filepath.Join(t.TempDir(), "run")
	if err := os.WriteFile(path, compressed, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := openRun(path, privateRunBlockBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer r.file.Close()
	var read [][]byte
	for range payloads {
		frame, err := r.readPayload()
		if err != nil {
			t.Fatal(err)
		}
		read = append(read, frame)
	}
	if _, err = r.readPayload(); err != io.EOF {
		t.Fatal("missing verified EOF", err)
	}
	for i := range payloads {
		if !bytes.Equal(read[i], payloads[i]) || cap(read[i]) != len(read[i]) {
			t.Fatal("later segment overwrote an earlier frame or left its capacity open", i)
		}
	}
}

func TestPrivateRunCompactFrameWriterKeepsIdenticalProofBytes(t *testing.T) {
	const prefix = 4 + len(compactRunMarker)
	frames := [][]byte{
		bytes.Repeat([]byte("q"), privateRunBlockBytes-prefix),
		[]byte("inside"),
		bytes.Repeat([]byte("x"), privateRunBlockBytes-2-2*prefix-len("inside")),
		[]byte("split-header"),
		bytes.Repeat([]byte("y"), privateRunBlockBytes-3*prefix-len("split-header")),
		[]byte("split-body"),
		bytes.Repeat([]byte("z"), 2*privateRunBlockBytes),
		[]byte("tail"),
	}
	var stored [2][]byte
	for mode := range stored {
		c := &compiler{ctx: context.Background(), options: Options{Limits: DefaultLimits()}}
		var out bytes.Buffer
		w, err := newPrivateRunWriter(c, &out)
		if err != nil {
			t.Fatal(err)
		}
		var sink io.Writer = w
		if mode == 0 {
			sink = struct{ io.Writer }{w}
		}
		for _, data := range frames {
			if err := writeRunFrame(sink, encoded{compact: true, data: data}); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil || c.used != uint64(out.Len()) {
			t.Fatalf("flush changed physical accounting: %d/%d %v", c.used, out.Len(), err)
		}
		stored[mode] = out.Bytes()
	}
	if !bytes.Equal(stored[0], stored[1]) {
		t.Fatal("fast compact frame writer changed stored bytes or segment proofs")
	}
}

func TestPrivateRunCompactFrameWriterPreservesCancellationAndAccounting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &compiler{ctx: ctx, options: Options{Limits: DefaultLimits()}}
	var out bytes.Buffer
	w, err := newPrivateRunWriter(c, &out)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	cancel()
	if err := writeRunFrame(w, encoded{compact: true, data: []byte("small")}); !errors.Is(err, context.Canceled) || len(w.pending) != 0 || out.Len() != len(privateRunMagic) {
		t.Fatalf("cancellation allowed a frame write: %v", err)
	}
	c.ctx = context.Background()
	out.Reset()
	w2, err := newPrivateRunWriter(c, &out)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	before := c.used
	c.options.Limits.ScratchBytes = before + 1
	data := bytes.Repeat([]byte("x"), privateRunBlockBytes-4-len(compactRunMarker))
	if err := writeRunFrame(w2, encoded{compact: true, data: data}); err == nil || c.used != before || out.Len() != len(privateRunMagic) {
		t.Fatalf("failed accounting wrote or charged a segment: %v", err)
	}
	if err := w2.Flush(); err == nil {
		t.Fatal("failed compact frame was not sticky")
	}
}

func TestRunRejectsMissingDeclaredFrameBody(t *testing.T) {
	wire := []byte{5, 0, 0, 0}
	compressed, _ := compressedRunFixture(t, wire)
	for _, data := range [][]byte{wire, compressed} {
		path := filepath.Join(t.TempDir(), "run")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		r, err := openRun(path, 16)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.next(); err != io.ErrUnexpectedEOF {
			t.Fatal("missing frame body passed as a complete input", err)
		}
		r.file.Close()
	}
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
