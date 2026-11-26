package intelligence

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func decodeBatchFrames(t *testing.T, count int) [][]byte {
	t.Helper()
	frames := make([][]byte, count)
	for i := range frames {
		var err error
		frames[i], err = json.Marshal(NormalizedRecord{Version: 3, Kind: RecordASNIdentity, ASNIdentity: &ASNIdentityEvidence{ASN: uint32(131072 + i), Name: fmt.Sprintf("Network %d", i)}})
		if err != nil {
			t.Fatal(err)
		}
	}
	return frames
}

func TestBatchRetainsExactFrameExtentsAcrossSlotReuse(t *testing.T) {
	frames := decodeBatchFrames(t, 257)
	raw := decodeBatchPayload(frames)
	var retained [][]byte
	count, err := walkRecordDecodeBatches(context.Background(), bytes.NewReader(raw), int64(len(raw)), uint64(len(frames)), func(_ NormalizedRecord, frame []byte) error {
		retained = append(retained, frame)
		return nil
	})
	if err != nil || count != uint64(len(frames)) || len(retained) != len(frames) {
		t.Fatalf("retained batch population differs: %d %d %v", count, len(retained), err)
	}
	for i, frame := range retained {
		if len(frame) != cap(frame) || !bytes.Equal(frame, frames[i]) {
			t.Fatalf("frame %d exposes another extent or was overwritten", i)
		}
	}
}

func decodeBatchPayload(frames [][]byte) []byte {
	var raw []byte
	for _, frame := range frames {
		raw = binary.LittleEndian.AppendUint32(raw, uint32(len(frame)))
		raw = append(raw, frame...)
	}
	return raw
}

func decodeBatchFixture(t testing.TB, frames [][]byte, tail []byte, compressed bool) (string, RecordPartition) {
	t.Helper()
	raw := append([]byte(recordHeader), decodeBatchPayload(frames)...)
	raw = append(raw, tail...)
	part := RecordPartition{Records: uint64(len(frames))}
	data := raw
	if compressed {
		encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20), zstd.WithEncoderCRC(true))
		if err != nil {
			t.Fatal(err)
		}
		data = append([]byte(compressedRecordHeader), encoder.EncodeAll(raw, nil)...)
		encoder.Close()
		part.Codec, part.DecodedBytes = "zstd-v1", int64(len(raw))
	}
	root := t.TempDir()
	return root, putRecordFixture(t, root, data, part)
}

func assertNoRecordDecodeWorkers(t *testing.T) {
	t.Helper()
	stack := make([]byte, 1<<20)
	deadline := time.Now().Add(time.Second)
	for {
		n := runtime.Stack(stack, true)
		if !bytes.Contains(stack[:n], []byte("intelligence.runRecordDecodeWorker(")) {
			return
		}
		// WaitGroup completion already synchronizes every worker access, but
		// its deferred Done can briefly precede the final runtime.goexit. Allow
		// that scheduler handoff without accepting an actually leaked worker.
		if time.Now().After(deadline) {
			t.Fatal("record decoder leaked a worker after completion")
		}
		time.Sleep(time.Millisecond)
	}
}

type observedBatchReader struct {
	reader         io.Reader
	read, cancelAt int
	cancel         context.CancelFunc
}

func (r *observedBatchReader) Read(data []byte) (int, error) {
	n, err := r.reader.Read(data)
	r.read += n
	if r.cancel != nil && r.read >= r.cancelAt {
		r.cancel()
	}
	return n, err
}

func TestRecordDecodeBatchReadAheadStaysWithinTwoSlots(t *testing.T) {
	frames := decodeBatchFrames(t, 133)
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("Network %d", i)
		frames[i] = bytes.Replace(frames[i], []byte(name), bytes.Repeat([]byte{'x'}, recordDecodeBatchBytes-len(frames[i])+len(name)), 1)
	}
	raw := decodeBatchPayload(frames)
	reader := &observedBatchReader{reader: bytes.NewReader(raw)}
	ends := make([]int, len(frames))
	for i, frame := range frames {
		ends[i] = len(frame) + 4
		if i > 0 {
			ends[i] += ends[i-1]
		}
	}
	seen, emittedBytes, readFrames := 0, 0, 0
	_, err := walkRecordDecodeBatches(context.Background(), reader, int64(len(raw)), uint64(len(frames)), func(record NormalizedRecord, data []byte) error {
		for readFrames < len(ends) && ends[readFrames] <= reader.read {
			readFrames++
		}
		if readFrames-seen > 2*recordDecodeBatchFrames || reader.read-emittedBytes > 2*(recordDecodeBatchBytes+4*recordDecodeBatchFrames)+4 {
			t.Fatal("read ahead exceeded two batches, including pending length header")
		}
		if record.ASNIdentity.ASN != uint32(131072+seen) || !bytes.Equal(data, frames[seen]) {
			t.Fatal("read-ahead changed FIFO ownership")
		}
		if seen == 0 {
			stack := make([]byte, 1<<20)
			n := runtime.Stack(stack, true)
			if count := bytes.Count(stack[:n], []byte("intelligence.runRecordDecodeWorker(")); count != 2 {
				t.Fatalf("fixed worker population changed: %d", count)
			}
		}
		emittedBytes += len(data) + 4
		seen++
		return nil
	})
	if err != nil || seen != len(frames) {
		t.Fatalf("bounded read-ahead: count%d err%v", seen, err)
	}
	assertNoRecordDecodeWorkers(t)
}

func TestRecordDecodeBatchObservedCancellationStopsPendingCallbacks(t *testing.T) {
	frames := decodeBatchFrames(t, 193)
	raw := decodeBatchPayload(frames)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancellation is deliberately observed during speculative reading of the
	// second batch. It stops pending callbacks even though the first batch has
	// valid earlier frames; serial wall-clock side effects are not emulated.
	reader := &observedBatchReader{reader: bytes.NewReader(raw), cancelAt: len(decodeBatchPayload(frames[:64])) + 1, cancel: cancel}
	seen := 0
	_, err := walkRecordDecodeBatches(ctx, reader, int64(len(raw)), uint64(len(frames)), func(NormalizedRecord, []byte) error { seen++; return nil })
	if !errors.Is(err, context.Canceled) || seen != 0 {
		t.Fatalf("observed cancellation delivered pending callbacks: %d %v", seen, err)
	}
	assertNoRecordDecodeWorkers(t)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	sentinel := errors.New("callback canceled and failed")
	_, err = walkRecordDecodeBatches(ctx, bytes.NewReader(raw), int64(len(raw)), uint64(len(frames)), func(NormalizedRecord, []byte) error { cancel(); return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("callback error was replaced by its own cancellation: %v", err)
	}
	assertNoRecordDecodeWorkers(t)
}

func TestRecordDecodeBatchBoundsIncludeExactOneMiBFrame(t *testing.T) {
	frames := decodeBatchFrames(t, 133)
	large := bytes.Replace(frames[3], []byte("Network 3"), bytes.Repeat([]byte{'x'}, recordDecodeBatchBytes-len(frames[3])+len("Network 3")), 1)
	if len(large) != recordDecodeBatchBytes {
		t.Fatal("fixture does not reach record limit")
	}
	frames[3] = large
	raw := decodeBatchPayload(frames)
	reader := recordBatchReader{ctx: context.Background(), reader: bytes.NewReader(raw), remaining: int64(len(raw)), expected: uint64(len(frames))}
	seen, batches, sawMaximum := 0, 0, false
	for reader.remaining > 0 {
		var batch recordDecodeBatch
		reader.fill(&batch)
		if batch.readErr != nil || batch.count == 0 || batch.count > 64 || batch.bytes > 1<<20 {
			t.Fatalf("batch exceeded hard limits: count%d bytes%d err%v", batch.count, batch.bytes, batch.readErr)
		}
		if batch.bytes == 1<<20 {
			sawMaximum = true
			if batch.count != 1 {
				t.Fatal("one-MiB record shared its batch")
			}
		}
		for _, frame := range batch.frames[:batch.count] {
			if !bytes.Equal(frame, frames[seen]) {
				t.Fatal("pending length changed FIFO frame identity")
			}
			seen++
		}
		batches++
	}
	if seen != len(frames) || batches < 4 || !sawMaximum {
		t.Fatal("byte/count boundary fixture was not exercised")
	}
	root, part := decodeBatchFixture(t, frames, nil, true)
	seen = 0
	if err := WalkStoredSource(context.Background(), root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(record NormalizedRecord) error {
		if record.ASNIdentity.ASN != uint32(131072+seen) {
			t.Fatal("batched callback order changed")
		}
		seen++
		return nil
	}); err != nil || seen != len(frames) {
		t.Fatalf("maximum frame walk: count%d err%v", seen, err)
	}
	assertNoRecordDecodeWorkers(t)
}

func TestRecordDecodeBatchHostileFramesRetainStrictSemantics(t *testing.T) {
	valid := decodeBatchFrames(t, 1)[0]
	cases := []struct {
		name  string
		frame []byte
	}{
		{"unknown", bytes.Replace(valid, []byte(`"Name"`), []byte(`"Unexpected"`), 1)},
		{"unknown-nested", bytes.Replace(valid, []byte(`"ASN":`), []byte(`"Unknown":true,"ASN":`), 1)},
		{"trailing", append(append([]byte(nil), valid...), []byte(` {}`)...)},
		{"utf8", bytes.Replace(valid, []byte("Network 0"), []byte{0xff}, 1)},
		{"union", bytes.Replace(valid, []byte(`"Kind":9`), []byte(`"Kind":4`), 1)},
		{"duplicate-case", bytes.Replace(valid, []byte(`"Version":3`), []byte(`"VERSION":0,"version":3`), 1)},
	}
	for _, test := range cases {
		for _, compressed := range []bool{false, true} {
			for _, size := range []struct{ total, ordinal int }{{16, 9}, {193, 0}, {193, 63}, {193, 64}, {193, 127}, {193, 128}, {193, 191}} {
				t.Run(fmt.Sprintf("%s/%t/%d-of-%d", test.name, compressed, size.ordinal, size.total), func(t *testing.T) {
					frames := decodeBatchFrames(t, size.total)
					ordinal := size.ordinal
					frames[ordinal] = test.frame
					_, expectedErr := decodeRecordWithPreviousDecoder(test.frame)
					root, part := decodeBatchFixture(t, frames, nil, compressed)
					seen := 0
					err := WalkStoredSource(context.Background(), root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(NormalizedRecord) error { seen++; return nil })
					if (err == nil) != (expectedErr == nil) || expectedErr != nil && seen != ordinal || expectedErr == nil && seen != len(frames) {
						t.Fatalf("strict acceptance or callback boundary changed: count%d err%v oracle%v", seen, err, expectedErr)
					}
					assertNoRecordDecodeWorkers(t)
				})
			}
		}
	}
}

func TestRecordDecodeBatchEarlierCallbackWinsLaterErrors(t *testing.T) {
	sentinel := errors.New("earlier callback failed")
	for _, failure := range []string{"decode-first-batch", "decode-second-batch", "truncated-header", "invalid-frame", "count", "checksum"} {
		t.Run(failure, func(t *testing.T) {
			frames := decodeBatchFrames(t, 130)
			var tail []byte
			if failure == "decode-first-batch" {
				frames[7] = []byte(`null`)
			}
			if failure == "decode-second-batch" {
				frames[70] = []byte(`null`)
			}
			if failure == "truncated-header" {
				tail = []byte{1, 2}
			}
			if failure == "invalid-frame" {
				tail = []byte{255, 255, 255, 255}
			}
			if failure == "checksum" {
				// Span multiple Zstd blocks: a checksum failure in a tiny single
				// block can legitimately prevent even the record header being read.
				for i := range frames {
					frames[i] = bytes.Replace(frames[i], []byte(fmt.Sprintf("Network %d", i)), bytes.Repeat([]byte{'x'}, 2048), 1)
				}
			}
			root, part := decodeBatchFixture(t, frames, tail, failure == "checksum")
			if failure == "count" {
				part.Records++
			}
			if failure == "checksum" {
				data, err := os.ReadFile(filepath.Join(root, ".atlas-private", "records-v2", partitionName(part)))
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				part = putRecordFixture(t, root, data, part)
			}
			seen := 0
			err := WalkStoredSource(context.Background(), root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(NormalizedRecord) error {
				seen++
				if seen == 4 {
					return sentinel
				}
				return nil
			})
			if !errors.Is(err, sentinel) || seen != 4 {
				t.Fatalf("future error outranked earlier callback: count%d err%v", seen, err)
			}
			assertNoRecordDecodeWorkers(t)
			if err := WalkStoredSource(context.Background(), root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(NormalizedRecord) error { return nil }); err == nil {
				t.Fatal("terminal error disappeared when no callback failed")
			}
			assertNoRecordDecodeWorkers(t)
		})
	}
}

func TestRecordDecodeBatchCancellationJoinsAllWorkers(t *testing.T) {
	frames := decodeBatchFrames(t, 193)
	root, part := decodeBatchFixture(t, frames, nil, true)
	for _, stop := range []int{1, 64, 65, 129} {
		for attempt := 0; attempt < 4; attempt++ {
			ctx, cancel := context.WithCancel(context.Background())
			seen := 0
			err := WalkStoredSource(ctx, root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(NormalizedRecord) error {
				seen++
				if seen == stop {
					cancel()
				}
				return nil
			})
			cancel()
			if !errors.Is(err, context.Canceled) || seen != stop {
				t.Fatalf("cancellation crossed callback boundary: count%d stop%d err%v", seen, stop, err)
			}
			assertNoRecordDecodeWorkers(t)
		}
	}
	path := filepath.Join(root, ".atlas-private", "records-v2", partitionName(part))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := WalkStoredSource(context.Background(), root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(NormalizedRecord) error { seen++; return nil }); err == nil || seen != 0 {
		t.Fatal("actual physical hash check was bypassed before concurrent decoding")
	}
	assertNoRecordDecodeWorkers(t)
}

func TestRecordDecodeBatchCanonicalFramesRemainOwnedAfterWalk(t *testing.T) {
	root := t.TempDir()
	store, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(context.Background())
	frames := decodeBatchFrames(t, 257)
	for _, data := range frames {
		record, err := decodeRecordFrame(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Append(record); err != nil {
			t.Fatal(err)
		}
	}
	parts, err := writer.FinishCanonical()
	if err != nil || len(parts) != 1 {
		t.Fatalf("canonical fixture: %v", err)
	}
	var retained []CanonicalRecordFrame
	if err := parts[0].Walk(context.Background(), func(frame CanonicalRecordFrame) error {
		record, err := frame.Record()
		if err != nil {
			return err
		}
		record.ASNIdentity.Name = "caller mutation"
		retained = append(retained, frame)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertNoRecordDecodeWorkers(t)
	other, err := NewRecordStore(t.TempDir(), DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	copyWriter := other.Writer(context.Background())
	for i, frame := range retained {
		if frame.EncodedBytes() != len(frames[i]) || !strings.Contains(string(frame.data), fmt.Sprintf("Network %d", i)) {
			t.Fatal("batch reuse overwrote a retained canonical frame")
		}
		if err := frame.AppendTo(copyWriter); err != nil {
			t.Fatal(err)
		}
	}
	copied, err := copyWriter.FinishCanonical()
	if err != nil || len(copied) != 1 || copied[0].Descriptor() != parts[0].Descriptor() {
		t.Fatalf("retained canonical bytes changed: %v", err)
	}
}
