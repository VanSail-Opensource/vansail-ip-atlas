package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func mixedTypedDecodeFrames(t testing.TB, size int) ([][]byte, []NormalizedRecord) {
	t.Helper()
	frames := make([][]byte, size)
	rows := make([]NormalizedRecord, 0, size)
	for i := range size {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{8, byte(i >> 16), byte(i >> 8), byte(i)}), 32)
		when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Add(time.Duration(i) * time.Second)
		row := NormalizedRecord{Version: 3}
		switch i % 3 {
		case 0:
			row.Kind = RecordGeo
			row.Geo = &GeoEvidence{Family: "mixed-geographic", Weight: 0.5, Prefix: prefix, PhysicalCountry: "US", Region: fmt.Sprintf("Region %d", i), City: fmt.Sprintf("City %d 東京", i), Coordinates: &Coordinates{Latitude: 20.125, Longitude: -30.75, Precision: 3}, Current: true}
		case 1:
			row.Kind = RecordPath
			row.Path = &ScopedPath{Prefix: prefix, Observation: PathObservation{Origin: uint32(131072 + i), Segments: []PathSegment{{Type: ASSequence, ASNs: []uint32{3356, 15169, uint32(131072 + i)}}}, Family: "mixed-routing", Current: true}}
			row.MRT = &MRTRouteIdentity{PeerKey: [32]byte{byte(i), byte(i >> 8)}, PeerIndex: uint16(i), PeerTable: 1, CapturedAt: when.Add(time.Hour)}
			row.MRTOriginatedAt = &when
		case 2:
			row.Kind = RecordASNIdentity
			row.ASNIdentity = &ASNIdentityEvidence{ASN: uint32(131072 + i), Name: fmt.Sprintf("Network \"%d\" π", i), Family: "mixed-identity", Weight: 0.75, Current: true}
		}
		data, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		frames[i] = data
		rows = append(rows, row)
	}
	return frames, rows
}

func TestTypedRecordDecodeRetainsOwnedRecords(t *testing.T) {
	const long = 5*recordDecodeBatchFrames + 13
	for _, compressed := range []bool{false, true} {
		for _, total := range []int{14, long} {
			t.Run(fmt.Sprintf("compressed-%t/records-%d", compressed, total), func(t *testing.T) {
				frames, expected := mixedTypedDecodeFrames(t, total)
				if _, ok := decodeWriterGeo(frames[0]); !ok {
					t.Fatal("did not exercise the geographic fast reader")
				}
				if _, ok := decodeWriterRouting(frames[1]); !ok {
					t.Fatal("did not exercise the MRT fast reader")
				}
				root, part := decodeBatchFixture(t, frames, nil, compressed)
				var retained []NormalizedRecord
				err := WalkStoredSource(context.Background(), root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(row NormalizedRecord) error {
					retained = append(retained, row)
					return nil
				})
				if err != nil || len(retained) != total {
					t.Fatalf("decoded population: %d, %v", len(retained), err)
				}
				for i, row := range retained {
					if !reflect.DeepEqual(row, expected[i]) {
						t.Fatalf("retained typed row %d changed after a buffer was reused", i)
					}
				}
			})
		}
	}
}

func TestCanonicalDecodeRetainsUnmodifiedRawFrames(t *testing.T) {
	for _, total := range []int{14, 5*recordDecodeBatchFrames + 13} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			rawFrames, _ := mixedTypedDecodeFrames(t, total)
			workspace, part := decodeBatchFixture(t, rawFrames, nil, true)
			ctx := context.Background()
			var compared, retained []CanonicalRecordFrame
			canonical, err := CompareCanonicalFrames(ctx, workspace, part, func(frame CanonicalRecordFrame) error {
				compared = append(compared, frame)
				return nil
			})
			if err != nil || canonical.Descriptor() != part {
				t.Fatalf("canonical comparison failed: %v", err)
			}
			err = canonical.Walk(ctx, func(frame CanonicalRecordFrame) error {
				retained = append(retained, frame)
				return nil
			})
			if err != nil || len(compared) != total || len(retained) != total {
				t.Fatalf("canonical frame population changed: %d / %d, %v", len(compared), len(retained), err)
			}
			for i, raw := range rawFrames {
				if !bytes.Equal(retained[i].data, raw) || !bytes.Equal(compared[i].data, raw) {
					t.Fatalf("retained raw frame %d changed across reads", i)
				}
			}
		})
	}
}

func BenchmarkTypedRecordDecodeOwnership(b *testing.B) {
	const count = 32768
	frames, _ := mixedTypedDecodeFrames(b, count)
	workspace, part := decodeBatchFixture(b, frames, nil, true)
	root, err := recordDirectory(workspace, false)
	if err != nil {
		b.Fatal(err)
	}
	for _, name := range []string{"RawOwned", "TypedOnly"} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(part.DecodedBytes)
			ctx := context.Background()
			for b.Loop() {
				seen := 0
				visit := func(row NormalizedRecord) error { seen++; return nil }
				if name == "TypedOnly" {
					err = walkPartition(ctx, root, part, visit)
				} else {
					err = walkPartitionFrames(ctx, root, part, func(row NormalizedRecord, _ []byte) error { return visit(row) })
				}
				if err != nil || seen != count {
					b.Fatalf("decoded %d records: %v", seen, err)
				}
			}
			b.ReportMetric(count, "records/op")
		})
	}
}

// Exercise the reader at its byte ceiling across repeated uses of one slot.
// The typed API does not expose raw frames; the internal slot boundary does.
func TestTypedDecodeSlotReusesBoundedBuffer(t *testing.T) {
	frames := decodeBatchFrames(t, 7)
	for i := range frames {
		name := fmt.Sprintf("Network %d", i)
		frames[i] = bytes.Replace(frames[i], []byte(name), bytes.Repeat([]byte{'x'}, recordDecodeBatchBytes-len(frames[i])+len(name)), 1)
	}
	raw := decodeBatchPayload(frames)
	reader := recordBatchReader{ctx: context.Background(), reader: bytes.NewReader(raw), remaining: int64(len(raw)), expected: uint64(len(frames))}
	var batch recordDecodeBatch
	var first *byte
	for i, expected := range frames {
		batch.reset(true)
		reader.fill(&batch)
		if batch.readErr != nil || batch.count != 1 || batch.bytes != recordDecodeBatchBytes || cap(batch.buffer) != recordDecodeBatchBytes || !bytes.Equal(batch.frames[0], expected) {
			t.Fatalf("reused slot %d escaped the byte/frame bounds or changed bytes", i)
		}
		if i == 0 {
			first = &batch.frames[0][0]
		} else if &batch.frames[0][0] != first {
			t.Fatalf("slot %d allocated a new raw buffer", i)
		}
	}
}
