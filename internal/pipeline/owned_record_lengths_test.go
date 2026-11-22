package pipeline

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestOwnedRecordLengthsPreserveMaterialization(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	lengths := make([]int, 0)
	for _, source := range state.Sources {
		for _, record := range source.Records {
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			lengths = append(lengths, len(data))
		}
	}
	collect := func(input MaterializationInputs) []via3.PublicRecord {
		t.Helper()
		var rows []via3.PublicRecord
		if err := IntelligenceProducer(state, policy, state.EvaluatedAt, input)(context.Background(), func(row via3.PublicRecord) error {
			rows = append(rows, row)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	want := collect(MaterializationInputs{VRPComplete: true})
	got := collect(MaterializationInputs{VRPComplete: true, encodedLengths: lengths})
	if len(want) == 0 || !reflect.DeepEqual(got, want) {
		t.Fatal("owned canonical sizes changed public rows or ordering")
	}
	for _, invalid := range [][]int{lengths[:len(lengths)-1], append(append([]int(nil), lengths...), 1), append([]int{0}, lengths[1:]...), append([]int{1<<20 + 1}, lengths[1:]...)} {
		if err := IntelligenceProducer(state, policy, state.EvaluatedAt, MaterializationInputs{encodedLengths: invalid})(context.Background(), func(via3.PublicRecord) error { return nil }); err == nil {
			t.Fatal("invalid owned lengths accepted")
		}
	}
	// Length reuse never bypasses the field and semantic validators.
	for i := range state.Sources[0].Records {
		if state.Sources[0].Records[i].Geo != nil {
			copy := *state.Sources[0].Records[i].Geo
			copy.City = strings.Repeat("x", 1025)
			state.Sources[0].Records[i].Geo = &copy
			break
		}
	}
	if err := IntelligenceProducer(state, policy, state.EvaluatedAt, MaterializationInputs{encodedLengths: lengths})(context.Background(), func(via3.PublicRecord) error { return nil }); err == nil {
		t.Fatal("owned sizes bypassed nested field bounds")
	}
}

func TestOwnedRecordLengthsRemainCollectorLocal(t *testing.T) {
	state, _, _, _, _ := intelligenceFixture(t)
	spool, err := newBulkSpool(t.TempDir(), state.EvaluatedAt, state.PolicyHash, 1<<30, func() uint64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.refresh(); err != nil {
		t.Fatal(err)
	}
	writer := spool.store.Writer(context.Background())
	for _, source := range state.Sources {
		for _, record := range source.Records {
			if record.Kind != intelligence.RecordGeo {
				continue
			}
			for range 2 {
				if err := writer.Append(record); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	parts, err := spool.finish(writer)
	if err != nil {
		t.Fatal(err)
	}
	bucket := &bulkBucket{parts: parts}
	_, err = spool.leaves(context.Background(), []*bulkBucket{bucket}, false, func(b *bulkBucket, got intelligence.BuildState) error {
		count := 0
		for _, source := range got.Sources {
			for _, record := range source.Records {
				data, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				if count >= len(b.recordBytes) || b.recordBytes[count] != len(data) {
					t.Fatal("canonical sizes lost deduplicated record order")
				}
				count++
			}
		}
		if count == 0 || count != len(b.recordBytes) {
			t.Fatal("missing collected sizes")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if bucket.recordBytes != nil {
		t.Fatal("completed leaf retained record bookkeeping")
	}
}

func TestOwnedRecordLengthsRejectUsageJoinWithSameRecordCount(t *testing.T) {
	state, policy := mappingFixture(t)
	state.Sources = state.Sources[:1]
	state.Sources[0].Records = []intelligence.NormalizedRecord{
		{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{ASN: 13335, Evidence: intelligence.UsageEvidence{Family: "synthetic", Type: "business", Current: true}}},
		{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("8.8.8.0/24"), Origins: []uint32{13335}}},
	}
	lengths := make([]int, len(state.Sources[0].Records))
	for i, record := range state.Sources[0].Records {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		lengths[i] = len(data)
	}
	for _, producer := range []Producer{
		IntelligenceProducer(state, policy, state.EvaluatedAt, MaterializationInputs{encodedLengths: lengths}),
		mappingProducer(state, policy, state.EvaluatedAt, lengths, false, netip.Prefix{}),
	} {
		if err := producer(context.Background(), func(via3.PublicRecord) error { t.Fatal("pre-join owned sizes emitted a record"); return nil }); err == nil || !strings.Contains(err.Error(), "precede ASN usage join") {
			t.Fatal("pre-join sizes accepted after equal-cardinality rewrite", err)
		}
	}
}
