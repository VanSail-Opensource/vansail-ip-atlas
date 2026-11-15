package pipeline

import (
	"context"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func TestStableSeedPreservesUnchangedInputPartitionIdentity(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	limits := intelligence.DefaultRecordStoreLimits()
	limits.PartitionRecords = 2
	store, err := intelligence.NewRecordStore(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	makeParts := func(city string) []intelligence.RecordPartition {
		writer := store.Writer(ctx)
		for i := 0; i < 4; i++ {
			value := "Original"
			if i == 0 {
				value = city
			}
			err := writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo,
				Geo: &intelligence.GeoEvidence{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{8, 8, byte(i), 0}), 24),
					PhysicalCountry: "US", City: value, Family: "fixture", Weight: 70, Current: true}})
			if err != nil {
				t.Fatal(err)
			}
		}
		parts, err := writer.Finish()
		if err != nil || len(parts) != 2 {
			t.Fatalf("parts=%d error=%v", len(parts), err)
		}
		return parts
	}
	clock := time.Unix(1700000000, 0).UTC()
	var outputs [][]intelligence.RecordPartition
	for _, city := range []string{"Original", "Changed"} {
		state := intelligence.BuildState{Version: 2, PolicyHash: [32]byte{1}, EvaluatedAt: clock,
			Sources: []intelligence.StoredSource{{ID: "fixture", Fingerprint: [32]byte{2}, ExpiresAt: clock.Add(time.Hour), RecordPartitions: makeParts(city)}}}
		spool, err := newBulkSpool(root, clock, state.PolicyHash, 1<<30, func() uint64 { return 0 })
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(spool.root)
		spatial, _, err := spool.seedStable(ctx, root, state)
		if err != nil || len(spatial[0].parts) != 2 {
			t.Fatalf("seed error=%v", err)
		}
		outputs = append(outputs, spatial[0].parts)
		var stable []intelligence.NormalizedRecord
		if err := spool.walk(ctx, spatial[0].parts, func(r intelligence.NormalizedRecord) error {
			stable = append(stable, r)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		cold, err := newBulkSpool(root, clock, state.PolicyHash, 1<<30, func() uint64 { return 0 })
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(cold.root)
		oldSpatial, _, err := cold.seed(ctx, root, state)
		if err != nil {
			t.Fatal(err)
		}
		var original []intelligence.NormalizedRecord
		if err := cold.walk(ctx, oldSpatial[0].parts, func(r intelligence.NormalizedRecord) error {
			original = append(original, r)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(stable, original) {
			t.Fatal("stable seed changed canonical record order or values")
		}
	}
	if outputs[0][0] == outputs[1][0] || outputs[0][1] != outputs[1][1] {
		t.Fatal("one changed input shifted an unrelated seed chunk")
	}
}
