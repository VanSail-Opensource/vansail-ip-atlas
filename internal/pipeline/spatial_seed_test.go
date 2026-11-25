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

func TestRoutedRiskRootsRetainMixedGroupsAndKeepAllPublicParts(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	clock := time.Unix(1700000000, 0).UTC()
	v4 := netip.MustParsePrefix("9.0.0.0/24")
	v6 := netip.MustParsePrefix("2001:4860::/32")
	geo := func(prefix netip.Prefix, city string) intelligence.NormalizedRecord {
		return intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{
			Prefix: prefix, PhysicalCountry: "US", City: city, Family: "fixture", Weight: 70, Current: true,
		}}
	}
	origin := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: v4, Origins: []uint32{13335}}}
	exact := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{
		Address: v6.Addr(), Scope: intelligence.Exact, Family: "fixture", Signal: "abuse", Weight: 80, SourcePublishedAt: clock, Current: true,
	}}
	state := intelligence.BuildState{Version: 1, PolicyHash: [32]byte{1}, EvaluatedAt: clock}
	for i, rows := range [][]intelligence.NormalizedRecord{
		{geo(v4, "Omitted v4"), geo(v6, "Omitted v6")},
		{geo(v4, "Retained v4"), origin},
		{geo(v6, "Retained v6"), exact},
	} {
		state.Sources = append(state.Sources, intelligence.StoredSource{ID: []string{"geo", "v4-mixed", "v6-mixed"}[i], ExpiresAt: clock.Add(time.Hour), Records: rows})
	}
	state = partitionSpatialFixture(t, root, state)
	for attempt := range 2 {
		spool, err := newBulkSpool(root, clock, state.PolicyHash, 1<<30, func() uint64 { return 0 })
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(spool.root)
		spool.reuse, err = openSpatialCache(ctx, root, [32]byte{4}, 64<<20, func(uint64) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		defer spool.reuse.Abort()
		roots, _, err := spool.seedStable(ctx, root, state)
		if err != nil {
			t.Fatal(err)
		}
		risk, separate := spool.routedRiskRoots(roots)
		if !separate || len(risk) != 2 || len(roots) != 2 {
			t.Fatal("expected two filtered risk roots")
		}
		for i, bucket := range risk {
			if !bucket.riskOnly || roots[i].riskOnly || !roots[i].active || len(roots[i].parts) != 2 || len(bucket.parts) != 1 {
				t.Fatalf("risk projection lost original or mixed group on attempt %d, family %d", attempt, i)
			}
			var seen []intelligence.RecordKind
			if err := spool.walk(ctx, bucket.parts, func(record intelligence.NormalizedRecord) error {
				seen = append(seen, record.Kind)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			want := [][]intelligence.RecordKind{{intelligence.RecordGeo, intelligence.RecordOrigins}, {intelligence.RecordGeo, intelligence.RecordEvidence}}
			if !reflect.DeepEqual(seen, want[i]) {
				t.Fatalf("mixed input rows changed on attempt %d: %v", attempt, seen)
			}
			bucket.active = false
		}
		if err := spool.gc(ctx); err != nil {
			t.Fatal(err)
		}
		for _, public := range roots {
			if err := spool.verifyParts(ctx, public.parts); err != nil {
				t.Fatal("risk cleanup removed public inputs", err)
			}
		}
		if err := spool.reuse.Prepare(ctx); err != nil {
			t.Fatal(err)
		}
		if err := spool.reuse.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
