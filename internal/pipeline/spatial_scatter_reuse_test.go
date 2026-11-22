package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestSpatialScatterReusePreservesBroadInheritedRowsAndExactNeighbors(t *testing.T) {
	ctx := context.Background()
	state, policy, _, _, _ := intelligenceFixture(t)
	state.Sources = state.Sources[:1]
	broad := netip.MustParsePrefix("0.0.0.0/0")
	state.Sources[0].Records = []intelligence.NormalizedRecord{
		{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Prefix: broad, Scope: intelligence.ExplicitPrefix, Family: "broad-risk", Signal: "abuse", Weight: 70, Current: true, SourcePublishedAt: state.EvaluatedAt}},
		{Version: 3, Kind: intelligence.RecordCoverage, Coverage: &intelligence.Coverage{Prefix: broad, Layer: intelligence.ExplicitPrefix, Family: "broad-risk", PublishedAt: state.EvaluatedAt, Current: true, Complete: true}},
	}
	for i := 0; i < 32; i++ {
		first := byte(8)
		if i >= 16 {
			first = 140
		}
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{first, byte(i % 16), 0, 0}), 24)
		state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Prefix: prefix, Family: "synthetic", PhysicalCountry: "US", City: "Original", Weight: 70, Current: true}})
	}
	for _, address := range []string{"8.0.0.1", "8.0.0.2"} {
		state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Address: netip.MustParseAddr(address), Scope: intelligence.Exact, Family: "neighbors", Signal: "abuse", Weight: 70, Current: true, SourcePublishedAt: state.EvaluatedAt}})
	}
	// A duplicate in a distinct input partition must not change the fit budget.
	state.Sources[0].Records = append(state.Sources[0].Records, state.Sources[0].Records[0])
	root := t.TempDir()
	type result struct{ scopes, rows []string }
	run := func(value intelligence.BuildState, cached bool, batch int) result {
		t.Helper()
		workspace := root
		if !cached {
			workspace = t.TempDir()
		}
		spool, err := newBulkSpool(workspace, value.EvaluatedAt, value.PolicyHash, DefaultLimits().ScratchBytes, func() uint64 { return 0 })
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(spool.root)
		spool.batchRecords = batch
		if cached {
			value = partitionSpatialFixture(t, workspace, value)
			spool.reuse, err = openSpatialCache(ctx, workspace, [32]byte{9}, 64<<20, func(uint64) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			defer spool.reuse.Abort()
		}
		roots, _, err := spool.seed(ctx, workspace, value)
		if err != nil {
			t.Fatal(err)
		}
		var out result
		var walk func(*bulkBucket) error
		walk = func(bucket *bulkBucket) error {
			if len(bucket.parts) == 0 {
				return nil
			}
			part, err := spool.collect(ctx, bucket, false)
			if errors.Is(err, errBulkPartition) {
				left, right, err := spool.splitSpatial(ctx, bucket)
				if err != nil {
					return err
				}
				if err = walk(left); err != nil {
					return err
				}
				return walk(right)
			}
			if err != nil {
				return err
			}
			out.scopes = append(out.scopes, bucket.prefix.String())
			return IntelligenceProducer(part, policy, value.EvaluatedAt, MaterializationInputs{scope: bucket.prefix})(ctx, func(row via3.PublicRecord) error {
				data, err := json.Marshal(row)
				out.rows = append(out.rows, string(data))
				return err
			})
		}
		for _, bucket := range roots {
			if err := walk(bucket); err != nil {
				t.Fatal(err)
			}
		}
		sort.Strings(out.rows)
		if cached {
			if err := spool.reuse.Prepare(ctx); err != nil {
				t.Fatal(err)
			}
			if err := spool.reuse.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	for phase := 0; phase < 2; phase++ {
		cached, cold := run(state, true, 20), run(state, false, 20)
		if !reflect.DeepEqual(cached, cold) || len(cached.scopes) != 2 || cached.scopes[0] != "0.0.0.0/1" || cached.scopes[1] != "128.0.0.0/1" {
			t.Fatal("cached per-input scatter changed inherited-row dedupe, first-fitting scope or public bytes", phase, cached.scopes, cold.scopes)
		}
		state = cloneSpatialFixture(t, state)
		state.Sources[0].Records[2].Geo.City = "Changed"
	}

	// Force a second scatter below /4, with an inherited multi-origin parent
	// and an explicit empty child. A changed city rebuilds only affected
	// stream groups. The ordinary coalesced path supplies the complete oracle.
	for _, origin := range []intelligence.OriginMapping{
		{Prefix: netip.MustParsePrefix("8.0.0.0/8"), Origins: []uint32{13335, 15169}},
		{Prefix: netip.MustParsePrefix("8.0.0.0/24")},
	} {
		state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &origin})
	}
	for phase := 0; phase < 2; phase++ {
		cached, cold := run(state, true, 12), run(state, false, 12)
		deep := false
		for _, scope := range cached.scopes {
			if netip.MustParsePrefix(scope).Bits() > 4 {
				deep = true
			}
		}
		if !deep || !reflect.DeepEqual(cached, cold) {
			t.Fatal("deep grouped scatter changed inherited origins or exact neighbor facts", phase)
		}
		state = cloneSpatialFixture(t, state)
		state.Sources[0].Records[2].Geo.City = "Another City"
	}
}
