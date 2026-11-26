package pipeline

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestPublicCoreReuseDropsRPKIOnlyOnAbsentQualification(t *testing.T) {
	ctx := context.Background()
	prefix := netip.MustParsePrefix("11.0.0.0/16")
	clock := int64(1794096000)
	build := func(t *testing.T, options Options, available bool) (Candidate, int) {
		t.Helper()
		root := options.Workspace
		cache, err := openSpatialCache(ctx, root, [32]byte{1}, options.Limits.ScratchBytes/4, func(uint64) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		defer cache.Abort()
		spool, err := newBulkSpool(root, time.Unix(clock, 0).UTC(), [32]byte{2}, options.Limits.ScratchBytes, cache.DiskBytes)
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(spool.root)
		spool.reuse = cache
		if err := spool.refresh(); err != nil {
			t.Fatal(err)
		}
		writer := spool.store.Writer(ctx)
		if err := writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins,
			Origins: &intelligence.OriginMapping{Prefix: prefix, Origins: []uint32{13335}}}); err != nil {
			t.Fatal(err)
		}
		parts, err := spool.finish(writer)
		if err != nil {
			t.Fatal(err)
		}
		visited := 0
		options.spatialSpool, options.prepareSpatialCache, options.commitSpatialCache = spool, cache.Prepare, cache.Commit
		options.materializationCache = &materializationCache{}
		candidate, err := Build(ctx, options, func(ctx context.Context, emit func(via3.PublicRecord) error) error {
			dependency := [32]byte{3}
			if available {
				dependency = [32]byte{4}
			}
			leaf := &bulkLeafReuse{domain: "public", dependencies: dependency, publicCore: [32]byte{5}, withoutRPKI: !available,
				contexts: map[uint32]intelligence.ASNContext{}, spool: spool, public: emit}
			_, err := spool.leavesReusing(ctx, []*bulkBucket{{prefix: prefix, parts: parts}}, true, leaf,
				func(_ *bulkBucket, _ intelligence.BuildState) error {
					visited++
					spool.publicRows++
					if err := emit(via3.PublicRecord{Version: 3, Kind: 4, Prefix: prefix, Network: &via3.NetworkData{Origins: []uint32{13335}}}); err != nil {
						return err
					}
					if available {
						spool.publicRows++
						return emit(via3.PublicRecord{Version: 3, Kind: 9, Prefix: prefix, ASN: 13335,
							RPKI: &via3.RPKIData{Status: 3, ObservedAt: clock - 3600, ValidUntil: clock + 3600}})
					}
					return nil
				})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return candidate, visited
	}
	options := testOptions(t)
	options.Clock, options.ValidUntil, options.Limits = clock, clock+7200, DefaultLimits()
	original, calls := build(t, options, true)
	if calls != 1 {
		t.Fatal("initial leaf never walked")
	}
	warm := options
	warm.Output = filepath.Join(warm.Workspace, "build-private", "no-rpki")
	updated, calls := build(t, warm, false)
	if calls != 0 || updated.Pointer == original.Pointer {
		t.Fatal("unavailable RPKI did not reuse the unchanged leaf minus RPKI")
	}
	cold := testOptions(t)
	cold.Clock, cold.ValidUntil, cold.Limits = warm.Clock, warm.ValidUntil, warm.Limits
	expected, calls := build(t, cold, false)
	if calls != 1 || expected.Pointer != updated.Pointer {
		t.Fatal("warm release differs from ordinary unavailable materialization")
	}
	reader, err := via3.OpenRelease(warm.Output, func() int64 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	answer, err := reader.Lookup(ctx, "11.0.0.1")
	if err != nil || len(answer.BGP.RPKI) != 1 || answer.BGP.RPKI[0].Status != "unavailable" || answer.BGP.RPKI[0].ObservedAt != nil {
		t.Fatal("replayed a stale observation or lost the origin", answer, err)
	}
}
