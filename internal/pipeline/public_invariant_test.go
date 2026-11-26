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

func TestClockInvariantPublicLeafRequiresUntimedScoringAndCurrentContext(t *testing.T) {
	ctx := context.Background()
	prefix := netip.MustParsePrefix("11.0.0.0/16")
	previousClock := time.Unix(1794096000, 0).UTC()
	for _, tc := range []struct {
		name                                           string
		evidence, coverage, contextChanged, retainRPKI bool
		wantVisits                                     int
	}{
		{name: "unchanged and untimed"},
		{name: "timed prefix evidence", evidence: true, wantVisits: 1},
		{name: "timed coverage", coverage: true, wantVisits: 1},
		{name: "changed ASN context", contextChanged: true, wantVisits: 1},
		{name: "current RPKI must be generated", retainRPKI: true, wantVisits: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := func(options Options, observed bool, asn float64, clockKey byte) (Candidate, int) {
				t.Helper()
				workspace := options.Workspace
				cache, err := openSpatialCache(ctx, workspace, [32]byte{1}, options.Limits.ScratchBytes/4, func(uint64) bool { return true })
				if err != nil {
					t.Fatal(err)
				}
				defer cache.Abort()
				spool, err := newBulkSpool(workspace, time.Unix(options.Clock, 0).UTC(), [32]byte{2}, options.Limits.ScratchBytes, cache.DiskBytes)
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(spool.root)
				spool.reuse = cache
				if err := spool.refresh(); err != nil {
					t.Fatal(err)
				}
				writer := spool.store.Writer(ctx)
				records := []intelligence.NormalizedRecord{{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: prefix, Origins: []uint32{13335}}}}
				if tc.evidence {
					records = append(records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Prefix: prefix, Scope: intelligence.ExplicitPrefix, Family: "test-family", Signal: "proxy", Weight: 70, Current: true, SourcePublishedAt: previousClock}})
				}
				if tc.coverage {
					records = append(records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordCoverage, Coverage: &intelligence.Coverage{Prefix: prefix, Layer: intelligence.ExplicitPrefix, Family: "test-family", Current: true, Complete: true, PublishedAt: previousClock}})
				}
				for _, row := range records {
					if err := writer.Append(row); err != nil {
						t.Fatal(err)
					}
				}
				parts, err := spool.finish(writer)
				if err != nil {
					t.Fatal(err)
				}
				visits := 0
				options.spatialSpool, options.prepareSpatialCache, options.commitSpatialCache = spool, cache.Prepare, cache.Commit
				options.materializationCache = &materializationCache{}
				candidate, err := Build(ctx, options, func(ctx context.Context, emit func(via3.PublicRecord) error) error {
					leaf := &bulkLeafReuse{domain: "public", dependencies: [32]byte{clockKey}, publicCore: [32]byte{clockKey + 10}, publicInvariant: [32]byte{42}, withoutRPKI: !observed,
						contexts: map[uint32]intelligence.ASNContext{13335: {Risk: asn, Confidence: 0.1, Contribution: 0.01, Present: true}}, spool: spool, public: emit}
					_, err := spool.leavesReusing(ctx, []*bulkBucket{{prefix: prefix, parts: parts}}, true, leaf, func(_ *bulkBucket, _ intelligence.BuildState) error {
						visits++
						spool.publicRows++
						if err := emit(via3.PublicRecord{Version: 3, Kind: 4, Prefix: prefix, Network: &via3.NetworkData{Origins: []uint32{13335}}}); err != nil {
							return err
						}
						if observed {
							spool.publicRows++
							return emit(via3.PublicRecord{Version: 3, Kind: 9, Prefix: prefix, ASN: 13335, RPKI: &via3.RPKIData{Status: 3, ObservedAt: options.Clock - 60, ValidUntil: options.Clock + 3600}})
						}
						return nil
					})
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				return candidate, visits
			}
			options := testOptions(t)
			options.Clock, options.ValidUntil, options.Limits = previousClock.Unix(), previousClock.Unix()+7200, DefaultLimits()
			original, visits := build(options, true, 0.2, 1)
			if visits != 1 {
				t.Fatal("first build did not validate the full leaf")
			}
			next := options
			next.Clock += 120
			next.Output = filepath.Join(next.Workspace, "build-private", "advanced")
			asn := 0.2
			if tc.contextChanged {
				asn = 0.3
			}
			updated, visits := build(next, tc.retainRPKI, asn, 2)
			if visits != tc.wantVisits || updated.Pointer == original.Pointer {
				t.Fatalf("unexpected warm behavior: visits %d, wanted %d", visits, tc.wantVisits)
			}
			cold := testOptions(t)
			cold.Clock, cold.ValidUntil, cold.Limits = next.Clock, next.ValidUntil, next.Limits
			expected, coldVisits := build(cold, tc.retainRPKI, asn, 2)
			if coldVisits != 1 || expected.Pointer != updated.Pointer {
				t.Fatal("clock-invariant replay changed current output")
			}
		})
	}
}
