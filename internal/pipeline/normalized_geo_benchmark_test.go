package pipeline

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// This synthetic diagnostic uses actual normalized storage and the production
// materializer, including independent city/coordinate votes and sparse exact
// evidence. It cannot qualify a source or replace hosted population evidence.
func BenchmarkNormalizedGeoMaterialization(b *testing.B) {
	for _, count := range []int{100000, 400000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			root := b.TempDir()
			ctx := context.Background()
			clock := time.Unix(1794096000, 0).UTC()
			store, err := intelligence.NewRecordStore(root, intelligence.DefaultRecordStoreLimits())
			if err != nil {
				b.Fatal(err)
			}
			writer := store.Writer(ctx)
			for i := 0; i < count; i++ {
				n := i / 2
				prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{11 + byte(n>>16), byte(n >> 8), byte(n), 0}), 24)
				geo := &intelligence.GeoEvidence{Prefix: prefix, Family: fmt.Sprintf("synthetic-family-%d", i%2), PhysicalCountry: "US", Region: "Synthetic Region", City: fmt.Sprintf("Synthetic City %d", n%97), Coordinates: &intelligence.Coordinates{Latitude: 37.1, Longitude: -122.2, Precision: 3}, Weight: 100, Current: true}
				if err := writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: geo}); err != nil {
					b.Fatal(err)
				}
				if i%2000 == 0 {
					e := &intelligence.Evidence{Address: prefix.Addr(), Scope: intelligence.Exact, Family: "synthetic-risk", Signal: "abuse", Weight: 70, Current: true, SourcePublishedAt: clock}
					if err := writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: e}); err != nil {
						b.Fatal(err)
					}
				}
			}
			parts, err := writer.Finish()
			if err != nil {
				b.Fatal(err)
			}
			state := intelligence.BuildState{Version: 2, PolicyHash: [32]byte{1}, EvaluatedAt: clock, Sources: []intelligence.StoredSource{{ID: "synthetic", Fingerprint: [32]byte{1}, ExpiresAt: clock.Add(time.Hour), RecordPartitions: parts}}}
			file, err := os.Open("../../configs/scoring.yaml")
			if err != nil {
				b.Fatal(err)
			}
			policy, err := intelligence.LoadPolicy(file)
			file.Close()
			if err != nil {
				b.Fatal(err)
			}
			for _, phase := range []string{"seed", "full"} {
				b.Run(phase, func(b *testing.B) {
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						b.StopTimer()
						if err := os.RemoveAll(filepath.Join(root, ".atlas-private", "materialization-cache-v1")); err != nil {
							b.Fatal(err)
						}
						options := Options{Workspace: root, Output: filepath.Join(root, "build-private", fmt.Sprintf("%s-%d", phase, i)), Mode: "synthetic", Clock: clock.Unix(), ValidUntil: clock.Add(time.Hour).Unix(), Limits: DefaultLimits()}
						options.ObserveStage = func(_ context.Context, stage Stage) func(bool) {
							started := time.Now()
							return func(bool) {
								b.ReportMetric(float64(time.Since(started).Microseconds())/1000, fmt.Sprintf("stage-%d-ms", stage))
							}
						}
						b.StartTimer()
						if phase == "seed" {
							spool, err := newBulkSpool(root, clock, state.PolicyHash, options.Limits.ScratchBytes, func() uint64 { return store.DiskBytes() })
							if err != nil {
								b.Fatal(err)
							}
							_, _, err = spool.seed(ctx, root, state)
							if err != nil {
								b.Fatal(err)
							}
							b.StopTimer()
							os.RemoveAll(spool.root)
							b.StartTimer()
						} else {
							result, err := BuildStreamedIntelligence(ctx, options, state, policy)
							if err != nil {
								b.Fatal(err)
							}
							b.StopTimer()
							b.Logf("public release %s manifest %s", result.Pointer.ReleaseID, result.Pointer.ManifestSHA256)
							b.ReportMetric(float64(count+(count+1999)/2000), "normalized-records")
							b.ReportMetric(float64(result.Stats.InputRecords), "public-input-records")
							b.ReportMetric(float64(result.Stats.UniqueRecords), "public-unique-records")
							b.ReportMetric(float64(result.Stats.ProcessRSSPeak), "rss-peak-bytes")
							if result.Stats.ProcessRSSMeasured {
								b.ReportMetric(1, "rss-measured")
							}
							b.ReportMetric(float64(result.Stats.ScratchPeak), "scratch-peak-bytes")
							b.ReportMetric(float64(result.Stats.OutputBytes), "output-bytes")
							b.ReportMetric(float64(result.Stats.Partitions), "partitions")
							os.RemoveAll(options.Output)
							b.StartTimer()
						}
					}
				})
			}
		})
	}
}
