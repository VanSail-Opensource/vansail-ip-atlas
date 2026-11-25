package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func BenchmarkDiskBackedCompile(b *testing.B) {
	var records []via3.PublicRecord
	for i := 0; i < 256; i++ {
		records = append(records, via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(fmt.Sprintf("203.0.%d.0/24", i)), Geo: &via3.GeoData{Country: "US", City: fmt.Sprintf("Synthetic City %d", i)}})
	}
	encoded, _ := json.Marshal(records)
	root := b.TempDir()
	limits := DefaultLimits()
	limits.RecordBytes = 2048
	limits.SortBytes = 16384
	limits.PartitionBytes = 32768
	limits.PartitionRecords = 32
	var samples []int64
	var scratch, rss uint64
	b.ReportAllocs()
	b.SetBytes(int64(len(encoded)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		result, err := Build(context.Background(), Options{Workspace: root, Output: filepath.Join(root, "build-private", fmt.Sprintf("candidate-%d", i)), Mode: "synthetic", Clock: 1794096000, ValidUntil: 1794099600, Limits: limits}, producer(records))
		if err != nil {
			b.Fatal(err)
		}
		samples = append(samples, time.Since(start).Nanoseconds())
		scratch = max(scratch, result.Stats.ScratchPeak)
		rss = max(rss, result.Stats.ProcessRSSPeak)
	}
	b.StopTimer()
	raw := append([]int64(nil), samples...)
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	percentile := func(p int) float64 { index := (len(samples)*p+99)/100 - 1; return float64(samples[max(index, 0)]) }
	b.ReportMetric(percentile(50), "p50-ns")
	b.ReportMetric(percentile(95), "p95-ns")
	b.ReportMetric(percentile(99), "p99-ns")
	b.ReportMetric(float64(scratch), "compiler-scratch-peak-B")
	b.ReportMetric(float64(rss), "compiler-process-RSS-peak-B")
	b.ReportMetric(float64(len(encoded)), "input-B")
	b.Logf("synthetic 256-record corpus; per-invocation samples_ns=%v; scratch excludes previous outputs and RSS excludes child processes", raw)
}

// This medium synthetic fixture exercises the same normalized-record storage
// and streamed materializer as production. It establishes cache work reduction,
// never source qualification or an official full-population performance result.
func BenchmarkStreamedMaterializationExactCache(b *testing.B) {
	root := b.TempDir()
	ctx := context.Background()
	store, err := intelligence.NewRecordStore(root, intelligence.DefaultRecordStoreLimits())
	if err != nil {
		b.Fatal(err)
	}
	writer := store.Writer(ctx)
	const count = 10000
	for i := 0; i < count; i++ {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{8, byte(i >> 8), byte(i), 0}), 24)
		if err := writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Prefix: prefix, Family: "synthetic-private", PhysicalCountry: "US", City: fmt.Sprintf("Synthetic City %d", i), Weight: 100, Current: true}}); err != nil {
			b.Fatal(err)
		}
	}
	parts, err := writer.Finish()
	if err != nil {
		b.Fatal(err)
	}
	clock := time.Unix(1794096000, 0).UTC()
	state := intelligence.BuildState{Version: 2, PolicyHash: [32]byte{1}, EvaluatedAt: clock, Sources: []intelligence.StoredSource{{ID: "synthetic", Fingerprint: [32]byte{1}, ExpiresAt: clock.Add(time.Hour), RecordPartitions: parts}}}
	policyFile, err := os.Open("../../configs/scoring.yaml")
	if err != nil {
		b.Fatal(err)
	}
	policy, err := intelligence.LoadPolicy(policyFile)
	_ = policyFile.Close()
	if err != nil {
		b.Fatal(err)
	}
	options := Options{Workspace: root, Mode: "synthetic", Clock: clock.Unix(), ValidUntil: clock.Add(time.Hour).Unix(), Limits: DefaultLimits()}
	for _, warm := range []bool{false, true} {
		name := "cold"
		if warm {
			name = "exact-warm"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				if !warm {
					if err := os.RemoveAll(filepath.Join(root, ".atlas-private", "materialization-cache-v1")); err != nil {
						b.Fatal(err)
					}
				}
				options.Output = filepath.Join(root, "build-private", name+"-"+fmt.Sprint(i))
				b.StartTimer()
				result, err := BuildStreamedIntelligence(ctx, options, state, policy)
				if err != nil || (result.Stats.MaterializationCacheHits == 1) != warm {
					b.Fatal("materialization or expected cache state failed", err)
				}
				b.StopTimer()
				if err := os.RemoveAll(options.Output); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
		})
	}
}
