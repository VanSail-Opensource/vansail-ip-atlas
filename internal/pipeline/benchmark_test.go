package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"testing"
	"time"

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
