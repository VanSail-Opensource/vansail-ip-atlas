package intelligence

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"os"
	"sort"
	"testing"
)

func reportBenchmark(b *testing.B, samples []int64, inputBytes int) {
	b.Helper()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	b.ReportMetric(float64(samples[len(samples)/2-1]), "p50-ns")
	b.ReportMetric(float64(samples[len(samples)*95/100-1]), "p95-ns")
	b.ReportMetric(float64(samples[len(samples)*99/100-1]), "p99-ns")
	b.ReportMetric(float64(len(samples)), "latency-samples")
	b.ReportMetric(float64(inputBytes), "input-B")
	b.ReportMetric(0, "temporary-disk-B")
	if rss, ok := peakRSS(); ok {
		b.ReportMetric(float64(rss), "peak-process-RSS-B")
	} else {
		b.Log("process RSS unavailable on this platform")
	}
}

func BenchmarkReconcile(b *testing.B) {
	policy, snapshot, hash := stateFixture()
	snapshot.Records = nil
	for i := 0; i < 64; i++ {
		v := riskEvidence(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}).String(), "synthetic-family", "proxy")
		snapshot.Records = append(snapshot.Records, NormalizedRecord{Version: 3, Kind: RecordEvidence, Evidence: &v})
	}
	previous, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash)
	if err != nil {
		b.Fatal(err)
	}
	input, _ := json.Marshal(snapshot)
	for _, mode := range []string{"full", "changed", "no_change"} {
		b.Run(mode, func(b *testing.B) {
			before := previous.State
			candidate := snapshot
			if mode == "full" {
				before = BuildState{}
			} else if mode == "changed" {
				candidate.PayloadHash = sha256.Sum256([]byte("synthetic changed payload"))
				candidate.ProofPayloadHash = candidate.PayloadHash
			}
			ticks := latencyClock()
			samples := make([]int64, 1000)
			for i := range samples {
				start := ticks()
				if _, err := Reconcile(before, []SourcePolicy{policy}, []SourceSnapshot{candidate}, clock(), hash); err != nil {
					b.Fatal(err)
				}
				samples[i] = ticks() - start
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Reconcile(before, []SourcePolicy{policy}, []SourceSnapshot{candidate}, clock(), hash); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			reportBenchmark(b, samples, len(input))
		})
	}
}

// Synthetic local smoke measurements. Hosted performance must independently
// measure the entire compiler process tree, scratch volume, and cold workload.
func BenchmarkLookup(b *testing.B) {
	f, err := os.Open("../../configs/scoring.yaml")
	if err != nil {
		b.Fatal(err)
	}
	p, err := LoadPolicy(f)
	_ = f.Close()
	if err != nil {
		b.Fatal(err)
	}
	records := make([]Evidence, 256)
	for i := range records {
		addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		records[i] = riskEvidence(addr.String(), "synthetic-family", "proxy")
	}
	engine, err := NewEngine(p, records, coverage(), mapping(), clock())
	if err != nil {
		b.Fatal(err)
	}
	input, _ := json.Marshal(records)
	samples := make([]int64, 1000)
	ticks := latencyClock()
	for i := range samples {
		start := ticks()
		_, err := engine.Lookup(records[i%len(records)].Address)
		if err != nil {
			b.Fatal(err)
		}
		samples[i] = ticks() - start
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Lookup(records[i%len(records)].Address)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(samples[499]), "p50-ns")
	b.ReportMetric(float64(samples[949]), "p95-ns")
	b.ReportMetric(float64(samples[989]), "p99-ns")
	b.ReportMetric(float64(len(samples)), "latency-samples")
	b.ReportMetric(float64(len(input)), "input-B")
	b.ReportMetric(0, "temporary-disk-B")
	if rss, ok := peakRSS(); ok {
		b.ReportMetric(float64(rss), "peak-process-RSS-B")
	} else {
		b.Log("process RSS unavailable on this platform")
	}
}
