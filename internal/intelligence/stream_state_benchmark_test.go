package intelligence

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Opt-in private payload replay. This does not create a real source review or
// certify publication/rights. The environment path is never copied into output.
func BenchmarkPartitionedPrivateASNFile(b *testing.B) {
	path := os.Getenv("ATLAS_PRIVATE_ASN_CSV")
	if path == "" {
		b.Skip("private capacity payload not selected")
	}
	f, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	h := sha256.New()
	input, err := io.Copy(h, f)
	_ = f.Close()
	if err != nil {
		b.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	policy, snapshot, binding := stateFixture()
	snapshot.PayloadHash = digest
	snapshot.ProofPayloadHash = digest
	snapshot.Records = nil
	samples := make([]int64, 0, b.N)
	var peakDisk int64
	var accepted uint64
	b.ReportAllocs()
	b.SetBytes(input)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		started := time.Now()
		root := b.TempDir()
		store, err := NewRecordStore(root, DefaultRecordStoreLimits())
		if err != nil {
			b.Fatal(err)
		}
		writer := store.Writer(context.Background())
		f, err := os.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		stats, err := ParseASNIdentityCSV(context.Background(), f, ParseLimits{3 << 30, 100_000_000, 1 << 20}, func(value ASNIdentityEvidence) error {
			return writer.Append(NormalizedRecord{Version: 3, Kind: RecordASNIdentity, ASNIdentity: &value})
		})
		_ = f.Close()
		if err != nil {
			_ = writer.Abort()
			b.Fatal(err)
		}
		snapshot.RecordPartitions, err = writer.Finish()
		if err != nil {
			b.Fatal(err)
		}
		plan, err := ReconcilePartitioned(context.Background(), root, BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
		if err != nil {
			b.Fatal(err)
		}
		if err = SavePartitionedState(context.Background(), root, plan.State, BuildState{}); err != nil {
			b.Fatal(err)
		}
		if err = SealPrivateState(context.Background(), root, binding); err != nil {
			b.Fatal(err)
		}
		if _, err = VerifyPrivateStateSeal(context.Background(), root, binding); err != nil {
			b.Fatal(err)
		}
		elapsed := time.Since(started).Nanoseconds()
		samples = append(samples, elapsed)
		accepted = stats.AcceptedRows
		entries, err := os.ReadDir(filepath.Join(root, ".atlas-private", "records-v2"))
		if err != nil {
			b.Fatal(err)
		}
		var disk int64
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				b.Fatal(err)
			}
			disk += info.Size()
		}
		if disk > peakDisk {
			peakDisk = disk
		}
	}
	b.StopTimer()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	for _, p := range []struct {
		name string
		n    int
	}{{"p50-ns", 50}, {"p95-ns", 95}, {"p99-ns", 99}} {
		b.ReportMetric(float64(samples[(len(samples)*p.n+99)/100-1]), p.name)
	}
	b.ReportMetric(float64(len(samples)), "samples")
	b.ReportMetric(float64(input), "input-B")
	b.ReportMetric(float64(accepted), "accepted-records")
	b.ReportMetric(float64(peakDisk), "temporary-disk-peak-B")
	rss, err := recordPeakRSS()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(rss), "peak-process-RSS-B")
	b.Logf("private replay only; payload_sha256=%x; process RSS excludes children and disk excludes unrelated workspace data", digest)
}
