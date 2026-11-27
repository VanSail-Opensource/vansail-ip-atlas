package pipeline

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestIPv6RiskProfilesMergeSplitAndRemainSparse(t *testing.T) {
	ctx := context.Background()
	quality := func(prefix string, exactLayer, prefixLayer float64, exact bool) via3.PublicRecord {
		q := &via3.QualityData{Exact: &exactLayer, Prefix: &prefixLayer}
		if risk := exactLayer + prefixLayer; risk > 0 {
			score := uint8(math.Floor(100*risk + .5))
			q.Score, q.Confidence, q.Reasons = &score, 1, 1
		}
		return via3.PublicRecord{Version: 3, Kind: 6, Prefix: netip.MustParsePrefix(prefix), Exact: exact, Quality: q}
	}
	best := quality("2001:db8:3:1::b/128", .237, .13, true)
	records := []via3.PublicRecord{
		quality("2001:db8:3:2::a/128", .0001, 0, true), // positive, rounded 0
		best,
		quality("2001:db8:3::/48", 0, .18, false),    // context alone is excluded
		quality("2001:db8:3:1::a/128", .05, 0, true), // same /64, ignored in max
		quality("2001:db8:3:ffff::a/128", 0, .1, true),
		best, // same exact input in another run never counts twice
	}
	// Force separate K7 shards and multiple bounded scatter/split passes.
	for i := 4; i < 43; i++ {
		records = append(records, quality(fmt.Sprintf("2001:db8:%x:2::a/128", i), .087, 0, true))
	}
	first := testOptions(t)
	a, err := Build(ctx, first, producer(records))
	if err != nil {
		t.Fatal(err)
	}
	if a.Stats.UniqueRecords != int64(len(records)-1) || a.Stats.SortRuns < 2 {
		t.Fatal("derived profile changed source accounting or fixture did not merge", a.Stats)
	}
	kinds := 0
	for _, o := range a.Manifest.Objects {
		if o.Kind == 7 {
			kinds++
		}
	}
	if kinds < 2 {
		t.Fatal("fixture did not split profile ranges")
	}
	second := testOptions(t)
	second.Limits.SortBytes *= 2
	slices.Reverse(records)
	b, err := Build(ctx, second, producer(records))
	if err != nil || a.Pointer != b.Pointer {
		t.Fatal("IPv6 summary depends on source or merge order", err)
	}
	open := func() *via3.Release {
		t.Helper()
		r, err := via3.OpenRelease(first.Output, func() int64 { return first.Clock })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		return r
	}
	memory, native := open(), open()
	if err := native.PrepareNativeIndex(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		q, prefix               string
		observed, positive, sum int
	}{{"2001:db8:3::1", "2001:db8:3::/48", 3, 2, 24}, {"2001:db8:4::1", "2001:db8:4::/48", 1, 1, 9}, {"2001:db8:2::1", "2001:db8:2::/48", 0, 0, 0}} {
		p, err := native.ClassC(ctx, want.q)
		if err != nil || p == nil || p.Prefix != want.prefix || p.Unit != "ipv6-/64" || p.TotalUnits != 65536 || len(p.Cells) != 0 ||
			p.ObservedCount != want.observed || p.PositiveCount != want.positive || p.ScoreSum != want.sum || p.ScoredCount != want.positive ||
			p.AssessedCount != 0 || p.AggregateScore == nil || *p.AggregateScore != 0 {
			t.Fatalf("%s profile changed: %+v %v", want.q, p, err)
		}
		other, err := memory.ClassC(ctx, want.q)
		if err != nil || !reflect.DeepEqual(p, other) {
			t.Fatal("native indexed profile differs from memory profile", err)
		}
	}
	missing, err := native.Lookup(ctx, "2001:db8:2::1")
	if err != nil || missing.Quality == nil || missing.Quality.Score == nil || *missing.Quality.Score != 0 ||
		missing.Quality.Confidence != "unrated" || len(missing.Quality.Reasons) != 0 || missing.Quality.Coverage.Layers.Exact != "unassessed" ||
		missing.Quality.Layers.Exact == nil || *missing.Quality.Layers.Exact != 0 || missing.Quality.Layers.Neighbors != nil {
		t.Fatal("numeric zero asserted unobserved risk was assessed", err)
	}
	forged := via3.PublicRecord{Version: 3, Kind: 7, Prefix: netip.MustParsePrefix("2001:db8:3::/48"),
		Profile: &via3.ProfileData{IPv6: &via3.IPv6ProfileData{ObservedCount: 1, PositiveCount: 1, ScoreSum: 5}}}
	if _, err := Build(ctx, testOptions(t), producer(append(records, forged))); err == nil {
		t.Fatal("producer provided an unsourced IPv6 profile")
	}
}

func TestIPv6RiskProfileDerivesFromActiveEvidenceInBothCompilerPaths(t *testing.T) {
	ctx := context.Background()
	state, policy, _, _, _ := intelligenceFixture(t)
	var evidence []intelligence.Evidence
	for i, input := range []struct{ address, signal string }{
		{"2001:db8:9:1::3", "malware"}, {"2001:db8:9:1::2", "proxy"}, {"2001:db8:9:2::2", "vpn"},
	} {
		x := intelligence.Evidence{Family: fmt.Sprintf("private-v6-%d", i), Signal: intelligence.Signal(input.signal), Scope: intelligence.Exact,
			Address: netip.MustParseAddr(input.address), SourcePublishedAt: state.EvaluatedAt, Current: true, Weight: 100}
		evidence = append(evidence, x)
		state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &x})
	}
	engine, err := intelligence.NewEngine(policy, evidence, nil, nil, state.EvaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	maxima := map[netip.Prefix]float64{}
	for _, row := range evidence {
		q, err := engine.Lookup(row.Address)
		if err != nil || q.Contributions[0] == nil || *q.Contributions[0] <= 0 {
			t.Fatal("fixture has no exact evidence", err)
		}
		bucket := netip.PrefixFrom(row.Address, 64).Masked()
		maxima[bucket] = max(maxima[bucket], *q.Contributions[0])
	}
	want := 0
	for _, v := range maxima {
		want += int(math.Floor(100*v + .5))
	}
	for _, streamed := range []bool{false, true} {
		opts := testOptions(t)
		opts.Limits = DefaultLimits()
		if streamed {
			_, err = BuildStreamedIntelligence(ctx, opts, state, policy)
		} else {
			_, err = BuildIntelligence(ctx, opts, state, policy)
		}
		if err != nil {
			t.Fatal(streamed, err)
		}
		r, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
		if err != nil {
			t.Fatal(err)
		}
		p, err := r.ClassC(ctx, "2001:db8:9:ffff::a")
		r.Close()
		if err != nil || p == nil || p.ObservedCount != 2 || p.PositiveCount != 2 || p.ScoreSum != want || len(p.Cells) != 0 {
			t.Fatal("materialized summary differs from current exact evidence", streamed, p, err)
		}
	}
}
