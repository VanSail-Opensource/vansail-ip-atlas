package main

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestStratumDiagnosticsUseOriginalTimedPopulationWithoutDisclosingQueries(t *testing.T) {
	c := subsetCorpus()
	for i := range c.Queries {
		c.Queries[i].Q = "PRIVATE_QUERY_SENTINEL"
	}
	samples := make([]int64, 100000)
	for i := range samples {
		samples[i] = int64(len(samples) - i)
	}
	before := slices.Clone(samples)
	queries := slices.Clone(c.Queries)
	rows, err := summarizeStrata(c.Queries, samples)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(samples, before) || !slices.Equal(c.Queries, queries) {
		t.Fatal("diagnostics changed the timed samples or private corpus")
	}
	names := []string{"ipv4_exact", "ipv4_lpm", "ipv6_exact", "ipv6_lpm", "moas", "sparse_asn", "dense_asn", "inherited", "unknown"}
	if len(rows) != len(names) {
		t.Fatal("diagnostic strata are not the fixed complete population")
	}
	totalQueries, totalSamples := 0, 0
	for i, row := range rows {
		if row.Stratum != names[i] {
			t.Fatal("stratum order changed")
		}
		totalQueries += row.CorpusQueries
		totalSamples += row.TimedSamples
		switch row.Stratum {
		case "ipv4_lpm", "unknown":
			want := []int64{50000, 95000, 99000}
			queries, count := 2500, 25000
			if row.Stratum == "unknown" {
				want = []int64{49999, 94999, 98999}
				queries, count = 7500, 75000
			}
			if row.CorpusQueries != queries || row.TimedSamples != count || row.P50 == nil || row.P95 == nil || row.P99 == nil ||
				!slices.Equal([]int64{*row.P50, *row.P95, *row.P99}, want) {
				t.Fatalf("incorrect modulo-corpus population or nearest-rank percentiles: %+v", row)
			}
		default:
			if row.CorpusQueries != 0 || row.TimedSamples != 0 || row.P50 != nil || row.P95 != nil || row.P99 != nil {
				t.Fatal("absent stratum fabricated a population or latency")
			}
		}
	}
	if totalQueries != 10000 || totalSamples != len(samples) {
		t.Fatal("diagnostic population differs from the existing measurement")
	}
	encoded, err := json.Marshal(rows)
	if err != nil || strings.Contains(string(encoded), "PRIVATE") {
		t.Fatal("diagnostics disclosed a query")
	}
	var public []map[string]json.RawMessage
	if json.Unmarshal(encoded, &public) != nil {
		t.Fatal("invalid diagnostic JSON")
	}
	for _, row := range public {
		keys := make([]string, 0, len(row))
		for key := range row {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if !reflect.DeepEqual(keys, []string{"corpus_queries", "p50_ns", "p95_ns", "p99_ns", "stratum", "timed_samples"}) {
			t.Fatal("unexpected public diagnostic field")
		}
	}
}

func TestStratumDiagnosticsRejectIncompleteOrUnknownPopulations(t *testing.T) {
	queries := subsetCorpus().Queries
	samples := make([]int64, 100000)
	for _, pair := range []struct {
		queries []query
		samples []int64
	}{{nil, samples}, {queries[:9999], samples}, {queries, samples[:99999]}, {queries, append(samples, 0)}} {
		if _, err := summarizeStrata(pair.queries, pair.samples); err == nil {
			t.Fatal("incomplete or oversized diagnostic population accepted")
		}
	}
	queries[0].Stratum = "PRIVATE_STRATUM_SENTINEL"
	if _, err := summarizeStrata(queries, samples); err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("unknown stratum accepted or disclosed")
	}
	queries[0].Stratum = "ipv4_lpm"
	samples[0] = -1
	if _, err := summarizeStrata(queries, samples); err == nil {
		t.Fatal("negative measured latency accepted")
	}
}

func TestObjectReadDiagnosticsRetainPhaseSnapshotsAndDeltas(t *testing.T) {
	reads, err := summarizeReads(1, 17, 17, 22)
	if err != nil || reads != (objectReadDiagnostics{1, 17, 17, 22, 16, 5}) {
		t.Fatalf("incorrect read counters: %+v %v", reads, err)
	}
	reads, err = summarizeReads(1, 1, 1, 1)
	if err != nil || reads.Warmup != 0 || reads.Timed != 0 {
		t.Fatal("warm cache fabricated object reads")
	}
	for _, counts := range [][4]int{{-1, 0, 0, 0}, {2, 1, 1, 1}, {1, 2, 1, 2}, {1, 2, 2, 1}} {
		if _, err := summarizeReads(counts[0], counts[1], counts[2], counts[3]); err == nil {
			t.Fatal("nonmonotonic object read counters accepted")
		}
	}
}
