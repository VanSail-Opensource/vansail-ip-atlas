package main

import (
	"errors"
	"slices"
)

func fixedStrata() [9]string {
	return [9]string{"ipv4_exact", "ipv4_lpm", "ipv6_exact", "ipv6_lpm", "moas", "sparse_asn", "dense_asn", "inherited", "unknown"}
}

type objectReadDiagnostics struct {
	BeforeWarmup int `json:"before_warmup"`
	AfterWarmup  int `json:"after_warmup"`
	BeforeTimed  int `json:"before_timed"`
	AfterTimed   int `json:"after_timed"`
	Warmup       int `json:"warmup"`
	Timed        int `json:"timed"`
}

func summarizeReads(beforeWarmup, afterWarmup, beforeTimed, afterTimed int) (objectReadDiagnostics, error) {
	if beforeWarmup < 0 || afterWarmup < beforeWarmup || beforeTimed < afterWarmup || afterTimed < beforeTimed {
		return objectReadDiagnostics{}, errors.New("invalid lookup object read counters")
	}
	return objectReadDiagnostics{beforeWarmup, afterWarmup, beforeTimed, afterTimed,
		afterWarmup - beforeWarmup, afterTimed - beforeTimed}, nil
}

type stratumDiagnostics struct {
	Stratum       string `json:"stratum"`
	CorpusQueries int    `json:"corpus_queries"` // Corpus slots, including repeated real queries.
	TimedSamples  int    `json:"timed_samples"`
	P50           *int64 `json:"p50_ns"` // Absent populations have null percentiles.
	P95           *int64 `json:"p95_ns"`
	P99           *int64 `json:"p99_ns"`
}

// summarizeStrata runs only after timing, allocation and RSS observations are
// complete. It partitions copies of the SAME raw samples by the benchmark's
// original modulo-corpus order. No private query text enters the diagnostics.
func summarizeStrata(queries []query, samples []int64) ([]stratumDiagnostics, error) {
	if len(queries) != 10000 || len(samples) != 100000 {
		return nil, errors.New("invalid lookup diagnostic population")
	}
	names := fixedStrata()
	positions := make(map[string]int, len(names))
	rows := make([]stratumDiagnostics, len(names))
	for i, name := range names {
		positions[name] = i
		rows[i].Stratum = name
	}
	for _, query := range queries {
		index, ok := positions[query.Stratum]
		if !ok {
			return nil, errors.New("invalid lookup diagnostic stratum")
		}
		rows[index].CorpusQueries++
	}
	// Every corpus slot occurs exactly ten times in the existing timed loop.
	// The total additional sample storage is bounded to 100000 int64 values.
	var groups [9][]int64
	for i, row := range rows {
		groups[i] = make([]int64, 0, row.CorpusQueries*(len(samples)/len(queries)))
	}
	for i, sample := range samples {
		if sample < 0 {
			return nil, errors.New("invalid lookup diagnostic latency")
		}
		index := positions[queries[i%len(queries)].Stratum]
		groups[index] = append(groups[index], sample)
	}
	for i, values := range groups {
		rows[i].TimedSamples = len(values)
		if len(values) == 0 {
			continue
		}
		slices.Sort(values)
		// Nearest-rank percentiles match the existing complete-population gate.
		p50 := values[(len(values)*50+99)/100-1]
		p95 := values[(len(values)*95+99)/100-1]
		p99 := values[(len(values)*99+99)/100-1]
		rows[i].P50, rows[i].P95, rows[i].P99 = &p50, &p95, &p99
	}
	return rows, nil
}
