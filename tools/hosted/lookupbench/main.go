// Command lookupbench measures individual complete indexed lookups on real VIA3.
// Raw per-call timings include the timer overhead; batch means are not p95s.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"vansail-ip-atlas/internal/via3"
	querycontract "vansail-ip-atlas/tools/query_contract"
)

type query struct {
	Q       string `json:"q"`
	Stratum string `json:"stratum"`
}
type corpus struct {
	FormatVersion    int     `json:"format_version"`
	Mode             string  `json:"mode"`
	GraphQuery       *string `json:"graph_query"`
	MapQuery         *string `json:"map_query"`
	InteractionQuery string  `json:"interaction_query"`
	ReleaseID        string  `json:"release_id"`
	UnknownQueries   struct {
		IPv4 string `json:"ipv4"`
		IPv6 string `json:"ipv6"`
		ASN  string `json:"asn"`
	} `json:"unknown_queries"`
	Availability []struct {
		Stratum        string `json:"stratum"`
		Status         string `json:"status"`
		SampledQueries int    `json:"sampled_queries"`
	} `json:"availability"`
	Queries []query `json:"queries"`
}

func validateCorpus(c corpus) error {
	fail := func() error { return errors.New("a versioned real 10000-query subset corpus is required") }
	digest, err := hex.DecodeString(c.ReleaseID)
	if c.FormatVersion != 2 || c.Mode != "production" || len(c.Queries) != 10000 || err != nil || len(digest) != 32 {
		return fail()
	}
	valid := func(q string) bool {
		input, err := querycontract.ParseInput(q)
		return err == nil && input.Canonical == q
	}
	interaction, err := netip.ParseAddr(c.InteractionQuery)
	if err != nil || !interaction.Is4() || !valid(c.InteractionQuery) {
		return fail()
	}
	if c.MapQuery != nil {
		address, err := netip.ParseAddr(*c.MapQuery)
		if err != nil || !address.Is4() || *c.MapQuery != c.InteractionQuery {
			return fail()
		}
	}
	if c.GraphQuery != nil && (!valid(*c.GraphQuery) || !strings.HasPrefix(*c.GraphQuery, "AS")) {
		return fail()
	}
	v4, e4 := netip.ParseAddr(c.UnknownQueries.IPv4)
	v6, e6 := netip.ParseAddr(c.UnknownQueries.IPv6)
	if e4 != nil || !v4.Is4() || e6 != nil || !v6.Is6() || v6.Is4In6() || !valid(c.UnknownQueries.IPv4) || !valid(c.UnknownQueries.IPv6) || !valid(c.UnknownQueries.ASN) || !strings.HasPrefix(c.UnknownQueries.ASN, "AS") {
		return fail()
	}
	strata := []string{"ipv4_exact", "ipv4_lpm", "ipv6_exact", "ipv6_lpm", "moas", "sparse_asn", "dense_asn", "inherited", "unknown"}
	if len(c.Availability) != len(strata) {
		return fail()
	}
	available := map[string]int{}
	counts := map[string]map[string]bool{}
	for i, row := range c.Availability {
		if row.Stratum != strata[i] || row.SampledQueries < 0 || row.SampledQueries > 1200 || (row.SampledQueries == 0 && row.Status != "absent") || (row.SampledQueries > 0 && row.Status != "observed") {
			return fail()
		}
		available[row.Stratum] = row.SampledQueries
		counts[row.Stratum] = map[string]bool{}
	}
	observed := 0
	for _, row := range c.Queries {
		if !valid(row.Q) || available[row.Stratum] == 0 {
			return fail()
		}
		counts[row.Stratum][row.Q] = true
		if row.Stratum != "unknown" {
			observed++
		}
	}
	for _, row := range c.Availability {
		if len(counts[row.Stratum]) > row.SampledQueries || row.SampledQueries > 0 && len(counts[row.Stratum]) == 0 {
			return fail()
		}
	}
	if observed == 0 || !counts["unknown"][c.UnknownQueries.IPv4] || !counts["unknown"][c.UnknownQueries.IPv6] || !counts["unknown"][c.UnknownQueries.ASN] {
		return fail()
	}
	return nil
}

func run() error {
	atlas := flag.String("atlas", "", "qualified production atlas directory")
	input := flag.String("corpus", "", "private versioned 10000-query corpus")
	output := flag.String("report", "", "source-free output report outside atlas")
	clock := flag.Int64("clock", time.Now().UTC().Unix(), "UTC evaluation clock")
	flag.Parse()
	if *atlas == "" || *input == "" || *output == "" || flag.NArg() != 0 || *clock < 0 {
		return errors.New("invalid lookup measurement arguments")
	}
	file, err := os.Open(*input)
	if err != nil {
		return errors.New("private lookup corpus unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return errors.New("lookup corpus exceeds bound")
	}
	var c corpus
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || validateCorpus(c) != nil {
		return errors.New("a versioned real 10000-query corpus is required")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("extra corpus JSON")
	}
	release, err := via3.OpenRelease(*atlas, func() int64 { return *clock })
	if err != nil {
		return errors.New("qualified lookup release unavailable")
	}
	if release.Manifest.Mode != "production" {
		return errors.New("synthetic lookups cannot qualify production latency")
	}
	if release.Manifest.ReleaseID != c.ReleaseID {
		return errors.New("lookup corpus belongs to another release")
	}
	var inputBytes int64
	for _, obj := range release.Manifest.Objects {
		inputBytes += int64(obj.Bytes)
	}
	ctx := context.Background()
	// Warm every query once. This exceeds the minimum 1000 warmups and cannot
	// accidentally label a first object decode as a cached lookup.
	for _, q := range c.Queries {
		if _, err := release.Lookup(ctx, q.Q); err != nil {
			return errors.New("corpus warmup failed")
		}
	}
	samples := make([]int64, 100000)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	started := time.Now()
	for i := range samples {
		q := c.Queries[i%len(c.Queries)].Q
		start := time.Now()
		answer, err := release.Lookup(ctx, q)
		samples[i] = time.Since(start).Nanoseconds()
		if err != nil {
			return errors.New("timed complete lookup failed")
		}
		runtime.KeepAlive(answer)
	}
	runtime.ReadMemStats(&after)
	duration := time.Since(started)
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	peak := int64(0)
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "VmHWM:") {
				fields := strings.Fields(line)
				if len(fields) == 3 {
					kb, _ := strconv.ParseInt(fields[1], 10, 64)
					peak = kb * 1024
				}
			}
		}
	}
	digest := sha256.Sum256(data)
	report := struct {
		Timing         string  `json:"timing"`
		CorpusQueries  int     `json:"corpus_queries"`
		Warmups        int     `json:"warmups"`
		CorpusSHA256   string  `json:"corpus_sha256"`
		ReleaseID      string  `json:"release_id"`
		InputBytes     int64   `json:"compressed_input_bytes"`
		Samples        []int64 `json:"samples_ns"`
		P50            int64   `json:"p50_ns"`
		P95            int64   `json:"p95_ns"`
		P99            int64   `json:"p99_ns"`
		Allocations    uint64  `json:"allocation_count"`
		AllocatedBytes uint64  `json:"allocated_bytes"`
		PeakRSS        int64   `json:"process_peak_rss_bytes"`
		ScratchBytes   int64   `json:"temporary_disk_bytes"`
		Duration       int64   `json:"runtime_ns"`
		GoVersion      string  `json:"go_version"`
	}{"individual-indexed-lookups", len(c.Queries), len(c.Queries), hex.EncodeToString(digest[:]), release.Manifest.ReleaseID, inputBytes,
		samples, sorted[49999], sorted[94999], sorted[98999], after.Mallocs - before.Mallocs, after.TotalAlloc - before.TotalAlloc, peak, 0, duration.Nanoseconds(), runtime.Version()}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	absoluteOutput, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	absoluteAtlas, err := filepath.Abs(*atlas)
	if err != nil {
		return err
	}
	if rel, err := filepath.Rel(absoluteAtlas, absoluteOutput); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("measurement report cannot enter atlas")
	}
	if err := os.MkdirAll(filepath.Dir(absoluteOutput), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(absoluteOutput, encoded, 0600); err != nil {
		return err
	}
	fmt.Printf("Measured %d complete production lookups; p95 %d ns\n", len(samples), report.P95)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
