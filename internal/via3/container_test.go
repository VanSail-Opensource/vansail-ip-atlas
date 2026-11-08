package via3

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

type goldenCorpus struct {
	Clock    int64    `json:"clock"`
	Pointer  Pointer  `json:"pointer"`
	Manifest Manifest `json:"manifest"`
	Objects  []struct {
		Info   ObjectInfo `json:"info"`
		Base64 string     `json:"base64"`
	} `json:"objects"`
	Vectors []struct {
		Q      string        `json:"q"`
		Answer LookupAnswer  `json:"answer"`
		ClassC *ClassCAnswer `json:"classC"`
	} `json:"vectors"`
}

func golden(t testing.TB) goldenCorpus {
	t.Helper()
	b, err := os.ReadFile("../../fixtures/bin/synthetic-via3.json")
	if err != nil {
		t.Fatal(err)
	}
	var g goldenCorpus
	if err = json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}
func memoryRelease(t testing.TB, g goldenCorpus, clock func() int64) *Release {
	t.Helper()
	objects := make(map[string][]byte)
	for _, o := range g.Objects {
		b, err := base64.StdEncoding.DecodeString(o.Base64)
		if err != nil {
			t.Fatal(err)
		}
		objects[o.Info.SHA256] = b
	}
	r, err := NewRelease(canonical(g.Pointer), canonical(g.Manifest), func(hash string) ([]byte, error) {
		b, ok := objects[hash]
		if !ok {
			return nil, fail("missing_object")
		}
		return b, nil
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSyntheticDeterministicGolden(t *testing.T) {
	g := golden(t)
	release, err := Synthetic(context.Background(), g.Clock)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(release.Pointer, g.Pointer) || !reflect.DeepEqual(release.Manifest, g.Manifest) || len(release.Objects) != len(g.Objects) {
		t.Fatal("frozen synthetic release bytes changed; review schema/golden amendment")
	}
	kinds := make(map[uint16]bool)
	for i, object := range release.Objects {
		expected := g.Objects[i]
		bytes, err := base64.StdEncoding.DecodeString(expected.Base64)
		if err != nil || !reflect.DeepEqual(object.Info, expected.Info) || !bytesEqual(object.Bytes, bytes) {
			t.Fatalf("non-deterministic object %d", i)
		}
		parsed, err := Read(context.Background(), bytes)
		if err != nil {
			t.Fatalf("kind%d: %v", object.Info.Kind, err)
		}
		kinds[parsed.Kind] = true
	}
	if len(kinds) != 14 {
		t.Fatal("not every frozen shard kind was exercised")
	}
	reader := memoryRelease(t, g, func() int64 { return g.Clock })
	for _, vector := range g.Vectors {
		t.Run(vector.Q, func(t *testing.T) {
			answer, err := reader.Lookup(context.Background(), vector.Q)
			if err != nil || !reflect.DeepEqual(answer, vector.Answer) {
				t.Fatalf("lookup mismatch: %v\ngot%s\nwant%s", err, canonical(answer), canonical(vector.Answer))
			}
			cells, err := reader.ClassC(context.Background(), vector.Q)
			if err != nil || !reflect.DeepEqual(cells, vector.ClassC) {
				t.Fatal("class C mismatch", err)
			}
		})
	}
}
func bytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }

func TestCorruptionClosedBeforeAllocation(t *testing.T) {
	g := golden(t)
	good, _ := base64.StdEncoding.DecodeString(g.Objects[0].Base64)
	cases := []struct {
		name, code string
		mutate     func([]byte) []byte
	}{
		{"short_header", "length", func(b []byte) []byte { return b[:63] }},
		{"exactly_24_mib", "length", func([]byte) []byte { return make([]byte, MaxFile) }},
		{"unknown_schema", "version", func(b []byte) []byte { p16(b, 6, 4); return b }},
		{"unknown_format", "version", func(b []byte) []byte { p16(b, 4, 4); return b }},
		{"bad_magic", "version", func(b []byte) []byte { b[0] = 255; return b }},
		{"reserved_header", "header", func(b []byte) []byte { b[45] = 1; return b }},
		{"unknown_codec", "header", func(b []byte) []byte { b[44] = 2; return b }},
		{"u64_overflow", "bounds", func(b []byte) []byte { p64(b, 72, ^uint64(0)); return b }},
		{"section_output_bomb", "bounds", func(b []byte) []byte { p64(b, 88, MaxSection+1); return b }},
		{"gap", "bounds", func(b []byte) []byte { p64(b, 72, u64(b, 72)+1); return b }},
		{"truncation", "bounds", func(b []byte) []byte { return b[:len(b)-1] }},
		{"trailing_bytes", "bounds", func(b []byte) []byte { b = append(b, 0); p64(b, 28, uint64(len(b))); return b }},
		{"checksum_mismatch", "integrity", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }},
		{"section_hash_mismatch", "integrity", func(b []byte) []byte { b[96] ^= 1; return b }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := Read(context.Background(), test.mutate(append([]byte(nil), good...)))
			if ErrorCode(err) != test.code {
				t.Fatalf("got%v want%s", err, test.code)
			}
		})
	}
	header := zstd.Header{SingleSegment: true, HasFCS: true, FrameContentSize: MaxWindow + 1, HasCheckSum: true}
	frame, err := header.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	frame = append(frame, 1, 0, 0, 0, 0, 0, 0)
	if ErrorCode(frameBounds(frame, MaxWindow+1)) != "decompression_limit" {
		t.Fatal("large decoder window accepted")
	}
}

func TestIndexedInheritedPrefixAndExactPrecedence(t *testing.T) {
	base := make([]byte, 8)
	p32(base, 0, bits(5))
	base[4] = 1
	exact := append([]byte(nil), base...)
	exact[4] = 4
	s := newShard(5, base, exact)
	s.set(8, prefixRows(key("203.0.0.0/16", false, 0)))
	s.set(1, prefixRows(key("203.0.113.1/32", true, 1)))
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		ip    string
		usage byte
	}{{"203.0.113.1", 4}, {"203.0.113.2", 1}, {"203.0.114.1", 1}} {
		row, _, ok := s.FindPrefix(netip.MustParseAddr(test.ip))
		if !ok || row[4] != test.usage {
			t.Fatal("inherited/exact mismatch", test)
		}
	}
	s.set(8, Vector(32))
	if _, _, ok := s.FindPrefix(netip.MustParseAddr("203.0.114.1")); ok {
		t.Fatal("withdrawn ancestor retained influence")
	}
}

func TestPresenceUnknownAndBounds(t *testing.T) {
	s := newShard(5, make([]byte, 8))
	s.set(1, prefixRows(key("2001:db8::/32", false, 0)))
	row := s.Record(0)
	row[6] = 1
	if ErrorCode(Validate(s)) != "record" {
		t.Fatal("absent true boolean survived")
	}
	row[6] = 0
	p32(row, 0, bits(7))
	if err := Validate(s); err != nil {
		t.Fatal("explicit false rejected", err)
	}
	dict := newShard(14)
	dict.set(5, intVector(0, 1))
	dict.set(6, BytesVector([]byte{255}))
	if ErrorCode(Validate(dict)) != "record" {
		t.Fatal("invalid UTF8 survived")
	}
	dict.set(5, intVector(0, 3))
	dict.set(6, BytesVector([]byte("e\u0301")))
	if ErrorCode(Validate(dict)) != "record" {
		t.Fatal("non-NFC dictionary survived")
	}
}

func TestExpiryAndUnknownBoundedReads(t *testing.T) {
	g := golden(t)
	now := g.Clock
	r := memoryRelease(t, g, func() int64 { return now })
	if _, err := r.Lookup(context.Background(), "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if r.Reads != 1 {
		t.Fatalf("unknown query scanned %d objects", r.Reads)
	}
	if _, err := r.Lookup(context.Background(), "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	now = g.Manifest.ValidUntil
	if _, err := r.Lookup(context.Background(), "203.0.113.1"); ErrorCode(err) != "expired" {
		t.Fatal("cache extended eligibility", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b, _ := base64.StdEncoding.DecodeString(g.Objects[0].Base64)
	if _, err := Read(ctx, b); err != context.Canceled {
		t.Fatal("cancellation ignored", err)
	}
}

func TestManifestIdentityAndTraversal(t *testing.T) {
	g := golden(t)
	p := g.Pointer
	p.ReleaseID = "../../../../../../../../../../../../../../../../../../../../../../../../"
	if _, err := NewRelease(canonical(p), canonical(g.Manifest), nil, func() int64 { return g.Clock }); ErrorCode(err) != "manifest" {
		t.Fatal("bad ID accepted")
	}
	p = g.Pointer
	p.ManifestPath = "/_atlas/releases/current/manifest.json"
	if _, err := NewRelease(canonical(p), canonical(g.Manifest), nil, func() int64 { return g.Clock }); ErrorCode(err) != "manifest" {
		t.Fatal("manifest alias accepted")
	}
	if validPartition("4:000000000000000000000000cb007101/24") || validPartition("6:20010db8000000000000000000000000/129") || validPartition("asn:23455:23457") {
		t.Fatal("invalid partition accepted")
	}
}

func BenchmarkLookup(b *testing.B) {
	g := golden(b)
	r := memoryRelease(b, g, func() int64 { return g.Clock })
	if _, err := r.Lookup(context.Background(), "203.0.113.1"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	var input int64
	for _, o := range g.Objects {
		input += int64(o.Info.Bytes)
	}
	// Windows clocks on this runner quantize short intervals. Batch means are
	// labeled explicitly; hosted per-query latency remains a separate gate.
	samples := make([]float64, 256)
	for i := range samples {
		start := time.Now()
		for j := 0; j < 128; j++ {
			if _, err := r.Lookup(context.Background(), "203.0.113.1"); err != nil {
				b.Fatal(err)
			}
		}
		samples[i] = float64(time.Since(start).Nanoseconds()) / 128
	}
	sort.Float64s(samples)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Lookup(context.Background(), "203.0.113.1"); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(input), "input-B")
	b.ReportMetric(float64(len(samples)), "latency-batch-samples")
	b.ReportMetric(0, "temporary-disk-B")
	if rss, ok := benchmarkPeakRSS(); ok {
		b.ReportMetric(float64(rss), "peak-process-RSS-B")
	} else {
		b.Log("process RSS unavailable on this platform")
	}
	for _, p := range []struct {
		name string
		n    int
	}{{"p50-batch-ns", 50}, {"p95-batch-ns", 95}, {"p99-batch-ns", 99}} {
		b.ReportMetric(samples[(len(samples)*p.n+99)/100-1], p.name)
	}
}
func BenchmarkIndexedPrefix(b *testing.B) {
	g := golden(b)
	r := memoryRelease(b, g, func() int64 { return g.Clock })
	addr := netip.MustParseAddr("203.0.113.1")
	b.ReportAllocs()
	samples := make([]float64, 256)
	for i := range samples {
		start := time.Now()
		for j := 0; j < 8192; j++ {
			if _, _, ok := r.router.findPrefix(addr); !ok {
				b.Fatal("missing")
			}
		}
		samples[i] = float64(time.Since(start).Nanoseconds()) / 8192
	}
	sort.Float64s(samples)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := r.router.findPrefix(addr); !ok {
			b.Fatal("missing")
		}
	}
	b.StopTimer()
	var input int
	for _, section := range r.router.Sections {
		input += len(section.Data)
	}
	b.ReportMetric(float64(input), "decoded-index-input-B")
	b.ReportMetric(float64(len(samples)), "latency-batch-samples")
	b.ReportMetric(0, "temporary-disk-B")
	if rss, ok := benchmarkPeakRSS(); ok {
		b.ReportMetric(float64(rss), "peak-process-RSS-B")
	} else {
		b.Log("process RSS unavailable on this platform")
	}
	for _, p := range []struct {
		name string
		n    int
	}{{"p50-batch-ns", 50}, {"p95-batch-ns", 95}, {"p99-batch-ns", 99}} {
		b.ReportMetric(samples[(len(samples)*p.n+99)/100-1], p.name)
	}
}
