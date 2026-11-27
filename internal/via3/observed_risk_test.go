package via3

import (
	"context"
	"net/netip"
	"testing"
)

func TestSchema6ObservedRiskCoverageAndTinyIPv6(t *testing.T) {
	zeroScore, contribution := uint8(0), 0.0000001
	input := CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: []PartitionInput{{Partition: "all", PrefixRoutes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, Records: []PublicRecord{{Version: 3, Kind: 6, Prefix: netip.MustParsePrefix("2001:db8::1/128"), Exact: true, Quality: &QualityData{Score: &zeroScore, Confidence: 1, Reasons: bits(9), Exact: &contribution}}}}}}
	built, err := Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{}
	for _, o := range built.Objects {
		objects[o.Info.SHA256] = o.Bytes
	}
	reader, err := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(hash string) ([]byte, error) { return objects[hash], nil }, func() int64 { return input.Clock })
	if err != nil {
		t.Fatal(err)
	}
	answer, err := reader.Lookup(context.Background(), "2001:db8::1")
	if err != nil || answer.Quality == nil || answer.Quality.Score == nil || *answer.Quality.Score != 0 || answer.Quality.Coverage.Status != "incomplete" || answer.Quality.Coverage.Layers.Neighbors != "not_applicable" {
		t.Fatalf("tiny IPv6 parity: %+v %v", answer, err)
	}
	for _, o := range built.Objects {
		old := append([]byte(nil), o.Bytes...)
		p16(old, 6, 5)
		if _, err := Read(context.Background(), old); ErrorCode(err) != "version" {
			t.Fatal("schema5 accepted by schema6 reader", err)
		}
	}
	input.Partitions[0].Records[0].Quality.CoverageComplete = true
	if _, err := Build(context.Background(), input); ErrorCode(err) != "record" {
		t.Fatal("incomplete IPv6 assessment claimed complete", err)
	}
}

func TestIPv6ProfileWireRejectsHostileLayouts(t *testing.T) {
	ctx := context.Background()
	good := func() Shard {
		row := make([]byte, 24)
		p32(row, 0, bits(21, 22))
		p32(row, 4, 65536)
		p32(row, 8, 65536)
		p32(row, 12, 55*65536)
		row[20], row[22] = 55, 1
		s := newShard(7, row)
		s.set(1, prefixRows(key("2001:db8::/48", false, 0)))
		return s
	}
	if _, err := Read(ctx, auditUncheckedContainer(t, good())); err != nil {
		t.Fatal("valid maximum /48 aggregate rejected", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Shard)
	}{
		{"nonempty-count-required", func(s *Shard) {
			p32(s.Record(0), 4, 0)
			p32(s.Record(0), 8, 0)
			p32(s.Record(0), 12, 0)
			s.Record(0)[20] = 0
		}},
		{"too-many-buckets", func(s *Shard) { p32(s.Record(0), 4, 65537) }},
		{"positive-exceeds-observed", func(s *Shard) { p32(s.Record(0), 4, 1) }},
		{"sum-exceeds-exact-layer", func(s *Shard) { p32(s.Record(0), 12, 55*65536+1) }},
		{"rounding-disagrees", func(s *Shard) { s.Record(0)[20] = 54 }},
		{"nonzero-reserved", func(s *Shard) { s.Record(0)[19] = 1 }},
		{"nonzero-confidence", func(s *Shard) { s.Record(0)[21] = 1 }},
		{"nonzero-terminal-byte", func(s *Shard) { s.Record(0)[23] = 1 }},
		{"wrong-presence-mask", func(s *Shard) { p32(s.Record(0), 0, bits(21)) }},
		{"wrong-marker", func(s *Shard) { s.Record(0)[22] = 2 }},
		{"wrong-family", func(s *Shard) { s.set(1, prefixRows(key("203.0.113.0/24", false, 0))) }},
		{"wrong-depth", func(s *Shard) { s.set(1, prefixRows(key("2001:db8::/64", false, 0))) }},
		{"unindexed-row", func(s *Shard) { s.set(1, prefixRows()) }},
		{"hidden-cells", func(s *Shard) { s.set(10, Vector(32, make([]byte, 32))) }},
		{"hidden-reference", func(s *Shard) {
			row := make([]byte, 40)
			p16(row, 0, 4)
			p32(row, 4, 64)
			s.set(7, Vector(40, row))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := good()
			tc.mutate(&s)
			if _, err := Read(ctx, auditUncheckedContainer(t, s)); ErrorCode(err) != "record" {
				t.Fatal("hostile authenticated /48 accepted", err)
			}
		})
	}
}
