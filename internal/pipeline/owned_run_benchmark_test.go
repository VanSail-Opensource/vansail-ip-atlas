package pipeline

import (
	"context"
	"net/netip"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

// Measures the real proved, compressed merge path (including rewriting its
// output) on interleaved keys from a complete 16-way fan-in.
func BenchmarkMergeOwnedPublicRuns(b *testing.B) {
	const rowsPerRun = 32768
	const fanIn = 16
	c := &compiler{ctx: context.Background(), scratch: b.TempDir(), options: Options{Limits: DefaultLimits()}}
	var inputs []string
	for source := range fanIn {
		path := c.next()
		w, err := c.newOwnedRunWriter(path)
		if err != nil {
			b.Fatal(err)
		}
		for i := range rowsPerRun {
			ordinal := i*fanIn + source
			prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{8, byte(ordinal >> 16), byte(ordinal >> 8), byte(ordinal)}), 32)
			row := via3.PublicRecord{Version: 3, Kind: 2, Prefix: prefix, Geo: &via3.GeoData{Country: "US", Region: "Washington", City: "Seattle"}}
			if i >= rowsPerRun*3/4 {
				row = via3.PublicRecord{Version: 3, Kind: 12, ASN: uint32(131072 + ordinal), Relationship: &via3.RelationshipData{To: 13335, Relation: 2, Observed: true, Inferred: true}}
			}
			frame, err := c.newCanonicalRunFrame(row)
			if err != nil {
				b.Fatal(err)
			}
			if err = w.AppendCanonical(frame); err != nil {
				b.Fatal(err)
			}
		}
		if err := w.Finish(); err != nil {
			b.Fatal(err)
		}
		inputs = append(inputs, path)
	}
	b.ReportAllocs()
	for b.Loop() {
		path, err := c.mergeGroup(inputs)
		if err != nil || c.runProofs.lookup(path) == nil {
			b.Fatalf("merge failed to produce a proved run: %v", err)
		}
		if err := c.remove(path); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(rowsPerRun*fanIn, "rows/op")
}
