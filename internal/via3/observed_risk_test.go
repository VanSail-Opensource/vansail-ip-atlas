package via3

import (
	"context"
	"net/netip"
	"testing"
)

func TestSchema4ObservedRiskCoverageAndTinyIPv6(t *testing.T) {
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
		p16(old, 6, 3)
		if _, err := Read(context.Background(), old); ErrorCode(err) != "version" {
			t.Fatal("schema3 accepted by schema4 reader", err)
		}
	}
	input.Partitions[0].Records[0].Quality.CoverageComplete = true
	if _, err := Build(context.Background(), input); ErrorCode(err) != "record" {
		t.Fatal("incomplete IPv6 assessment claimed complete", err)
	}
}
