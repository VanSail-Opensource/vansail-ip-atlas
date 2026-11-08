package via3

import (
	"context"
	"net/netip"
	"testing"
)

func TestTypedCompilerAllFactFamiliesAndProductionGate(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	zero := 0.0
	score := uint8(100)
	no := false
	cone := uint32(1)
	records := []PublicRecord{
		{Version: 3, Kind: 2, Prefix: prefix, Geo: &GeoData{Country: "US", Region: "St. Louis", City: "Example City"}},
		{Version: 3, Kind: 3, Prefix: prefix, Coordinates: &CoordinateData{Latitude: 10.125, Longitude: -20.125, Precision: 3}},
		{Version: 3, Kind: 4, Prefix: prefix, Network: &NetworkData{Name: "Example Network", Organization: "Example", Origins: []uint32{13335, 13335}}},
		{Version: 3, Kind: 5, Prefix: prefix, Usage: &UsageData{Type: 1, Assignment: 1, Anycast: &no, DirectedBroadcast: &no}},
		{Version: 3, Kind: 6, Prefix: netip.MustParsePrefix("203.0.113.1/32"), Exact: true, Quality: &QualityData{Score: &score, Confidence: 2, Exact: &zero, Prefix: &zero, ASN: &zero, Neighbors: &zero}},
		{Version: 3, Kind: 7, Prefix: prefix, Profile: &ProfileData{Cells: []CellData{{Address: netip.MustParseAddr("203.0.113.1"), Usage: 1, Score: &score, Confidence: 2, ExactRisk: &zero, AttachNetwork: true}}}},
		{Version: 3, Kind: 8, ASN: 13335, ASNAggregate: &ASNData{Name: "Example Network", Country: "US", Risk: &zero, Confidence: 2, Prefixes: []netip.Prefix{prefix}, CustomerCone: &cone, NetworkClass: 2, Stability: 2}},
		{Version: 3, Kind: 9, Prefix: prefix, ASN: 13335, RPKI: &RPKIData{Status: 1, MaximumLength: 24}},
		{Version: 3, Kind: 10, Prefix: prefix, Origins: &OriginsData{ASNs: []uint32{13335}}},
		{Version: 3, Kind: 11, ASN: 13335, Path: &PathData{GraphEligible: true, Visibility: 2, Segments: []SegmentData{{Type: 1, ASNs: []uint32{13335, 3356}}}}},
		{Version: 3, Kind: 12, ASN: 13335, Relationship: &RelationshipData{To: 3356, Relation: 1, Observed: true, Inferred: true}},
		{Version: 3, Kind: 13, ASN: 13335, Tier1: &TierData{NetworkClass: 2, Stability: 2}},
	}
	input := CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: []PartitionInput{{Partition: "all", PrefixRoutes: []netip.Prefix{prefix}, ASNRoutes: []uint32{13335}, Records: records}}}
	built, err := Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[uint16]bool{}
	objects := map[string][]byte{}
	for _, object := range built.Objects {
		kinds[object.Info.Kind] = true
		objects[object.Info.SHA256] = object.Bytes
	}
	if len(kinds) != 14 {
		t.Fatalf("typed compiler omitted shard kinds: %v", kinds)
	}
	reader, err := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(hash string) ([]byte, error) { return objects[hash], nil }, func() int64 { return input.Clock })
	if err != nil {
		t.Fatal(err)
	}
	answer, err := reader.Lookup(context.Background(), "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if answer.Geo == nil || answer.Geo.Region == nil || *answer.Geo.Region != "St. Louis" || answer.Quality == nil || answer.Quality.Score == nil || *answer.Quality.Score != 100 || len(answer.Network.Origins) != 1 || len(answer.BGP.RPKI) != 1 || answer.BGP.RPKI[0].Status != "valid" {
		t.Fatal("typed facts changed during assembly")
	}
	profile, err := reader.ClassC(context.Background(), "203.0.113.1")
	if err != nil || profile == nil || profile.Cells[1].Score == nil || profile.Cells[2].Score != nil || profile.AggregateScore != nil {
		t.Fatal("sparse profile became clean", err)
	}
	input.Mode = "production"
	if _, err = Build(context.Background(), input); ErrorCode(err) != "production_blocked" {
		t.Fatal("compiler bypassed production qualification")
	}
	calls := 0
	input.ProductionGate = func(context.Context) error { calls++; return fail("production_blocked") }
	if _, err = Build(context.Background(), input); ErrorCode(err) != "production_blocked" || calls != 1 {
		t.Fatal("production rejection not propagated")
	}
}

func TestTypedAnycastBoundariesRequireExplicitUnknownFacts(t *testing.T) {
	parent := netip.MustParsePrefix("203.0.0.0/16")
	scope := netip.MustParsePrefix("203.0.113.0/24")
	child := netip.MustParsePrefix("203.0.113.2/32")
	yes, no := true, false
	records := []PublicRecord{{Version: 3, Kind: 2, Prefix: parent, Inherited: true, Geo: &GeoData{Country: "US", City: "Example City"}}, {Version: 3, Kind: 3, Prefix: parent, Inherited: true, Coordinates: &CoordinateData{Latitude: 1, Longitude: 2, Precision: 3}}, {Version: 3, Kind: 5, Prefix: scope, Usage: &UsageData{Anycast: &yes}}}
	input := PartitionInput{Partition: "4:000000000000000000000000cb007100/24", Records: records}
	if _, err := CompilePartition(context.Background(), input); ErrorCode(err) != "record" {
		t.Fatal("anycast leaked inherited city/coordinate facts")
	}
	input.Records = append(input.Records, PublicRecord{Version: 3, Kind: 2, Prefix: scope, Geo: &GeoData{Country: "US"}}, PublicRecord{Version: 3, Kind: 3, Prefix: scope, Coordinates: &CoordinateData{Unknown: true}})
	if _, err := CompilePartition(context.Background(), input); err != nil {
		t.Fatal("properly materialized unknown facts rejected", err)
	}
	// A more-specific explicit non-anycast entity may retain its own city/point.
	input.Records = append(input.Records, PublicRecord{Version: 3, Kind: 5, Prefix: child, Exact: true, Usage: &UsageData{Anycast: &no}}, PublicRecord{Version: 3, Kind: 2, Prefix: child, Exact: true, Geo: &GeoData{Country: "US", City: "Child City"}}, PublicRecord{Version: 3, Kind: 3, Prefix: child, Exact: true, Coordinates: &CoordinateData{Latitude: 3, Longitude: 4, Precision: 3}})
	if _, err := CompilePartition(context.Background(), input); err != nil {
		t.Fatal("descendant contaminated its parent scope", err)
	}
}
