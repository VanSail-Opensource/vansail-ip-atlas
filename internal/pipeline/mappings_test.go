package pipeline

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func mappingFixture(t *testing.T) (intelligence.BuildState, intelligence.Policy) {
	t.Helper()
	file, err := os.Open("../../configs/scoring.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	policy, err := intelligence.LoadPolicy(file)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1794096000, 0).UTC()
	parent := netip.MustParsePrefix("203.0.0.0/16")
	child := netip.MustParsePrefix("203.0.113.0/24")
	anycast := netip.MustParsePrefix("203.0.114.0/24")
	missing := netip.MustParsePrefix("203.0.115.0/24")
	yes := true
	state := intelligence.BuildState{Version: 1, PolicyHash: sha256.Sum256([]byte("synthetic private policy")), EvaluatedAt: now}
	for _, family := range []string{"private-alpha", "private-bravo"} {
		state.Sources = append(state.Sources, intelligence.StoredSource{ID: family, Fingerprint: sha256.Sum256([]byte(family)), ExpiresAt: now.Add(time.Hour), Records: []intelligence.NormalizedRecord{
			{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Family: family, Weight: 100, Prefix: parent, PhysicalCountry: "US", Region: "Parent Region", City: "Parent City", Coordinates: &intelligence.Coordinates{Latitude: 10, Longitude: 20, Precision: 3}, Current: true}},
		}})
	}
	state.Sources[0].Records = append(state.Sources[0].Records,
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Family: "private-alpha", Weight: 100, Prefix: child, PhysicalCountry: "DE", Current: true}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Family: "private-alpha", Weight: 100, Prefix: missing, PhysicalCountry: "US", Current: true}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{Prefix: parent, Evidence: intelligence.UsageEvidence{Family: "private-alpha", Type: "residential", Assignment: "native", Current: true}}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{Prefix: child, Evidence: intelligence.UsageEvidence{Family: "private-alpha", Type: "business", Current: true}}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{Prefix: anycast, Evidence: intelligence.UsageEvidence{Family: "private-alpha", Anycast: &yes, Current: true}}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: parent, Origins: []uint32{13335}}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: parent, Origins: []uint32{15169, 13335}}},
	)
	return state, policy
}

func TestMappingMaterializationParentFallbackConflictAnycastAndMOAS(t *testing.T) {
	state, policy := mappingFixture(t)
	opts := testOptions(t)
	// Three mapping rows at each boundary remain indivisible together.
	opts.Limits.PartitionRecords = 8
	first, err := Build(context.Background(), opts, MappingProducer(state, policy, state.EvaluatedAt))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		q             string
		country, city *string
		usage         string
		coordinate    bool
	}{{"203.0.112.1", str("US"), str("Parent City"), "residential", true}, {"203.0.113.1", nil, nil, "unknown", false}, {"203.0.114.1", str("US"), nil, "residential", false}, {"203.0.115.1", str("US"), str("Parent City"), "residential", true}} {
		a, err := reader.Lookup(context.Background(), tc.q)
		if err != nil {
			t.Fatal(err)
		}
		if a.Geo == nil || !sameString(a.Geo.Country, tc.country) || !sameString(a.Geo.City, tc.city) || (a.Geo.Latitude != nil) != tc.coordinate || a.Usage == nil || a.Usage.Type != tc.usage {
			t.Fatalf("mapping boundary changed for %s: geo=%+v usage=%+v", tc.q, a.Geo, a.Usage)
		}
		if a.Network == nil || a.Network.Prefix != "203.0.0.0/16" || !slices.Equal(a.Network.Origins, []uint32{13335, 15169}) || !slices.Equal(a.BGP.Origins, a.Network.Origins) {
			t.Fatal("MOAS/original announced prefix changed", tc.q, a.Network, a.BGP)
		}
	}
	second := testOptions(t)
	second.Limits.PartitionRecords = 8
	slices.Reverse(state.Sources)
	for i := range state.Sources {
		slices.Reverse(state.Sources[i].Records)
	}
	again, err := Build(context.Background(), second, MappingProducer(state, policy, state.EvaluatedAt))
	if err != nil {
		t.Fatal(err)
	}
	if again.Pointer != first.Pointer {
		t.Fatal("private source ordering changed public immutable release")
	}
}
func str(value string) *string     { return &value }
func sameString(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

func TestMappingWithdrawalRetractsParentCityAndCoordinates(t *testing.T) {
	state, policy := mappingFixture(t)
	state.Sources = state.Sources[:1]
	opts := testOptions(t)
	opts.Limits.PartitionRecords = 8
	_, err := Build(context.Background(), opts, MappingProducer(state, policy, state.EvaluatedAt))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
	if err != nil {
		t.Fatal(err)
	}
	a, err := reader.Lookup(context.Background(), "203.0.112.1")
	if err != nil || a.Geo == nil || a.Geo.City != nil || a.Geo.Latitude != nil {
		t.Fatal("withdrawn family retained city/point", a.Geo, err)
	}
}

func TestMappingMaterializerRejectsUnsupportedOrStaleStateBeforeAnyEmission(t *testing.T) {
	for _, kind := range []string{"unsupported", "expired", "different-clock", "bad-union", "mapped-supernet"} {
		t.Run(kind, func(t *testing.T) {
			state, policy := mappingFixture(t)
			clock := state.EvaluatedAt
			switch kind {
			case "unsupported":
				state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordCoverage, Coverage: &intelligence.Coverage{}})
			case "expired":
				state.Sources[0].ExpiresAt = clock
			case "different-clock":
				clock = clock.Add(time.Second)
			case "bad-union":
				state.Sources[0].Records[0].Usage = &intelligence.ScopedUsage{}
			case "mapped-supernet":
				state.Sources[0].Records[0].Geo.Prefix = netip.MustParsePrefix("::ffff:203.0.113.0/95")
			}
			calls := 0
			err := MappingProducer(state, policy, clock)(context.Background(), func(via3.PublicRecord) error { calls++; return nil })
			if err == nil || calls != 0 {
				t.Fatal("invalid state emitted partial mapping facts", err, calls)
			}
		})
	}
}

func TestMappingReleaseCannotOutliveReceiptOrQualifyPartialProduction(t *testing.T) {
	state, policy := mappingFixture(t)
	for _, kind := range []string{"expiry", "clock", "production"} {
		t.Run(kind, func(t *testing.T) {
			opts := testOptions(t)
			switch kind {
			case "expiry":
				opts.ValidUntil++
			case "clock":
				opts.Clock++
			case "production":
				opts.Mode = "production"
				opts.ProductionGate = func(context.Context) error { return nil }
			}
			if _, err := BuildMappings(context.Background(), opts, state, policy); err == nil {
				t.Fatal("unsafe mapping-only release published")
			}
		})
	}
	opts := testOptions(t)
	opts.Limits.PartitionRecords = 8
	if _, err := BuildMappings(context.Background(), opts, state, policy); err != nil {
		t.Fatal("valid same-clock bounded mapping release rejected", err)
	}
}
