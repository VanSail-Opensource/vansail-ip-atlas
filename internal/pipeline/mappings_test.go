package pipeline

import (
	"context"
	"crypto/sha256"
	"maps"
	"net/netip"
	"os"
	"reflect"
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

func TestMappingAncestorStackRestoresParentsAcrossBranchesAndFamilies(t *testing.T) {
	state, policy := mappingFixture(t)
	state.Sources = state.Sources[:1]
	source := &state.Sources[0]
	source.Records = nil
	expected := map[string]string{
		"0.0.0.0/0": "US", "8.0.0.0/8": "DE", "8.0.0.0/16": "BR",
		"8.0.0.0/24": "BR", "8.1.0.0/24": "DE", "9.0.0.0/8": "US",
		"::/0": "CA", "2001:db8::/32": "FR", "2001:db8::/48": "FR",
		"2001:db9::/32": "CA",
	}
	for _, p := range []string{"0.0.0.0/0", "8.0.0.0/8", "8.0.0.0/16", "::/0", "2001:db8::/32"} {
		source.Records = append(source.Records, intelligence.NormalizedRecord{
			Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{
				Family: source.ID, Prefix: netip.MustParsePrefix(p), PhysicalCountry: expected[p], Weight: 100, Current: true,
			},
		})
	}
	for _, p := range []string{"8.0.0.0/24", "8.1.0.0/24", "9.0.0.0/8", "2001:db8::/48", "2001:db9::/32"} {
		source.Records = append(source.Records, intelligence.NormalizedRecord{
			Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{
				Prefix: netip.MustParsePrefix(p), Evidence: intelligence.UsageEvidence{Family: source.ID, Type: "business", Current: true},
			},
		})
	}
	got := map[string]string{}
	err := MappingProducer(state, policy, state.EvaluatedAt)(context.Background(), func(row via3.PublicRecord) error {
		if row.Geo != nil {
			got[row.Prefix.String()] = row.Geo.Country
		}
		return nil
	})
	if err != nil || !maps.Equal(got, expected) {
		t.Fatalf("inherited mapping across nested siblings and families: got %v, err %v", got, err)
	}
}

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

func TestCompactMappingValuesPreserveUnknownsAndNetworkPrefixes(t *testing.T) {
	state, policy := mappingFixture(t)
	parent := netip.MustParsePrefix("203.0.0.0/16")
	same := *state.Sources[1].Records[0].Geo
	same.Prefix = netip.MustParsePrefix("203.0.40.0/24")
	state.Sources[1].Records = append(state.Sources[1].Records,
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &same},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: same.Prefix, Origins: []uint32{13335, 15169}}},
	)
	// An explicit unknown must mask a known parent. A first all-unknown row
	// must retain its presence even where no parent exists.
	for _, p := range []netip.Prefix{parent, netip.MustParsePrefix("2001:db8::/32")} {
		state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{
			Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{
				Prefix: p, Evidence: intelligence.UsageEvidence{Family: state.Sources[0].ID, Current: true},
			},
		})
	}
	ctx := context.Background()
	build := func(compact bool) (*via3.Release, int) {
		t.Helper()
		o := testOptions(t)
		o.Limits.PartitionRecords = 6
		count := 0
		producer := mappingProducer(state, policy, state.EvaluatedAt, nil, compact, netip.Prefix{}, nil)
		_, err := Build(ctx, o, func(ctx context.Context, emit func(via3.PublicRecord) error) error {
			return producer(ctx, func(r via3.PublicRecord) error { count++; return emit(r) })
		})
		if err != nil {
			t.Fatal(err)
		}
		release, err := via3.OpenRelease(o.Output, func() int64 { return o.Clock })
		if err != nil {
			t.Fatal(err)
		}
		return release, count
	}
	dense, before := build(false)
	sparse, after := build(true)
	if after >= before {
		t.Fatalf("redundant reference rows remained: %d >= %d", after, before)
	}
	for _, q := range []string{"203.0.0.1", "203.0.40.0", "203.0.40.255", "203.0.41.0", "203.0.113.0", "203.0.114.1", "203.0.115.1", "203.1.0.0", "2001:db8::1", "2001:db9::1"} {
		want, err := dense.Lookup(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		got, err := sparse.Lookup(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		want.ReleaseID = got.ReleaseID
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("lookup differed at %s: got %+v, want %+v", q, got, want)
		}
	}
}
