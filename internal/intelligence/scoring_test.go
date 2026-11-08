package intelligence

import (
	"context"
	"math"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testPolicy(t *testing.T) Policy {
	t.Helper()
	f, err := os.Open("../../configs/scoring.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	policy, err := LoadPolicy(f)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
func clock() time.Time { return time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC) }
func riskEvidence(addr, family string, signal Signal) Evidence {
	return Evidence{Family: family, Signal: signal, Scope: Exact, Address: netip.MustParseAddr(addr), SourcePublishedAt: clock(), Weight: 100, Current: true}
}
func mapping() []OriginMapping {
	return []OriginMapping{{netip.MustParsePrefix("192.0.2.0/24"), []uint32{100}}}
}
func coverage() []Coverage {
	out := []Coverage{}
	for _, family := range []string{"complete-a", "complete-b"} {
		for _, layer := range []Scope{Exact, ExplicitPrefix, Neighbors24} {
			out = append(out, Coverage{Family: family, Layer: layer, Prefix: netip.MustParsePrefix("192.0.2.0/24"), PublishedAt: clock(), Current: true, Complete: true})
		}
		out = append(out, Coverage{Family: family, Layer: ASN, ASN: 100, PublishedAt: clock(), Current: true, Complete: true})
	}
	return out
}
func closeRisk(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-12 {
		t.Fatalf("got %.17g want %.17g", got, want)
	}
}

func TestScoringConfigAndPositiveOnly(t *testing.T) {
	p := testPolicy(t)
	closeRisk(t, p.Signals["malware"].Beta, 2)
	closeRisk(t, p.Weights[2], .15)
	addr := netip.MustParseAddr("192.0.2.1")
	engine, err := NewEngine(p, []Evidence{riskEvidence(addr.String(), "a", "malware")}, nil, mapping(), clock())
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Lookup(addr)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != nil || result.Confidence != "unrated" || result.Reasons&ReasonMalware == 0 {
		t.Fatalf("positive-only must retain reason and unrated quality: %+v", result)
	}
	closeRisk(t, *result.Contributions[0], .55*(1-math.Exp(-2)))
	if result.Contributions[1] != nil {
		t.Fatal("unobserved prefix must remain absent")
	}
	other, _ := engine.Lookup(netip.MustParseAddr("192.0.2.2"))
	if other.Reasons&ReasonMalware != 0 || other.Score != nil {
		t.Fatal("one host contaminated another exact host")
	}
}
func TestFamilyOrderAliasAndMonotonicity(t *testing.T) {
	p := testPolicy(t)
	addr := netip.MustParseAddr("192.0.2.1")
	base := riskEvidence(addr.String(), "a", "proxy")
	alias := base
	alias.Signal = "cloudflare_proxyip"
	inputs := [][]Evidence{{base}, {base, base, alias}, {alias, base, base}}
	var expected QualityResult
	for i, input := range inputs {
		e, err := NewEngine(p, input, coverage(), mapping(), clock())
		if err != nil {
			t.Fatal(err)
		}
		result, _ := e.Lookup(addr)
		if i == 0 {
			expected = result
		} else if !reflect.DeepEqual(result, expected) {
			t.Fatalf("family order/alias changed result: %+v %+v", expected, result)
		}
	}
	independent := base
	independent.Family = "b"
	e, err := NewEngine(p, []Evidence{base, independent}, coverage(), mapping(), clock())
	if err != nil {
		t.Fatal(err)
	}
	result, _ := e.Lookup(addr)
	if *result.Score > *expected.Score {
		t.Fatal("added independent risk improved quality")
	}
}
func TestCompleteCoverageMOASAndIPv6(t *testing.T) {
	p := testPolicy(t)
	e, err := NewEngine(p, nil, coverage(), mapping(), clock())
	if err != nil {
		t.Fatal(err)
	}
	q, _ := e.Lookup(netip.MustParseAddr("192.0.2.1"))
	if q.Score == nil || *q.Score != 100 || q.Confidence != "low" {
		t.Fatalf("authoritatively assessed negatives: %+v", q)
	}
	moas := mapping()
	moas[0].Origins = []uint32{100, 200}
	e, err = NewEngine(p, nil, coverage(), moas, clock())
	if err != nil {
		t.Fatal(err)
	}
	q, _ = e.Lookup(netip.MustParseAddr("192.0.2.1"))
	if q.Score != nil {
		t.Fatal("unassessed MOAS origin yielded score")
	}
	q, _ = e.Lookup(netip.MustParseAddr("2001:db8::1"))
	if q.Score != nil {
		t.Fatal("IPv6 must remain unrated")
	}
}
func TestExpiryRetractionNeighborSelfExclusionAndASNCap(t *testing.T) {
	p := testPolicy(t)
	self := riskEvidence("192.0.2.1", "self", "malware")
	neighbor := riskEvidence("192.0.2.2", "neighbor", "proxy")
	engine, err := NewEngine(p, []Evidence{self, neighbor}, nil, mapping(), clock())
	if err != nil {
		t.Fatal(err)
	}
	context := engine.NeighborContext(self.Address)
	closeRisk(t, context.Confidence, 1.0/48)
	closeRisk(t, context.Risk, 1-math.Exp(-16*(1-math.Exp(-.28))/255))
	if engine.ASNContext(100).Contribution > .15 {
		t.Fatal("ASN exceeded cap")
	}
	withdrawn := neighbor
	withdrawn.Current = false
	e, err := NewEngine(p, []Evidence{self, withdrawn}, nil, mapping(), clock())
	if err != nil {
		t.Fatal(err)
	}
	if e.NeighborContext(self.Address).Present {
		t.Fatal("withdrawn neighbor retained influence")
	}
	e, err = NewEngine(p, []Evidence{self}, nil, mapping(), clock().Add(720*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	q, _ := e.Lookup(self.Address)
	if q.Reasons != 0 || q.Contributions[0] != nil {
		t.Fatal("stale exact evidence retained")
	}
	old := self
	old.SubscriptionLiteral = true
	old.ItemPublishedAt = clock().Add(-168 * time.Hour)
	e, err = NewEngine(p, []Evidence{old}, nil, mapping(), clock())
	if err != nil {
		t.Fatal(err)
	}
	q, _ = e.Lookup(self.Address)
	if q.Reasons != 0 {
		t.Fatal("republished old subscription item retained")
	}
}
func TestSparseProfileDoesNotImputeCleanAndLPM(t *testing.T) {
	p := testPolicy(t)
	maps := append(mapping(), OriginMapping{netip.MustParsePrefix("192.0.2.128/25"), []uint32{200, 300}})
	e, err := NewEngine(p, []Evidence{riskEvidence("192.0.2.1", "a", "malware")}, nil, maps, clock())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.Origins(netip.MustParseAddr("192.0.2.200")), []uint32{200, 300}) {
		t.Fatal("lost MOAS LPM")
	}
	profile, err := e.Profile24(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.Cells) != 1 || profile.AggregateScore != nil || profile.PositiveCount != 1 {
		t.Fatalf("sparse profile imputed facts: %+v", profile)
	}
}
func TestInvalidInputsAndClock(t *testing.T) {
	p := testPolicy(t)
	v := riskEvidence("192.0.2.1", "a", "malware")
	v.Weight = math.NaN()
	if _, err := NewEngine(p, []Evidence{v}, nil, nil, clock()); err == nil {
		t.Fatal("nonfinite evidence accepted")
	}
	v = riskEvidence("192.0.2.1", "a", "malware")
	v.SourcePublishedAt = clock().Add(25 * time.Hour)
	if _, err := NewEngine(p, []Evidence{v}, nil, nil, clock()); err == nil {
		t.Fatal("future source accepted")
	}
	if _, err := LoadPolicy(strings.NewReader("a: &x [1]\nb: *x")); err == nil {
		t.Fatal("aliased config accepted")
	}
	if _, err := Millionths(math.NaN()); err == nil {
		t.Fatal("nonfinite public contribution accepted")
	}
	zoned := netip.MustParseAddr("::ffff:192.0.2.1%zone")
	v = riskEvidence("192.0.2.1", "a", "proxy")
	v.Address = zoned
	if _, err := NewEngine(p, []Evidence{v}, nil, mapping(), clock()); err == nil {
		t.Fatal("mapped source address lost zone before rejection")
	}
	e, err := NewEngine(p, nil, nil, mapping(), clock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Lookup(zoned); err == nil {
		t.Fatal("mapped query lost zone before rejection")
	}
	if _, err := e.Profile24(zoned); err == nil {
		t.Fatal("mapped profile query lost zone")
	}
	if e.Origins(zoned) != nil || e.NeighborContext(zoned).Present {
		t.Fatal("zoned address got contextual facts")
	}
}

func TestPartialNeighborCoverageExcludesOnlyQueryAndMappedPrefixes(t *testing.T) {
	p := testPolicy(t)
	full := coverage()
	partial := []Coverage{}
	for _, v := range full {
		if v.Layer != Neighbors24 {
			partial = append(partial, v)
			continue
		}
		for host := 0; host < 256; host++ {
			if host == 1 {
				continue
			}
			copy := v
			copy.Prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(host)}), 32)
			partial = append(partial, copy)
		}
	}
	e, err := NewEngine(p, nil, partial, []OriginMapping{{netip.MustParsePrefix("::ffff:192.0.2.0/120"), []uint32{100}}}, clock())
	if err != nil {
		t.Fatal(err)
	}
	q, _ := e.Lookup(netip.MustParseAddr("::ffff:192.0.2.1"))
	if q.Score == nil || *q.Score != 100 {
		t.Fatal("255 assessed neighbors incorrectly require queried cell")
	}
	q, _ = e.Lookup(netip.MustParseAddr("192.0.2.2"))
	if q.Score != nil {
		t.Fatal("an actually unassessed neighbor became clean")
	}
}

func TestResidentialMobileAndProviderBiasSentinels(t *testing.T) {
	p := testPolicy(t)
	bad := riskEvidence("198.51.100.1", "bad-host", "malware")
	maps := append(mapping(), OriginMapping{netip.MustParsePrefix("198.51.100.0/24"), []uint32{200}})
	direct := bad
	direct.Scope = ASN
	direct.ASN = 200
	direct.Address = netip.Addr{}
	relations := NewRelationships(true)
	_ = relations.Add(200, 100, Customer)
	for _, usageType := range []string{"residential", "mobile"} {
		e, err := NewEngine(p, []Evidence{bad, direct}, coverage(), maps, clock())
		if err != nil {
			t.Fatal(err)
		}
		q, _ := e.Lookup(netip.MustParseAddr("192.0.2.1"))
		usage := FuseUsage([]UsageEvidence{{Family: "classification", Type: usageType, Current: true}})
		if usage.Type != usageType || q.Score == nil || *q.Score != 100 || q.Reasons&(ReasonMalware|ReasonAbuse|ReasonSubnetContext|ReasonASNContext) != 0 {
			t.Fatalf("%s/provider context contamination: %+v", usageType, q)
		}
		if e.NeighborContext(netip.MustParseAddr("192.0.2.1")).Present {
			t.Fatal("other subnet contaminated neighbor layer")
		}
	}
}

func TestGeoHierarchySupportCoordinatesAndAnycast(t *testing.T) {
	p := testPolicy(t)
	records := []GeoEvidence{{Family: "a", Weight: 80, PhysicalCountry: "US", Region: "North", City: "Cafe\u0301", Coordinates: &Coordinates{10.1115, -20.1115, 3}, Current: true}, {Family: "b", Weight: 70, PhysicalCountry: "US", Region: "North", City: "Café", Coordinates: &Coordinates{50, 50, 4}, Current: true}, {Family: "c", Weight: 100, PhysicalCountry: "US", Region: "South", City: "Other", Current: true}}
	result, err := FuseGeo(p, records, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.City == nil || *result.City != "Café" || result.Coordinates == nil {
		t.Fatalf("lost hierarchy/support/NFC: %+v", result)
	}
	closeRisk(t, result.Coordinates.Latitude, 10.112)
	closeRisk(t, result.Coordinates.Longitude, -20.112)
	result, err = FuseGeo(p, records, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.City != nil || result.Coordinates != nil || result.Region == nil {
		t.Fatal("anycast suppression failed")
	}
	records = records[:1]
	result, err = FuseGeo(p, records, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Region != nil || result.City != nil {
		t.Fatal("one family manufactured fine location")
	}
}

func TestGeoFieldLPMAndMappedPrefixNormalization(t *testing.T) {
	p := testPolicy(t)
	index, err := NewGeoIndex(p, []GeoEvidence{{Family: "a", Weight: 90, Prefix: netip.MustParsePrefix("::ffff:192.0.2.0/120"), PhysicalCountry: "US", Current: true}, {Family: "a", Weight: 80, Prefix: netip.MustParsePrefix("192.0.2.1/32"), PhysicalCountry: "CA", Current: true}, {Family: "b", Weight: 80, Prefix: netip.MustParsePrefix("192.0.2.1/32"), PhysicalCountry: "CA", Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := index.Lookup(netip.MustParseAddr("192.0.2.1"), false)
	if err != nil || result.PhysicalCountry == nil || *result.PhysicalCountry != "CA" {
		t.Fatal("mapped parent incorrectly outranked native exact prefix")
	}
	index, err = NewGeoIndex(p, []GeoEvidence{{Family: "a", Weight: 90, Prefix: netip.MustParsePrefix("192.0.2.0/24"), PhysicalCountry: "US", Current: true}, {Family: "a", Weight: 90, Prefix: netip.MustParsePrefix("192.0.2.1/32"), RegistrationCountry: "CA", Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	result, err = index.Lookup(netip.MustParseAddr("192.0.2.1"), false)
	if err != nil || result.PhysicalCountry == nil || *result.PhysicalCountry != "US" || result.RegistrationCountry == nil || *result.RegistrationCountry != "CA" {
		t.Fatal("missing child field erased independently inherited parent fact")
	}
}
func TestUsageIndependentFlagsAndUnsafeLabels(t *testing.T) {
	truth := true
	falsity := false
	result := FuseUsage([]UsageEvidence{{Family: "a", Type: "residential", Anycast: &truth, Current: true}, {Family: "b", Type: "hosting", DirectedBroadcast: &falsity, Current: true}})
	if result.Type != "unknown" || result.Assignment != "unknown" || result.Anycast == nil || !*result.Anycast || result.DirectedBroadcast == nil || *result.DirectedBroadcast {
		t.Fatalf("usage/assignment/boolean presence conflated: %+v", result)
	}
	if got := SafeLabel("Example ISP https://private.example user:secret user@example.com isp.example"); got != "Example ISP" {
		t.Fatalf("unsafe label survived: %q", got)
	}
}
func TestRPKIReverseRelationshipsAndPathSemantics(t *testing.T) {
	v, err := NewVRPIndex([]VRP{{netip.MustParsePrefix("192.0.2.0/24"), 24, 100}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if v.Validate(netip.MustParsePrefix("192.0.2.0/24"), 100) != RPKIValid || v.Validate(netip.MustParsePrefix("192.0.2.0/24"), 200) != RPKIInvalid || v.Validate(netip.MustParsePrefix("192.0.2.0/25"), 100) != RPKIInvalid || v.Validate(netip.MustParsePrefix("198.51.100.0/24"), 100) != RPKINotFound {
		t.Fatal("per-origin RPKI or maximum length lost")
	}
	v.current = false
	if v.Validate(netip.MustParsePrefix("192.0.2.0/24"), 100) != RPKIUnknown {
		t.Fatal("missing VRPs treated as not_found")
	}
	r := NewRelationships(true)
	if err := r.Add(100, 200, Customer); err != nil {
		t.Fatal(err)
	}
	if r.Relation(200, 100) != TransitUpstream || r.Relation(100, 200) != Customer || r.Relation(100, 300) != UnknownRelation {
		t.Fatal("relationship perspective wrong")
	}
	_ = r.Add(100, 200, Peer)
	if r.Relation(200, 100) != UnknownRelation {
		t.Fatal("conflicting edge became peer")
	}
	paths, err := RankPaths([]PathObservation{{Origin: 100, Family: "a", Current: true, Segments: []PathSegment{{ASSequence, []uint32{300, 200, 100, 100}}}}, {Origin: 100, Family: "a", Current: true, OriginOutward: true, Segments: []PathSegment{{ASSequence, []uint32{100}}, {ASSet, []uint32{200, 300}}}}}, r)
	if err != nil {
		t.Fatal(err)
	}
	eligible := 0
	for _, path := range paths {
		if path.GraphEligible {
			eligible++
			if !reflect.DeepEqual(path.Segments[0].ASNs, []uint32{100, 100, 200, 300}) {
				t.Fatal("original prepends/orientation not retained")
			}
		}
	}
	if eligible != 1 {
		t.Fatal("AS set became ordered path")
	}
}
func TestGraphBudgetsAndNoInventedGaps(t *testing.T) {
	observations := []PathObservation{}
	for i := 0; i < 4; i++ {
		observations = append(observations, PathObservation{Origin: 100, Family: "a", Current: true, OriginOutward: true, Segments: []PathSegment{{ASSequence, []uint32{100, 200, 300, uint32(400 + i)}}}})
	}
	paths, err := RankPaths(observations, nil)
	if err != nil {
		t.Fatal(err)
	}
	graph := ProjectGraph(paths, nil)
	if len(graph.Nodes) > 24 || !graph.Truncated {
		t.Fatal("graph budget/truncation failed")
	}
	exits := 0
	for _, edge := range graph.Edges {
		if edge.From == 300 {
			exits++
		}
		if !edge.Observed || edge.Relation != "unknown" {
			t.Fatal("invented relation")
		}
	}
	if exits != 3 {
		t.Fatalf("got %d second-hop exits", exits)
	}
	for _, route := range graph.Routes {
		if len(route.Nodes) < 3 {
			t.Fatal("protected hop dropped")
		}
	}
}
func TestTier1BootstrapStabilityMissingInputsCyclesAndBudget(t *testing.T) {
	r := NewRelationships(true)
	for _, edge := range [][2]uint32{{100, 200}, {100, 300}, {200, 300}} {
		_ = r.Add(edge[0], edge[1], Peer)
	}
	for _, provider := range []uint32{100, 200, 300} {
		_ = r.Add(provider, provider+1, Customer)
	}
	paths := []PathObservation{}
	for _, asn := range []uint32{100, 200, 300} {
		for _, family := range []string{"ris", "views"} {
			paths = append(paths, PathObservation{Origin: asn, Family: family, Current: true, OriginOutward: true, Segments: []PathSegment{{ASSequence, []uint32{asn}}}})
		}
	}
	first, err := DeriveTier1(context.Background(), r, paths, clock(), clock(), "policy", nil, 10000)
	if err != nil {
		t.Fatal(err)
	}
	candidates := 0
	for _, v := range first.Results {
		if v.ASN == 100 || v.ASN == 200 || v.ASN == 300 {
			if v.Class != "unknown" || v.Stability != "pending" {
				t.Fatalf("bootstrap fabricated stability: %+v", v)
			}
			candidates++
		}
	}
	if candidates != 3 {
		t.Fatal("core not derived")
	}
	next, err := DeriveTier1(context.Background(), r, paths, clock().Add(24*time.Hour), clock().Add(24*time.Hour), "policy", &first, 10000)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range next.Results {
		if first.RawCandidates[v.ASN] && v.Class != "tier1_candidate" {
			t.Fatal("second qualified snapshot failed")
		}
	}
	missing, _ := DeriveTier1(context.Background(), r, paths[:1], clock(), clock(), "policy", nil, 10000)
	if missing.Eligible {
		t.Fatal("one family qualified Tier-1")
	}
	if _, err := DeriveTier1(context.Background(), r, paths, clock(), clock(), "policy", nil, 1); err != ErrGraphBudget {
		t.Fatalf("budget was silently relaxed: %v", err)
	}
	_ = r.Add(101, 100, Customer)
	cyclic, _ := DeriveTier1(context.Background(), r, paths, clock(), clock(), "policy", nil, 10000)
	if cyclic.Eligible {
		t.Fatal("cyclic graph qualified")
	}
}
