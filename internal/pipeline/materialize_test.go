package pipeline

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"os"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func intelligenceFixture(t *testing.T) (intelligence.BuildState, intelligence.Policy, []intelligence.Evidence, []intelligence.Coverage, []intelligence.OriginMapping) {
	t.Helper()
	state, policy := mappingFixture(t)
	parent := netip.MustParsePrefix("203.0.0.0/16")
	mapping := []intelligence.OriginMapping{{Prefix: parent, Origins: []uint32{13335, 15169}}}
	evidence := []intelligence.Evidence{
		{Family: "private-alpha", Signal: "malware", Scope: intelligence.Exact, Address: netip.MustParseAddr("203.0.113.0"), Weight: 100, Current: true, SourcePublishedAt: state.EvaluatedAt},
		{Family: "private-bravo", Signal: "proxy", Scope: intelligence.ExplicitPrefix, Prefix: netip.MustParsePrefix("203.0.113.0/24"), Weight: 100, Current: true, SourcePublishedAt: state.EvaluatedAt},
		{Family: "private-alpha", Signal: "abuse", Scope: intelligence.ASN, ASN: 13335, Weight: 100, Current: true, SourcePublishedAt: state.EvaluatedAt},
	}
	coverage := []intelligence.Coverage{}
	for _, family := range []string{"private-alpha", "private-bravo"} {
		for _, layer := range []intelligence.Scope{intelligence.Exact, intelligence.ExplicitPrefix, intelligence.Neighbors24} {
			coverage = append(coverage, intelligence.Coverage{Family: family, Layer: layer, Prefix: parent, PublishedAt: state.EvaluatedAt, Current: true, Complete: true})
		}
		for _, asn := range []uint32{13335, 15169} {
			coverage = append(coverage, intelligence.Coverage{Family: family, Layer: intelligence.ASN, ASN: asn, PublishedAt: state.EvaluatedAt, Current: true, Complete: true})
		}
	}
	for i := range evidence {
		state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &evidence[i]})
	}
	for i := range coverage {
		state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordCoverage, Coverage: &coverage[i]})
	}
	state.Sources[0].Records = append(state.Sources[0].Records,
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordVRP, VRP: &intelligence.VRP{Prefix: parent, MaxLength: 16, ASN: 13335}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordRelationship, Relationship: &intelligence.RelationshipRecord{From: 13335, To: 15169, Relation: intelligence.TransitUpstream}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordPath, Path: &intelligence.ScopedPath{Prefix: parent, Observation: intelligence.PathObservation{Origin: 13335, Family: "private-alpha", Current: true, OriginOutward: true, Segments: []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{13335, 15169}}}}}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordPath, Path: &intelligence.ScopedPath{Prefix: parent, Observation: intelligence.PathObservation{Origin: 15169, Family: "private-alpha", Current: true, OriginOutward: true, Segments: []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{15169, 13335}}}}}},
	)
	return state, policy, evidence, coverage, mapping
}

func TestIntelligenceMaterializerQualityBoundariesMOASAndDirectedPaths(t *testing.T) {
	state, policy, evidence, coverage, mapping := intelligenceFixture(t)
	engine, err := intelligence.NewEngine(policy, evidence, coverage, mapping, state.EvaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	opts := testOptions(t)
	opts.Limits = DefaultLimits()
	candidate, err := BuildIntelligence(context.Background(), opts, state, policy, MaterializationInputs{VRPComplete: true})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
	if err != nil {
		t.Fatal(err)
	}
	profile, err := reader.ClassC(context.Background(), "203.0.113.0")
	if err != nil || profile == nil || profile.ObservedCount != 1 || profile.PositiveCount != 1 || len(profile.Cells) != 256 || !profile.Cells[0].Observed || profile.Cells[1].Observed {
		t.Fatal("sparse exact /24 observation changed", profile, err)
	}
	for _, query := range []string{"203.0.0.0", "203.0.112.255", "203.0.113.0", "203.0.113.1", "203.0.113.2", "203.0.113.127", "203.0.113.255", "203.0.114.0", "203.0.255.255"} {
		want, err := engine.Lookup(netip.MustParseAddr(query))
		if err != nil {
			t.Fatal(err)
		}
		got, err := reader.Lookup(context.Background(), query)
		if err != nil {
			t.Fatal(query, err)
		}
		if got.Quality == nil || got.Quality.Score == nil || *got.Quality.Score != *want.Score || !slices.Equal(got.Quality.Reasons, intelligence.ReasonNames(want.Reasons)) {
			t.Fatalf("quality changed at %s: got=%+v want=%+v", query, got.Quality, want)
		}
		for i, actual := range []*float64{got.Quality.Layers.Exact, got.Quality.Layers.Prefix, got.Quality.Layers.ASN, got.Quality.Layers.Neighbors} {
			if actual == nil || want.Contributions[i] == nil || math.Abs(*actual-*want.Contributions[i]) > .00000051 {
				t.Fatalf("layer %d changed at %s", i, query)
			}
		}
		if len(got.BGP.RPKI) != 2 || got.BGP.RPKI[0].Status != "valid" || got.BGP.RPKI[1].Status != "invalid" {
			t.Fatal("MOAS origin validation changed", got.BGP.RPKI)
		}
		if len(got.BGP.Paths) != 2 || !slices.Equal(got.BGP.Paths[0].ASNs, []uint32{13335, 15169}) {
			t.Fatal("observed path lost", got.BGP.Paths)
		}
		if len(got.BGP.Relationships) != 2 || got.BGP.Relationships[0].Relation != "transit_upstream" || got.BGP.Relationships[1].Relation != "customer" {
			t.Fatal("directed reverse path changed", got.BGP.Relationships)
		}
	}
	second := testOptions(t)
	second.Limits = DefaultLimits()
	slices.Reverse(state.Sources)
	for i := range state.Sources {
		slices.Reverse(state.Sources[i].Records)
	}
	again, err := BuildIntelligence(context.Background(), second, state, policy, MaterializationInputs{VRPComplete: true})
	if err != nil || candidate.Pointer != again.Pointer {
		t.Fatal("source ordering changed materialization", err)
	}
}

func TestIntelligenceMaterializerRejectsInvalidReceiptAndProduction(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	opts := testOptions(t)
	opts.Mode = "production"
	if _, err := BuildIntelligence(context.Background(), opts, state, policy); err == nil {
		t.Fatal("synthetic state certified production")
	}
	state.Sources[0].ExpiresAt = state.EvaluatedAt
	emitted := 0
	err := IntelligenceProducer(state, policy, state.EvaluatedAt)(context.Background(), func(via3.PublicRecord) error { emitted++; return nil })
	if err == nil || emitted != 0 {
		t.Fatal("expired receipt emitted facts", emitted, err)
	}
}

func TestQualityRegionsNeverSampleDescendantAtAncestorAddress(t *testing.T) {
	var regions qualityRegions
	for _, value := range []string{"::/0", "::/128", "2001:db8::/32", "2001:db8::/128", "0.0.0.0/0", "0.0.0.0/32", "203.0.113.0/24", "203.0.113.0/32"} {
		if err := regions.add(netip.MustParsePrefix(value)); err != nil {
			t.Fatal(err)
		}
	}
	var got []netip.Prefix
	if err := regions.visit(context.Background(), func(prefix netip.Prefix) error { got = append(got, prefix); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"::", "::1", "2001:db8::", "2001:db8::1", "0.0.0.0", "0.0.0.1", "203.0.113.0", "203.0.113.1", "255.255.255.255"} {
		count := 0
		for _, prefix := range got {
			if prefix.Contains(netip.MustParseAddr(query)) {
				count++
			}
		}
		if count != 1 {
			t.Fatal("non-disjoint quality regions", query, count)
		}
	}
	if !slices.Contains(got, netip.MustParsePrefix("::/128")) || !slices.Contains(got, netip.MustParsePrefix("203.0.113.0/32")) {
		t.Fatal("exact exception lost")
	}
}

func TestIntelligenceMaterializerIPv6MappedAndNonlinearPaths(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	state.Sources[0].Records = append(state.Sources[0].Records,
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Family: "private-test", Signal: "proxy", Scope: intelligence.Exact, Address: netip.MustParseAddr("2001:db8::"), SourcePublishedAt: state.EvaluatedAt, Current: true, Weight: 100}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("2001:db8::/32"), Origins: []uint32{13335}}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("::ffff:198.51.100.0/120"), Origins: []uint32{13335}}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordVRP, VRP: &intelligence.VRP{Prefix: netip.MustParsePrefix("::ffff:198.51.100.0/120"), MaxLength: 120, ASN: 13335}},
		intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordPath, Path: &intelligence.ScopedPath{Prefix: netip.MustParsePrefix("2001:db8::/32"), Observation: intelligence.PathObservation{Origin: 13335, Family: "private-test", Current: true, OriginOutward: true, Segments: []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{13335, 64512, 15169}}}}}},
	)
	opts := testOptions(t)
	opts.Limits = DefaultLimits()
	if _, err := BuildIntelligence(context.Background(), opts, state, policy, MaterializationInputs{VRPComplete: true}); err != nil {
		t.Fatal(err)
	}
	reader, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"2001:db8::", "2001:db8::1"} {
		answer, err := reader.Lookup(context.Background(), query)
		if err != nil || answer.Quality == nil || answer.Quality.Score != nil {
			t.Fatal("IPv6 quality changed", answer.Quality, err)
		}
		if slices.Contains(answer.Quality.Reasons, "proxy") != (query == "2001:db8::") {
			t.Fatal("IPv6 exact observation propagated", query, answer.Quality)
		}
		found := false
		for _, path := range answer.BGP.Paths {
			if slices.Contains(path.ASNs, uint32(64512)) {
				found = true
				if path.GraphEligible {
					t.Fatal("private-ASN observed path graph enabled")
				}
			}
		}
		if !found {
			t.Fatal("nonlinear observation discarded")
		}
	}
	answer, err := reader.Lookup(context.Background(), "198.51.100.1")
	if err != nil || len(answer.BGP.RPKI) != 1 || answer.BGP.RPKI[0].Status != "valid" {
		t.Fatal("mapped VRP normalization changed", answer.BGP.RPKI, err)
	}
}

func TestIntelligenceMaterializerMissingVRPSnapshotAndInputWithdrawal(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	for _, kind := range []string{"partial", "missing"} {
		t.Run(kind, func(t *testing.T) {
			copyState := state
			copyState.Sources = append([]intelligence.StoredSource(nil), state.Sources...)
			inputs := MaterializationInputs{}
			if kind == "missing" {
				inputs.VRPComplete = true
				for i := range copyState.Sources {
					copyState.Sources[i].Records = nil
					for _, record := range state.Sources[i].Records {
						if record.Kind != intelligence.RecordVRP {
							copyState.Sources[i].Records = append(copyState.Sources[i].Records, record)
						}
					}
				}
			}
			opts := testOptions(t)
			opts.Limits = DefaultLimits()
			if _, err := BuildIntelligence(context.Background(), opts, copyState, policy, inputs); err != nil {
				t.Fatal(err)
			}
			reader, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
			if err != nil {
				t.Fatal(err)
			}
			answer, err := reader.Lookup(context.Background(), "203.0.113.1")
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range answer.BGP.RPKI {
				if item.Status != "unavailable" {
					t.Fatal("missing or partial snapshot became assessed", item)
				}
			}
		})
	}
	opts := testOptions(t)
	opts.Limits = DefaultLimits()
	checks := 0
	sentinel := errors.New("input withdrawn")
	opts.InputGate = func(context.Context) error {
		checks++
		if checks == 2 {
			return sentinel
		}
		return nil
	}
	if _, err := BuildIntelligence(context.Background(), opts, state, policy); !errors.Is(err, sentinel) {
		t.Fatal("final input gate not enforced", err)
	}
	if _, err := os.Stat(opts.Output); !os.IsNotExist(err) {
		t.Fatal("withdrawn input left candidate", err)
	}
}
