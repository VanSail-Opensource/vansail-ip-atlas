package pipeline

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestMRTUnknownOriginBoundaryPreservesPublicLookupAndUsage(t *testing.T) {
	state, policy := mappingFixture(t)
	state.Sources = state.Sources[:1]
	state.Sources[0].Records = nil
	appendRecord := func(record intelligence.NormalizedRecord) {
		record.Version = 3
		state.Sources[0].Records = append(state.Sources[0].Records, record)
	}
	for _, asn := range []uint32{13335, 15169} {
		appendRecord(intelligence.NormalizedRecord{Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{ASN: asn, ObservedAt: state.EvaluatedAt, Evidence: intelligence.UsageEvidence{Family: "private-alpha", Type: "hosting", Current: true}}})
	}
	appendRecord(intelligence.NormalizedRecord{Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Family: "private-alpha", Signal: "abuse", Scope: intelligence.ASN, ASN: 13335, Weight: 100, Current: true, SourcePublishedAt: state.EvaluatedAt}})
	var mappings []intelligence.OriginMapping
	for _, group := range [][3]string{{"11.0.0.0/16", "11.0.1.0/24", "11.0.2.0/24"}, {"2001:4860::/32", "2001:4860:1::/48", "2001:4860:2::/48"}} {
		parent := netip.MustParsePrefix(group[0])
		for _, mapping := range []intelligence.OriginMapping{
			{Prefix: parent, Origins: []uint32{13335}},
			{Prefix: netip.MustParsePrefix(group[1]), Origins: []uint32{}},
			{Prefix: netip.MustParsePrefix(group[2]), Origins: []uint32{}},
			// Another peer's positive observation at exactly the same prefix
			// remains usable; the unknown peer adds no invented MOAS member.
			{Prefix: netip.MustParsePrefix(group[2]), Origins: []uint32{15169}},
		} {
			mappings = append(mappings, mapping)
			appendRecord(intelligence.NormalizedRecord{Kind: intelligence.RecordOrigins, Origins: &mapping})
		}
		appendRecord(intelligence.NormalizedRecord{Kind: intelligence.RecordVRP, VRP: &intelligence.VRP{Prefix: parent, MaxLength: uint8(parent.Bits()), ASN: 13335}})
		appendRecord(intelligence.NormalizedRecord{Kind: intelligence.RecordPath, Path: &intelligence.ScopedPath{Prefix: parent, Observation: intelligence.PathObservation{Origin: 13335, Family: "private-alpha", Current: true, OriginOutward: true, Segments: []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{13335, 15169}}}}}})
	}
	appendRecord(intelligence.NormalizedRecord{Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Family: "private-alpha", Signal: "malware", Scope: intelligence.Exact, Address: netip.MustParseAddr("11.0.1.1"), Weight: 100, Current: true, SourcePublishedAt: state.EvaluatedAt}})
	engine, err := intelligence.NewEngine(policy, nil, nil, mappings, state.EvaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, streamed := range []bool{false, true} {
		options := testOptions(t)
		options.Limits = DefaultLimits()
		if streamed {
			_, err = BuildStreamedIntelligence(context.Background(), options, state, policy)
		} else {
			_, err = BuildIntelligence(context.Background(), options, state, policy)
		}
		if err != nil {
			t.Fatal(streamed, err)
		}
		reader, err := via3.OpenRelease(options.Output, func() int64 { return options.Clock })
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			ip, prefix string
			origins    []uint32
		}{
			{"11.0.1.1", "11.0.1.0/24", nil},
			{"2001:4860:1::1", "2001:4860:1::/48", nil},
			{"11.0.2.1", "11.0.2.0/24", []uint32{15169}},
			{"2001:4860:2::1", "2001:4860:2::/48", []uint32{15169}},
			{"11.0.3.1", "11.0.0.0/16", []uint32{13335}},
			{"2001:4860:3::1", "2001:4860::/32", []uint32{13335}},
		} {
			answer, err := reader.Lookup(context.Background(), tc.ip)
			if err != nil || answer.Network == nil || answer.Network.Prefix != tc.prefix || !slices.Equal(answer.Network.Origins, tc.origins) || !slices.Equal(answer.BGP.Origins, tc.origins) || !slices.Equal(engine.Origins(netip.MustParseAddr(tc.ip)), tc.origins) {
				t.Fatalf("streamed=%v ip=%s lost observed origin boundary: %+v err=%v", streamed, tc.ip, answer, err)
			}
			if len(tc.origins) == 0 {
				if len(answer.ASNs) != 0 || len(answer.BGP.Paths) != 0 || len(answer.BGP.RPKI) != 0 || len(answer.BGP.Relationships) != 0 || len(answer.BGP.Tier1) != 0 || answer.Usage == nil || answer.Usage.Type != "unknown" || answer.Quality != nil && answer.Quality.Layers.ASN != nil {
					t.Fatalf("streamed=%v ip=%s inherited unsupported routing/ASN context: %+v", streamed, tc.ip, answer)
				}
			} else if answer.Usage == nil || answer.Usage.Type != "hosting" {
				t.Fatal("positive same-prefix observation lost usage", streamed, tc.ip, answer.Usage)
			}
		}
		profile, err := reader.ClassC(context.Background(), "11.0.1.1")
		if err != nil || profile == nil || !profile.Cells[1].Observed || len(profile.Cells[1].Origins) != 0 || profile.Cells[1].Usage != "unknown" {
			t.Fatal("Class C inherited broader origin or ASN usage", streamed, profile, err)
		}
		var announced []string
		cursor := uint32(0)
		for {
			page, err := reader.Prefixes(context.Background(), "AS13335", cursor)
			if err != nil {
				t.Fatal(err)
			}
			announced = append(announced, page.Prefixes...)
			if page.NextCursor == nil {
				break
			}
			if *page.NextCursor <= cursor || len(announced) > 2 {
				t.Fatal("unknown prefix became a positive ASN announcement", page)
			}
			cursor = *page.NextCursor
		}
		if !slices.Equal(announced, []string{"11.0.0.0/16", "2001:4860::/32"}) {
			t.Fatal("unknown prefix became a positive ASN announcement", streamed, announced)
		}
	}
}
