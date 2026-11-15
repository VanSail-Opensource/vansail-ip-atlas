package pipeline

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestExpiredRPKISnapshotMaterializesExactAnnouncementStatusAndClocks(t *testing.T) {
	state, policy := mappingFixture(t)
	state.Sources = state.Sources[:1]
	observed := state.EvaluatedAt.Add(-4 * time.Hour)
	coverage := observed.Add(time.Hour)
	parent := netip.MustParsePrefix("11.0.0.0/16")
	state.Sources[0].Records = []intelligence.NormalizedRecord{
		{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: parent, Origins: []uint32{13335, 15169}}},
		{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("11.0.1.0/24"), Origins: []uint32{13335}}},
		{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("8.8.8.0/24"), Origins: []uint32{13335}}},
		{Version: 3, Kind: intelligence.RecordVRP, VRP: &intelligence.VRP{Prefix: parent, ASN: 13335, MaxLength: 16, ValidUntil: observed.Add(2 * time.Hour)}},
		{Version: 3, Kind: intelligence.RecordVRP, VRP: &intelligence.VRP{Prefix: parent, ASN: 13335, MaxLength: 16, ValidUntil: observed.Add(3 * time.Hour)}},
		{Version: 3, Kind: intelligence.RecordVRP, VRP: &intelligence.VRP{Prefix: netip.MustParsePrefix("1.1.1.0/24"), ASN: 13335, MaxLength: 24, ValidUntil: coverage}},
	}
	for _, dated := range []bool{false, true} {
		inputs := MaterializationInputs{VRPComplete: true}
		if dated {
			inputs.RPKIObservedAt, inputs.RPKICoverageValidUntil = observed, coverage
		}
		options := testOptions(t)
		options.Limits = DefaultLimits()
		candidate, err := BuildIntelligence(context.Background(), options, state, policy, inputs)
		if err != nil || candidate.Manifest.SchemaVersion != 5 || candidate.Manifest.ValidUntil != options.ValidUntil {
			t.Fatal("snapshot expiry altered whole-release eligibility", err)
		}
		reader, err := via3.OpenRelease(options.Output, func() int64 { return options.Clock })
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			ip        string
			statuses  []string
			deadlines []time.Time
		}{
			{"11.0.2.1", []string{"valid", "invalid"}, []time.Time{observed.Add(3 * time.Hour), coverage}},
			{"11.0.1.1", []string{"invalid"}, []time.Time{coverage}},
			{"8.8.8.1", []string{"not_found"}, []time.Time{coverage}},
		} {
			answer, err := reader.Lookup(context.Background(), tc.ip)
			if err != nil || len(answer.BGP.RPKI) != len(tc.statuses) {
				t.Fatal(err, answer.BGP.RPKI)
			}
			for i, result := range answer.BGP.RPKI {
				if dated {
					if result.Status != tc.statuses[i] || result.ObservedAt == nil || *result.ObservedAt != observed.Unix() || result.ValidUntil == nil || *result.ValidUntil != tc.deadlines[i].Unix() {
						t.Fatal("retained snapshot validation changed", tc.ip, result)
					}
				} else if result.Status != "unavailable" || result.ObservedAt != nil || result.ValidUntil != nil {
					t.Fatal("legacy completeness invented snapshot clocks", result)
				}
			}
		}
	}
}

func TestUndatedRPKIStillRejectsMalformedRetainedVRP(t *testing.T) {
	state, policy := mappingFixture(t)
	state.Sources = state.Sources[:1]
	state.Sources[0].Records = []intelligence.NormalizedRecord{{Version: 3, Kind: intelligence.RecordVRP, VRP: &intelligence.VRP{Prefix: netip.MustParsePrefix("11.0.0.0/16"), MaxLength: 8, ASN: 13335}}}
	for _, complete := range []bool{false, true} {
		options := testOptions(t)
		options.Limits = DefaultLimits()
		if _, err := BuildIntelligence(context.Background(), options, state, policy, MaterializationInputs{VRPComplete: complete}); err == nil {
			t.Fatal("unavailable RPKI bypassed retained record validation", complete)
		}
	}
}
