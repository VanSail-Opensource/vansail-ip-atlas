package pipeline

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestRegisteredNetworkNamesPreserveIndependentScopesAndWithdrawals(t *testing.T) {
	ctx := context.Background()
	base, policy := mappingFixture(t)
	observed := base.EvaluatedAt.Add(-time.Hour)
	expiry := base.EvaluatedAt.Add(time.Hour)
	prefix := netip.MustParsePrefix
	blockName := func(p, name string, isp intelligence.RIPESubscriberISP) intelligence.NormalizedRecord {
		return intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordNetworkName, NetworkName: &intelligence.NetworkNameRecord{Prefix: prefix(p), Name: name, ModifiedAt: observed, SubscriberISP: isp}}
	}
	base.Sources[0].Records = []intelligence.NormalizedRecord{
		{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: prefix("2a00:1450::/32"), Origins: []uint32{15169}}},
		{Version: 3, Kind: intelligence.RecordNetworkOrganization, NetworkOrganization: &intelligence.NetworkOrganizationRecord{Prefix: prefix("2a00:1450:1000::/36"), Organization: "Google"}},
		{Version: 3, Kind: intelligence.RecordVRP, VRP: &intelligence.VRP{Prefix: prefix("2a00:1450::/32"), MaxLength: 32, ASN: 15169, ValidUntil: expiry}},
	}
	base.Sources[1].Records = []intelligence.NormalizedRecord{
		blockName("2a00:1450::/32", "ALLOCATION", intelligence.RIPETelenet),
		blockName("2a00:1450:1100::/40", "SUBNET", intelligence.RIPESTC),
		blockName("2a00:1450:1110::/44", "", intelligence.RIPEUnknownISP),
		blockName("2a00:1450:1200::/40", "CONFLICT-A", intelligence.RIPETelenet),
		blockName("2a00:1450:1200::/40", "CONFLICT-B", intelligence.RIPESTC),
	}
	for _, streamed := range []bool{false, true} {
		for _, withdrawn := range []bool{false, true} {
			state := base
			if withdrawn {
				state.Sources = state.Sources[:1]
			}
			opts := testOptions(t)
			opts.Limits = DefaultLimits()
			opts.Clock, opts.ValidUntil = base.EvaluatedAt.Unix(), expiry.Unix()
			var err error
			if streamed {
				_, err = BuildStreamedIntelligence(ctx, opts, partitionSpatialFixture(t, opts.Workspace, state), policy)
			} else {
				_, err = Build(ctx, opts, IntelligenceProducer(state, policy, base.EvaluatedAt, MaterializationInputs{VRPComplete: true, RPKIObservedAt: observed, RPKICoverageValidUntil: expiry}))
			}
			if err != nil {
				t.Fatal(err)
			}
			reader, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				ip, name, org, isp string
			}{
				{"2a00:1450::1", "ALLOCATION", "", "Telenet"},
				{"2a00:1450:1300::1", "ALLOCATION", "Google", "Telenet"},
				{"2a00:1450:1101::1", "SUBNET", "Google", "stc"},
				{"2a00:1450:1111::1", "", "Google", ""},
				{"2a00:1450:1201::1", "", "Google", ""},
				{"2a00:1450:2101::1", "ALLOCATION", "", "Telenet"},
				{"2a01:1450::1", "", "", ""},
				{"8.8.8.8", "", "", ""},
			} {
				result, err := reader.Lookup(ctx, tc.ip)
				if err != nil {
					t.Fatal(err)
				}
				if !prefix("2a00:1450::/32").Contains(netip.MustParseAddr(tc.ip)) {
					if result.Network != nil || len(result.BGP.Origins) != 0 {
						t.Fatal(tc.ip, "unobserved family or adjacent scope gained a network")
					}
					continue
				}
				wantName, wantISP := tc.name, tc.isp
				if withdrawn {
					wantName, wantISP = "", ""
				}
				net := result.Network
				if net == nil || !matchesOptionalLabel(net.Name, wantName) || !matchesOptionalLabel(net.Organization, tc.org) || !matchesOptionalLabel(net.ISP, wantISP) || !slices.Equal(net.Origins, []uint32{15169}) || !slices.Equal(result.BGP.Origins, net.Origins) {
					t.Fatalf("%s streamed=%t withdrawn=%t network=%+v bgp=%+v", tc.ip, streamed, withdrawn, net, result.BGP.Origins)
				}
				if !streamed && (len(result.BGP.RPKI) != 1 || result.BGP.RPKI[0].Status != "valid") {
					t.Fatal(tc.ip, "registered block boundary replaced the authorized route", result.BGP.RPKI)
				}
			}
		}
	}
}

func matchesOptionalLabel(value *string, want string) bool {
	return value == nil && want == "" || value != nil && *value == want
}
