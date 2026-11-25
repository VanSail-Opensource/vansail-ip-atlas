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

func TestNetworkOrganizationKeepsAlignmentWithObservedRoutes(t *testing.T) {
	ctx := context.Background()
	base, policy := mappingFixture(t)
	route := func(prefix string, asns ...uint32) intelligence.NormalizedRecord {
		return intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix(prefix), Origins: asns}}
	}
	owner := func(prefix, name string) intelligence.NormalizedRecord {
		return intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordNetworkOrganization, NetworkOrganization: &intelligence.NetworkOrganizationRecord{Prefix: netip.MustParsePrefix(prefix), Organization: name}}
	}
	observed := base.EvaluatedAt.Add(-time.Hour)
	expiry := base.EvaluatedAt.Add(time.Hour)
	base.Sources = base.Sources[:1]
	base.Sources[0].Records = []intelligence.NormalizedRecord{
		route("8.8.0.0/16", 15169), owner("8.8.8.0/24", "Google"), route("8.8.8.128/25", 13335), route("8.8.8.192/26"),
		{Version: 3, Kind: intelligence.RecordVRP, VRP: &intelligence.VRP{Prefix: netip.MustParsePrefix("8.8.0.0/16"), MaxLength: 16, ASN: 15169, ValidUntil: expiry}},
		owner("2001:4860::/32", "Google"), owner("2001:4860:1::/48", "Different holder"), owner("2001:4860:1::/48", "Google"),
	}
	for _, streamed := range []bool{false, true} {
		options := testOptions(t)
		options.Limits = DefaultLimits()
		options.Clock = base.EvaluatedAt.Unix()
		options.ValidUntil = expiry.Unix()
		var err error
		if streamed {
			_, err = BuildStreamedIntelligence(ctx, options, partitionSpatialFixture(t, options.Workspace, base), policy)
		} else {
			_, err = Build(ctx, options, IntelligenceProducer(base, policy, base.EvaluatedAt, MaterializationInputs{VRPComplete: true, RPKIObservedAt: observed, RPKICoverageValidUntil: expiry}))
		}
		if err != nil {
			t.Fatal(err)
		}
		r, err := via3.OpenRelease(options.Output, func() int64 { return options.Clock })
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			ip, prefix, org string
			asns            []uint32
		}{
			{"8.8.9.9", "8.8.0.0/16", "", []uint32{15169}}, {"8.8.8.8", "8.8.8.0/24", "Google", []uint32{15169}}, {"8.8.8.129", "8.8.8.128/25", "Google", []uint32{13335}}, {"8.8.8.193", "8.8.8.192/26", "Google", nil}, {"2001:4860::1", "2001:4860::/32", "Google", nil}, {"2001:4860:1::1", "2001:4860:1::/48", "", nil}, {"9.9.9.9", "", "", nil},
		} {
			a, e := r.Lookup(ctx, tc.ip)
			if e != nil {
				t.Fatal(tc.ip, e)
			}
			if (a.Network != nil) != (tc.prefix != "") {
				t.Fatal(tc.ip, a.Network)
			}
			if a.Network == nil {
				continue
			}
			org := ""
			if a.Network.Organization != nil {
				org = *a.Network.Organization
			}
			if a.Network.Prefix != tc.prefix || org != tc.org || a.Network.Name != nil || a.Network.ISP != nil || !slices.Equal(a.Network.Origins, tc.asns) || !slices.Equal(a.BGP.Origins, tc.asns) {
				t.Fatalf("%s incorrect network or origins: %+v %+v", tc.ip, a.Network, a.BGP.Origins)
			}
			if !streamed && tc.ip == "8.8.8.8" && (len(a.BGP.RPKI) != 1 || a.BGP.RPKI[0].Status != "valid") {
				t.Fatalf("ownership /24 replaced the authorized /16 announcement: %+v", a.BGP.RPKI)
			}
		}
	}
}
