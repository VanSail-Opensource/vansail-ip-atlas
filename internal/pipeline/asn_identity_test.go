package pipeline

import (
	"context"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestASNIdentityMaterializerPreservesRiskPrefixesAndIPFactOwners(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordASNIdentity, ASNIdentity: &intelligence.ASNIdentityEvidence{ASN: 13335, Name: "Synthetic Edge", Organization: "Hosting Operator", Country: "DE", Family: "private-alpha", Weight: 100, Current: true}})
	opts := testOptions(t)
	opts.Limits = DefaultLimits()
	first, err := BuildIntelligence(context.Background(), opts, state, policy)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
	if err != nil {
		t.Fatal(err)
	}
	answer, err := reader.Lookup(context.Background(), "203.0.112.1")
	if err != nil || len(answer.ASNs) != 2 {
		t.Fatal(err)
	}
	asn := answer.ASNs[0]
	if asn.Name == nil || *asn.Name != "Synthetic Edge" || asn.Organization == nil || *asn.Organization != "Hosting Operator" || asn.Country == nil || *asn.Country != "DE" || asn.Risk == nil || len(asn.Prefixes) != 1 || asn.Prefixes[0] != "203.0.0.0/16" {
		t.Fatal("identity erased context or announced prefixes", asn)
	}
	if answer.Geo == nil || answer.Geo.Country == nil || *answer.Geo.Country != "US" || answer.Usage == nil || answer.Usage.Type != "residential" || asn.NetworkClass != "unknown" {
		t.Fatal("ASN identity became IP location/usage or Tier-1 classification", answer.Geo, answer.Usage, asn)
	}
	slices.Reverse(state.Sources)
	for i := range state.Sources {
		slices.Reverse(state.Sources[i].Records)
	}
	second := testOptions(t)
	second.Limits = DefaultLimits()
	again, err := BuildIntelligence(context.Background(), second, state, policy)
	if err != nil || again.Pointer != first.Pointer {
		t.Fatal("source ordering changed identity release", err)
	}
}
