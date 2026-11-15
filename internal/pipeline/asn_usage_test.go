package pipeline

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestASNUsageJoinPreservesMOASUnknownAndExplicitPriority(t *testing.T) {
	index := asnUsageIndex{}
	for _, v := range []struct {
		asn  uint32
		kind string
	}{{13335, "hosting"}, {15169, "business"}} {
		if err := index.add(&intelligence.ScopedUsage{ASN: v.asn, ObservedAt: time.Now(), Evidence: intelligence.UsageEvidence{Family: "example", Type: v.kind, Current: true}}); err != nil {
			t.Fatal(err)
		}
	}
	parent := netip.MustParsePrefix("8.8.0.0/16")
	child := netip.MustParsePrefix("8.8.8.0/24")
	if got := index.joined(child, []uint32{13335, 15169}).Usage.Evidence.Type; got != "unknown" {
		t.Fatal(got)
	}
	if got := index.joined(child, []uint32{13335, 19281}).Usage.Evidence.Type; got != "unknown" {
		t.Fatal(got)
	}
	fallback := []intelligence.UsageEvidence{index.joined(parent, []uint32{13335}).Usage.Evidence, index.joined(child, []uint32{15169}).Usage.Evidence}
	if got := intelligence.FuseUsage(fallback).Type; got != "business" {
		t.Fatal("more specific current origin lost", got)
	}
	fallback = append(fallback, intelligence.UsageEvidence{Family: "direct", Type: "residential", Current: true})
	if got := intelligence.FuseUsage(fallback).Type; got != "residential" {
		t.Fatal("ASN context overrode direct usage", got)
	}
	state := intelligence.BuildState{Sources: []intelligence.StoredSource{{Records: []intelligence.NormalizedRecord{
		{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{ASN: 13335, ObservedAt: time.Now(), Evidence: intelligence.UsageEvidence{Family: "one", Type: "hosting", Current: true}}},
		{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: parent, Origins: []uint32{13335}}},
		{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: child, Origins: []uint32{15169}}},
	}}}}
	joined, err := joinASNUsage(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if state.Sources[0].Records[0].Usage.ASN != 13335 {
		t.Fatal("mutated authenticated source state")
	}
	var found bool
	for _, r := range joined.Sources[0].Records {
		if r.Usage != nil && r.Usage.Prefix == child {
			found = true
			if r.Usage.Evidence.Type != "unknown" {
				t.Fatal("unknown origin inherited parent")
			}
		}
	}
	if !found {
		t.Fatal("missing more-specific unknown boundary")
	}
}

func TestASNUsageBoundedAndStreamedLookupAgree(t *testing.T) {
	state, policy := mappingFixture(t)
	state.Sources = state.Sources[:1]
	state.Sources[0].Records = []intelligence.NormalizedRecord{
		{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{ASN: 13335, ObservedAt: state.EvaluatedAt, Evidence: intelligence.UsageEvidence{Family: "private-context", Type: "hosting", Current: true}}},
		{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("8.0.0.0/8"), Origins: []uint32{13335}}},
		{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("8.8.0.0/16"), Origins: []uint32{13335, 15169}}},
		{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{Prefix: netip.MustParsePrefix("8.8.8.0/24"), Evidence: intelligence.UsageEvidence{Family: "direct", Type: "residential", Current: true}}},
	}
	for _, streamed := range []bool{false, true} {
		options := testOptions(t)
		options.Limits = DefaultLimits()
		var err error
		if streamed {
			_, err = BuildStreamedIntelligence(context.Background(), options, state, policy)
		} else {
			_, err = Build(context.Background(), options, MappingProducer(state, policy, state.EvaluatedAt))
		}
		if err != nil {
			t.Fatal(streamed, err)
		}
		reader, err := via3.OpenRelease(options.Output, func() int64 { return options.Clock })
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ ip, usage string }{{"8.7.1.1", "hosting"}, {"8.8.1.1", "unknown"}, {"8.8.8.1", "residential"}} {
			answer, err := reader.Lookup(context.Background(), tc.ip)
			if err != nil || answer.Usage == nil || answer.Usage.Type != tc.usage {
				t.Fatalf("streamed=%v ip=%s usage=%+v err=%v", streamed, tc.ip, answer.Usage, err)
			}
		}
	}
}
