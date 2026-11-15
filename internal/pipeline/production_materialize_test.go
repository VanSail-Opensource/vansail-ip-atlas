package pipeline

import (
	"context"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestProductionMaterializerNeverAcceptsEngineeringAssertions(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	options := testOptions(t)
	options.Mode = "production"
	options.ProductionGate = func(context.Context) error { return nil }
	if _, err := BuildProductionIntelligence(context.Background(), options, state, policy, ProductionInputs{}); err == nil {
		t.Fatal("caller gate manufactured source or Tier-1 qualification")
	}
}

func TestAdmittedStateCannotBecomePublishableSyntheticData(t *testing.T) {
	for _, streamed := range []bool{false, true} {
		state, policy, _, _, _ := intelligenceFixture(t)
		state.Sources[0].Receipt = &intelligence.SourceReceipt{PayloadVerified: true, SchemaVerified: true}
		options := testOptions(t)
		options.Limits = DefaultLimits()
		var candidate Candidate
		var err error
		if streamed {
			candidate, err = BuildStreamedIntelligence(context.Background(), options, state, policy)
		} else {
			candidate, err = BuildIntelligence(context.Background(), options, state, policy)
		}
		if err != nil {
			t.Fatal(err)
		}
		if candidate.Manifest.Mode != "engineering" {
			t.Fatal("known real intake was mislabeled as synthetic")
		}
		if _, err = via3.OpenRelease(options.Output, func() int64 { return options.Clock }); err == nil {
			t.Fatal("private engineering output opened as a public release")
		}
	}
}

func TestVerifiedGlobalVRPAbsenceSurvivesEmptySpatialBucket(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	var records []intelligence.NormalizedRecord
	for _, record := range state.Sources[0].Records {
		if record.Kind != intelligence.RecordVRP {
			records = append(records, record)
		}
	}
	state.Sources[0].Records = records
	for _, verified := range []bool{false, true} {
		seen := 0
		err := IntelligenceProducer(state, policy, state.EvaluatedAt, MaterializationInputs{VRPComplete: true, verifiedEmptyVRP: verified})(context.Background(), func(record via3.PublicRecord) error {
			if record.Kind == 9 {
				seen++
				want := uint8(0)
				if verified {
					want = 3
				}
				if record.RPKI.Status != want {
					t.Fatalf("verified=%v status=%d", verified, record.RPKI.Status)
				}
			}
			return nil
		})
		if err != nil || seen == 0 {
			t.Fatal(err)
		}
	}
}

func TestBulkMaterializerCrossPartitionASNContextAndCanonicalParity(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	ctx := context.Background()
	original := state.Sources[0].Records
	// One announcement and complete coverage extend across disjoint /8 buckets.
	state.Sources[0].Records = nil
	for _, record := range original {
		if record.Evidence != nil && record.Evidence.Scope == intelligence.ASN {
			continue
		}
		if record.Coverage != nil && record.Coverage.Layer != intelligence.ASN {
			v := *record.Coverage
			v.Prefix = netip.MustParsePrefix("0.0.0.0/0")
			record.Coverage = &v
		}
		state.Sources[0].Records = append(state.Sources[0].Records, record)
	}
	state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("8.0.0.0/8"), Origins: []uint32{13335}}})
	for _, first := range []byte{8, 203} {
		for i := 0; i < 20; i++ {
			addr := netip.AddrFrom4([4]byte{first, 0, 1, byte(i)})
			state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Family: "private-other", Signal: "malware", Scope: intelligence.Exact, Address: addr, Weight: 100, Current: true, SourcePublishedAt: state.EvaluatedAt}})
		}
	}
	// Match the absent qualified graph's truthful unknown relation in this fixture;
	// the public production entry separately requires genuine qualified objects.
	baseline := testOptions(t)
	baseline.Limits = DefaultLimits()
	if _, err := Build(ctx, baseline, IntelligenceProducer(state, policy, state.EvaluatedAt, MaterializationInputs{})); err != nil {
		t.Fatal(err)
	}
	actual := testOptions(t)
	actual.Limits = DefaultLimits()
	spool, err := newBulkSpool(actual.Workspace, state.EvaluatedAt, state.PolicyHash, actual.Limits.ScratchBytes, func() uint64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if spool.prefixFile != nil {
			_ = spool.prefixFile.Close()
		}
		_ = os.RemoveAll(spool.root)
	}()
	spool.batchBytes = 80 << 10
	actual.prefixProvider = spool.providePrefixes
	if _, err = Build(ctx, actual, bulkIntelligenceProducer(actual.Workspace, state, policy, state.EvaluatedAt, ProductionInputs{}, spool)); err != nil {
		t.Fatal(err)
	}
	expected, err := via3.OpenRelease(baseline.Output, func() int64 { return baseline.Clock })
	if err != nil {
		t.Fatal(err)
	}
	got, err := via3.OpenRelease(actual.Output, func() int64 { return actual.Clock })
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"8.0.1.0", "8.0.1.69", "8.0.1.70", "203.0.1.0", "203.0.113.0", "203.0.113.1", "AS13335", "AS15169"} {
		want, err := expected.Lookup(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		answer, err := got.Lookup(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		want.ReleaseID = answer.ReleaseID
		want.BGP.Tier1 = answer.BGP.Tier1
		if !reflect.DeepEqual(answer, want) {
			t.Fatalf("canonical answer changed at %s\ngot=%+v\nwant=%+v", q, answer, want)
		}
	}
	for _, q := range []string{"8.0.1.0", "203.0.1.0"} {
		want, err := expected.ClassC(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		answer, err := got.ClassC(ctx, q)
		if err != nil || !reflect.DeepEqual(answer, want) {
			t.Fatalf("/24 changed at %s: %v", q, err)
		}
	}
}

func TestBulkMaterializerNoOriginsPreservesClusteredRiskAndNeighbors(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	state.Sources[0].Records = nil
	for i := 0; i < 12; i++ {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{8, 8, byte(i), 0}), 24)
		state.Sources[0].Records = append(state.Sources[0].Records,
			intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Prefix: prefix, Family: "synthetic-geo", PhysicalCountry: "US", Weight: 70, Current: true}},
			intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Address: prefix.Addr().Next(), Scope: intelligence.Exact, Family: "synthetic-risk", Signal: "abuse", Weight: 70, Current: true, SourcePublishedAt: state.EvaluatedAt}})
	}
	ctx := context.Background()
	baseline := testOptions(t)
	baseline.Limits = DefaultLimits()
	if _, err := Build(ctx, baseline, IntelligenceProducer(state, policy, state.EvaluatedAt)); err != nil {
		t.Fatal(err)
	}
	actual := testOptions(t)
	actual.Limits = DefaultLimits()
	spool, err := newBulkSpool(actual.Workspace, state.EvaluatedAt, state.PolicyHash, actual.Limits.ScratchBytes, func() uint64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(spool.root)
	spool.batchRecords = 4
	if _, err = Build(ctx, actual, bulkIntelligenceProducer(actual.Workspace, state, policy, state.EvaluatedAt, ProductionInputs{}, spool)); err != nil {
		t.Fatal(err)
	}
	if !spool.hasExact || len(spool.prefixIndex) != 0 {
		t.Fatal("fixture did not exercise no-origin exact observations")
	}
	for _, bucket := range spool.all {
		if len(bucket.parts) > 0 && bucket.prefix.Bits() > 1 {
			goto narrowed
		}
	}
	t.Fatal("fixture did not subdivide normalized spatial data")
narrowed:
	want, err := via3.OpenRelease(baseline.Output, func() int64 { return baseline.Clock })
	if err != nil {
		t.Fatal(err)
	}
	got, err := via3.OpenRelease(actual.Output, func() int64 { return actual.Clock })
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"8.8.0.0", "8.8.0.1", "8.8.0.2", "8.8.11.1", "8.8.11.255", "8.8.12.1", "8.9.0.1", "1.1.1.1"} {
		a, err := want.Lookup(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		b, err := got.Lookup(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		a.ReleaseID = b.ReleaseID
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("no-origin lookup changed at %s: want=%+v got=%+v", query, a, b)
		}
	}
	for _, query := range []string{"8.8.0.0", "8.8.11.0"} {
		a, err := want.ClassC(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		b, err := got.ClassC(ctx, query)
		if err != nil || !reflect.DeepEqual(a, b) {
			t.Fatalf("no-origin /24 changed at %s: %v", query, err)
		}
	}
}
