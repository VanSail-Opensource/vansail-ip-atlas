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

func TestSpatialOutputsOnlyMatchFormerPostFilter(t *testing.T) {
	ctx := context.Background()
	state, policy, _, _, _ := intelligenceFixture(t)
	inputs := MaterializationInputs{scope: netip.MustParsePrefix("203.0.0.0/16"),
		VRPComplete: true, RPKIObservedAt: state.EvaluatedAt, RPKICoverageValidUntil: state.EvaluatedAt.Add(time.Hour)}
	var kinds [14]bool
	baseline := IntelligenceProducer(state, policy, state.EvaluatedAt, inputs)
	filtered := func(ctx context.Context, emit func(via3.PublicRecord) error) error {
		return baseline(ctx, func(row via3.PublicRecord) error {
			kinds[row.Kind] = true
			if row.Kind >= 8 && row.Kind != 9 {
				return nil
			}
			return emit(row)
		})
	}
	coldOptions := testOptions(t)
	coldOptions.Limits = DefaultLimits()
	before, err := Build(ctx, coldOptions, filtered)
	if err != nil || !kinds[8] || !kinds[9] || !kinds[10] || !kinds[11] || !kinds[12] {
		t.Fatal("fixture did not exercise each output selection", kinds, err)
	}
	inputs.spatialOutputsOnly = true
	spatial := IntelligenceProducer(state, policy, state.EvaluatedAt, inputs)
	projected := func(ctx context.Context, emit func(via3.PublicRecord) error) error {
		return spatial(ctx, func(row via3.PublicRecord) error {
			if row.Kind >= 8 && row.Kind != 9 {
				t.Fatalf("spatial pass assembled a row owned elsewhere: kind %d", row.Kind)
			}
			return emit(row)
		})
	}
	streamOptions := testOptions(t)
	streamOptions.Limits = coldOptions.Limits
	after, err := Build(ctx, streamOptions, projected)
	if err != nil || before.Pointer != after.Pointer || !slices.Equal(before.Manifest.Objects, after.Manifest.Objects) {
		t.Fatal("spatial output changed the frozen public bytes", err)
	}
}

func TestSpatialOutputsOnlyStillValidatesNonemittedASNs(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	// Incomplete ASN coverage is not used by Engine; the former ASN collection
	// still rejected it, so the spatial path must check it before dropping it.
	state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{
		Version: 3, Kind: intelligence.RecordCoverage, Coverage: &intelligence.Coverage{
			ASN: 64512, Layer: intelligence.ASN, Family: "private-alpha", Current: true,
		}})
	inputs := MaterializationInputs{scope: netip.MustParsePrefix("203.0.0.0/16"), spatialOutputsOnly: true}
	if err := IntelligenceProducer(state, policy, state.EvaluatedAt, inputs)(context.Background(), func(via3.PublicRecord) error {
		t.Fatal("invalid ASN coverage emitted spatial output")
		return nil
	}); err == nil {
		t.Fatal("invalid ASN coverage was accepted")
	}
}
