package intelligence

import (
	"context"
	"errors"
	"testing"
)

func tiedTier1PeerPool(t *testing.T, count int) (*RelationshipIndex, []PathObservation) {
	t.Helper()
	relations := NewRelationships(true)
	var paths []PathObservation
	for i := 0; i < count; i++ {
		provider, customer := uint32(1000+i), uint32(2000+i)
		if err := relations.Add(provider, customer, Customer); err != nil {
			t.Fatal(err)
		}
		for _, family := range []string{"fixture-ris", "fixture-views"} {
			paths = append(paths, PathObservation{Origin: provider, Family: family, Current: true, OriginOutward: true, Segments: []PathSegment{{ASSequence, []uint32{provider}}}})
		}
	}
	return relations, paths
}

func TestTier1PeerCorePeelingConsumesExistingWorkBudget(t *testing.T) {
	relations, paths := tiedTier1PeerPool(t, 64)
	result, err := DeriveTier1(context.Background(), relations, paths, clock(), clock(), "fixture-policy", nil, 5000)
	if !errors.Is(err, ErrGraphBudget) || result.Eligible || len(result.RawCandidates) != 0 {
		t.Fatal("percentile-tied peer-core work bypassed the graph budget", err, result.Eligible)
	}
}

type cancelTier1AfterChecks struct {
	context.Context
	checks, limit int
}

func (ctx *cancelTier1AfterChecks) Err() error {
	ctx.checks++
	if ctx.checks >= ctx.limit {
		return context.Canceled
	}
	return nil
}

func TestTier1PeerCorePeelingChecksCancellation(t *testing.T) {
	relations, paths := tiedTier1PeerPool(t, 64)
	ctx := &cancelTier1AfterChecks{Context: context.Background(), limit: 300}
	result, err := DeriveTier1(ctx, relations, paths, clock(), clock(), "fixture-policy", nil, 1_000_000)
	if !errors.Is(err, context.Canceled) || result.Eligible || len(result.RawCandidates) != 0 {
		t.Fatal("peer-core peeling ignored cancellation", err, ctx.checks)
	}
}
