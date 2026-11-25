package intelligence

import (
	"context"
	"reflect"
	"testing"
)

func TestTier1ObservedVisibilityUsesCompleteDirectedRelationships(t *testing.T) {
	path := func(family string, kind SegmentType, outward bool, asns ...uint32) PathObservation {
		return PathObservation{Origin: 100, Current: true, Family: family, OriginOutward: outward,
			Segments: []PathSegment{{Type: kind, ASNs: asns}}}
	}
	paths := []PathObservation{
		path("a", ASSequence, true, 100, 100, 200, 300),
		path("a", ASSequence, true, 100, 200, 300),
		path("b", ASSequence, false, 400, 200, 100),
		path("c", ASSet, true, 100, 500),
		path("d", ASSequence, true, 100, 200, 100),
	}
	var summary tier1PathSummary
	for _, p := range paths {
		summary.collect(p)
	}
	relations := NewRelationships(true)
	if err := relations.Add(100, 200, Customer); err != nil {
		t.Fatal(err)
	}
	if err := relations.Add(200, 300, Peer); err != nil {
		t.Fatal(err)
	}
	read := pathVisibilityReader(func(visit func(PathObservation) error) error {
		for _, p := range paths {
			if err := visit(p); err != nil {
				return err
			}
		}
		return nil
	})
	want, err := read(relations)
	if err != nil {
		t.Fatal(err)
	}
	got, err := summary.resolve(t.Context(), relations)
	if err != nil || !summary.available() || !reflect.DeepEqual(got, want) || len(summary.edges) != 3 ||
		len(got.families) != 4 || got.pairs != 6 || !reflect.DeepEqual(got.incidentUnknown, map[uint32]bool{200: true, 400: true}) {
		t.Fatal("observed adjacency or visibility changed", err, got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := summary.resolve(ctx, relations); err != context.Canceled {
		t.Fatal("cancelled graph was resolved", err)
	}
}

func TestTier1SummaryFallsBackOnCapacityAndPathErrors(t *testing.T) {
	p := PathObservation{Origin: 100, Current: true, Family: "a", OriginOutward: true,
		Segments: []PathSegment{{Type: ASSequence, ASNs: []uint32{100, 200}}}}
	for _, cause := range []string{"edge-limit", "invalid"} {
		var summary tier1PathSummary
		summary.collect(p)
		if cause == "edge-limit" {
			for i := uint32(0); len(summary.edges) <= tier1RetainedPathEntries; i++ {
				summary.edges[ASNEdge{From: 1234, To: i}] = struct{}{}
			}
			summary.collect(p)
		} else {
			bad := p
			bad.Origin = 500
			summary.collect(bad)
		}
		summary.collect(p)
		if !summary.replay || summary.available() || summary.edges != nil || summary.visibility.byASN != nil {
			t.Fatal("partial path population survived fallback", cause)
		}
	}
}
