package intelligence

import (
	"context"
	"fmt"
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
		summary.collect(p, nil)
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
	if err != nil || !summary.available(relations) || !reflect.DeepEqual(got, want) || len(summary.edges) != 3 ||
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
		summary.collect(p, nil)
		if cause == "edge-limit" {
			for i := uint32(0); len(summary.edges) <= tier1RetainedPathEntries; i++ {
				summary.edges[ASNEdge{From: 1234, To: i}] = struct{}{}
			}
			summary.collect(p, nil)
		} else {
			bad := p
			bad.Origin = 500
			summary.collect(bad, nil)
		}
		summary.collect(p, nil)
		if !summary.replay || summary.available(nil) || summary.edges != nil || summary.visibility.byASN != nil {
			t.Fatal("partial path population survived fallback", cause)
		}
	}
}

func TestTier1VisibilityAfterObservedRelationships(t *testing.T) {
	relations := NewRelationships(true)
	discovery := tier1Discovery{relations: relations, sources: make([]tier1SourceDiscovery, 3)}
	relationship := func(a, b uint32) NormalizedRecord {
		return NormalizedRecord{Kind: RecordRelationship, Relationship: &RelationshipRecord{From: a, To: b, Relation: Customer}}
	}
	discovery.collect(0, relationship(100, 200))
	paths := []PathObservation{
		{Origin: 100, Current: true, Family: "a", OriginOutward: true, Segments: []PathSegment{{Type: ASSequence, ASNs: []uint32{100, 100, 200, 300}}}},
		{Origin: 100, Current: true, Family: "b", Segments: []PathSegment{{Type: ASSequence, ASNs: []uint32{300, 200, 100}}}},
	}
	for _, p := range paths {
		discovery.collect(1, NormalizedRecord{Kind: RecordPath, Path: &ScopedPath{Observation: p}})
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
	got, err := discovery.paths.resolve(t.Context(), relations)
	if err != nil || !discovery.paths.available(relations) || discovery.paths.available(NewRelationships(true)) ||
		discovery.paths.edges != nil || !reflect.DeepEqual(got, want) || !got.incidentUnknown[200] || !got.incidentUnknown[300] {
		t.Fatalf("direct visibility changed: got %+v, want %+v, error %v", got, want, err)
	}
	if _, err := discovery.paths.resolve(t.Context(), NewRelationships(true)); err == nil {
		t.Fatal("direct summary accepted an unrelated graph")
	}
	discovery.collect(2, relationship(200, 300))
	if discovery.paths.available(relations) || discovery.paths.visibility.byASN != nil || !discovery.paths.replay {
		t.Fatal("a later verified relationship did not invalidate the provisional summary")
	}
	complete, err := read(relations)
	if err != nil || len(complete.incidentUnknown) != 0 {
		t.Fatalf("fixture did not require replay against the complete relationship graph: %+v, %v", complete, err)
	}
}

func TestTier1DirectVisibilityKeepsPathAndPairLimits(t *testing.T) {
	relations := NewRelationships(true)
	if err := relations.Add(100, 200, Customer); err != nil {
		t.Fatal(err)
	}
	path := PathObservation{Origin: 100, Family: "a", Current: true, OriginOutward: true,
		Segments: []PathSegment{{Type: ASSequence, ASNs: []uint32{100, 200}}}}
	for _, cause := range []string{"pairs", "invalid"} {
		t.Run(cause, func(t *testing.T) {
			var summary tier1PathSummary
			summary.collect(path, relations)
			bad := path
			switch cause {
			case "pairs":
				summary.visibility.pairs = tier1RetainedPathEntries
				bad.Family = "b"
			case "invalid":
				bad.Origin = 300
			}
			summary.collect(bad, relations)
			if summary.available(relations) || !summary.replay || summary.visibility.families != nil {
				t.Fatal("partial direct path summary survived a required replay")
			}
		})
	}
}

func TestTier1VisibilityBeyondRetainedAdjacencyLimit(t *testing.T) {
	relations := NewRelationships(true)
	if err := relations.Add(300000, 300001, Customer); err != nil {
		t.Fatal(err)
	}
	var direct, deferred tier1PathSummary
	path := PathObservation{Origin: 300000, Family: "a", Current: true, OriginOutward: true,
		Segments: []PathSegment{{Type: ASSequence, ASNs: make([]uint32, 2)}}}
	walk := func(visit func(PathObservation) error) error {
		const asns = tier1RetainedPathEntries/2 + 1
		for shift := range uint32(2) {
			for i := range uint32(asns) {
				path.Origin = 300000 + i
				path.Segments[0].ASNs[0], path.Segments[0].ASNs[1] = path.Origin, 300000+(i+1+shift)%asns
				if err := visit(path); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(func(p PathObservation) error {
		direct.collect(p, relations)
		deferred.collect(p, nil)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !direct.available(relations) || direct.edges != nil || !deferred.replay {
		t.Fatal("already observed graph did not eliminate the retained-adjacency cliff")
	}
	want, err := pathVisibilityReader(walk)(relations)
	if err != nil {
		t.Fatal(err)
	}
	got, err := direct.resolve(t.Context(), relations)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("direct visibility differed from complete replay", err)
	}
}

func FuzzTier1ShortSequenceMatchesCanonicalVisibility(f *testing.F) {
	f.Add(byte(0), []byte{8, 9, 10})
	f.Add(byte(1), []byte{8, 8, 10})
	f.Add(byte(1), []byte{8, 10, 8})
	f.Add(byte(5), []byte{8, 9, 15})
	f.Add(byte(9), []byte{8, 1, 15})
	f.Add(byte(33), []byte{8, 9, 10, 11, 12, 13, 14, 15})
	f.Add(byte(128), []byte{9, 10, 11, 22})
	f.Fuzz(func(t *testing.T, flags byte, data []byte) {
		if len(data) > 64 {
			t.Skip()
		}
		asns := make([]uint32, len(data))
		for i, b := range data {
			switch b {
			case 0:
				asns[i] = 0
			case 1:
				asns[i] = 64512
			default:
				asns[i] = 300000 + uint32(b)
			}
		}
		observation := PathObservation{
			Current: flags&128 == 0, Family: "one", OriginOutward: flags&1 != 0,
			Segments: []PathSegment{{Type: SegmentType(1 + flags>>1&3), ASNs: asns}},
		}
		if flags&16 != 0 {
			observation.Family = ""
		}
		if flags&32 != 0 && len(asns) > 2 {
			observation.Segments[0].ASNs = asns[:2]
			observation.Segments = append(observation.Segments, PathSegment{Type: ASSequence, ASNs: asns[2:]})
		}
		if flags&64 == 0 && len(asns) != 0 {
			observation.Origin = asns[len(asns)-1]
			if observation.OriginOutward {
				observation.Origin = asns[0]
			}
		}

		got, want := newTier1Visibility(), newTier1Visibility()
		var gotEdges, wantEdges []ASNEdge
		gotErr := got.add(observation, func(edge ASNEdge) { gotEdges = append(gotEdges, edge) })
		var wantErr error
		if observation.Current && observation.Family != "" {
			var path Path
			path, wantErr = canonicalPath(observation)
			if wantErr == nil {
				want.families[observation.Family] = struct{}{}
				if path.GraphEligible {
					var prior uint32
					for _, segment := range path.Segments {
						for _, asn := range segment.ASNs {
							want.byASN[asn] = map[string]struct{}{observation.Family: {}}
							if prior != 0 && prior != asn {
								wantEdges = append(wantEdges, ASNEdge{From: prior, To: asn})
							}
							prior = asn
						}
					}
					want.pairs = len(want.byASN)
				}
			}
		}
		if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotEdges, wantEdges) {
			t.Fatalf("fast visibility differs from canonical for %+v: got %+v %v %v, want %+v %v %v",
				observation, got, gotEdges, gotErr, want, wantEdges, wantErr)
		}
	})
}
