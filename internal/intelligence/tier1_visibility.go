package intelligence

import (
	"context"
	"errors"
)

type tier1Visibility struct {
	families        map[string]struct{}
	byASN           map[uint32]map[string]struct{}
	pairs           int
	incidentUnknown map[uint32]bool
}

func newTier1Visibility() tier1Visibility {
	return tier1Visibility{families: make(map[string]struct{}), byASN: make(map[uint32]map[string]struct{})}
}

func (s *tier1Visibility) add(v PathObservation, edge func(ASNEdge)) error {
	if !v.Current || v.Family == "" {
		return nil
	}
	sequence := shortTier1Sequence(v)
	var path Path
	if sequence == nil {
		var err error
		path, err = canonicalPath(v)
		if err != nil {
			return err
		}
	}
	s.families[v.Family] = struct{}{}
	if len(s.families) > 1000 {
		return ErrGraphBudget
	}
	var prior uint32
	if sequence != nil {
		for i := range sequence {
			j := i
			if !v.OriginOutward {
				j = len(sequence) - 1 - i
			}
			asn := sequence[j]
			if err := s.addASN(v.Family, prior, asn, edge); err != nil {
				return err
			}
			prior = asn
		}
		return nil
	}
	if path.GraphEligible {
		for _, segment := range path.Segments {
			for _, asn := range segment.ASNs {
				if err := s.addASN(v.Family, prior, asn, edge); err != nil {
					return err
				}
				prior = asn
			}
		}
	}
	return nil
}

func (s *tier1Visibility) addASN(family string, prior, asn uint32, edge func(ASNEdge)) error {
	if _, exists := s.byASN[asn][family]; !exists {
		s.pairs++
		if s.pairs > 1_000_000 || len(s.byASN) >= 200_000 && s.byASN[asn] == nil {
			return ErrGraphBudget
		}
		addFamily(s.byASN, asn, family)
	}
	if prior != 0 && prior != asn {
		edge(ASNEdge{From: prior, To: asn})
	}
	return nil
}

// A short sequence of public ASNs with the expected origin and no
// nonconsecutive repetitions already has the visibility-relevant shape of a
// graph-eligible canonical path. The caller reads it in canonical orientation,
// without allocating either a reversed copy or unused path serialization.
// The general decoder handles every other path and all validation errors.
func shortTier1Sequence(v PathObservation) []uint32 {
	if len(v.Segments) != 1 || v.Segments[0].Type != ASSequence {
		return nil
	}
	asns := v.Segments[0].ASNs
	if len(asns) == 0 || len(asns) > 12 {
		return nil
	}
	first := asns[0]
	if !v.OriginOutward {
		first = asns[len(asns)-1]
	}
	if first != v.Origin {
		return nil
	}
	for i, asn := range asns {
		if !IsPublicASN(asn) {
			return nil
		}
		if i > 0 && asn == asns[i-1] {
			continue
		}
		for _, earlier := range asns[:i] {
			if earlier == asn {
				return nil
			}
		}
	}
	return asns
}

func (s *tier1Visibility) relation(relations *RelationshipIndex, edge ASNEdge) {
	if relations.Relation(edge.From, edge.To) == UnknownRelation {
		s.incidentUnknown[edge.From] = true
		s.incidentUnknown[edge.To] = true
	}
}

func pathVisibilityReader(walk func(func(PathObservation) error) error) func(*RelationshipIndex) (tier1Visibility, error) {
	return func(relations *RelationshipIndex) (tier1Visibility, error) {
		v := newTier1Visibility()
		v.incidentUnknown = make(map[uint32]bool)
		err := walk(func(path PathObservation) error {
			return v.add(path, func(edge ASNEdge) { v.relation(relations, edge) })
		})
		return v, err
	}
}

// Collect visibility during the initial authenticated traversal. With an
// already observed relationship graph, interpret adjacencies directly and
// discard the summary if any later relationship could change those answers.
// Otherwise defer interpretation by retaining distinct directed adjacencies.
type tier1PathSummary struct {
	visibility           tier1Visibility
	edges                map[ASNEdge]struct{}
	provisionalRelations *RelationshipIndex
	replay               bool
}

// Larger inputs use the ordinary verified second pass. This memory bound
// never selects a smaller population for evaluating a graph.
const tier1RetainedPathEntries = 256 * 1024

func (s *tier1PathSummary) observeRelationship() {
	if s.provisionalRelations != nil {
		*s = tier1PathSummary{replay: true}
	}
}

func (s *tier1PathSummary) collect(path PathObservation, relations *RelationshipIndex) {
	if s.replay {
		return
	}
	if s.visibility.families == nil {
		s.visibility = newTier1Visibility()
		if relations != nil && len(relations.edges) > 0 {
			s.provisionalRelations = relations
			s.visibility.incidentUnknown = make(map[uint32]bool)
		} else {
			s.edges = make(map[ASNEdge]struct{})
		}
	}
	err := s.visibility.add(path, func(edge ASNEdge) {
		if s.provisionalRelations != nil {
			// Once both endpoints already have an unknown incident edge, no
			// further relationship lookup can change the visibility summary.
			if !s.visibility.incidentUnknown[edge.From] || !s.visibility.incidentUnknown[edge.To] {
				s.visibility.relation(s.provisionalRelations, edge)
			}
		} else {
			s.edges[edge] = struct{}{}
		}
	})
	if err != nil || len(s.edges) > tier1RetainedPathEntries || s.visibility.pairs > tier1RetainedPathEntries {
		*s = tier1PathSummary{replay: true}
	}
}

func (s *tier1PathSummary) available(relations *RelationshipIndex) bool {
	return !s.replay && (s.edges != nil || s.provisionalRelations != nil && s.provisionalRelations == relations)
}

func (s *tier1PathSummary) resolve(ctx context.Context, relations *RelationshipIndex) (tier1Visibility, error) {
	if !s.available(relations) {
		return tier1Visibility{}, errors.New("unavailable Tier-1 path summary")
	}
	v := s.visibility
	if s.provisionalRelations != nil {
		return v, ctx.Err()
	}
	v.incidentUnknown = make(map[uint32]bool)
	for edge := range s.edges {
		if err := ctx.Err(); err != nil {
			return tier1Visibility{}, err
		}
		v.relation(relations, edge)
	}
	return v, ctx.Err()
}
