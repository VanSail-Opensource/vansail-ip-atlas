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
	p, err := canonicalPath(v)
	if err != nil {
		return err
	}
	s.families[v.Family] = struct{}{}
	if len(s.families) > 1000 {
		return ErrGraphBudget
	}
	if !p.GraphEligible {
		return nil
	}
	var prior uint32
	for _, segment := range p.Segments {
		for _, asn := range segment.ASNs {
			if _, exists := s.byASN[asn][v.Family]; !exists {
				s.pairs++
				if s.pairs > 1_000_000 || len(s.byASN) >= 200_000 && s.byASN[asn] == nil {
					return ErrGraphBudget
				}
				addFamily(s.byASN, asn, v.Family)
			}
			if prior != 0 && prior != asn {
				edge(ASNEdge{From: prior, To: asn})
			}
			prior = asn
		}
	}
	return nil
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
