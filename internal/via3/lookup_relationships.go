package via3

import "context"

// An ordinal belongs to a manifest-verified kind-12 object; None is a miss in
// that immutable source run. Always acquire the object's current verified bytes
// before using the ordinal. No decoded shard or public relationship is retained.
type relationshipPosition struct {
	ref     *objectReference
	ordinal uint32
}

const relationshipPositionBytes = 16

// Small graph components are copied into the query's bounded stack storage
// before reading another object, which may reclaim all optional graph indexes.
type graphComponents struct {
	positions  [64]relationshipPosition
	graphOwner *objectReference
	asn        uint32
	known      bool
}

func (c *graphComponents) prepare(s *Shard, asn uint32, g *pathGraph) {
	if len(g.pairs) == 0 || len(g.pairs) > len(c.positions) {
		return
	}
	c.graphOwner, c.asn = s.lookup.owner, asn
	if len(g.positions) == len(g.pairs) {
		copy(c.positions[:], g.positions)
		c.known = true
	}
}

func (r *Release) retainGraphComponents(c *graphComponents, pairs int) {
	if c.known || c.graphOwner == nil || !r.canRetainGraph(c.graphOwner, pairs*relationshipPositionBytes) {
		return
	}
	s := c.graphOwner.shard
	if s == nil || s.lookup == nil || s.lookup.graphIndex == nil {
		return
	}
	slots := &s.lookup.graphIndex.slots
	slot := &slots[c.asn%uint32(len(slots))]
	if slot.asn != c.asn || slot.graph == nil || len(slot.graph.pairs) != pairs || slot.graph.positions != nil {
		return
	}
	r.chargeGraph(c.graphOwner, pairs*relationshipPositionBytes)
	slot.graph.positions = make([]relationshipPosition, pairs)
	copy(slot.graph.positions, c.positions[:pairs])
}

func (r *Release) relationshipAnswers(ctx context.Context, pairs []uint64, c *graphComponents) ([]RelationshipAnswer, error) {
	edges := make([]RelationshipAnswer, 0, len(pairs))
	for i := 0; i < len(pairs); {
		if err := ctx.Err(); err != nil {
			return edges, err
		}
		from := uint32(pairs[i] >> 32)
		var s *Shard
		var err error
		var first, end uint32
		var source *objectReference
		if c.known {
			source = c.positions[i].ref
			if source != nil {
				s, err = r.objectReference(ctx, source)
				if err == nil && s.Kind != 12 {
					return edges, fail("record")
				}
			}
		} else {
			s, err = r.asnDestination(ctx, from, 12)
			if err == nil && s != nil {
				first, end, _ = s.asnBounds(from)
			}
		}
		if err != nil {
			return edges, err
		}
		for ; i < len(pairs) && uint32(pairs[i]>>32) == from; i++ {
			if err := ctx.Err(); err != nil {
				return edges, err
			}
			to := uint32(pairs[i])
			edge := RelationshipAnswer{From: from, To: to, Relation: "unknown", Observed: true}
			var row []byte
			if c.known {
				pos := c.positions[i]
				if pos.ref != source {
					return edges, fail("record")
				}
				if pos.ordinal != None {
					if s == nil {
						return edges, fail("record")
					}
					row = s.Record(pos.ordinal)
					if len(row) != 16 || u32(row, 4) != from || u32(row, 8) != to {
						return edges, fail("record")
					}
				}
			} else {
				pos := relationshipPosition{ordinal: None}
				if s != nil {
					if s.lookup != nil {
						pos.ref = s.lookup.owner
					}
					if pos.ref == nil {
						c.graphOwner = nil
					}
					if first < end {
						found, ordinal, ok := s.relationshipPosition(first, end, to)
						if ok {
							row, pos.ordinal = found, ordinal
						}
					}
				}
				if c.graphOwner != nil {
					c.positions[i] = pos
				}
			}
			if row != nil {
				edge.Relation = []string{"unknown", "transit_upstream", "peer", "customer", "sibling"}[row[12]]
				edge.Inferred = row[13]&2 != 0
			}
			edges = append(edges, edge)
		}
	}
	return edges, nil
}
