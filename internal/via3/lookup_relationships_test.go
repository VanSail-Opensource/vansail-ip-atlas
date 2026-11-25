package via3

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
)

func TestRelationshipPositionsReadCurrentVerifiedObject(t *testing.T) {
	const asn = 13335
	g := golden(t)
	r := memoryRelease(t, g, func() int64 { return g.Clock })
	first, err := r.Lookup(context.Background(), "AS13335")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		answer, err := r.Lookup(context.Background(), "AS13335")
		if err != nil || !reflect.DeepEqual(answer, first) {
			t.Fatal("cached indices changed entire lookup", err)
		}
	}
	var owner *objectReference
	var graph *pathGraph
	for _, ref := range r.references {
		if ref.info.Kind != 11 || ref.shard == nil || ref.shard.lookup.graphIndex == nil {
			continue
		}
		slot := ref.shard.lookup.graphIndex.slots[asn%8]
		if slot.asn == asn {
			owner, graph = ref, slot.graph
			break
		}
	}
	if graph == nil || len(graph.positions) == 0 || len(graph.positions) != len(graph.pairs) || owner.shard.lookup.graphIndex.bytes != graphTableBytes+graph.bytes() {
		t.Fatal("verified fixture did not retain charged source ordinals")
	}
	var components graphComponents
	components.prepare(owner.shard, asn, graph)
	if !components.known {
		t.Fatal("missing ordinal projection")
	}
	pairs := slices.Clone(graph.pairs)
	var target *objectReference
	for _, pos := range graph.positions {
		if pos.ref != nil && pos.ordinal != None {
			target = pos.ref
			break
		}
	}
	if target == nil {
		t.Fatal("fixture lacks an observed relationship row")
	}
	r.evictReference(target)
	if target.shard != nil {
		t.Fatal("a graph ordinal retained the decoded relationship shard")
	}
	load := r.load
	r.load = func(hash string) ([]byte, error) {
		b, err := load(hash)
		if err == nil && hash == target.info.SHA256 {
			b = bytes.Clone(b)
			b[len(b)-1] ^= 1
		}
		return b, err
	}
	r.beginQuery()
	_, err = r.relationshipAnswers(context.Background(), pairs, &components)
	r.endQuery()
	if ErrorCode(err) != "integrity" {
		t.Fatal("stored ordinal bypassed verification on reload", err)
	}
	r.load = load
	r.beginQuery()
	edges, err := r.relationshipAnswers(context.Background(), pairs, &components)
	r.endQuery()
	if err != nil || !reflect.DeepEqual(edges, first.BGP.Relationships) {
		t.Fatal("verified reload changed relationship values", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.relationshipAnswers(ctx, pairs, &components); err != context.Canceled {
		t.Fatal("cached component ignored cancellation", err)
	}
}

func TestRelationshipProjectionFailsClosedForWrongStoredOrdinal(t *testing.T) {
	g := golden(t)
	r := memoryRelease(t, g, func() int64 { return g.Clock })
	shard, err := r.asnDestination(context.Background(), 13335, 12)
	if err != nil || shard == nil {
		t.Fatal(err)
	}
	var c graphComponents
	c.known = true
	c.positions[0] = relationshipPosition{shard.lookup.owner, 999999}
	if _, err := r.relationshipAnswers(context.Background(), []uint64{uint64(13335)<<32 | 3356}, &c); ErrorCode(err) != "record" {
		t.Fatal("accepted an out-of-range relationship position", err)
	}
}
