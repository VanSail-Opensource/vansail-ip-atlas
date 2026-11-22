package via3

import (
	"context"
	"reflect"
	"testing"
)

func TestNativeGraphComponentsSurviveSourceEvictionAndAnswerMutation(t *testing.T) {
	g := golden(t)
	clock := g.Clock
	r, err := OpenRelease(fileGolden(t, g), func() int64 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx := context.Background()
	if err := r.PrepareNativeIndex(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	want, err := memoryRelease(t, g, func() int64 { return clock }).Lookup(ctx, "AS13335")
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.Lookup(ctx, "AS13335")
	if err != nil || !reflect.DeepEqual(first, want) {
		t.Fatal("prepared answer differs", err)
	}
	facts := &r.native.facts
	var paths *componentEntry
	for key, entry := range facts.slots {
		if key.kind == factPaths && key.a == 13335 {
			paths = entry
			break
		}
	}
	if paths == nil {
		t.Fatal("verified path object did not produce a bounded numeric component")
	}
	graph := paths.value.(*pathGraph)
	if len(graph.pairs) == 0 || len(graph.positions) != 0 || paths.bytes != graph.bytes()+componentEntryBytes {
		t.Fatal("path and position backing store must be owned and accounted separately")
	}
	key := paths.key
	key.kind = factPathPositions
	entry := facts.slots[key]
	if entry == nil || entry.bytes != componentEntryBytes+entry.value.(*nativePathRelationships).bytes() || len(entry.value.(*nativePathRelationships).codes) != len(graph.pairs) {
		t.Fatal("missing or incorrectly charged path relationship ordinals")
	}
	owner := paths.key.source.shard.lookup.owner
	if owner.cache {
		r.evictReference(owner)
	}
	if owner.shard != nil {
		t.Fatal("path component kept the original shard resident")
	}
	mutateLookupValue(reflect.ValueOf(&first).Elem())
	second, err := r.Lookup(ctx, "AS13335")
	if err != nil || !reflect.DeepEqual(second, want) || facts.slots[paths.key] != paths {
		t.Fatal("eviction or caller mutation changed verified path component", err)
	}
	// Even a detached relationship projection must re-admit all contributing
	// kind-12 sources. A new request cannot spend the accumulated space twice
	// or bypass the declared original-object ceiling.
	bundle := entry.value.(*nativePathRelationships)
	checked := false
	for _, position := range bundle.positions {
		if position.ref == nil {
			continue
		}
		ref := position.ref
		if ref.cache {
			r.evictReference(ref)
		}
		prior := ref.onsite.decoded
		ref.onsite.decoded = PublicObjectDecoded + 1
		_, err := r.Lookup(ctx, "AS13335")
		ref.onsite.decoded = prior
		if ErrorCode(err) != "resource_limit" {
			t.Fatal("prepared relationship skipped original source admission", err)
		}
		checked = true
		break
	}
	if !checked {
		t.Fatal("fixture missed a required relationship source")
	}
	clock = r.Manifest.ValidUntil
	if _, err := r.Lookup(ctx, "AS13335"); err == nil {
		t.Fatal("cached graph bypassed release expiry")
	}
}
