package via3

import (
	"context"
	"slices"
	"testing"
)

func TestNativePrefixComponentsRetainPackedImmutableSpans(t *testing.T) {
	r, want, _ := prefixPageOwnershipFixture(t)
	defer r.Close()
	ctx := context.Background()
	if err := r.PrepareNativeIndex(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	lookup := func() []string {
		t.Helper()
		a, err := r.Lookup(ctx, "AS13335")
		if err != nil || len(a.ASNs) != 1 || !slices.Equal(a.ASNs[0].Prefixes, want) {
			t.Fatal("prepared first page differs from canonical spelling", err)
		}
		return a.ASNs[0].Prefixes
	}
	first := lookup()
	var entry *componentEntry
	for _, e := range r.native.facts.integers {
		if e.key.kind == factPrefixes {
			if entry != nil {
				t.Fatal("fixture should populate exactly one prefix component")
			}
			entry = e
		}
	}
	if entry == nil {
		t.Fatal("lookup did not exercise the native prefix component")
	}
	compact, ok := entry.value.(nativePrefixLabels)
	if !ok || len(compact.offsets) != len(want)+1 || cap(compact.offsets) != len(compact.offsets) || int(compact.offsets[len(want)]) != len(compact.text) {
		t.Fatal("native component must own packed canonical text and exact offsets")
	}
	if entry.bytes != componentEntryBytes+40+2*(len(want)+1)+len(compact.text) || entry.bytes >= componentEntryBytes+prefixSpanBytes(want)+24 {
		t.Fatal("packed cache accounting differs or has no savings")
	}
	first[0] = "first caller mutation"
	second := lookup()
	r.native.facts.trim(0)
	if r.native.facts.find(entry.key) != nil {
		t.Fatal("completed query unexpectedly pins the prefix component")
	}
	third := lookup()
	third[1] = "second caller mutation"
	if !slices.Equal(second, want) {
		t.Fatal("mutation or cache pressure changed an existing caller result")
	}
}
