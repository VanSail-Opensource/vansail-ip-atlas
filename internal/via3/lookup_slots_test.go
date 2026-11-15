package via3

import (
	"context"
	"testing"
)

func assertSlotAccounting(t *testing.T, r *Release, references []*objectReference) {
	t.Helper()
	live, cached, active := 0, 0, 0
	for _, reference := range references {
		if reference.query || reference.cache || reference.router {
			live += reference.size
		} else if reference.shard != nil || reference.size != 0 {
			t.Fatal("unowned slot retained decoded backing or its live charge")
		}
		if reference.cache {
			cached += reference.size
		} else if reference.previous != nil || reference.next != nil {
			t.Fatal("evicted slot retained cache links")
		}
		if reference.query {
			active += reference.size
		}
	}
	if live != r.residentBytes || cached != r.cacheBytes || active != r.activeBytes {
		t.Fatalf("slot accounting differs: live%d/%d cache%d/%d active%d/%d", live, r.residentBytes, cached, r.cacheBytes, active, r.activeBytes)
	}
	seen := map[*objectReference]bool{}
	var previous *objectReference
	for entry := r.cacheHead; entry != nil; entry = entry.next {
		if seen[entry] || !entry.cache || entry.previous != previous {
			t.Fatal("cache list is cyclic, duplicated or inconsistent")
		}
		seen[entry] = true
		previous = entry
	}
	if previous != r.cacheTail {
		t.Fatal("cache tail differs from FIFO traversal")
	}
	for _, reference := range references {
		if seen[reference] != reference.cache {
			t.Fatal("cache flag differs from FIFO membership")
		}
	}
	clear(seen)
	for _, reference := range r.usedReferences {
		if seen[reference] || !reference.query {
			t.Fatal("query slot recorded more than once or without a pin")
		}
		seen[reference] = true
	}
	for _, reference := range references {
		if seen[reference] != reference.query {
			t.Fatal("query pin differs from used-slot membership")
		}
	}
}

func TestObjectSlotsKeepUniqueLiveChargesThroughCacheEviction(t *testing.T) {
	r := &Release{}
	router, a, b, extra := &objectReference{}, &objectReference{}, &objectReference{}, &objectReference{}
	references := []*objectReference{router, a, b, extra}
	// These are accounting fixtures: tiny placeholders avoid allocating three
	// 32MiB buffers just to exercise the exact declared-size admission limits.
	load := func(reference *objectReference) {
		t.Helper()
		if err := r.admitReference(reference, PublicObjectDecoded); err != nil {
			t.Fatal(err)
		}
		reference.shard = &Shard{}
		r.cacheReference(reference)
		assertSlotAccounting(t, r, references)
	}
	load(router)
	router.router = true
	r.endQuery()
	r.beginQuery()
	load(a) // Router leaves the cache but remains uniquely resident.
	load(b) // A leaves the cache but its current query pin survives.
	if router.cache || a.cache || !b.cache || a.shard == nil || router.shard == nil {
		t.Fatal("cache eviction lost query/router pins or evicted the wrong object")
	}
	if err := r.admitReference(a, PublicObjectDecoded); err != nil || len(r.usedReferences) != 2 {
		t.Fatal("duplicate admission charged or recorded a query pin twice", err)
	}
	if ErrorCode(r.admitReference(extra, 1)) != "resource_limit" {
		t.Fatal("cache eviction hid three uniquely pinned buffers from the live cap")
	}
	assertSlotAccounting(t, r, references)
	r.endQuery()
	assertSlotAccounting(t, r, references)
	if r.residentBytes != PublicObjectDecoded || a.shard != nil || b.shard != nil {
		t.Fatal("query-only buffers survived completion")
	}
	for _, entry := range r.usedReferences[:cap(r.usedReferences)] {
		if entry != nil {
			t.Fatal("query backing array retained old pins")
		}
	}
}

func TestObjectSlotFIFOStaysBoundedAcrossReadmission(t *testing.T) {
	r := &Release{}
	a, b := &objectReference{}, &objectReference{}
	references := []*objectReference{a, b}
	for i := 0; i < 100; i++ {
		r.beginQuery()
		for _, entry := range references {
			if err := r.admitReference(entry, PublicCacheDecoded/2); err != nil {
				t.Fatal(err)
			}
			entry.shard = &Shard{}
			r.cacheReference(entry)
			r.cacheReference(entry) // A repeated hit must not add another FIFO link.
		}
		r.endQuery()
		assertSlotAccounting(t, r, references)
		if r.cacheHead != a || r.cacheTail != b {
			t.Fatal("cache readmission changed FIFO ordering")
		}
		r.evictReference(a)
		r.evictReference(a)
		r.evictReference(b)
		assertSlotAccounting(t, r, references)
	}
}

func TestPinnedRouterSlotReusesBackingAfterCacheEviction(t *testing.T) {
	g := golden(t)
	r := memoryRelease(t, g, func() int64 { return g.Clock })
	var router *objectReference
	for _, reference := range r.references {
		if reference.router {
			router = reference
		}
	}
	before, reads := r.router, r.Reads
	r.evictReference(router)
	r.beginQuery()
	again, err := r.object(context.Background(), router.info.SHA256)
	if err != nil || again != before || r.Reads != reads || r.residentBytes != r.routerBytes {
		t.Fatal("pinned router was decoded twice or double charged", err)
	}
	r.endQuery()
	if router.shard != before || router.query || router.cache {
		t.Fatal("router pin changed with query completion")
	}
}

func TestFailedObjectSlotLoadReleasesPredecodeCharge(t *testing.T) {
	g := golden(t)
	r := memoryRelease(t, g, func() int64 { return g.Clock })
	if len(r.references) != len(g.Objects) || cap(r.usedReferences) != len(g.Objects) {
		t.Fatal("reference/query slots are not bounded by the manifest inventory")
	}
	target := r.router.lookup.references[0]
	target.info.Kind = 1 // Force a validated-payload/schema mismatch after decoding.
	before := r.residentBytes
	for i := 0; i < 2; i++ {
		r.beginQuery()
		if _, err := r.objectReference(context.Background(), target); ErrorCode(err) != "schema" {
			t.Fatal("schema mismatch was accepted", err)
		}
		if target.shard != nil || target.cache || !target.query || target.size == 0 {
			t.Fatal("failed load retained a decoded pointer or lost its admission charge")
		}
		r.endQuery()
		if target.shard != nil || target.query || target.size != 0 || r.residentBytes != before {
			t.Fatal("failed load leaked query residency")
		}
	}
}
