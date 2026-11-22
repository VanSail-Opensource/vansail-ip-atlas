package via3

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
)

func TestNativePrefixScopesRespectNestedSourcesAndMissingRanges(t *testing.T) {
	ctx := context.Background()
	partition := PartitionInput{Partition: "all", PrefixRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
	for _, fact := range []struct {
		prefix, country string
		inherited       bool
	}{
		{"0.0.0.0/0", "CA", true}, {"203.0.0.0/16", "US", true}, {"203.0.113.0/24", "DE", false}, {"203.0.113.1/32", "JP", false}, {"203.0.114.0/24", "GB", false},
		{"2001:db8::/32", "CA", true}, {"2001:db8:100::/48", "US", false}, {"2001:db8:100::1/128", "JP", false},
	} {
		partition.Records = append(partition.Records, PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(fact.prefix), Exact: !fact.inherited && netip.MustParsePrefix(fact.prefix).IsSingleIP(), Inherited: fact.inherited, Geo: &GeoData{Country: fact.country}})
	}
	const clock = 1700000000
	built, err := Build(ctx, CompileInput{Mode: "synthetic", Clock: clock, ValidUntil: clock + 3600, Partitions: []PartitionInput{partition}})
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{}
	for _, o := range built.Objects {
		objects[o.Info.SHA256] = o.Bytes
	}
	open := func() *Release {
		r, err := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(h string) ([]byte, error) { return objects[h], nil }, func() int64 { return clock })
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	normal, index := open(), open()
	defer normal.Close()
	defer index.Close()
	if err := index.PrepareNativeIndex(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	queries := []string{"0.0.0.0", "255.255.255.255", "203.0.112.255", "203.0.113.0", "203.0.113.1", "203.0.113.2", "203.0.113.255", "203.0.114.0", "203.0.114.255", "203.0.115.0", "::", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::", "2001:db8:ff:ffff:ffff:ffff:ffff:ffff", "2001:db8:100::", "2001:db8:100::1", "2001:db8:100::2", "2001:db8:101::", "2001:db9::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}
	for pass := 0; pass < 3; pass++ {
		if pass == 2 {
			index.native.facts.trim(0)
			if index.native.facts.first != nil || index.native.facts.bytes != 0 {
				t.Fatal("inactive component retained")
			}
		}
		for _, q := range queries {
			want, err := normal.Lookup(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			got, err := index.Lookup(ctx, q)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("query %s pass %d: %v", q, pass, err)
			}
			mutateLookupValue(reflect.ValueOf(&got).Elem())
		}
		for i, j := 0, len(queries)-1; i < j; i, j = i+1, j-1 {
			queries[i], queries[j] = queries[j], queries[i]
		}
	}
	if index.native.facts.bytes == 0 {
		t.Fatal("test did not exercise cached scopes")
	}
}

func TestCompactFactKeyKeepsEverySelectorDistinct(t *testing.T) {
	seen := map[uint64]componentKey{}
	for _, slot := range []uint16{0, 1, 18498} {
		s := &indexedShard{slot: slot}
		for _, k := range []componentKind{factLabel, factPrefixes, factASN, factEdge, factRPKI, factOrigins, factIP, factPaths, factPathPositions} {
			for _, a := range []uint32{0, 1, 1<<22 - 1, 1 << 22, 1<<32 - 1} {
				for _, b := range []uint32{0, 1, 1<<13 - 1, 1 << 13, 1<<22 - 1, 1 << 22} {
					key := componentKey{source: s, kind: k, a: a, b: b}
					n, ok := key.integerKey()
					if k == factIP || k == factRPKI || k == factEdge && (a >= 1<<22 || b >= 1<<22) || k != factEdge && b >= 1<<13 {
						if ok {
							t.Fatal("lossy compact key accepted", k, a, b)
						}
						continue
					}
					if !ok {
						t.Fatal("short selector unexpectedly fell back", k)
					}
					if prior, found := seen[n]; found {
						t.Fatal("distinct component selectors collided", key, prior)
					}
					seen[n] = key
				}
			}
		}
	}
}

func TestNativeComponentPressureHonorsPinsAndSecondChance(t *testing.T) {
	index := &nativeIndex{}
	pages := &nativePages{epoch: 1}
	r := &Release{native: index}
	pages.owner = r
	index.pages = pages
	facts := &index.facts
	facts.pages = pages
	facts.active = true
	source := &indexedShard{slot: 1}
	key := func(i uint32) componentKey { return componentKey{source: source, kind: factASN, a: i} }
	for i := uint32(1); i <= 4; i++ {
		if !facts.put(key(i), i, 0) {
			t.Fatal("test component rejected")
		}
	}
	facts.trim(0)
	if facts.bytes != 4*componentEntryBytes || pages.metadata != facts.bytes {
		t.Fatal("query-pinned component evicted")
	}
	pages.next()
	// Populate the clock and then explicitly access an older position. This
	// entry stays pinned while a less recently used unpinned position is removed.
	facts.find(key(2)).recent = false
	facts.get(key(1))
	facts.trim(3 * componentEntryBytes)
	if facts.find(key(1)) == nil || facts.find(key(2)) != nil || facts.find(key(3)) == nil {
		t.Fatal("clock discarded a pinned or recently used entry")
	}
	facts.trim(0)
	if facts.bytes != componentEntryBytes || pages.metadata != facts.bytes {
		t.Fatal("failed to reclaim all unpinned entries")
	}
	pages.next()
	facts.trim(0)
	if facts.bytes != 0 || pages.metadata != 0 || facts.first != nil || facts.last != nil || facts.integers != nil {
		t.Fatal("inactive component directory or storage remains")
	}
}
