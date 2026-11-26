package pipeline

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func TestBulkScatterRoutesMatchEveryOverlappingTerminal(t *testing.T) {
	for _, parent := range []string{"0.0.0.0/0", "8.16.0.0/13", "9.9.8.0/21", "::/0", "2001:db8::/29", "2001:db8::8/125"} {
		root := &bulkBucket{prefix: netip.MustParsePrefix(parent)}
		var terminals []*bulkBucket
		var expand func(*bulkBucket, int)
		expand = func(node *bulkBucket, d int) {
			if d == 0 {
				terminals = append(terminals, node)
				return
			}
			left, right, err := bulkChildren(node)
			if err != nil {
				t.Fatal(err)
			}
			expand(left, d-1)
			expand(right, d-1)
		}
		ceiling := 128
		if root.prefix.Addr().Is4() {
			ceiling = 24
		}
		expand(root, min(4, ceiling-root.prefix.Bits()))
		routes, err := newBulkScatterRoutes(root.prefix, terminals)
		if err != nil {
			t.Fatal(err)
		}
		inputs := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("fd00::/8")}
		for _, node := range terminals {
			for bits := 0; bits <= node.prefix.Addr().BitLen(); bits++ {
				inputs = append(inputs, netip.PrefixFrom(node.prefix.Addr(), bits).Masked())
			}
		}
		for _, p := range inputs {
			var expected []int
			for i, node := range terminals {
				if p.Contains(node.prefix.Addr()) || node.prefix.Contains(p.Addr()) {
					expected = append(expected, i)
				}
			}
			first, last := routes.overlapping(p)
			var got []int
			for i := first; i < last; i++ {
				got = append(got, i)
			}
			if !slices.Equal(got, expected) {
				t.Fatalf("%s routes %s to %v, expected %v", parent, p, got, expected)
			}
		}
		reversed := slices.Clone(terminals)
		slices.Reverse(reversed)
		if _, err := newBulkScatterRoutes(root.prefix, reversed); err == nil {
			t.Fatalf("%s accepted misordered terminals", parent)
		}
	}
}

func TestScatterGroupsKeepUnchangedSourcesTogetherAcrossWithdrawal(t *testing.T) {
	var parts []intelligence.RecordPartition
	for i := range 89 {
		parts = append(parts, intelligence.RecordPartition{SHA256: [32]byte{byte(i + 1)}})
	}
	root := &bulkBucket{prefix: netip.MustParsePrefix("0.0.0.0/0"), parts: parts, sourceEnds: []int{4, 41, 89}}
	full := scatterInputGroups(root, 16, 16000, true)
	withdrawn := &bulkBucket{prefix: root.prefix, parts: parts[4:], sourceEnds: []int{37, 85}}
	retained := scatterInputGroups(withdrawn, 16, 15400, true)
	if len(full) < 3 || !reflect.DeepEqual(full[1:], retained) {
		t.Fatalf("unchanged publisher parts were rebatched: groups %d vs %d", len(full), len(retained))
	}
	limited := scatterInputGroups(root, 16, 256, true)
	if len(limited) != 1 || !slices.Equal(limited[0], parts) {
		t.Fatal("stable groups exceeded the remaining partition envelope")
	}
}
