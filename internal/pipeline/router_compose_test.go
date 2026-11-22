package pipeline

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func routeObject(kind uint16) via3.ObjectInfo {
	return via3.ObjectInfo{Kind: kind, SHA256: fmt.Sprintf("%064x", kind), Bytes: 64, Partition: "all"}
}

func TestComposeRoutesFullVectorsAtIndependentBoundaries(t *testing.T) {
	input := []route{
		{prefix: netip.MustParsePrefix("0.0.0.0/0"), destinations: []via3.ObjectInfo{routeObject(2), routeObject(3), routeObject(5)}},
		{prefix: netip.MustParsePrefix("8.0.0.0/8"), destinations: []via3.ObjectInfo{routeObject(4), routeObject(7)}},
		{prefix: netip.MustParsePrefix("8.8.8.0/24"), destinations: []via3.ObjectInfo{routeObject(6)}},
		{prefix: netip.MustParsePrefix("8.8.8.0/24"), destinations: []via3.ObjectInfo{routeObject(9), routeObject(10)}},
		{prefix: netip.MustParsePrefix("9.0.0.0/8"), destinations: []via3.ObjectInfo{routeObject(4)}},
		{prefix: netip.MustParsePrefix("::/0"), destinations: []via3.ObjectInfo{routeObject(2)}},
		{prefix: netip.MustParsePrefix("2001:db8::/32"), destinations: []via3.ObjectInfo{routeObject(6)}},
		{asns: []uint32{13335, 15169}, destinations: []via3.ObjectInfo{routeObject(8)}},
		{asns: []uint32{3356, 13335}, destinations: []via3.ObjectInfo{routeObject(11)}},
		{asns: []uint32{3356}, destinations: []via3.ObjectInfo{routeObject(12), routeObject(13)}},
	}
	got, err := composeRoutes(input, 12)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]uint16{{2, 3, 5}, {2, 3, 4, 5, 7}, {2, 3, 4, 5, 6, 7, 9, 10}, {2, 3, 4, 5}, {2}, {2, 6}, {11, 12, 13}, {8, 11}, {8}}
	if len(got) != len(want) {
		t.Fatal("boundary lost", len(got))
	}
	for i, r := range got {
		var kinds []uint16
		for _, d := range r.destinations {
			kinds = append(kinds, d.Kind)
		}
		if !slices.Equal(kinds, want[i]) {
			t.Fatal("ancestor erased or unrelated sibling inherited", i, kinds)
		}
	}
	slices.Reverse(input)
	again, err := composeRoutes(input, 12)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("route arrival order changes complete vectors", err)
	}
}

func TestComposeRoutesRejectsSameKindOverlap(t *testing.T) {
	for _, input := range [][]route{
		{{prefix: netip.MustParsePrefix("0.0.0.0/0"), destinations: []via3.ObjectInfo{routeObject(2)}}, {prefix: netip.MustParsePrefix("8.8.8.0/24"), destinations: []via3.ObjectInfo{routeObject(2)}}},
		{{asns: []uint32{13335}, destinations: []via3.ObjectInfo{routeObject(8)}}, {asns: []uint32{13335}, destinations: []via3.ObjectInfo{routeObject(8)}}},
	} {
		if _, err := composeRoutes(input, 1); err == nil {
			t.Fatal("overlapping fact group accepted")
		}
	}
}

func TestComposeRoutesChargesInheritedVectorsAndHeaders(t *testing.T) {
	input := []route{
		{prefix: netip.MustParsePrefix("0.0.0.0/0"), destinations: []via3.ObjectInfo{routeObject(2), routeObject(3), routeObject(4), routeObject(5), routeObject(7), routeObject(9), routeObject(10)}},
		{prefix: netip.MustParsePrefix("8.8.8.0/24"), destinations: []via3.ObjectInfo{routeObject(6)}},
	}
	// Exact output cost is 40 headers + 76 parent + 80 child. A planner
	// charging only the child's local kind would incorrectly accept this.
	directoryCount := uint64((via3.PublicObjectDecoded - 172) / 40)
	if _, err := composeRoutes(input, directoryCount); via3.ErrorCode(err) != "resource_limit" {
		t.Fatal("inherited full vector escaped the router decoded limit", err)
	}
	if _, err := composeRoutes(input, directoryCount-1); err != nil {
		t.Fatal("bounded composed router rejected", err)
	}
	if _, err := composeRoutes(nil, ^uint64(0)); via3.ErrorCode(err) != "resource_limit" {
		t.Fatal("directory arithmetic overflow accepted", err)
	}
}
