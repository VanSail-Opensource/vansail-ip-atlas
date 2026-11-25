package pipeline

import (
	"errors"
	"net/netip"
	"sort"

	"vansail-ip-atlas/internal/via3"
)

var errRouteComposition = errors.New("conflicting private route destinations")

// mergeDestinations preserves one immutable destination per kind. Partition
// leaves within a fact group are disjoint; overlapping kinds therefore indicate
// an invalid plan, even when their object hashes happen to be identical.
func mergeDestinations(a, b []via3.ObjectInfo) ([]via3.ObjectInfo, error) {
	var selected [14]via3.ObjectInfo
	for _, list := range [][]via3.ObjectInfo{a, b} {
		for _, info := range list {
			if groupForKind(info.Kind) == allFacts || selected[info.Kind].Kind != 0 {
				return nil, errRouteComposition
			}
			selected[info.Kind] = info
		}
	}
	out := make([]via3.ObjectInfo, 0, len(a)+len(b))
	for _, info := range selected {
		if info.Kind != 0 {
			out = append(out, info)
		}
	}
	return out, nil
}

func sameDestinations(a, b []via3.ObjectInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Kind != b[i].Kind || a[i].SHA256 != b[i].SHA256 {
			return false
		}
	}
	return true
}

func prefixBefore(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return a.Addr().Is4()
	}
	if a.Addr() != b.Addr() {
		return a.Addr().Less(b.Addr())
	}
	return a.Bits() < b.Bits()
}

// composeRoutes combines independently partitioned fact groups without changing
// the reader's single LPM or exact-ASN router lookup. A narrower boundary inherits
// every ancestor destination from the other groups, including unknown/tombstone
// records. A group's leaves never overlap, so no same-kind replacement is valid.
// Charge the exact five decoded vectors before allocating their output rows.
func composeRoutes(input []route, directoryCount uint64) ([]route, error) {
	const headers = 5 * 8
	if directoryCount > (via3.PublicObjectDecoded-headers)/40 {
		return nil, &via3.Error{Code: "resource_limit"}
	}
	used := uint64(headers) + directoryCount*40
	charge := func(bytes uint64) error {
		if bytes > via3.PublicObjectDecoded-used {
			return &via3.Error{Code: "resource_limit"}
		}
		used += bytes
		return nil
	}
	var prefixes []route
	type asnReference struct{ asn, route uint32 }
	var asnCount uint64
	for _, r := range input {
		if r.prefix.IsValid() {
			prefixes = append(prefixes, r)
		} else {
			asnCount += uint64(len(r.asns))
		}
	}
	// Input ASN references are already charged by registerCompiledRoute. Keep a
	// second bound here so direct callers cannot allocate an unbounded join.
	if asnCount > via3.PublicObjectDecoded/8 || uint64(len(prefixes)) > via3.PublicObjectDecoded/32 {
		return nil, &via3.Error{Code: "resource_limit"}
	}
	asnRefs := make([]asnReference, 0, int(asnCount))
	for i, r := range input {
		if !r.prefix.IsValid() {
			for _, asn := range r.asns {
				asnRefs = append(asnRefs, asnReference{asn, uint32(i)})
			}
		}
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixBefore(prefixes[i].prefix, prefixes[j].prefix) })
	var out []route
	var ancestors []int // at most 129 address-prefix depths
	for i := 0; i < len(prefixes); {
		prefix := prefixes[i].prefix
		for len(ancestors) != 0 {
			parent := out[ancestors[len(ancestors)-1]].prefix
			if parent.Addr().BitLen() == prefix.Addr().BitLen() && parent.Contains(prefix.Addr()) {
				break
			}
			ancestors = ancestors[:len(ancestors)-1]
		}
		var destinations []via3.ObjectInfo
		if len(ancestors) != 0 {
			destinations = out[ancestors[len(ancestors)-1]].destinations
		}
		for i < len(prefixes) && prefixes[i].prefix == prefix {
			var err error
			destinations, err = mergeDestinations(destinations, prefixes[i].destinations)
			if err != nil {
				return nil, err
			}
			i++
		}
		if err := charge(32 + 16 + 4*uint64(len(destinations))); err != nil {
			return nil, err
		}
		out = append(out, route{prefix: prefix, destinations: destinations})
		ancestors = append(ancestors, len(out)-1)
	}
	sort.Slice(asnRefs, func(i, j int) bool { return asnRefs[i].asn < asnRefs[j].asn })
	for i := 0; i < len(asnRefs); {
		asn := asnRefs[i].asn
		var destinations []via3.ObjectInfo
		for i < len(asnRefs) && asnRefs[i].asn == asn {
			var err error
			destinations, err = mergeDestinations(destinations, input[asnRefs[i].route].destinations)
			if err != nil {
				return nil, err
			}
			i++
		}
		if len(out) != 0 && !out[len(out)-1].prefix.IsValid() && sameDestinations(out[len(out)-1].destinations, destinations) {
			if err := charge(8); err != nil {
				return nil, err
			}
			out[len(out)-1].asns = append(out[len(out)-1].asns, asn)
		} else {
			if err := charge(8 + 16 + 4*uint64(len(destinations))); err != nil {
				return nil, err
			}
			out = append(out, route{asns: []uint32{asn}, destinations: destinations})
		}
	}
	return out, nil
}
