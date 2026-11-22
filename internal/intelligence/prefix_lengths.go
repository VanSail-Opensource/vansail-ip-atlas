package intelligence

import "net/netip"

// prefixLengths lists only populated lengths in a canonical prefix map,
// most specific first. Index membership is independent of the map values.
type prefixLengths struct{ v4, v6 []uint8 }

// indexPrefixLengths builds the read-only per-family length lists.
func indexPrefixLengths[V any](entries map[netip.Prefix]V) prefixLengths {
	var depths prefixLengths
	if len(entries) == 0 {
		return depths
	}
	var v4 [33]bool
	var v6 [129]bool
	for p := range entries {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is4() {
			v4[p.Bits()] = true
		} else {
			v6[p.Bits()] = true
		}
	}
	for i := len(v4) - 1; i >= 0; i-- {
		if v4[i] {
			depths.v4 = append(depths.v4, uint8(i))
		}
	}
	for i := len(v6) - 1; i >= 0; i-- {
		if v6[i] {
			depths.v6 = append(depths.v6, uint8(i))
		}
	}
	return depths
}

// forAddress returns a borrowed read-only list for the address family.
func (d prefixLengths) forAddress(addr netip.Addr) []uint8 {
	if addr.Is4() {
		return d.v4
	}
	return d.v6
}
