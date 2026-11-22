package via3

import (
	"bytes"
	"net/netip"
	"slices"
	"sort"
)

type prefixComponent struct {
	row    []byte
	winner netip.Prefix
}

func componentAddress(ip netip.Addr) (a [16]byte, family int) {
	if ip.Is4() {
		v := ip.As4()
		copy(a[12:], v[:])
		return a, 0
	}
	return ip.As16(), 1
}
func maskedComponentAddress(a [16]byte, family, bits int) [16]byte {
	if family == 0 {
		bits += 96
	}
	i := bits / 8
	if bits%8 != 0 {
		a[i] &= byte(0xff << (8 - bits%8))
		i++
	}
	clear(a[i:])
	return a
}

// Within an aligned cell, the selected longest prefix cannot change unless a
// strictly more-specific key in either verified source index starts there.
func (s *Shard) hasChildKey(a [16]byte, family, bits int) bool {
	cell := maskedComponentAddress(a, family, bits)
	for section, id := range []uint16{1, 8} {
		bounds := s.lookup.prefixes[section].families
		first, end := bounds[family], bounds[family+1]
		if first == end {
			continue
		}
		f := s.disk.prefixFences[section][family]
		if len(f) > 0 {
			k := max(0, sort.Search(len(f), func(i int) bool { return bytes.Compare(f[i][:], cell[:]) >= 0 })-1)
			first = blockFirst(first, k, prefixBlockRows)
		}
		stop := end
		if len(f) > 0 {
			stop = min(end, (first/prefixBlockRows+1)*prefixBlockRows)
		}
		// The first row after shorter keys at the cell start is the only
		// candidate. Equal-start prefix chains can straddle a page boundary.
		for first < end {
			var found uint32
			if stop-first <= prefixBlockRows {
				block := s.rowSpan(id, first, stop-first)
				found = first + uint32(sort.Search(len(block)/32, func(i int) bool {
					key := block[i*32 : (i+1)*32]
					cmp := bytes.Compare(key[4:20], cell[:])
					return cmp > 0 || cmp == 0 && int(key[1]) > bits
				}))
			} else {
				found = first + uint32(sort.Search(int(stop-first), func(i int) bool {
					key := s.row(id, first+uint32(i))
					cmp := bytes.Compare(key[4:20], cell[:])
					return cmp > 0 || cmp == 0 && int(key[1]) > bits
				}))
			}
			if found < stop {
				key := s.row(id, found)
				var addr [16]byte
				copy(addr[:], key[4:20])
				if maskedComponentAddress(addr, family, bits) == cell {
					return true
				}
				break
			}
			first = stop
			stop = min(end, (first/prefixBlockRows+1)*prefixBlockRows)
		}
	}
	return false
}
func (s *Shard) cachedPoint(ip netip.Addr) ([]byte, netip.Prefix, bool) {
	ip = ip.Unmap()
	a, family := componentAddress(ip)
	d, c := s.disk, s.components()
	scopes := d.scopes[family]
	i := sort.Search(len(scopes), func(i int) bool { return bytes.Compare(scopes[i].key.address[:], a[:]) > 0 }) - 1
	if i >= 0 {
		e := scopes[i]
		if e.key.address == maskedComponentAddress(a, family, int(e.key.depth)) {
			c.use(e)
			v := e.value.(prefixComponent)
			return v.row, v.winner, v.winner.IsValid()
		}
	}
	row, winner, ok := s.findPrefixWithin(ip, ip.BitLen())
	lo, hi := 0, ip.BitLen()
	if ok {
		lo = winner.Bits()
	}
	for lo < hi {
		mid := (lo + hi) / 2
		if s.hasChildKey(a, family, mid) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	key := s.componentKey(factIP, 0, 0)
	key.family = byte(family)
	key.depth = byte(lo)
	key.address = maskedComponentAddress(a, family, lo)
	if c.put(key, prefixComponent{bytes.Clone(row), winner}, len(row)+88) {
		// get/put and all query work run under the release mutex. trim may
		// have evicted neighbors since the initial search.
		scopes = d.scopes[family]
		pos := sort.Search(len(scopes), func(i int) bool { return bytes.Compare(scopes[i].key.address[:], key.address[:]) >= 0 })
		if pos == len(scopes) || scopes[pos].key.address != key.address {
			d.scopes[family] = slices.Insert(scopes, pos, c.slots[key])
		}
	}
	return row, winner, ok
}
func (d *indexedShard) dropScope(e *componentEntry) {
	group := &d.scopes[e.key.family]
	scopes := *group
	i := sort.Search(len(scopes), func(i int) bool { return bytes.Compare(scopes[i].key.address[:], e.key.address[:]) >= 0 })
	if i == len(scopes) || scopes[i] != e {
		return
	}
	scopes = slices.Delete(scopes, i, i+1)
	if len(scopes) == 0 {
		scopes = nil
	} else if cap(scopes) > 2*len(scopes) {
		scopes = slices.Clone(scopes)
	}
	*group = scopes
}
