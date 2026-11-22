package via3

import mathbits "math/bits"

// The router's sorted ASN keys occupy few high-16 and high-24 bands. A
// presence bit and a word's first ordinal locate the original key and record.
// The directory cannot turn a gap between adjacent ASNs into a match.
type routerASNDirectory struct {
	firstHigh uint32
	high      []uint16
	bands     [][256]uint16
	blocks    []routerASNBlock
	bytes     int
}

type routerASNBlock struct {
	presence [4]uint64
	first    [4]uint32
}

type routerASNShape struct {
	firstHigh, highCount, bands, blocks int
}

func routerASNLayout(keys []byte) routerASNShape {
	if len(keys) == 0 {
		return routerASNShape{}
	}
	first := u32(keys, 0)
	last := u32(keys, len(keys)-8)
	firstHigh, lastHigh := int(first>>16), int(last>>16)
	shape := routerASNShape{firstHigh: firstHigh, highCount: lastHigh - firstHigh + 1, bands: 1, blocks: 1}
	previous := first
	for p := 8; p < len(keys); p += 8 {
		asn := u32(keys, p)
		if asn>>16 != previous>>16 {
			shape.bands++
		}
		if asn>>8 != previous>>8 {
			shape.blocks++
		}
		previous = asn
	}
	return shape
}

func (s routerASNShape) size() int {
	// The struct's three slice headers, firstHigh, alignment and byte charge
	// fit in 88 bytes on each supported architecture.
	return 88 + s.highCount*2 + s.bands*512 + s.blocks*48
}

func (s routerASNShape) build(keys []byte) *routerASNDirectory {
	d := &routerASNDirectory{
		firstHigh: uint32(s.firstHigh), high: make([]uint16, s.highCount),
		bands: make([][256]uint16, s.bands), blocks: make([]routerASNBlock, s.blocks), bytes: s.size(),
	}
	var previous uint32
	band, block := -1, -1
	for p := 0; p < len(keys); p += 8 {
		asn := u32(keys, p)
		if p == 0 || asn>>16 != previous>>16 {
			band++
			d.high[(asn>>16)-d.firstHigh] = uint16(band + 1)
		}
		if p == 0 || asn>>8 != previous>>8 {
			block++
			d.bands[band][uint8(asn>>8)] = uint16(block + 1)
		}
		word := (asn >> 6) & 3
		entry := &d.blocks[block]
		if entry.presence[word] == 0 {
			entry.first[word] = uint32(p / 8)
		}
		entry.presence[word] |= uint64(1) << (asn & 63)
		previous = asn
	}
	return d
}

func (d *routerASNDirectory) ordinal(asn uint32) (uint32, bool) {
	high := (asn >> 16) - d.firstHigh
	if high >= uint32(len(d.high)) {
		return 0, false
	}
	band := d.high[high]
	if band == 0 {
		return 0, false
	}
	block := d.bands[band-1][uint8(asn>>8)]
	if block == 0 {
		return 0, false
	}
	entry := &d.blocks[block-1]
	word := (asn >> 6) & 3
	mask, bit := entry.presence[word], uint64(1)<<(asn&63)
	if mask&bit == 0 {
		return 0, false
	}
	return entry.first[word] + uint32(mathbits.OnesCount64(mask&(bit-1))), true
}

func (r *Release) prepareRouterASNs(ref *objectReference, s *Shard) {
	keys := s.lookup.rows[2]
	shape := routerASNLayout(keys)
	size := shape.size()
	// Expensive sparse layouts retain the original binary search. The size
	// limit also keeps every one-based band and block number within uint16.
	if size > len(keys) || size > 512<<10 || !r.reservePrefixMetadata(ref, size) {
		return
	}
	s.lookup.owner = ref
	s.lookup.routerASNs = shape.build(keys)
}

func (r *Release) releaseRouterASNs() {
	if r.router == nil || r.router.lookup == nil {
		return
	}
	index := r.router.lookup
	if index.routerASNs == nil {
		return
	}
	size := index.routerASNs.bytes
	index.routerASNs = nil
	ref := index.owner
	ref.size -= size
	r.residentBytes -= size
	r.routerBytes -= size
	if ref.query {
		r.activeBytes -= size
	}
	if ref.cache {
		r.cacheBytes -= size
	}
	if r.native != nil {
		r.native.pages.routerBytes -= size
		r.native.pages.setMetadata(0)
	}
}
