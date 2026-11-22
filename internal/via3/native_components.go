package via3

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
)

// Components belong to one verified source object. Never retain a complete
// query or answer. Cache metadata shares the existing native page allowance.
const nativeComponentLimit = PublicCacheDecoded / 2
const nativeComponentEntryLimit = nativeComponentLimit / 64
const componentEntryBytes = 224 // map key and pointer, entry, links, interface and allocation overhead

type componentKind byte

const (
	factLabel componentKind = iota + 1
	factPrefixes
	factASN
	factEdge
	factRPKI
	factOrigins
	factIP
	factPaths
	factPathPositions
)

type componentKey struct {
	source        *indexedShard
	address       [16]byte
	a, b          uint32
	kind          componentKind
	depth, family byte
}
type componentEntry struct {
	key            componentKey
	value          any
	bytes          int
	epoch          uint64
	recent         bool
	previous, next *componentEntry
}
type nativeComponents struct {
	pages        *nativePages
	slots        map[componentKey]*componentEntry
	integers     map[uint64]*componentEntry
	peakIntegers int
	first, last  *componentEntry
	bytes        int
	peakSlots    int
	active       bool
	allPinned    uint64
}

var retryWithoutComponents = errors.New("native component working set")

func (c *nativeComponents) unlink(e *componentEntry) {
	if e.previous == nil {
		c.first = e.next
	} else {
		e.previous.next = e.next
	}
	if e.next == nil {
		c.last = e.previous
	} else {
		e.next.previous = e.previous
	}
	e.previous, e.next = nil, nil
}

// A cache hit marks the component used in this operation. Move or remove
// entries only on pressure; the two-pass clock drops unpinned, unused entries
// before recently used entries. No lookup writes another component's links.
func (c *nativeComponents) use(e *componentEntry) {
	e.epoch = c.pages.epoch
	e.recent = true
}
func (c *nativeComponents) append(e *componentEntry) {
	e.previous = c.last
	if c.last == nil {
		c.first = e
	} else {
		c.last.next = e
	}
	c.last = e
}

// Every prepared object has a distinct (<18,500) immutable manifest slot.
// The short path is an injective representation of the full kind/source/key;
// out-of-range values and address selectors retain their full structural key.
func (k componentKey) integerKey() (uint64, bool) {
	var selector uint64
	switch k.kind {
	case factLabel, factPrefixes, factASN, factOrigins, factPaths, factPathPositions:
		if k.b >= 1<<13 {
			return 0, false
		}
		selector = uint64(k.a)<<13 | uint64(k.b)
	case factEdge:
		if k.a >= 1<<22 || k.b >= 1<<22 {
			return 0, false
		}
		selector = uint64(k.a)<<22 | uint64(k.b)
	default:
		return 0, false
	}
	return uint64(k.source.slot)<<49 | uint64(k.kind)<<45 | selector, true
}
func (c *nativeComponents) find(k componentKey) *componentEntry {
	if i, ok := k.integerKey(); ok {
		return c.integers[i]
	}
	return c.slots[k]
}
func (c *nativeComponents) get(k componentKey) (any, bool) {
	if !c.active {
		return nil, false
	}
	e := c.find(k)
	if e == nil {
		return nil, false
	}
	c.use(e)
	return e.value, true
}
func (c *nativeComponents) trim(limit int) {
	if c.bytes <= limit || c.first == nil || c.allPinned != 0 && c.allPinned == c.pages.epoch {
		return
	}
	for pass := 0; pass < 2 && c.bytes > limit; pass++ {
		for e := c.first; e != nil && c.bytes > limit; {
			next := e.next
			if e.epoch != c.pages.epoch {
				if limit != 0 && e.recent && pass == 0 {
					e.recent = false
				} else {
					c.unlink(e)
					if e.key.kind == factIP {
						e.key.source.dropScope(e)
					}
					if i, short := e.key.integerKey(); short {
						delete(c.integers, i)
					} else {
						delete(c.slots, e.key)
					}
					c.bytes -= e.bytes
					c.pages.setMetadata(-e.bytes)
				}
			}
			e = next
		}
	}
	if c.bytes > limit {
		c.allPinned = c.pages.epoch
	}
	compactComponentMap(&c.slots, &c.peakSlots)
	compactComponentMap(&c.integers, &c.peakIntegers)
}
func compactComponentMap[K comparable](table *map[K]*componentEntry, peak *int) {
	count := len(*table)
	if count == 0 {
		*table = nil
		*peak = 0
		return
	}
	if count >= *peak/2 {
		return
	}
	out := make(map[K]*componentEntry, count)
	for k, v := range *table {
		out[k] = v
	}
	*table = out
	*peak = count
}
func (c *nativeComponents) put(k componentKey, v any, owned int) bool {
	size := componentEntryBytes + owned
	if !c.active || size > nativeComponentEntryLimit {
		return false
	}
	if e := c.find(k); e != nil {
		c.use(e)
		return true
	}
	limit := min(nativeComponentLimit, PublicCacheDecoded-c.pages.routerBytes-(c.pages.metadata-c.bytes)-rowPageSize)
	if size > limit {
		return false
	}
	c.trim(limit - size)
	if size > limit-c.bytes || !c.pages.owner.mayKeepNativeMetadata(size) {
		return false
	}
	e := &componentEntry{key: k, value: v, bytes: size}
	if i, short := k.integerKey(); short {
		if c.integers == nil {
			c.integers = make(map[uint64]*componentEntry)
		}
		c.integers[i] = e
		c.peakIntegers = max(c.peakIntegers, len(c.integers))
	} else {
		if c.slots == nil {
			c.slots = make(map[componentKey]*componentEntry)
		}
		c.slots[k] = e
		c.peakSlots = max(c.peakSlots, len(c.slots))
	}
	c.bytes += size
	c.pages.setMetadata(size)
	c.append(e)
	c.use(e)
	return true
}
func (s *Shard) componentKey(kind componentKind, a, b uint32) componentKey {
	return componentKey{source: s.disk, kind: kind, a: a, b: b}
}
func (s *Shard) components() *nativeComponents { return &s.disk.pages.owner.native.facts }

// The result is always an independently owned mutable answer. The second
// attempt is possible only for optional component pin pressure. All original
// source-object admission and identity checks run again on every attempt.
func (r *Release) Lookup(ctx context.Context, q string) (LookupAnswer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.native == nil || PublicCacheDecoded-r.native.pages.routerBytes-r.native.fenceBytes < componentEntryBytes+rowPageSize {
		return r.lookupOnce(ctx, q)
	}
	c := &r.native.facts
	c.active = true
	a, err := r.lookupOnce(ctx, q)
	c.active = false
	if err != retryWithoutComponents {
		return a, err
	}
	c.trim(0)
	return r.lookupOnce(ctx, q)
}

// The immutable aggregate and its first page descriptor reside in the same
// signed kind-8 object. Reading them together avoids another private-page
// access when the regular full lookup opens that first logical page.
type nativeASNFact struct {
	row       []byte
	firstPage []byte
}

func (s *Shard) cachedASN(asn uint32) nativeASNFact {
	c := s.components()
	k := s.componentKey(factASN, asn, 0)
	if v, ok := c.get(k); ok {
		return v.(nativeASNFact)
	}
	first, _, ok := s.asnBounds(asn)
	var fact nativeASNFact
	if ok {
		fact.row = s.Record(first)
		if s.Kind == 8 && u32(fact.row, 40) != 0 {
			fact.firstPage = s.row(12, u32(fact.row, 36))
		}
	}
	if c.active && len(fact.row) == 0 {
		c.put(k, fact, 48)
		return fact
	}
	if c.active {
		data := make([]byte, len(fact.row)+len(fact.firstPage))
		copy(data, fact.row)
		copy(data[len(fact.row):], fact.firstPage)
		fact.row = data[:len(fact.row):len(fact.row)]
		fact.firstPage = data[len(fact.row):]
		c.put(k, fact, 48+len(data))
	}
	return fact
}
func (s *Shard) cachedRPKI(addr netip.Addr, origin uint32, announcement netip.Prefix) ([]byte, bool) {
	if !announcement.IsValid() || !announcement.Contains(addr.Unmap()) {
		return nil, false
	}
	c := s.components()
	k := s.componentKey(factRPKI, origin, 0)
	p := announcement.Masked()
	k.address = p.Addr().As16()
	k.depth = byte(p.Bits())
	if p.Addr().Is4() {
		k.family = 4
	} else {
		k.family = 6
	}
	if v, ok := c.get(k); ok {
		row := v.([]byte)
		return row, len(row) != 0
	}
	row, ok := s.findRPKIRow(addr, origin, announcement)
	if c.active {
		c.put(k, bytes.Clone(row), len(row)+24)
	}
	return row, ok
}
