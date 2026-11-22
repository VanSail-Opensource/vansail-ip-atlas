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
	previous, next *componentEntry
}
type nativeComponents struct {
	pages       *nativePages
	slots       map[componentKey]*componentEntry
	first, last *componentEntry
	bytes       int
	peakSlots   int
	active      bool
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
func (c *nativeComponents) use(e *componentEntry) {
	if c.last != e {
		if e.previous != nil || e.next != nil || c.first == e {
			c.unlink(e)
		}
		e.previous = c.last
		if c.last == nil {
			c.first = e
		} else {
			c.last.next = e
		}
		c.last = e
	}
	e.epoch = c.pages.epoch
}
func (c *nativeComponents) get(k componentKey) (any, bool) {
	if !c.active {
		return nil, false
	}
	e := c.slots[k]
	if e == nil {
		return nil, false
	}
	c.use(e)
	return e.value, true
}
func (c *nativeComponents) trim(limit int) {
	for c.bytes > limit && c.first != nil && c.first.epoch != c.pages.epoch {
		e := c.first
		c.unlink(e)
		if e.key.kind == factIP {
			e.key.source.dropScope(e)
		}
		delete(c.slots, e.key)
		c.bytes -= e.bytes
		c.pages.setMetadata(-e.bytes)
	}
	c.compactSlots()
}
func (c *nativeComponents) compactSlots() {
	count := len(c.slots)
	if count == 0 {
		c.slots = nil
		c.peakSlots = 0
		return
	}
	if count >= c.peakSlots/2 {
		return
	}
	compact := make(map[componentKey]*componentEntry, count)
	for k, v := range c.slots {
		compact[k] = v
	}
	c.slots = compact
	c.peakSlots = count
}
func (c *nativeComponents) put(k componentKey, v any, owned int) bool {
	size := componentEntryBytes + owned
	if !c.active || size > nativeComponentEntryLimit {
		return false
	}
	if e := c.slots[k]; e != nil {
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
	if c.slots == nil {
		c.slots = make(map[componentKey]*componentEntry)
	}
	e := &componentEntry{key: k, value: v, bytes: size}
	c.slots[k] = e
	c.peakSlots = max(c.peakSlots, len(c.slots))
	c.bytes += size
	c.pages.setMetadata(size)
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

func (s *Shard) cachedASN(asn uint32) ([]byte, bool) {
	c := s.components()
	k := s.componentKey(factASN, asn, 0)
	if v, ok := c.get(k); ok {
		row := v.([]byte)
		return row, len(row) != 0
	}
	first, _, ok := s.asnBounds(asn)
	var row []byte
	if ok {
		row = s.Record(first)
	}
	if c.active {
		c.put(k, bytes.Clone(row), len(row)+24)
	}
	return row, ok
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
