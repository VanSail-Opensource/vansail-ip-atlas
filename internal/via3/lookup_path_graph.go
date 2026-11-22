package via3

import "slices"

// These numeric projections belong to one validated kind-11 shard. They contain
// no query, relationship lookup, mutable answer, labels, or release clock.
type graphPath struct {
	first, count uint32
	segments     uint16
	visibility   byte
	eligible     bool
}
type graphSegment struct {
	count uint32
	kind  byte
}
type pathGraph struct {
	paths     []graphPath
	segments  []graphSegment
	values    []uint32
	positions []relationshipPosition
	pairs     []uint64 // sorted consecutive directed hops of graph-eligible paths
}
type graphSlot struct {
	asn   uint32
	graph *pathGraph
}
type pathGraphIndex struct {
	slots [8]graphSlot
	bytes int
}

// A bounded direct-mapped admission window avoids constructing graph indexes
// for one-off ASNs. A collision replaces the prior numeric index.
const graphTableBytes = 160
const graphHeaderBytes = 128

func (r *Release) releaseGraphMetadata(ref *objectReference) {
	if ref.shard == nil || ref.shard.lookup == nil || ref.shard.lookup.graphIndex == nil {
		return
	}
	size := ref.shard.lookup.graphIndex.bytes
	r.countNativeMetadata(-size)
	ref.shard.lookup.graphIndex = nil
	ref.size -= size
	r.residentBytes -= size
	if ref.query {
		r.activeBytes -= size
	}
	if ref.cache {
		r.cacheBytes -= size
	}
}

func (r *Release) canRetainGraph(ref *objectReference, bytes int) bool {
	return r.mayKeepNativeMetadata(bytes) && ref != nil && ref.query && ref.cache &&
		bytes <= PublicObjectDecoded-ref.size && bytes <= PublicCacheDecoded-r.cacheBytes && bytes <= PublicLiveDecoded-r.residentBytes
}

func (r *Release) chargeGraph(ref *objectReference, bytes int) {
	r.countNativeMetadata(bytes)
	ref.size += bytes
	r.residentBytes += bytes
	r.activeBytes += bytes
	r.cacheBytes += bytes
	ref.shard.lookup.graphIndex.bytes += bytes
}

func (g *pathGraph) bytes() int {
	return graphHeaderBytes + 12*cap(g.paths) + 8*cap(g.segments) + 4*cap(g.values) + 8*cap(g.pairs) + relationshipPositionBytes*cap(g.positions)
}

func (r *Release) pathGraph(s *Shard, asn uint32) *pathGraph {
	if s.lookup == nil {
		return nil
	}
	ref := s.lookup.owner
	if ref == nil || !ref.query {
		return nil
	}
	if s.disk != nil && s.components().active {
		return r.nativePathGraph(s, asn)
	}
	if !ref.cache {
		return nil
	}
	index := s.lookup.graphIndex
	if index == nil {
		if !r.canRetainGraph(ref, graphTableBytes) {
			return nil
		}
		index = new(pathGraphIndex)
		s.lookup.graphIndex = index
		r.chargeGraph(ref, graphTableBytes)
	}
	slot := &index.slots[asn%uint32(len(index.slots))]
	if slot.asn != asn {
		if slot.graph != nil {
			r.chargeGraph(ref, -slot.graph.bytes())
		}
		*slot = graphSlot{asn: asn}
		return nil
	}
	if slot.graph == nil {
		if !r.canRetainGraph(ref, graphHeaderBytes) {
			return nil
		}
		slot.graph = buildPathGraph(s, asn, func(size int) bool {
			if !r.canRetainGraph(ref, size) {
				return false
			}
			r.chargeGraph(ref, size)
			return true
		})
	}
	return slot.graph
}

// A prepared native release can retain independent per-origin numeric paths
// across source-row eviction. The map key always identifies the verified path
// object as well as the origin. No public answer aliases the cached arrays.
func (r *Release) nativePathGraph(s *Shard, asn uint32) *pathGraph {
	cache := s.components()
	key := s.componentKey(factPaths, asn, 0)
	if existing, ok := cache.get(key); ok {
		return existing.(*pathGraph)
	}
	graph := buildPathGraph(s, asn, func(size int) bool {
		total := componentEntryBytes + size
		return total <= nativeComponentEntryLimit && r.mayKeepNativeMetadata(total)
	})
	if graph != nil && cache.put(key, graph, graph.bytes()) {
		return graph
	}
	return nil
}

func buildPathGraph(s *Shard, asn uint32, reserve func(int) bool) *pathGraph {
	first, end, ok := s.asnBounds(asn)
	if !ok || end-first > 12 {
		return nil
	}
	const width = 24
	rows := s.rowSpan(3, first, end-first)
	nSegs, nASNs, maxPairs := 0, 0, 0
	for offset := 0; offset < len(rows); offset += width {
		row := rows[offset : offset+width]
		start := u32(row, 8)
		n := int(u16(row, 12))
		count := 0
		for i := 0; i < n; i++ {
			count += int(u32(s.row(9, start+uint32(i)), 8))
		}
		nSegs += n
		nASNs += count
		if row[14]&1 != 0 {
			maxPairs += max(0, count-1)
		}
	}
	size := graphHeaderBytes + 12*int(end-first) + 8*nSegs + 4*nASNs + 8*maxPairs
	if nASNs > PublicPathASNs || !reserve(size) {
		return nil
	}
	g := &pathGraph{paths: make([]graphPath, 0, end-first), segments: make([]graphSegment, 0, nSegs), values: make([]uint32, 0, nASNs), pairs: make([]uint64, 0, maxPairs)}
	for offset := 0; offset < len(rows); offset += width {
		row := rows[offset : offset+width]
		start := u32(row, 8)
		path := graphPath{first: uint32(len(g.values)), segments: u16(row, 12), visibility: row[15], eligible: row[14]&1 != 0}
		for i := 0; i < int(path.segments); i++ {
			seg := s.row(9, start+uint32(i))
			count := u32(seg, 8)
			ints := s.rowSpan(4, u32(seg, 4), count)
			g.segments = append(g.segments, graphSegment{count, seg[0]})
			for j := 0; j < int(count); j++ {
				g.values = append(g.values, u32(ints, j*4))
			}
		}
		values := g.values[path.first:]
		path.count = uint32(len(values))
		g.paths = append(g.paths, path)
		if path.eligible {
			g.pairs = appendPathPairs(g.pairs, values)
		}
	}
	slices.Sort(g.pairs)
	g.pairs = slices.Compact(g.pairs)
	return g
}

func appendPathPairs(pairs []uint64, values []uint32) []uint64 {
	for i := 1; i < len(values); i++ {
		if values[i-1] != values[i] {
			pairs = append(pairs, uint64(values[i-1])<<32|uint64(values[i]))
		}
	}
	return pairs
}

// If a budget would fail partway, the ordinary path decoder preserves the
// exact failing segment and all preceding complete paths.
func (g *pathGraph) fits(b *answerBudget) bool {
	return len(g.values) <= PublicPathASNs-b.paths && 16*len(g.values)+128*len(g.segments) <= PublicAnswerBytes-b.bytes
}

func (g *pathGraph) appendPaths(paths []PathAnswer, asn uint32, b *answerBudget) []PathAnswer {
	b.paths += len(g.values)
	b.bytes += 16*len(g.values) + 128*len(g.segments)
	paths = slices.Grow(paths, len(g.paths))
	segments := make([]SegmentAnswer, len(g.segments))
	n := len(g.values)
	values := make([]uint32, 2*n)
	copy(values, g.values)
	copy(values[n:], g.values)
	sj := 0
	for _, p := range g.paths {
		a, z := int(p.first), int(p.first+p.count)
		sz := sj + int(p.segments)
		path := PathAnswer{Origin: asn, ASNs: values[a:z:z], Visibility: []string{"unknown", "low", "medium", "high"}[p.visibility], GraphEligible: p.eligible, Segments: segments[sj:sz:sz]}
		pos := n + a
		for i, seg := range g.segments[sj:sz] {
			end := pos + int(seg.count)
			path.Segments[i] = SegmentAnswer{Type: []string{"", "sequence", "set", "confederation_sequence", "confederation_set"}[seg.kind], ASNs: values[pos:end:end]}
			pos = end
		}
		sj = sz
		paths = append(paths, path)
	}
	return paths
}
