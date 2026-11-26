package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"

	"vansail-ip-atlas/internal/intelligence"
)

const geoLayoutDomain = "geo-layout"
const geoLayoutRowBytes = 21
const geoLayoutMinSkipped = 1024

// A fitted, fully validated ordinary leaf produced this projection of its
// deduplicated raw input, before any generated role or coverage joins. The key
// binds the exact ordered normalized parts, scope, policy and fit limits. Both
// the omitted geographic votes and the retained records keep their exact cost.
type geoLayout struct {
	Parts, Boundaries         int
	GeoRecords, GeoCharge     int
	OtherRecords, OtherCharge int
}

func (g *geoLayout) valid() bool {
	return g != nil && g.Parts > 0 && g.Parts <= 16384 &&
		g.GeoRecords >= geoLayoutMinSkipped && g.GeoRecords <= 100000 &&
		g.Boundaries > 0 && g.Boundaries <= g.GeoRecords &&
		g.OtherRecords >= 0 && g.OtherRecords <= 100000-g.GeoRecords &&
		g.GeoCharge >= 1024*g.GeoRecords && g.GeoCharge <= 96<<20 && g.GeoCharge%2 == 0 &&
		g.OtherCharge >= 1024*g.OtherRecords && g.OtherCharge <= (96<<20)-g.GeoCharge && g.OtherCharge%2 == 0 &&
		(g.OtherRecords != 0 || g.OtherCharge == 0)
}

func (g *geoLayout) streamSize() uint64 {
	return uint64(geoLayoutRowBytes*g.Boundaries + 4*g.OtherRecords + (g.OtherCharge-1024*g.OtherRecords)/2)
}

type geoLayoutBoundary struct {
	prefix netip.Prefix
	count  int
}

type geoLayoutRecord struct {
	record intelligence.NormalizedRecord
	size   int
	digest [32]byte
}

type geoLayoutReplay struct {
	entry      spatialCacheEntry
	boundaries []geoLayoutBoundary
	other      []geoLayoutRecord
}

func (s *bulkSpool) geoLayoutKey(b *bulkBucket, policy [32]byte) ([32]byte, error) {
	return s.leafKey(geoLayoutDomain, b, false, policy)
}

func (s *bulkSpool) retainExistingGeoLayout(ctx context.Context, b *bulkBucket, policy [32]byte) error {
	key, err := s.geoLayoutKey(b, policy)
	if err != nil {
		return err
	}
	entry, hit, err := s.reuse.Lookup(ctx, geoLayoutDomain, key)
	if err != nil || !hit {
		return err
	}
	_, err = s.reuse.Retain(ctx, entry, nil)
	return err
}

func (s *bulkSpool) loadGeoLayout(ctx context.Context, b *bulkBucket, policy [32]byte) (*geoLayoutReplay, error) {
	key, err := s.geoLayoutKey(b, policy)
	if err != nil {
		return nil, err
	}
	entry, hit, err := s.reuse.Lookup(ctx, geoLayoutDomain, key)
	if err != nil || !hit {
		return nil, err
	}
	// The value projection is an independent optional cache entry. Boundaries
	// alone cannot substitute for the missing validated geographic votes.
	location, err := s.leafKey("location", b, false, policy)
	if err != nil {
		return nil, err
	}
	if _, hit, err := s.reuse.Lookup(ctx, "location", location); err != nil || !hit {
		return nil, err
	}
	layout := entry.Leaf.GeoLayout
	if !layout.valid() || layout.Parts != len(b.parts) ||
		layout.GeoRecords+layout.OtherRecords > s.batchRecords || layout.GeoCharge+layout.OtherCharge > s.batchBytes {
		return nil, errSpatialCache
	}
	// The compiler separately completed the current strict normalized-source
	// walk when seeding. Still rehash every exact part at this derived boundary.
	if err := s.verifyParts(ctx, b.parts); err != nil {
		return nil, err
	}
	input, err := s.openSpatialStream(ctx, entry.Leaf.Stream)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	result := &geoLayoutReplay{
		entry: entry, boundaries: make([]geoLayoutBoundary, 0, layout.Boundaries),
		other: make([]geoLayoutRecord, 0, layout.OtherRecords),
	}
	var previous netip.Prefix
	var count int
	var row [geoLayoutRowBytes]byte
	for i := 0; i < layout.Boundaries; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(input.reader, row[:]); err != nil {
			return nil, err
		}
		address := netip.AddrFrom16([16]byte(row[:16]))
		if b.prefix.Addr().Is4() {
			address = address.Unmap()
		}
		prefix := netip.PrefixFrom(address, int(row[16]))
		n := int(binary.LittleEndian.Uint32(row[17:]))
		if !validSpatialPrefix(prefix) || !prefix.Overlaps(b.prefix) || n <= 0 || n > 8192 ||
			previous.IsValid() && !locationPrefixLess(previous, prefix) || n > layout.GeoRecords-count {
			return nil, errSpatialCache
		}
		previous, count = prefix, count+n
		result.boundaries = append(result.boundaries, geoLayoutBoundary{prefix, n})
	}
	remaining := (layout.OtherCharge - 1024*layout.OtherRecords) / 2
	seen := make(map[[32]byte]bool, layout.OtherRecords)
	for i := 0; i < layout.OtherRecords; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(input.reader, row[:4]); err != nil {
			return nil, err
		}
		size := int(binary.LittleEndian.Uint32(row[:4]))
		if size <= 0 || size > 1<<20 || size > remaining {
			return nil, errSpatialCache
		}
		data := make([]byte, size)
		if _, err = io.ReadFull(input.reader, data); err != nil {
			return nil, err
		}
		var r intelligence.NormalizedRecord
		if err := json.Unmarshal(data, &r); err != nil || r.Validate() != nil || r.Kind == intelligence.RecordGeo {
			return nil, errSpatialCache
		}
		canonical, err := json.Marshal(r)
		if err != nil || !bytes.Equal(data, canonical) {
			return nil, errSpatialCache
		}
		prefix, err := spatialPrefix(r)
		digest := sha256.Sum256(data)
		if err != nil || !prefix.Overlaps(b.prefix) || seen[digest] {
			return nil, errSpatialCache
		}
		seen[digest] = true
		remaining -= size
		result.other = append(result.other, geoLayoutRecord{r, size, digest})
	}
	if _, err := io.ReadFull(input.reader, row[:1]); err != io.EOF || count != layout.GeoRecords || remaining != 0 {
		return nil, errSpatialCache
	}
	if err := input.verify(); err != nil {
		return nil, err
	}
	return result, nil
}

// Stage a layout only after normal collection and successful materialization.
// The supplementary cache does not increase any product or scratch limit.
func (s *bulkSpool) retainGeoLayout(ctx context.Context, b *bulkBucket, policy [32]byte, state intelligence.BuildState) (returnErr error) {
	if b.geoReplay != nil {
		_, err := s.reuse.Retain(ctx, b.geoReplay.entry, nil)
		return err
	}
	if b.geoRawCount < geoLayoutMinSkipped || len(state.Sources) != 1 ||
		len(b.recordBytes) != len(state.Sources[0].Records) || b.geoRawCount > len(b.recordBytes) {
		return nil
	}
	locationKey, err := s.leafKey("location", b, false, policy)
	if err != nil {
		return err
	}
	if _, staged := s.reuse.entries[spatialCacheEntryKey{"location", locationKey}]; !staged {
		return nil
	}
	key, err := s.geoLayoutKey(b, policy)
	if err != nil {
		return err
	}
	layout := geoLayout{Parts: len(b.parts)}
	counts := make(map[netip.Prefix]int)
	raw := state.Sources[0].Records[:b.geoRawCount]
	for i, r := range raw {
		charge := 2*b.recordBytes[i] + 1024
		if r.Geo == nil {
			layout.OtherRecords++
			layout.OtherCharge += charge
			continue
		}
		prefix, err := canonicalMappingPrefix(r.Geo.Prefix)
		if err != nil || !r.Geo.Current || !prefix.Overlaps(b.prefix) {
			return errSpatialCache
		}
		counts[prefix]++
		layout.GeoRecords++
		layout.GeoCharge += charge
	}
	layout.Boundaries = len(counts)
	// Limit cold preparation cost. A geo-heavy leaf is the useful population.
	if layout.GeoRecords < geoLayoutMinSkipped || layout.OtherCharge > layout.GeoCharge/4 {
		return nil
	}
	if !layout.valid() {
		return errSpatialCache
	}
	prefixes := make([]netip.Prefix, 0, len(counts))
	for prefix := range counts {
		prefixes = append(prefixes, prefix)
	}
	sortPrefixes(prefixes)
	w, err := s.newSpatialStream(ctx)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, w.abort()) }()
	appendBytes := func(data []byte) error {
		if w.disabled {
			return nil
		}
		if _, err := w.writer.Write(data); err != nil {
			if errors.Is(err, errSpatialStreamCapacity) {
				return w.disable()
			}
			return err
		}
		w.decoded += uint64(len(data))
		return nil
	}
	var row [geoLayoutRowBytes]byte
	for _, p := range prefixes {
		address := p.Addr().As16()
		copy(row[:16], address[:])
		row[16] = uint8(p.Bits())
		binary.LittleEndian.PutUint32(row[17:], uint32(counts[p]))
		if err := appendBytes(row[:]); err != nil || w.disabled {
			return err
		}
		w.records++
	}
	for i, r := range raw {
		if r.Kind == intelligence.RecordGeo {
			continue
		}
		data, err := json.Marshal(r)
		if err != nil || len(data) != b.recordBytes[i] {
			return errSpatialCache
		}
		binary.LittleEndian.PutUint32(row[:4], uint32(len(data)))
		if err := appendBytes(row[:4]); err != nil || w.disabled {
			return err
		}
		if err := appendBytes(data); err != nil || w.disabled {
			return err
		}
		w.records++
	}
	stream, retained, err := w.finish()
	if err != nil || !retained {
		return err
	}
	entry := spatialCacheEntry{Domain: geoLayoutDomain, Key: key, Leaf: &spatialCacheLeaf{GeoLayout: &layout, Stream: stream}}
	_, err = s.reuse.Retain(ctx, entry, map[[32]byte]string{stream.SHA256: w.path})
	return err
}
