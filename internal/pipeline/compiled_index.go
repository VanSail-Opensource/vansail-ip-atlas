package pipeline

import (
	"encoding/binary"
	"math"
	"net/netip"

	"vansail-ip-atlas/internal/via3"
)

// Each route's object identity already appears in its authenticated subtree
// inventory. An override records the route's narrower scope when shared bytes
// have the inventory scope "all". Keep ordinals in the resident cache as well
// as on disk; expand only one requested or validated subtree at a time.
type compiledIndexEntry struct {
	Objects []via3.ObjectInfo    `json:"o"`
	Routes  []compiledIndexRoute `json:"r"`
}
type compiledIndexRoute struct {
	Prefix       netip.Prefix `json:"p,omitzero"`
	ASNDeltas    []byte       `json:"a,omitempty"`
	Destinations []uint16     `json:"d"`
	Scopes       []string     `json:"s,omitempty"`
}

// The caller owns and has validated entry's original shapes and object scopes.
func packCompiledIndex(entry *compiledPartitionEntry) *compiledIndexEntry {
	packed := &compiledIndexEntry{Objects: entry.Objects, Routes: make([]compiledIndexRoute, len(entry.Routes))}
	ordinals := make(map[string]uint16, len(entry.Objects))
	for i, object := range entry.Objects {
		ordinals[object.SHA256] = uint16(i)
	}
	for i, r := range entry.Routes {
		out := &packed.Routes[i]
		out.Prefix = r.Prefix
		var last uint32
		for _, asn := range r.ASNs {
			out.ASNDeltas = binary.AppendUvarint(out.ASNDeltas, uint64(asn-last))
			last = asn
		}
		out.Destinations = make([]uint16, len(r.Destinations))
		for j, d := range r.Destinations {
			id := ordinals[d.SHA256]
			out.Destinations[j] = id
			if d.Partition != entry.Objects[id].Partition {
				if out.Scopes == nil {
					out.Scopes = make([]string, len(r.Destinations))
				}
				out.Scopes[j] = d.Partition
			}
		}
	}
	return packed
}

// The ordinary route validator requires strictly increasing public ASNs. Bound
// the exact decoded allocation before interpreting their positive deltas.
func unpackCompiledASNs(encoded []byte, limit int) ([]uint32, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	if len(encoded) > 5*limit {
		return nil, errSpatialCache
	}
	count := 0
	for _, b := range encoded {
		if b < 0x80 {
			count++
		}
	}
	if count == 0 || count > limit {
		return nil, errSpatialCache
	}
	asns := make([]uint32, 0, count)
	var last uint32
	for len(encoded) != 0 {
		delta, n := binary.Uvarint(encoded)
		if n <= 0 || n > 5 || (n > 1 && encoded[n-1] == 0) || delta == 0 || delta > math.MaxUint32-uint64(last) {
			return nil, errSpatialCache
		}
		last += uint32(delta)
		asns = append(asns, last)
		encoded = encoded[n:]
	}
	return asns, nil
}

func (packed *compiledIndexEntry) expand() (*compiledPartitionEntry, error) {
	limits := DefaultLimits()
	if len(packed.Objects) == 0 || len(packed.Objects) > limits.MaxObjects || len(packed.Routes) == 0 || len(packed.Routes) > limits.MaxObjects {
		return nil, errSpatialCache
	}
	entry := &compiledPartitionEntry{Objects: packed.Objects, Routes: make([]compiledRoute, len(packed.Routes))}
	remainingASNs := via3.PublicObjectDecoded / 8
	for i, r := range packed.Routes {
		if len(r.Destinations) == 0 || len(r.Destinations) > 12 || r.Scopes != nil && len(r.Scopes) != len(r.Destinations) {
			return nil, errSpatialCache
		}
		out := &entry.Routes[i]
		asns, err := unpackCompiledASNs(r.ASNDeltas, min(limits.PartitionRecords, remainingASNs))
		if err != nil {
			return nil, err
		}
		remainingASNs -= len(asns)
		out.Prefix, out.ASNs = r.Prefix, asns
		out.Destinations = make([]via3.ObjectInfo, len(r.Destinations))
		override := false
		for j, id := range r.Destinations {
			if int(id) >= len(packed.Objects) {
				return nil, errSpatialCache
			}
			d := packed.Objects[id]
			if r.Scopes != nil && r.Scopes[j] != "" {
				if d.Partition != "all" || r.Scopes[j] == "all" {
					return nil, errSpatialCache
				}
				d.Partition = r.Scopes[j]
				override = true
			}
			out.Destinations[j] = d
		}
		if r.Scopes != nil && !override {
			return nil, errSpatialCache
		}
	}
	return entry, nil
}

func (e spatialCacheEntry) packed() spatialCacheEntry {
	if e.Compiled != nil {
		e.Packed = packCompiledIndex(e.Compiled)
		e.Compiled = nil
	}
	return e
}

func (e spatialCacheEntry) expanded() (spatialCacheEntry, error) {
	if e.Packed != nil {
		if e.Compiled != nil || e.Domain != "compiled" {
			return spatialCacheEntry{}, errSpatialCache
		}
		var err error
		e.Compiled, err = e.Packed.expand()
		if err != nil {
			return spatialCacheEntry{}, err
		}
		e.Packed = nil
	}
	return e, nil
}
