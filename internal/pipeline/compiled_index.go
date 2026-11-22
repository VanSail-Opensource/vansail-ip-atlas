package pipeline

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"net/netip"

	"vansail-ip-atlas/internal/via3"
)

// Each route's object identity already appears in its authenticated subtree
// inventory. An override records the route's narrower scope when shared bytes
// have the inventory scope "all". Keep ordinals in the resident cache as well
// as on disk; expand only one requested or validated subtree at a time.
type compiledIndexEntry struct {
	Objects []via3.ObjectInfo     `json:"o,omitempty"` // signed version 2
	Table   *compiledIndexObjects `json:"t,omitempty"`
	Routes  []compiledIndexRoute  `json:"r"`
}

// Immutable object columns share the same ordinal. The complete SHA-256 bytes
// appear once per object, in the compiler's original digest order.
type compiledIndexObjects struct {
	Hashes []byte   `json:"h"`
	Sizes  []int    `json:"b"`
	Kinds  []byte   `json:"k"`
	Scopes []string `json:"s"`
}

func packCompiledObjects(objects []via3.ObjectInfo) *compiledIndexObjects {
	n := len(objects)
	table := &compiledIndexObjects{
		Hashes: make([]byte, n*sha256.Size),
		Sizes:  make([]int, n),
		Kinds:  make([]byte, n),
		Scopes: make([]string, n),
	}
	for i, object := range objects {
		// compiledPartitionFiles has already checked the full lowercase hash,
		// kind, byte count and scope, including the sorted nonduplicate order.
		_, _ = hex.Decode(table.Hashes[i*sha256.Size:(i+1)*sha256.Size], []byte(object.SHA256))
		table.Sizes[i], table.Kinds[i], table.Scopes[i] = object.Bytes, byte(object.Kind), object.Partition
	}
	return table
}

func (t *compiledIndexObjects) expand(maximum int) ([]via3.ObjectInfo, error) {
	n := len(t.Sizes)
	if n == 0 || n > maximum || len(t.Hashes) != n*sha256.Size || len(t.Kinds) != n || len(t.Scopes) != n {
		return nil, errSpatialCache
	}
	objects := make([]via3.ObjectInfo, n)
	for i := range objects {
		objects[i] = via3.ObjectInfo{
			Bytes:     t.Sizes[i],
			Kind:      uint16(t.Kinds[i]),
			Partition: t.Scopes[i],
			SHA256:    hex.EncodeToString(t.Hashes[i*sha256.Size : (i+1)*sha256.Size]),
		}
	}
	return objects, nil
}

type compiledIndexRoute struct {
	Prefix       netip.Prefix `json:"p,omitzero"`
	ASNDeltas    []byte       `json:"a,omitempty"`
	Destinations []uint16     `json:"d"`
	Scopes       []string     `json:"s,omitempty"`
}

// The caller owns and has validated entry's original shapes and object scopes.
func packCompiledIndex(entry *compiledPartitionEntry) *compiledIndexEntry {
	packed := &compiledIndexEntry{
		Table:  packCompiledObjects(entry.Objects),
		Routes: make([]compiledIndexRoute, len(entry.Routes)),
	}
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
	if len(packed.Routes) == 0 || len(packed.Routes) > limits.MaxObjects {
		return nil, errSpatialCache
	}
	objects := packed.Objects
	if packed.Table != nil {
		if objects != nil {
			return nil, errSpatialCache
		}
		var err error
		objects, err = packed.Table.expand(limits.MaxObjects)
		if err != nil {
			return nil, err
		}
	}
	if len(objects) == 0 || len(objects) > limits.MaxObjects {
		return nil, errSpatialCache
	}
	entry := &compiledPartitionEntry{Objects: objects, Routes: make([]compiledRoute, len(packed.Routes))}
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
			if int(id) >= len(objects) {
				return nil, errSpatialCache
			}
			d := objects[id]
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
	} else if e.Packed != nil && e.Packed.Objects != nil {
		// Upgrade an authenticated version-2 inventory before comparing it
		// with entries retained in this generation.
		p := *e.Packed
		p.Table = packCompiledObjects(p.Objects)
		p.Objects = nil
		e.Packed = &p
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

func (e spatialCacheEntry) matchesIndexVersion(version int) bool {
	if e.Domain != "compiled" {
		return e.Packed == nil && e.Compiled == nil
	}
	switch version {
	case 1:
		return e.Compiled != nil && e.Packed == nil
	case 2:
		return e.Compiled == nil && e.Packed != nil && e.Packed.Objects != nil && e.Packed.Table == nil
	case 3:
		return e.Compiled == nil && e.Packed != nil && e.Packed.Objects == nil && e.Packed.Table != nil
	}
	return false
}
