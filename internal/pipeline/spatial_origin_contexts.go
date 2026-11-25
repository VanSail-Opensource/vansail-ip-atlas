package pipeline

import (
	"crypto/sha256"
	"encoding/json"

	"vansail-ip-atlas/internal/intelligence"
)

// Public spatial rows consult the global ASN risk context only through the
// origin mappings in their own collected input, including inherited routes.
// The leaf key independently binds every ordered input, the clock, policy,
// coverage and joined usage. The authenticated origin set includes ASNs with
// no current context so a later first observation also invalidates its leaf.
type leafOriginContexts struct {
	ASNDeltas []byte   `json:"a,omitempty"`
	Digest    [32]byte `json:"h"`
}

func newLeafOriginContexts(origins []uint32, contexts map[uint32]intelligence.ASNContext) (*leafOriginContexts, error) {
	if contexts == nil { // The engine would use locally derived ASN contexts.
		return nil, nil
	}
	digest, err := leafContextDigest(origins, contexts)
	if err != nil {
		return nil, err
	}
	return &leafOriginContexts{ASNDeltas: packASNDeltas(origins), Digest: digest}, nil
}

func (scope *leafOriginContexts) origins() ([]uint32, error) {
	if scope.Digest == ([32]byte{}) {
		return nil, errSpatialCache
	}
	asns, err := unpackASNDeltas(scope.ASNDeltas, maxMaterializationASNs)
	if err != nil {
		return nil, err
	}
	for _, asn := range asns {
		if !intelligence.IsPublicASN(asn) {
			return nil, errSpatialCache
		}
	}
	return asns, nil
}

func (scope *leafOriginContexts) matches(contexts map[uint32]intelligence.ASNContext) (bool, error) {
	if scope == nil || contexts == nil {
		return false, nil
	}
	asns, err := scope.origins()
	if err != nil {
		return false, err
	}
	digest, err := leafContextDigest(asns, contexts)
	return digest == scope.Digest, err
}

func leafContextDigest(asns []uint32, contexts map[uint32]intelligence.ASNContext) ([32]byte, error) {
	h := sha256.New()
	h.Write([]byte("atlas-public-leaf-origin-contexts-v1\x00"))
	encoder := json.NewEncoder(h)
	for _, asn := range asns {
		// The engine also returns a zero context for absent ASNs. Hash the
		// entire typed value one origin at a time within bounded memory.
		row := struct {
			ASN     uint32
			Context intelligence.ASNContext
		}{asn, contexts[asn]}
		if err := encoder.Encode(row); err != nil {
			return [32]byte{}, err
		}
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}
