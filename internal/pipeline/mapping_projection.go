package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

const mappingDomain = "mapping"

type mappingProducerFactory func(locations *locationProjection, emitLocation, emitNetwork bool) Producer

func isMappingFact(kind uint16) bool { return kind >= 2 && kind <= 5 }

func mappingStreamIndex(kind uint16) int {
	if kind == 4 {
		return 1
	}
	return 0
}

func acceptsMappingFact(scope netip.Prefix, stream int, record via3.PublicRecord) bool {
	return isMappingFact(record.Kind) && mappingStreamIndex(record.Kind) == stream && !record.Exact && !record.Inherited && validSpatialPrefix(record.Prefix) &&
		(scope.Contains(record.Prefix.Addr()) || record.Prefix.Contains(scope.Addr()))
}

func (s *bulkSpool) mappingKeys(bucket *bulkBucket, policy [32]byte, origins []uint32) ([2][32]byte, error) {
	var keys [2][32]byte
	// Collect adds an unknown contextual row for otherwise unmatched origin
	// prefixes when the global join is enabled. Those unknown boundaries are
	// retained, so its enabled bit is necessary even for unrelated origins.
	h := sha256.New()
	h.Write([]byte("atlas-joined-mapping-usage-v1\x00"))
	h.Write(policy[:])
	if len(s.usage) != 0 && len(origins) != 0 {
		h.Write([]byte{1})
		encoder := json.NewEncoder(h)
		for _, asn := range origins {
			if rows := s.usage[asn]; len(rows) != 0 {
				kind := intelligence.FuseUsage(rows).Type
				if kind != "unknown" {
					row := struct {
						ASN  uint32
						Type string
					}{asn, kind}
					if err := encoder.Encode(row); err != nil {
						return keys, err
					}
				}
			}
		}
	} else {
		h.Write([]byte{0})
	}
	var dependencies [32]byte
	copy(dependencies[:], h.Sum(nil))
	key, err := s.leafKey("mapping-location", bucket, false, dependencies)
	if err != nil {
		return keys, err
	}
	keys[0] = key
	// Network facts depend only on original spatial records. A global role
	// update can never change their exact prefix, name, organization or origins.
	keys[1], err = s.leafKey("mapping-network", bucket, false, policy)
	return keys, err
}

// Project only clock-independent outputs from the mapping pass. The keys bind
// all ordered normalized records and any joined ASN usage consulted by each
// stream. The caller has already collected the current leaf under its normal
// resource limits, and still runs the current-clock scoring and RPKI passes.
func (s *bulkSpool) materializeMappings(ctx context.Context, bucket *bulkBucket, policy [32]byte, produce mappingProducerFactory, emit func(via3.PublicRecord) error) (returnErr error) {
	if s.reuse == nil || s.replaySink == nil {
		return produce(nil, true, true)(ctx, emit)
	}
	keys, err := s.mappingKeys(bucket, policy, bucket.originASNs)
	if err != nil {
		return err
	}
	var hits [2]bool
	var verified bool
	defer func() {
		for i, w := range s.mappingStreams {
			s.mappingStreams[i] = nil
			if w != nil {
				returnErr = errors.Join(returnErr, w.abort())
			}
		}
	}()
	for i, key := range keys {
		entry, hit, err := s.reuse.Lookup(ctx, mappingDomain, key)
		if err != nil {
			return err
		}
		hits[i] = hit
		if !hit {
			w, err := s.newSpatialStream(ctx)
			if err != nil {
				return err
			}
			// A verified replay is tapped by the new full-leaf stream, never
			// by its sibling because each tap accepts only its own kinds.
			s.mappingStreams[i] = w
			continue
		}
		if !verified {
			if err = s.verifyParts(ctx, bucket.parts); err != nil {
				return err
			}
			verified = true
		}
		stream := entry.Leaf.Stream
		if err = s.replayPublicMatching(ctx, stream, emit, func(record via3.PublicRecord) bool {
			return acceptsMappingFact(bucket.prefix, i, record)
		}); err != nil {
			return err
		}
		// The canonical compiler sink taps this into the new full-leaf stream,
		// but does not call the logical wrapper which increments publicRows.
		s.publicRows += stream.Records
		if _, err = s.reuse.Retain(ctx, entry, nil); err != nil {
			return err
		}
	}
	if hits[0] {
		if err := s.retainLocations(ctx, bucket, policy); err != nil {
			return err
		}
	}
	if hits[0] && hits[1] {
		return nil
	}
	var locations *locationProjection
	if !hits[0] {
		locations, err = s.openLocations(ctx, bucket, policy)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, locations.close()) }()
	}
	if err = produce(locations, !hits[0], !hits[1])(ctx, emit); err != nil {
		return err
	}
	if err = locations.finish(ctx); err != nil {
		return err
	}
	for i, writer := range s.mappingStreams {
		if writer == nil {
			continue
		}
		stream, retained, err := writer.finish()
		if err != nil {
			return err
		}
		if !retained {
			continue
		}
		files := map[[32]byte]string{}
		if stream != (spatialCacheStream{}) {
			files[stream.SHA256] = writer.path
		}
		entry := spatialCacheEntry{Domain: mappingDomain, Key: keys[i], Leaf: &spatialCacheLeaf{Stream: stream}}
		if _, err = s.reuse.Retain(ctx, entry, files); err != nil {
			return err
		}
	}
	return nil
}

func (s *bulkSpool) retainMappings(ctx context.Context, bucket *bulkBucket, policy [32]byte, origins []uint32) error {
	keys, err := s.mappingKeys(bucket, policy, origins)
	if err != nil {
		return err
	}
	for _, key := range keys {
		entry, hit, err := s.reuse.Lookup(ctx, mappingDomain, key)
		if err != nil {
			return err
		}
		if hit {
			if _, err := s.reuse.Retain(ctx, entry, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
