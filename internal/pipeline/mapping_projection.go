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

// The public mapping pass consumes only these record groups. Direct and
// generated Usage both reach the ordinary collection deduplicator first.
func mappingInputStream(kind intelligence.RecordKind) int {
	switch kind {
	case intelligence.RecordGeo, intelligence.RecordUsage:
		return 0
	case intelligence.RecordOrigins, intelligence.RecordNetworkOrganization, intelligence.RecordNetworkName:
		return 1
	default:
		return -1
	}
}

func (s *bulkSpool) semanticMappingKey(bucket *bulkBucket, policy [32]byte, stream int) ([32]byte, error) {
	if bucket.mappingInput[stream] == ([32]byte{}) {
		return [32]byte{}, nil
	}
	return spatialReuseKey("mapping-semantic-input", struct {
		Policy, Inputs                   [32]byte
		Prefix                           netip.Prefix
		Stream, BatchBytes, BatchRecords int
	}{policy, bucket.mappingInput[stream], bucket.prefix, stream, s.batchBytes, s.batchRecords})
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

// Project only clock-independent outputs from the mapping pass. The exact key
// binds the ordered physical inputs and joined usage. An optional alias binds
// precisely the ordered, deduplicated current records these kinds consume.
// Both attempts follow ordinary bounded collection and do not cache scores,
// RPKI or qualification. A full public hit can carry a linked alias using its
// authenticated physical entry, without collecting the same inputs twice.
func (s *bulkSpool) materializeMappings(ctx context.Context, bucket *bulkBucket, policy [32]byte, produce mappingProducerFactory, emit func(via3.PublicRecord) error) (returnErr error) {
	if s.reuse == nil || s.replaySink == nil {
		return produce(nil, true, true)(ctx, emit)
	}
	keys, err := s.mappingKeys(bucket, policy, bucket.originASNs)
	if err != nil {
		return err
	}
	var hits [2]bool
	var semantic [2][32]byte
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
		semantic[i], err = s.semanticMappingKey(bucket, policy, i)
		if err != nil {
			return err
		}
		entry, hit, err := s.reuse.Lookup(ctx, mappingDomain, key)
		if err != nil {
			return err
		}
		if hit && semantic[i] != ([32]byte{}) && entry.Leaf.MappingInput != ([32]byte{}) && entry.Leaf.MappingInput != semantic[i] {
			return errSpatialCache
		}
		if !hit && semantic[i] != ([32]byte{}) {
			entry, hit, err = s.reuse.Lookup(ctx, mappingDomain, semantic[i])
			if err != nil {
				return err
			}
			if hit && entry.Leaf.MappingInput != ([32]byte{}) {
				return errSpatialCache
			}
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
		entry.Key = key
		if semantic[i] != ([32]byte{}) {
			entry.Leaf.MappingInput = semantic[i]
		}
		if err := s.retainMappingStream(ctx, entry, nil); err != nil {
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
		entry := spatialCacheEntry{Domain: mappingDomain, Key: keys[i], Leaf: &spatialCacheLeaf{Stream: stream, MappingInput: semantic[i]}}
		if err := s.retainMappingStream(ctx, entry, files); err != nil {
			return err
		}
	}
	return nil
}

// Both cache entries refer to the same already verified immutable stream.
func (s *bulkSpool) retainMappingStream(ctx context.Context, entry spatialCacheEntry, files map[[32]byte]string) error {
	stream := entry.Leaf.Stream
	if files == nil && stream != (spatialCacheStream{}) {
		path, err := s.reuse.ObjectPath(stream.SHA256)
		if err != nil {
			return err
		}
		files = map[[32]byte]string{stream.SHA256: path}
	}
	if _, err := s.reuse.Retain(ctx, entry, files); err != nil {
		return err
	}
	if entry.Leaf.MappingInput != ([32]byte{}) {
		alias := spatialCacheEntry{Domain: mappingDomain, Key: entry.Leaf.MappingInput, Leaf: &spatialCacheLeaf{Stream: stream}}
		_, err := s.reuse.Retain(ctx, alias, files)
		return err
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
			if err := s.retainMappingStream(ctx, entry, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
