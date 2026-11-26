package pipeline

import (
	"context"
	"errors"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

type bulkLeafReuse struct {
	domain                string
	contexts              map[uint32]intelligence.ASNContext
	dependencies          [32]byte
	publicCore            [32]byte
	publicInvariant       [32]byte
	withoutRPKI           bool
	locationPolicy        [32]byte
	riskShape             [32]byte
	riskPolicy, riskInput [32]byte
	riskHit               *spatialCacheLeaf
	spool                 *bulkSpool
	public                func(via3.PublicRecord) error
	risk                  func(spatialRiskEvent) error
	writer                *spatialStreamWriter
}

func (r *bulkLeafReuse) recordRisk(event spatialRiskEvent) error {
	if r == nil || r.writer == nil {
		return nil
	}
	return r.writer.appendRisk(event)
}

func (r *bulkLeafReuse) begin(ctx context.Context) error {
	writer, err := r.spool.newSpatialStream(ctx)
	if err != nil {
		return err
	}
	r.writer = writer
	r.riskInput, r.riskHit = [32]byte{}, nil
	if r.domain == "public" {
		r.spool.publicRows = 0
		r.spool.publicStream = writer
	}
	return nil
}

func (r *bulkLeafReuse) finish(ctx context.Context, key, coreKey, invariantKey [32]byte, origins []uint32) (returnErr error) {
	writer := r.writer
	r.writer = nil
	r.spool.publicStream = nil
	defer func() { returnErr = errors.Join(returnErr, writer.abort()) }()
	var stream spatialCacheStream
	path := writer.path
	if r.riskHit != nil {
		stream = r.riskHit.Stream
		if stream != (spatialCacheStream{}) {
			var err error
			path, err = r.spool.reuse.ObjectPath(stream.SHA256)
			if err != nil {
				return err
			}
		}
	} else {
		var retained bool
		var err error
		stream, retained, err = writer.finish()
		if err != nil || !retained {
			return err
		}
	}
	if r.domain == "public" && writer.records != r.spool.publicRows {
		// A direct producer consumer without the compiler's post-validation tap
		// cannot create a reusable public stream. Its normal output still works.
		return nil
	}
	entry := spatialCacheEntry{Domain: r.domain, Key: key, Leaf: &spatialCacheLeaf{Stream: stream, RiskInput: r.riskInput}}
	if r.domain == "public" {
		scope, err := newLeafOriginContexts(origins, r.contexts)
		if err != nil {
			return err
		}
		entry.Leaf.OriginContexts = scope
	}
	files := map[[32]byte]string{}
	if stream != (spatialCacheStream{}) {
		files[stream.SHA256] = path
	}
	if err := r.retainRiskInput(ctx, entry, files); err != nil {
		return err
	}
	retained, err := r.spool.reuse.Retain(ctx, entry, files)
	if err != nil || !retained {
		return err
	}
	// Each alias authenticates the exact same checked stream. Both require
	// absent RPKI qualification, regardless of the original stream's rows.
	for _, alias := range []struct {
		domain string
		key    [32]byte
	}{{publicCoreDomain, coreKey}, {publicInvariantDomain, invariantKey}} {
		if alias.key != ([32]byte{}) {
			entry.Domain, entry.Key = alias.domain, alias.key
			if _, err := r.spool.reuse.Retain(ctx, entry, files); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *bulkLeafReuse) abort() error {
	r.spool.publicStream = nil
	if r.writer == nil {
		return nil
	}
	err := r.writer.abort()
	r.writer = nil
	return err
}

func (r *bulkLeafReuse) replay(ctx context.Context, stream spatialCacheStream) error {
	if r.domain == "public" {
		return r.spool.replayPublic(ctx, stream, r.public)
	}
	return r.spool.replayRisk(ctx, stream, r.risk)
}

const rawSplitDomain = "raw-split"
const riskShapeDomain = "risk-shape"
const publicCoreDomain = "public-core"
const publicInvariantDomain = "public-invariant"

// Small buckets take the normal collect path without a second cache lookup.
// Overlapping records can overstate this estimate. Only collect itself may
// certify that the distinct raw records actually overflow.
func (s *bulkSpool) mayOverflowRaw(parts []intelligence.RecordPartition) bool {
	var records, cost int64
	for _, p := range parts {
		size := p.DecodedBytes
		if p.Codec == "" {
			size = p.Bytes
		}
		records += int64(p.Records)
		cost += 2*size + 1024*int64(p.Records)
		if records > int64(s.batchRecords) || records > 100_000 || cost > int64(s.batchBytes) {
			return true
		}
	}
	return false
}

// Raw records are added and deduplicated before any optional role or coverage
// join. If they already overflow, every clock and role assignment must split
// this exact ordered input at the same geometry and working-set limits.
func (s *bulkSpool) collectWithSplitProof(ctx context.Context, b *bulkBucket, coverage bool) (intelligence.BuildState, error) {
	if s.reuse == nil || !s.mayOverflowRaw(b.parts) {
		return s.collect(ctx, b, coverage)
	}
	key, err := s.leafKey(rawSplitDomain, b, false, [32]byte{})
	if err != nil {
		return intelligence.BuildState{}, err
	}
	entry, hit, err := s.reuse.Lookup(ctx, rawSplitDomain, key)
	if err != nil {
		return intelligence.BuildState{}, err
	}
	if hit {
		if err := s.verifyParts(ctx, b.parts); err != nil {
			return intelligence.BuildState{}, err
		}
		if _, err := s.reuse.Retain(ctx, entry, nil); err != nil {
			return intelligence.BuildState{}, err
		}
		b.recordBytes = nil
		return intelligence.BuildState{}, errRawBulkPartition
	}
	state, err := s.collectRaw(ctx, b, coverage, errRawBulkPartition)
	if errors.Is(err, errRawBulkPartition) {
		entry = spatialCacheEntry{Domain: rawSplitDomain, Key: key, Leaf: &spatialCacheLeaf{Split: true}}
		if _, keepErr := s.reuse.Retain(ctx, entry, nil); keepErr != nil {
			return intelligence.BuildState{}, keepErr
		}
	}
	return state, err
}

func (s *bulkSpool) leavesReusing(ctx context.Context, roots []*bulkBucket, coverage bool, reuse *bulkLeafReuse, visit func(*bulkBucket, intelligence.BuildState) error) ([]*bulkBucket, error) {
	if reuse == nil || s.reuse == nil {
		return s.leaves(ctx, roots, coverage, visit)
	}
	var leaves []*bulkBucket
	var walk func(*bulkBucket) error
	walk = func(bucket *bulkBucket) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(bucket.parts) == 0 {
			return nil
		}
		key, err := s.leafKey(reuse.domain, bucket, coverage, reuse.dependencies)
		if err != nil {
			return err
		}
		var shapeKey [32]byte
		var coreKey [32]byte
		var invariantKey [32]byte
		if reuse.publicCore != ([32]byte{}) {
			coreKey, err = s.leafKey(publicCoreDomain, bucket, coverage, reuse.publicCore)
			if err != nil {
				return err
			}
		}
		var entry spatialCacheEntry
		var hit bool
		if reuse.riskShape != ([32]byte{}) {
			shapeKey, err = s.leafKey(riskShapeDomain, bucket, coverage, reuse.riskShape)
			if err != nil {
				return err
			}
			entry, hit, err = s.reuse.Lookup(ctx, riskShapeDomain, shapeKey)
			if err != nil {
				return err
			}
		}
		if !hit {
			entry, hit, err = s.reuse.Lookup(ctx, reuse.domain, key)
		}
		if err != nil {
			return err
		}
		coreHit := false
		if !hit && reuse.withoutRPKI && coreKey != ([32]byte{}) {
			entry, hit, err = s.reuse.Lookup(ctx, publicCoreDomain, coreKey)
			if err != nil {
				return err
			}
			coreHit = hit
		}
		if !hit && reuse.withoutRPKI && reuse.publicInvariant != ([32]byte{}) {
			invariantKey, err = s.leafKey(publicInvariantDomain, bucket, coverage, reuse.publicInvariant)
			if err != nil {
				return err
			}
			entry, hit, err = s.reuse.Lookup(ctx, publicInvariantDomain, invariantKey)
			if err != nil {
				return err
			}
			coreHit = hit
		}
		if hit && reuse.domain == "public" && !entry.Leaf.Split {
			hit, err = entry.Leaf.OriginContexts.matches(reuse.contexts)
			if err != nil {
				return err
			}
		}
		if hit {
			if err := s.verifyParts(ctx, bucket.parts); err != nil {
				return err
			}
			if coverage {
				if err := s.verifyParts(ctx, s.coverage); err != nil {
					return err
				}
			}
			if !entry.Leaf.Split {
				if coreHit {
					err = s.replayPublicFiltered(ctx, entry.Leaf.Stream, reuse.public, nil, true)
				} else {
					err = reuse.replay(ctx, entry.Leaf.Stream)
				}
				if err != nil {
					return err
				}
				if err := reuse.retainRiskInput(ctx, entry, nil); err != nil {
					return err
				}
				if _, err := s.reuse.Retain(ctx, entry, nil); err != nil {
					return err
				}
				if !coreHit && coreKey != ([32]byte{}) {
					if prior, found, err := s.reuse.Lookup(ctx, publicCoreDomain, coreKey); err != nil {
						return err
					} else if found {
						if _, err := s.reuse.Retain(ctx, prior, nil); err != nil {
							return err
						}
					}
				}
				if entry.Domain != publicInvariantDomain && reuse.publicInvariant != ([32]byte{}) {
					invariantKey, err = s.leafKey(publicInvariantDomain, bucket, coverage, reuse.publicInvariant)
					if err != nil {
						return err
					}
					if prior, found, err := s.reuse.Lookup(ctx, publicInvariantDomain, invariantKey); err != nil {
						return err
					} else if found {
						if _, err := s.reuse.Retain(ctx, prior, nil); err != nil {
							return err
						}
					}
				}
				if reuse.locationPolicy != ([32]byte{}) {
					if err := s.retainLocations(ctx, bucket, reuse.locationPolicy); err != nil {
						return err
					}
					if err := s.retainExistingGeoLayout(ctx, bucket, reuse.locationPolicy); err != nil {
						return err
					}
					origins, err := entry.Leaf.OriginContexts.origins()
					if err != nil {
						return err
					}
					if err := s.retainMappings(ctx, bucket, reuse.locationPolicy, origins); err != nil {
						return err
					}
				}
				leaves = append(leaves, bucket)
				return nil
			}
			if _, err := s.reuse.Retain(ctx, entry, nil); err != nil {
				return err
			}
		} else {
			if reuse.locationPolicy != ([32]byte{}) && s.replaySink != nil {
				bucket.geoCapture = true
				bucket.geoReplay, err = s.loadGeoLayout(ctx, bucket, reuse.locationPolicy)
				if err != nil {
					return err
				}
			}
			state, err := s.collectWithSplitProof(ctx, bucket, coverage)
			if err == nil {
				untimedScoring := bucket.geoReplay == nil && !bucket.timedScoring
				if err := reuse.begin(ctx); err != nil {
					return err
				}
				if err = visit(bucket, state); err != nil {
					return errors.Join(err, reuse.abort())
				}
				if bucket.geoCapture {
					if err := s.retainGeoLayout(ctx, bucket, reuse.locationPolicy, state); err != nil {
						return errors.Join(err, reuse.abort())
					}
				}
				bucket.recordBytes = nil
				bucket.geoReplay = nil
				if shapeKey != ([32]byte{}) && !bucket.riskExact {
					// A fully validated leaf without any exact observation cannot
					// produce a time-dependent event, even as the clock changes.
					if reuse.writer.records != 0 || reuse.riskHit != nil && reuse.riskHit.Stream != (spatialCacheStream{}) {
						return errors.Join(errSpatialCache, reuse.abort())
					}
					if err := reuse.abort(); err != nil {
						return err
					}
					if _, err := s.reuse.Retain(ctx, spatialCacheEntry{Domain: riskShapeDomain, Key: shapeKey, Leaf: &spatialCacheLeaf{}}, nil); err != nil {
						return err
					}
				} else {
					// A successful full collect proves this leaf has no dated risk
					// evidence or coverage. Current origin contexts and exact physical
					// input are still checked at replay. Clock-dependent RPKI
					// rows are never replayed across this alias.
					invariantKey = [32]byte{}
					if reuse.publicInvariant != ([32]byte{}) && untimedScoring {
						invariantKey, err = s.leafKey(publicInvariantDomain, bucket, coverage, reuse.publicInvariant)
						if err != nil {
							return errors.Join(err, reuse.abort())
						}
					}
					if err := reuse.finish(ctx, key, coreKey, invariantKey, bucket.originASNs); err != nil {
						return err
					}
				}
				bucket.originASNs = nil
				leaves = append(leaves, bucket)
				return nil
			}
			bucket.geoReplay = nil
			if !errors.Is(err, errBulkPartition) {
				return err
			}
			if !errors.Is(err, errRawBulkPartition) {
				domain := reuse.domain
				if shapeKey != ([32]byte{}) {
					domain, key = riskShapeDomain, shapeKey
				}
				entry = spatialCacheEntry{Domain: domain, Key: key, Leaf: &spatialCacheLeaf{Split: true}}
				if _, err := s.reuse.Retain(ctx, entry, nil); err != nil {
					return err
				}
			}
		}
		var left, right *bulkBucket
		if bucket.asn {
			left, right, err = s.split(ctx, bucket)
		} else {
			left, right, err = s.splitSpatial(ctx, bucket)
		}
		if err != nil {
			return err
		}
		if err = walk(left); err != nil {
			return err
		}
		return walk(right)
	}
	for _, root := range roots {
		if err := walk(root); err != nil {
			return nil, err
		}
	}
	return leaves, s.auditLogicalSplits(ctx)
}
