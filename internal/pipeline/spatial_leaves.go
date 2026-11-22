package pipeline

import (
	"context"
	"errors"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

type bulkLeafReuse struct {
	domain         string
	dependencies   [32]byte
	locationPolicy [32]byte
	spool          *bulkSpool
	public         func(via3.PublicRecord) error
	risk           func(spatialRiskEvent) error
	writer         *spatialStreamWriter
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
	if r.domain == "public" {
		r.spool.publicRows = 0
		r.spool.publicStream = writer
	}
	return nil
}

func (r *bulkLeafReuse) finish(ctx context.Context, key [32]byte) (returnErr error) {
	writer := r.writer
	r.writer = nil
	r.spool.publicStream = nil
	defer func() { returnErr = errors.Join(returnErr, writer.abort()) }()
	stream, retained, err := writer.finish()
	if err != nil || !retained {
		return err
	}
	if r.domain == "public" && writer.records != r.spool.publicRows {
		// A direct producer consumer without the compiler's post-validation tap
		// cannot create a reusable public stream. Its normal output still works.
		return nil
	}
	entry := spatialCacheEntry{Domain: r.domain, Key: key, Leaf: &spatialCacheLeaf{Stream: stream}}
	files := map[[32]byte]string{}
	if stream != (spatialCacheStream{}) {
		files[stream.SHA256] = writer.path
	}
	_, err = r.spool.reuse.Retain(ctx, entry, files)
	return err
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
		entry, hit, err := s.reuse.Lookup(ctx, reuse.domain, key)
		if err != nil {
			return err
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
				if err := reuse.replay(ctx, entry.Leaf.Stream); err != nil {
					return err
				}
				if _, err := s.reuse.Retain(ctx, entry, nil); err != nil {
					return err
				}
				if reuse.locationPolicy != ([32]byte{}) {
					if err := s.retainLocations(ctx, bucket, reuse.locationPolicy); err != nil {
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
			state, err := s.collectWithSplitProof(ctx, bucket, coverage)
			if err == nil {
				if err := reuse.begin(ctx); err != nil {
					return err
				}
				if err = visit(bucket, state); err != nil {
					return errors.Join(err, reuse.abort())
				}
				bucket.recordBytes = nil
				if err := reuse.finish(ctx, key); err != nil {
					return err
				}
				leaves = append(leaves, bucket)
				return nil
			}
			if !errors.Is(err, errBulkPartition) {
				return err
			}
			if !errors.Is(err, errRawBulkPartition) {
				entry = spatialCacheEntry{Domain: reuse.domain, Key: key, Leaf: &spatialCacheLeaf{Split: true}}
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
