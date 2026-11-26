package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// This optional reuse envelope is deliberately smaller than source admission.
// Very fragmented or inline inputs keep the existing coalesced cold path rather
// than multiplying small category streams beyond the normalized-object budget.
const spatialCacheInputPartitions = 1024

func canReuseSpatialState(state intelligence.BuildState) bool {
	count := 0
	for _, source := range state.Sources {
		if len(source.Records) != 0 || len(source.RecordPartitions) == 0 {
			return false
		}
		count += len(source.RecordPartitions)
		if count > spatialCacheInputPartitions {
			return false
		}
	}
	return count > 0
}

func spatialReuseKey(domain string, value any) ([32]byte, error) {
	h := sha256.New()
	_, _ = h.Write([]byte("atlas-spatial-reuse-v1\x00" + domain + "\x00"))
	if err := json.NewEncoder(h).Encode(value); err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

type spatialDependencies struct {
	Policy                                 intelligence.Policy
	PolicyHash                             [32]byte
	Clock                                  time.Time
	Usage                                  asnUsageIndex
	Coverage                               []intelligence.RecordPartition
	VRPComplete                            bool
	RPKIObservedAt, RPKICoverageValidUntil time.Time
}

func (s *bulkSpool) leafKey(domain string, b *bulkBucket, coverage bool, dependencies [32]byte) ([32]byte, error) {
	return spatialReuseKey(domain, struct {
		Dependencies             [32]byte
		Prefix                   netip.Prefix
		First, Last              uint32
		ASN, Coverage            bool
		BatchBytes, BatchRecords int
		Parts                    []intelligence.RecordPartition
	}{dependencies, b.prefix, b.first, b.last, b.asn, coverage, s.batchBytes, s.batchRecords, b.parts})
}

func (s *bulkSpool) verifyParts(ctx context.Context, parts []intelligence.RecordPartition) error {
	return intelligence.VerifyStoredSourceObjects(ctx, s.root, intelligence.StoredSource{RecordPartitions: parts})
}

// Import verifies the ordinary immutable object. A later strict traversal can
// separately compare every stored frame with the writer's canonical encoding.
func (s *bulkSpool) importCachedGroups(ctx context.Context, groups [][]intelligence.RecordPartition) error {
	if s.reuse == nil {
		return errors.New("spatial cache is unavailable")
	}
	// Take an actual inventory before the batch. The store then reserves each
	// new object and verifies every imported or preexisting destination. No
	// writers, garbage collection or cache staging run during this batch.
	count := 0
	for _, parts := range groups {
		for _, part := range parts {
			if count%128 == 0 {
				if err := s.refresh(); err != nil {
					return err
				}
			}
			from, err := s.reuse.ObjectPath(part.SHA256)
			if err != nil {
				return err
			}
			if err := s.store.ImportPartition(ctx, from, part); err != nil {
				return err
			}
			count++
		}
	}
	if count == 0 {
		return ctx.Err()
	}
	if err := s.refresh(); err != nil {
		return err
	}
	return ctx.Err()
}

func (s *bulkSpool) cachePartFiles(groups ...[]intelligence.RecordPartition) map[[32]byte]string {
	files := make(map[[32]byte]string)
	for _, parts := range groups {
		for _, part := range parts {
			files[part.SHA256] = filepath.Join(s.root, ".atlas-private", "records-v2", hex.EncodeToString(part.SHA256[:])+".records")
		}
	}
	return files
}

// scatterGroupSize keeps independently reusable batches at the two family
// roots, where a source change is cheapest to isolate. Every deeper scope
// streams its ordered inputs through one writer per terminal. Keeping separate
// tails for every input at every four-bit descent multiplies small files while
// the first spatial pass retains all finished leaves for the second pass.
func scatterGroupSize(parent *bulkBucket, terminals, freeSlots int, reuse bool) int {
	n := len(parent.parts)
	if n == 0 || !reuse || parent.prefix.Bits() != 0 {
		return max(1, n)
	}
	// Budget the extra tail files across root groups against 1/32 of the
	// remaining slots. Under pressure, use one shared group, the minimum
	// necessary to scatter the input. Writers charge all actual files.
	groups := max(1, freeSlots/(32*terminals))
	return max(1, (n+groups-1)/groups)
}

func appendSourceEnd(ends []int, count int) []int {
	if count != 0 && (len(ends) == 0 || ends[len(ends)-1] != count) {
		return append(ends, count)
	}
	return ends
}

// At a family root, keep contiguous runs from unrelated sources together.
// Removing or replacing another source must not change their cache identity.
// Keep both the ordered input and the existing limit on scatter destinations.
func scatterInputGroups(parent *bulkBucket, terminals, freeSlots int, reuse bool) [][]intelligence.RecordPartition {
	n := len(parent.parts)
	if reuse && parent.prefix.Bits() == 0 && len(parent.sourceEnds) != 0 && parent.sourceEnds[len(parent.sourceEnds)-1] == n {
		const stableGroupSize = 32
		maxGroups := max(1, freeSlots/(32*terminals))
		groups := make([][]intelligence.RecordPartition, 0, min(maxGroups, len(parent.sourceEnds)))
		start := 0
		for _, end := range parent.sourceEnds {
			if end <= start || end > n {
				break
			}
			for start < end && len(groups) < maxGroups {
				next := min(end, start+stableGroupSize)
				groups = append(groups, parent.parts[start:next])
				start = next
			}
			if start != end {
				break
			}
		}
		if start == n {
			return groups
		}
	}
	size := scatterGroupSize(parent, terminals, freeSlots, reuse)
	groups := make([][]intelligence.RecordPartition, 0, (n+size-1)/size)
	for start := 0; start < n; start += size {
		groups = append(groups, parent.parts[start:min(n, start+size)])
	}
	return groups
}

func (s *bulkSpool) scatterTerminals(ctx context.Context, parent *bulkBucket, terminal []*bulkBucket) error {
	routes, err := newBulkScatterRoutes(parent.prefix, terminal)
	if err != nil {
		return err
	}
	groups := scatterInputGroups(parent, len(terminal), s.store.RemainingPartitionSlots(), s.reuse != nil)
	for _, parts := range groups {
		entry := spatialCacheEntry{Domain: "scatter", Scatter: &spatialCacheScatter{}}
		hit := false
		if s.reuse != nil {
			key, err := spatialReuseKey("scatter", struct {
				Prefix netip.Prefix
				Parts  []intelligence.RecordPartition
			}{parent.prefix, parts})
			if err != nil {
				return err
			}
			entry.Key = key
			cached, found, err := s.reuse.Lookup(ctx, "scatter", key)
			if err != nil {
				return err
			}
			if found {
				if err := s.verifyParts(ctx, parts); err != nil {
					return err
				}
				entry, hit = cached, true
			}
		}
		if !hit {
			var err error
			entry.Scatter.Terminals, err = s.scatterFresh(ctx, parts, terminal, routes)
			if err != nil {
				return err
			}
		}
		if len(entry.Scatter.Terminals) != len(terminal) {
			return errors.New("cached scatter terminal count differs")
		}
		var retained [][]intelligence.RecordPartition
		for i, value := range entry.Scatter.Terminals {
			if value.Prefix != terminal[i].prefix {
				return errors.New("cached scatter scope differs")
			}
			terminal[i].parts = append(terminal[i].parts, value.Parts...)
			if value.Cover.IsValid() {
				terminal[i].cover = bulkPrefixCover(terminal[i].cover, value.Cover)
			}
			retained = append(retained, value.Parts)
		}
		if hit {
			if err := s.importCachedGroups(ctx, retained); err != nil {
				return err
			}
		}
		if s.reuse != nil {
			if _, err := s.reuse.Retain(ctx, entry, s.cachePartFiles(retained...)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *bulkSpool) scatterFresh(ctx context.Context, parts []intelligence.RecordPartition, terminal []*bulkBucket, routes bulkScatterRoutes) ([]spatialCacheTerminal, error) {
	writers := make([]*intelligence.RecordWriter, len(terminal))
	values := make([]spatialCacheTerminal, len(terminal))
	for i, node := range terminal {
		writers[i] = s.store.Writer(ctx)
		defer writers[i].Abort()
		values[i].Prefix = node.prefix
	}
	if err := s.walkOwned(ctx, parts, func(record intelligence.NormalizedRecord, frame intelligence.CanonicalRecordFrame) error {
		prefix, err := spatialPrefix(record)
		if err != nil {
			return err
		}
		first, end := routes.overlapping(prefix)
		for i := first; i < end; i++ {
			value := &values[i]
			value.Cover = bulkPrefixCover(value.Cover, prefix)
			if frame.EncodedBytes() != 0 {
				err = frame.AppendTo(writers[i])
			} else {
				err = writers[i].Append(record)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	for i, writer := range writers {
		parts, err := s.finish(writer)
		if err != nil {
			return nil, err
		}
		values[i].Parts = parts
	}
	return values, nil
}
