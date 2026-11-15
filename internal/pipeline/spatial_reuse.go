package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
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
	Contexts                               map[uint32]intelligence.ASNContext
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

// Cached normalized streams are imported as ordinary immutable objects. They
// never acquire the process-local canonical-frame capability of a live writer.
func (s *bulkSpool) importCachedParts(ctx context.Context, parts []intelligence.RecordPartition) error {
	if len(parts) == 0 {
		return ctx.Err()
	}
	if s.reuse == nil {
		return errors.New("spatial cache is unavailable")
	}
	if err := s.refresh(); err != nil {
		return err
	}
	for _, part := range parts {
		if err := ctx.Err(); err != nil {
			return err
		}
		from, err := s.reuse.ObjectPath(part.SHA256)
		if err != nil {
			return err
		}
		to := filepath.Join(s.root, ".atlas-private", "records-v2", hex.EncodeToString(part.SHA256[:])+".records")
		if _, err = os.Lstat(to); err == nil {
			continue // the full descriptor and actual bytes are verified below
		} else if !os.IsNotExist(err) {
			return err
		}
		used := s.external() + s.pathBytes + s.store.DiskBytes()
		if part.Bytes <= 0 || used >= s.maximum || uint64(part.Bytes) >= s.maximum-used {
			return errors.New("cached normalized objects exceed scratch budget")
		}
		if err = os.Link(from, to); err != nil {
			input, err := os.Open(from)
			if err != nil {
				return err
			}
			output, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				_ = input.Close()
				return err
			}
			n, copyErr := io.Copy(output, io.LimitReader(&cacheContextReader{ctx: ctx, r: input}, part.Bytes+1))
			err = errors.Join(copyErr, input.Close(), output.Close())
			if err != nil || n != part.Bytes {
				return errors.Join(err, errors.New("cached normalized object length differs"))
			}
		}
		// Refresh after each imported object so the next reservation includes it.
		if err := s.refresh(); err != nil {
			return err
		}
	}
	return s.verifyParts(ctx, parts)
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

func (s *bulkSpool) scatterTerminals(ctx context.Context, parent *bulkBucket, terminal []*bulkBucket) error {
	groups := [][]intelligence.RecordPartition{parent.parts}
	if s.reuse != nil {
		groups = make([][]intelligence.RecordPartition, len(parent.parts))
		for i, part := range parent.parts {
			groups[i] = []intelligence.RecordPartition{part}
		}
	}
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
			entry.Scatter.Terminals, err = s.scatterFresh(ctx, parts, terminal)
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
			if hit {
				if err := s.importCachedParts(ctx, value.Parts); err != nil {
					return err
				}
			}
			terminal[i].parts = append(terminal[i].parts, value.Parts...)
			if value.Cover.IsValid() {
				terminal[i].cover = bulkPrefixCover(terminal[i].cover, value.Cover)
			}
			retained = append(retained, value.Parts)
		}
		if s.reuse != nil {
			if _, err := s.reuse.Retain(ctx, entry, s.cachePartFiles(retained...)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *bulkSpool) scatterFresh(ctx context.Context, parts []intelligence.RecordPartition, terminal []*bulkBucket) ([]spatialCacheTerminal, error) {
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
		for i := range values {
			value := &values[i]
			if !prefix.Contains(value.Prefix.Addr()) && !value.Prefix.Contains(prefix.Addr()) {
				continue
			}
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
