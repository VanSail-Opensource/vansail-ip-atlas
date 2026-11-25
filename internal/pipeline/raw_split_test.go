package pipeline

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func TestRawSplitReusesOnlyExactCurrentObjectsAndGeometry(t *testing.T) {
	s, roots := spatialTestSpool(t, "8.8.8.0/24", "9.9.9.0/24", "11.0.0.0/8")
	b := roots[0]
	open := func() *spatialCache { return hostileOpenSpatial(t, s.root, 64<<20, func(uint64) bool { return true }) }
	s.reuse = open()
	s.batchRecords = 1
	if _, err := s.collectWithSplitProof(t.Context(), b, false); !errors.Is(err, errRawBulkPartition) {
		t.Fatal("raw records did not overflow", err)
	}
	key, err := s.leafKey(rawSplitDomain, b, false, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if _, hit, err := s.reuse.Lookup(t.Context(), rawSplitDomain, key); err != nil || !hit {
		t.Fatal("missing raw proof", err)
	}
	if err = s.reuse.Prepare(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.reuse.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.reuse.Abort(); err != nil {
		t.Fatal(err)
	}
	s.reuse = open()
	t.Cleanup(func() { _ = s.reuse.Abort() })
	s.clock = s.clock.Add(24 * time.Hour)
	s.usage = asnUsageIndex{13335: nil}
	if _, err := s.collectWithSplitProof(t.Context(), b, true); !errors.Is(err, errRawBulkPartition) {
		t.Fatal("clock and role changes lost raw split", err)
	}
	if len(s.reuse.entries) != 1 {
		t.Fatal("exact prior proof was not carried")
	}
	diff := *b
	diff.prefix = netip.MustParsePrefix("8.0.0.0/7")
	changed, err := s.leafKey(rawSplitDomain, &diff, false, [32]byte{})
	if err != nil || changed == key {
		t.Fatal("geometry not bound", err)
	}
	s.batchRecords = 10
	state, err := s.collectWithSplitProof(t.Context(), b, true)
	if err != nil || len(state.Sources[0].Records) != 3 {
		t.Fatal("a larger collection inherited a stale split", err)
	}
	s.batchRecords = 1
	var file string
	for _, p := range s.cachePartFiles(b.parts) {
		file = p
		break
	}
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err = os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.collectWithSplitProof(t.Context(), b, false); err == nil || errors.Is(err, errBulkPartition) {
		t.Fatal("changed bytes accepted a split proof", err)
	}
}

func TestRawSplitExcludesJoinedCoverageAndASNRoles(t *testing.T) {
	s, _ := spatialTestSpool(t, "8.0.0.0/8")
	put := func(row intelligence.NormalizedRecord) []intelligence.RecordPartition {
		writer := s.store.Writer(t.Context())
		defer writer.Abort()
		if err := writer.Append(row); err != nil {
			t.Fatal(err)
		}
		parts, err := s.finish(writer)
		if err != nil {
			t.Fatal(err)
		}
		return parts
	}
	prefix := netip.MustParsePrefix("8.0.0.0/8")
	origin := put(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: prefix, Origins: []uint32{13335}}})
	// The same record appears twice, so the physical estimate can exceed the
	// bound, while the raw deduplicated collection fits exactly.
	b := &bulkBucket{prefix: prefix, parts: append(append([]intelligence.RecordPartition{}, origin...), origin...)}
	s.batchRecords = 1
	s.reuse = hostileOpenSpatial(t, s.root, 64<<20, func(uint64) bool { return true })
	defer s.reuse.Abort()
	s.coverage = put(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordCoverage, Coverage: &intelligence.Coverage{Layer: intelligence.ASN, ASN: 13335, Family: "sample", PublishedAt: s.clock, Current: true, Complete: true}})
	for _, coverage := range []bool{true, false} {
		if !coverage {
			s.usage = asnUsageIndex{13335: nil}
		}
		if _, err := s.collectWithSplitProof(t.Context(), b, coverage); !errors.Is(err, errBulkPartition) || errors.Is(err, errRawBulkPartition) {
			t.Fatal("joined overflow was certified as raw", err)
		}
	}
	if len(s.reuse.entries) != 0 {
		t.Fatal("joined data created a raw split proof")
	}
	s.usage = nil
	state, err := s.collectWithSplitProof(t.Context(), b, false)
	if err != nil || len(state.Sources[0].Records) != 1 {
		t.Fatal("withdrawing joined data did not restore fitting bucket", err)
	}
}
