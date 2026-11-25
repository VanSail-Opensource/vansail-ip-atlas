package pipeline

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func TestRoutingSortReuseChecksInputsAndRanksWithCurrentRelations(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	contract := [32]byte{1}
	newSpool := func() *bulkSpool {
		t.Helper()
		s, err := newBulkSpool(root, time.Unix(1, 0), contract, DefaultLimits().ScratchBytes, func() uint64 { return 0 })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(s.root) })
		if err = s.refresh(); err != nil {
			t.Fatal(err)
		}
		s.reuse, err = openSpatialCache(ctx, root, contract, 32<<20, func(uint64) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.reuse.Abort() })
		writer := s.store.Writer(ctx)
		for _, next := range []uint32{15169, 13335} {
			path := intelligence.PathObservation{Current: true, OriginOutward: true, Origin: 32934, Family: "one", Segments: []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{32934, next}}}}
			if err = writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordPath, Path: &intelligence.ScopedPath{Prefix: netip.MustParsePrefix("8.8.8.0/24"), Observation: path}}); err != nil {
				t.Fatal(err)
			}
		}
		s.pathParts, err = writer.Finish()
		if err != nil {
			t.Fatal(err)
		}
		writer = s.store.Writer(ctx)
		for _, net := range []string{"2001:db8::/32", "8.8.8.0/24", "8.8.8.0/24"} {
			if err = writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix(net), Origins: []uint32{32934}}}); err != nil {
				t.Fatal(err)
			}
		}
		s.prefixParts, err = writer.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	run := func(s *bulkSpool, known uint32) ([]uint32, []netip.Prefix) {
		t.Helper()
		relations := intelligence.NewRelationships(true)
		if err := relations.Add(32934, known, intelligence.Peer); err != nil {
			t.Fatal(err)
		}
		if err := s.preparePrefixes(ctx); err != nil {
			t.Fatal(err)
		}
		defer s.prefixFile.Close()
		var prefixes []netip.Prefix
		present, err := s.providePrefixes(ctx, 32934, func(p netip.Prefix) error { prefixes = append(prefixes, p); return nil })
		if err != nil || !present {
			t.Fatal("prefix provider", err)
		}
		var order []uint32
		err = s.reducePaths(ctx, relations, func(p intelligence.Path, rank uint16) error { order = append(order, p.Segments[0].ASNs[1]); return nil })
		if err != nil {
			t.Fatal(err)
		}
		return order, prefixes
	}
	first := newSpool()
	a, p := run(first, 15169)
	if len(first.reuse.entries) != 2 {
		t.Fatal("both route streams must be retained")
	}
	if err := first.reuse.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.reuse.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	second := newSpool()
	parts := append([]intelligence.RecordPartition(nil), second.pathParts...)
	b, q := run(second, 13335)
	if !reflect.DeepEqual(a, []uint32{15169, 13335}) || !reflect.DeepEqual(b, []uint32{13335, 15169}) || !reflect.DeepEqual(p, q) || !reflect.DeepEqual(p, []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24"), netip.MustParsePrefix("2001:db8::/32")}) {
		t.Fatal("stale relation ranking or changed prefix index", a, b, p, q)
	}
	if err := second.reuse.Abort(); err != nil {
		t.Fatal(err)
	}
	third := newSpool()
	neverSort := func(func(bulkPathRow) error) error { return errors.New("unexpected sort") }
	path, err := third.sortRoutingRows(ctx, sortedPathsDomain, parts, neverSort)
	if err != nil || path == "" {
		t.Fatal("expected immutable reuse", err)
	}
	if err = third.removePathFile(path); err != nil {
		t.Fatal(err)
	}
	key, err := spatialReuseKey(sortedPathsDomain, parts)
	if err != nil {
		t.Fatal(err)
	}
	entry, hit, err := third.reuse.Lookup(ctx, sortedPathsDomain, key)
	if err != nil || !hit {
		t.Fatal("expected retained route stream", err)
	}
	for _, size := range []uint64{entry.Leaf.Stream.DecodedBytes - 1, entry.Leaf.Stream.DecodedBytes + 1} {
		wrong := entry.Leaf.Stream
		wrong.DecodedBytes = size
		if _, err := third.restoreRoutingSort(ctx, wrong); err == nil {
			t.Fatal("cached sort accepted a changed decoded length")
		}
	}
	different := append([]intelligence.RecordPartition(nil), parts...)
	different[0].Records++
	miss := errors.New("sort required")
	if _, err := third.sortRoutingRows(ctx, sortedPathsDomain, different, func(func(bulkPathRow) error) error { return miss }); !errors.Is(err, miss) {
		t.Fatal("changed input descriptor reused the sorted file", err)
	}
	for _, name := range third.cachePartFiles(parts) {
		if err = os.WriteFile(name, []byte("modified"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = third.sortRoutingRows(ctx, sortedPathsDomain, parts, neverSort); err == nil {
		t.Fatal("changed source partition authorized a sort hit")
	}
}

func TestSortedRoutingCacheRejectsInvalidStreamsAndLegacyDomain(t *testing.T) {
	valid := spatialCacheEntry{Domain: sortedPathsDomain, Key: [32]byte{1}, Leaf: &spatialCacheLeaf{Stream: spatialCacheStream{SHA256: [32]byte{2}, Records: 1, Bytes: 34, DecodedBytes: 120}}}
	if valid.matchesIndexVersion(3) || !valid.matchesIndexVersion(4) {
		t.Fatal("sorted routing domain schema mismatch")
	}
	for _, bad := range []func(*spatialCacheLeaf){func(l *spatialCacheLeaf) { l.Split = true }, func(l *spatialCacheLeaf) { l.Stream.Records++ }, func(l *spatialCacheLeaf) { l.Stream.DecodedBytes = sortedRoutingBytes + 1 }, func(l *spatialCacheLeaf) { l.Stream.SHA256 = [32]byte{} }} {
		entry := cloneSpatialEntry(valid)
		bad(entry.Leaf)
		if _, err := spatialCacheFiles(entry); err == nil {
			t.Fatal("invalid sorted routing stream retained")
		}
	}
}
