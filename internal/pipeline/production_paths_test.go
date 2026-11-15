package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"sort"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func TestBulkPathsOneOriginLargeDuplicatesAndDistinctPopulation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	var binding [32]byte
	binding[0] = 1
	spool, err := newBulkSpool(root, time.Unix(1794096000, 0), binding, 512<<20, func() uint64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(spool.root)
	if err = spool.refresh(); err != nil {
		t.Fatal(err)
	}
	writer := spool.store.Writer(ctx)
	defer writer.Abort()
	appendPath := func(next uint32, family string, index int) error {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 0}), 24)
		return writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordPath, Path: &intelligence.ScopedPath{Prefix: prefix, Observation: intelligence.PathObservation{Origin: 13335, Family: family, Current: true, OriginOutward: true, Segments: []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{13335, next}}}}}})
	}
	for i := 0; i < 200000; i++ {
		if err = appendPath(15169, "one-family", i); err != nil {
			t.Fatal(err)
		}
	}
	const distinct = 100005
	expected := make([]uint32, 0, distinct)
	for i := 0; i < distinct; i++ {
		next := uint32(131072 + i)
		expected = append(expected, next)
		if err = appendPath(next, "one-family", i); err != nil {
			t.Fatal(err)
		}
	}
	for _, family := range []string{"family-two", "family-three", "family-four"} {
		if err = appendPath(200000, family, 1); err != nil {
			t.Fatal(err)
		}
	}
	spool.pathParts, err = writer.Finish()
	if err != nil {
		t.Fatal(err)
	}
	var paths []intelligence.Path
	if err = spool.reducePaths(ctx, nil, func(path intelligence.Path, rank uint16) error {
		if int(rank) != len(paths) {
			t.Fatal("rank sequence changed")
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 12 || paths[0].Segments[0].ASNs[1] != 200000 || paths[0].VisibilityBand != 3 {
		t.Fatalf("visibility or bounded selection changed: %d", len(paths))
	}
	expected = append(expected, 15169)
	sort.Slice(expected, func(i, j int) bool {
		var a, b [4]byte
		binary.LittleEndian.PutUint32(a[:], expected[i])
		binary.LittleEndian.PutUint32(b[:], expected[j])
		return bytes.Compare(a[:], b[:]) < 0
	})
	index := 0
	for _, path := range paths[1:] {
		for expected[index] == 200000 {
			index++
		}
		if path.Segments[0].ASNs[1] != expected[index] {
			t.Fatalf("canonical tie order changed: got %d want %d", path.Segments[0].ASNs[1], expected[index])
		}
		index++
		if path.VisibilityBand != 1 {
			t.Fatal("duplicates manufactured independent visibility")
		}
	}
	if spool.pathBytes != 0 {
		t.Fatal("path sort files survived reduction")
	}
}
