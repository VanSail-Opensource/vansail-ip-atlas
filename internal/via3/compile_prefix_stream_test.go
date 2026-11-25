package via3

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
)

func TestASNPrefixPagesPackManyOwnersWithinPagesFileBudget(t *testing.T) {
	for _, shape := range []struct {
		name           string
		asns, prefixes int
	}{{"twenty-thousand-small-ASNs", 20000, 1}, {"interleaved-owner-spans", 10, 20}} {
		t.Run(shape.name, func(t *testing.T) {
			asns := make([]uint32, shape.asns)
			records := make([]PublicRecord, shape.asns)
			prefixAt := func(asn, index int) netip.Prefix {
				value := shape.asns*index + shape.asns - 1 - asn
				return netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(value >> 16), byte(value >> 8), byte(value)}), 32)
			}
			for i := range asns {
				asns[i] = uint32(131072 + i)
				records[i] = PublicRecord{Version: 3, Kind: 8, ASN: asns[i], ASNAggregate: &ASNData{}}
			}
			provider := func(ctx context.Context, asn uint32, emit func(netip.Prefix) error) (bool, error) {
				for i := 0; i < shape.prefixes; i++ {
					if err := emit(prefixAt(int(asn-131072), i)); err != nil {
						return false, err
					}
				}
				return true, nil
			}
			input := CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: []PartitionInput{{Partition: "all", ASNRoutes: asns, Records: records, PrefixProvider: provider}}}
			built, err := Build(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if len(built.Objects) > (shape.asns*shape.prefixes+255)/256+2 {
				t.Fatalf("small ASN lists created per-owner files: %d", len(built.Objects))
			}
			objects := map[string][]byte{}
			for _, object := range built.Objects {
				objects[object.Info.SHA256] = object.Bytes
			}
			reader, err := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(hash string) ([]byte, error) { return objects[hash], nil }, func() int64 { return input.Clock })
			if err != nil {
				t.Fatal(err)
			}
			indexes := []int{0, shape.asns / 2, shape.asns - 1}
			for _, index := range indexes {
				cursor := uint32(0)
				seen := 0
				for {
					page, err := reader.Prefixes(context.Background(), fmt.Sprintf("AS%d", asns[index]), cursor)
					if err != nil {
						t.Fatal(err)
					}
					for _, prefix := range page.Prefixes {
						if prefix != prefixAt(index, seen).String() {
							t.Fatalf("owner %d offset/span lost prefix %d: %s", index, seen, prefix)
						}
						seen++
					}
					if page.NextCursor == nil {
						break
					}
					cursor = *page.NextCursor
				}
				if seen != shape.prefixes {
					t.Fatalf("owner prefix count %d/%d", seen, shape.prefixes)
				}
			}
		})
	}
}

func TestPackedPhysicalPrefixObjectsPreserveLogicalCursors(t *testing.T) {
	// The two owners interleave inside the second original 256-input batch.
	// One owner then continues across another full batch. The third owner
	// crosses both the physical object and packing window boundaries.
	prefix := func(n int) netip.Prefix {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(n >> 16), byte(n >> 8), byte(n)}), 32)
	}
	var first, second, long []netip.Prefix
	for i := 0; i < 400; i++ {
		first = append(first, prefix(2*i))
		second = append(second, prefix(513+2*i))
	}
	for i := 0; i < 9000; i++ {
		long = append(long, prefix(2000+i))
	}
	input := CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: []PartitionInput{{
		Partition: "all", ASNRoutes: []uint32{1, 2, 3}, Records: []PublicRecord{
			{Version: 3, Kind: 8, ASN: 1, ASNAggregate: &ASNData{Prefixes: first}},
			{Version: 3, Kind: 8, ASN: 2, ASNAggregate: &ASNData{Prefixes: second}},
			{Version: 3, Kind: 8, ASN: 3, ASNAggregate: &ASNData{Prefixes: long}},
		},
	}}}
	built, err := Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	objects := make(map[string][]byte)
	physical := 0
	for _, obj := range built.Objects {
		objects[obj.Info.SHA256] = obj.Bytes
		if rows := len(obj.Shard.RowsMust(11)) / 24; rows > 0 {
			physical++
			if rows > prefixObjectRows {
				t.Fatalf("physical page has %d rows", rows)
			}
		}
	}
	if physical > 8 {
		t.Fatalf("%d physical objects for 39 logical input batches", physical)
	}
	release, err := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(hash string) ([]byte, error) { return objects[hash], nil }, func() int64 { return input.Clock })
	if err != nil {
		t.Fatal(err)
	}
	check := func(asn string, prefixes []netip.Prefix, sizes []int) {
		t.Helper()
		seen := 0
		for cursor, size := range sizes {
			page, err := release.Prefixes(context.Background(), asn, uint32(cursor))
			if err != nil || len(page.Prefixes) != size {
				t.Fatalf("%s cursor %d: got %d prefixes, want %d: %v", asn, cursor, len(page.Prefixes), size, err)
			}
			for _, got := range page.Prefixes {
				if got != prefixes[seen].String() {
					t.Fatalf("%s prefix %d changed", asn, seen)
				}
				seen++
			}
			if cursor+1 == len(sizes) {
				if page.NextCursor != nil {
					t.Fatalf("%s has extra cursor", asn)
				}
			} else if page.NextCursor == nil || *page.NextCursor != uint32(cursor+1) {
				t.Fatalf("%s cursor %d is missing", asn, cursor+1)
			}
		}
		if seen != len(prefixes) {
			t.Fatalf("%s has only %d prefixes", asn, seen)
		}
	}
	singletons := make([]int, 112)
	for i := range singletons {
		singletons[i] = 1
	}
	check("AS1", first, append(append([]int{256}, singletons...), 32))
	check("AS2", second, append(append([]int{}, singletons...), 256, 32))
	sizes := []int{224}
	for rest := len(long) - 224; rest > 0; rest -= 256 {
		sizes = append(sizes, min(256, rest))
	}
	check("AS3", long, sizes)
}

func TestPackedPrefixSpansShareBoundariesAndRestoreOverlaps(t *testing.T) {
	key := func(n byte) []byte {
		return PrefixKey(netip.PrefixFrom(netip.AddrFrom4([4]byte{11, 0, 0, n}), 32), false, 0)[:24]
	}
	test := func(t *testing.T, starts []byte, wantObjects int) {
		var sizes []int
		p := prefixPagePacker{byASN: make(map[uint32][]prefixPageSpan), write: func(rows [][]byte) (BuiltObject, error) {
			s := newShard(8)
			s.set(11, Vector(24, rows...))
			sizes = append(sizes, len(rows))
			return BuiltObject{Shard: s}, nil
		}}
		for i, start := range starts {
			rows := [][]byte{key(start), key(start + 1)}
			p.window = append(p.window, prefixLogicalPage{rows: rows, spans: []prefixSpanPlacement{{asn: uint32(i + 1), rows: rows}}})
		}
		if err := p.writeWindow(); err != nil {
			t.Fatal(err)
		}
		if len(sizes) != wantObjects {
			t.Fatalf("got %d objects, want %d", len(sizes), wantObjects)
		}
		if wantObjects == 1 && sizes[0] != len(starts)+1 {
			t.Fatalf("shared boundaries consumed %d rows", sizes[0])
		}
		for i, start := range starts {
			spans := p.byASN[uint32(i+1)]
			if len(spans) != 1 || spans[0].count != 2 {
				t.Fatal("logical page size changed")
			}
			span := spans[0]
			rows := span.object.Shard.RowsMust(11)
			if keyCompare(rows[span.first*24:], key(start)) != 0 || keyCompare(rows[(span.first+1)*24:], key(start+1)) != 0 {
				t.Fatal("logical span changed")
			}
		}
	}
	t.Run("shared-boundaries", func(t *testing.T) { test(t, []byte{1, 2, 3, 4}, 1) })
	t.Run("overlapping-pages", func(t *testing.T) { test(t, []byte{1, 1, 1}, 3) })
}
