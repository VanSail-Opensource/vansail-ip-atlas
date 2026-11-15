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
