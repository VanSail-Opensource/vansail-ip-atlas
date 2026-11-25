package via3

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"testing"
)

func TestPackedPrefixSpansReturnOwnedLogicalPages(t *testing.T) {
	ctx := context.Background()
	asns := []uint32{13335, 15169}
	records := make([]PublicRecord, len(asns))
	want := make(map[uint32][]string)
	for index, asn := range asns {
		prefixes := make([]netip.Prefix, 2*prefixPageSize)
		for i := range prefixes {
			prefixes[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(index), byte(i >> 8), byte(i)}), 32)
			want[asn] = append(want[asn], prefixes[i].String())
		}
		records[index] = PublicRecord{Version: 3, Kind: 8, ASN: asn, ASNAggregate: &ASNData{Prefixes: prefixes}}
	}
	built, err := Build(ctx, CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: []PartitionInput{{Partition: "all", ASNRoutes: asns, Records: records}}})
	if err != nil {
		t.Fatal(err)
	}
	objects := make(map[string][]byte, len(built.Objects))
	for _, object := range built.Objects {
		objects[object.Info.SHA256] = object.Bytes
	}
	release, err := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(h string) ([]byte, error) { return objects[h], nil }, func() int64 { return 1700000000 })
	if err != nil {
		t.Fatal(err)
	}
	for repeat := 0; repeat < 2; repeat++ {
		for _, asn := range asns {
			q := "AS" + strconv.FormatUint(uint64(asn), 10)
			for _, page := range []int{1, 0} {
				answer, err := release.Prefixes(ctx, q, uint32(page))
				if err != nil || !slices.Equal(answer.Prefixes, want[asn][page*prefixPageSize:(page+1)*prefixPageSize]) {
					t.Fatalf("incorrect page %d for %s: %v", page, q, err)
				}
				answer.Prefixes[0] = "caller-owned value"
			}
			answer, err := release.Lookup(ctx, q)
			if err != nil || len(answer.ASNs) != 1 || !slices.Equal(answer.ASNs[0].Prefixes, want[asn][:prefixPageSize]) {
				t.Fatalf("incorrect first page for %s: %v", q, err)
			}
		}
	}
	installed := 0
	for _, ref := range release.references {
		if ref.shard != nil && ref.shard.lookup != nil {
			installed += len(ref.shard.lookup.prefixSpans)
		}
	}
	if installed != 4 {
		t.Fatalf("packed physical objects retained %d of four logical spans", installed)
	}
}

func TestPackedPrefixSpanChargesAndReleasesIndexStorage(t *testing.T) {
	shard := prefixMetadataPageFixture(t, 2*prefixPageSize)
	ref := &objectReference{shard: &shard}
	r := &Release{}
	base := decodedSize(&shard)
	if err := r.admitReference(ref, base); err != nil {
		t.Fatal(err)
	}
	r.cacheReference(ref)
	// Middle insertions, replacement, subset and partial-overlap lookups.
	cases := []struct {
		first  uint32
		labels []string
	}{{20, []string{"twenty"}}, {2, []string{"two", "three"}}, {10, []string{"ten"}}, {2, []string{"two", "three", "four"}}}
	for _, v := range cases {
		r.retainPrefixSpan(ref, v.first, v.labels)
		got := shard.cachedPrefixSpan(v.first, uint32(len(v.labels)))
		if !slices.Equal(got, v.labels) {
			t.Fatal("cached labels differ from requested span")
		}
		v.labels[0] = "mutated answer"
		if got[0] == v.labels[0] {
			t.Fatal("cached slice aliases returned answer")
		}
		want := prefixSpanHeaderBytes * cap(shard.lookup.prefixSpans)
		for _, span := range shard.lookup.prefixSpans {
			want += prefixSpanBytes(span.labels)
		}
		if ref.prefixLabelBytes != want || ref.size != base+want || r.cacheBytes != base+want || r.activeBytes != base+want || r.residentBytes != base+want {
			t.Fatalf("incorrect sparse metadata accounting: want %d", want)
		}
	}
	if got := shard.cachedPrefixSpan(3, 2); !slices.Equal(got, []string{"three", "four"}) {
		t.Fatal("lost contained span")
	}
	if shard.cachedPrefixSpan(4, 2) != nil {
		t.Fatal("cached partial span as complete")
	}
	before := ref.size
	r.cacheBytes = PublicCacheDecoded
	r.retainPrefixSpan(ref, 33, []string{"cannot fit"})
	if ref.size != before || shard.cachedPrefixSpan(33, 1) != nil {
		t.Fatal("optional index bypassed full cache")
	}
	r.cacheBytes = before
	r.releasePrefixMetadata(ref)
	if ref.prefixLabelBytes != 0 || ref.size != base || r.residentBytes != base || r.activeBytes != base || r.cacheBytes != base || shard.lookup.prefixSpans != nil {
		t.Fatal("metadata survived optional reclamation")
	}
	r.endQuery()
	r.evictReference(ref)
	if ref.shard != nil || r.residentBytes != 0 || r.cacheBytes != 0 {
		t.Fatal("evicted object retained its index")
	}
}
