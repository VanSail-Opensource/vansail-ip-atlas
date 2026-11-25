package via3

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"testing"
)

func TestNativePageDirectoriesMatchEverySortedKeyAndFallback(t *testing.T) {
	ctx := context.Background()
	v4 := netip.MustParsePrefix("203.0.0.0/16")
	v6 := netip.MustParsePrefix("2001:db8::/32")
	partition := PartitionInput{Partition: "all", PrefixRoutes: []netip.Prefix{v4, v6}}
	const n = 640
	for i := 0; i < n; i++ {
		asn := uint32(10000 + i)
		partition.ASNRoutes = append(partition.ASNRoutes, asn)
		v4ip := netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)})
		var address [16]byte
		copy(address[:], []byte{0x20, 1, 0x0d, 0xb8})
		address[14], address[15] = byte(i>>8), byte(i)
		partition.Records = append(partition.Records,
			PublicRecord{Version: 3, Kind: 2, Prefix: netip.PrefixFrom(v4ip, 32), Exact: true, Geo: &GeoData{Country: "CA"}},
			PublicRecord{Version: 3, Kind: 2, Prefix: netip.PrefixFrom(netip.AddrFrom16(address), 128), Exact: true, Geo: &GeoData{Country: "US"}},
			PublicRecord{Version: 3, Kind: 8, ASN: asn, ASNAggregate: &ASNData{Name: "Checked Owner"}},
			PublicRecord{Version: 3, Kind: 9, Prefix: v4, ASN: asn, RPKI: &RPKIData{Status: uint8(i%2 + 1), MaximumLength: 24, ObservedAt: 1699990000, ValidUntil: 1699993600}})
	}
	built, err := Build(ctx, CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: []PartitionInput{partition}})
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{}
	byKind := map[uint16]string{}
	for _, o := range built.Objects {
		objects[o.Info.SHA256] = o.Bytes
		byKind[o.Info.Kind] = o.Info.SHA256
	}
	open := func() *Release {
		r, e := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(h string) ([]byte, error) { return objects[h], nil }, func() int64 { return 1700000000 })
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	base, disk := open(), open()
	defer base.Close()
	defer disk.Close()
	if err := disk.PrepareNativeIndex(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []uint16{2, 8, 9} {
		want, e := base.object(ctx, byKind[kind])
		if e != nil {
			t.Fatal(e)
		}
		got, e := disk.object(ctx, byKind[kind])
		if e != nil {
			t.Fatal(e)
		}
		for _, fallback := range []bool{false, true} {
			if fallback {
				got.disk.asnFences = nil
				got.disk.prefixFences = [2][2][][16]byte{}
				got.disk.rpkiFences = [2][][20]byte{}
			}
			for i := -1; i <= n; i++ {
				asn := uint32(10000 + i)
				ip := netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)})
				switch kind {
				case 2:
					for _, addr := range []netip.Addr{ip, netip.AddrFrom16([16]byte{0x20, 1, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)})} {
						a, p, ok := want.findPrefix(addr)
						b, q, gotOK := got.findPrefix(addr)
						if !bytes.Equal(a, b) || p != q || ok != gotOK {
							t.Fatalf("prefix key %d fallback %t", i, fallback)
						}
					}
				case 8:
					a, ok := want.ASNRecord(asn)
					b, gotOK := got.ASNRecord(asn)
					if !bytes.Equal(a, b) || ok != gotOK {
						t.Fatalf("ASN key %d fallback %t", i, fallback)
					}
				case 9:
					a, ok := want.FindRPKI(ip, asn, v4)
					b, gotOK := got.FindRPKI(ip, asn, v4)
					if !bytes.Equal(a, b) || ok != gotOK {
						t.Fatalf("RPKI origin %d fallback %t", i, fallback)
					}
				}
			}
		}
	}
}

func TestNativePrefixSpellingsOwnMaximumPage(t *testing.T) {
	reader, want, _ := prefixPageOwnershipFixture(t)
	defer reader.Close()
	if err := reader.PrepareNativeIndex(context.Background(), t.TempDir()); err != nil {
		t.Fatal(err)
	}
	page, err := reader.Prefixes(context.Background(), "AS13335", 0)
	if err != nil || !slices.Equal(page.Prefixes, want) {
		t.Fatal("mixed-family indexed prefix page differs", err)
	}
	reader.Close()
	if !slices.Equal(page.Prefixes, want) {
		t.Fatal("lifetime of indexed spellings depends on an open reader")
	}
}

func TestReclaimingNativeSearchDirectoryRestoresLiveCapacity(t *testing.T) {
	index := &nativeIndex{fenceBytes: rowPageSize}
	pages := &nativePages{routerBytes: PublicCacheDecoded - rowPageSize, metadata: rowPageSize}
	index.pages = pages
	r := &Release{native: index, references: map[string]*objectReference{}}
	pages.owner = r
	pages.setMetadata(0)
	before := pages.live
	pages.reclaimOptional()
	if index.fenceBytes != 0 || pages.metadata != 0 || pages.live != before+1 {
		t.Fatal("optional search keys blocked a required private page")
	}
	pages.reclaimOptional()
	if pages.live != before+1 {
		t.Fatal("released optional search keys twice")
	}
}
