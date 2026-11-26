package pipeline

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func BenchmarkMixedGeographicLayoutReplay(b *testing.B) {
	ctx := context.Background()
	root := b.TempDir()
	clock := time.Unix(1795705800, 0).UTC()
	identity := [32]byte{1}
	limits := DefaultLimits()
	cache, err := openSpatialCache(ctx, root, identity, limits.ScratchBytes/4, func(uint64) bool { return true })
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = cache.Abort() })
	spool, err := newBulkSpool(root, clock, identity, limits.ScratchBytes, cache.DiskBytes)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = os.RemoveAll(spool.root) })
	spool.reuse = cache
	if err = spool.refresh(); err != nil {
		b.Fatal(err)
	}
	const geoRecords = 30000
	const nonGeoRecords = geoRecords / 6
	writer := spool.store.Writer(ctx)
	b.Cleanup(func() { _ = writer.Abort() })
	for i := range geoRecords {
		addr := [16]byte{0x20, 1, 0x0d, 0xb8}
		binary.BigEndian.PutUint32(addr[4:8], uint32(i))
		p := netip.PrefixFrom(netip.AddrFrom16(addr), 64)
		g := &intelligence.GeoEvidence{Prefix: p, Family: "geo", Weight: 95, PhysicalCountry: "US", Region: "Example Region", City: "Sample City", Current: true}
		if err = writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: g}); err != nil {
			b.Fatal(err)
		}
		if i%6 != 0 {
			continue
		}
		r := intelligence.NormalizedRecord{Version: 3}
		if i%12 == 0 {
			r.Kind, r.Origins = intelligence.RecordOrigins, &intelligence.OriginMapping{Prefix: p, Origins: []uint32{13335}}
		} else {
			r.Kind, r.NetworkName = intelligence.RecordNetworkName, &intelligence.NetworkNameRecord{Prefix: p, Name: "Sample-Network", ModifiedAt: clock}
		}
		if err = writer.Append(r); err != nil {
			b.Fatal(err)
		}
	}
	parts, err := spool.finish(writer)
	if err != nil {
		b.Fatal(err)
	}
	bucket := bulkBucket{prefix: netip.MustParsePrefix("2001:db8::/32"), parts: parts}
	source, err := spool.collect(ctx, &bucket, true)
	if err != nil {
		b.Fatal(err)
	}
	locationKey, err := spool.leafKey("location", &bucket, false, identity)
	if err != nil {
		b.Fatal(err)
	}
	if retained, err := cache.Retain(ctx, spatialCacheEntry{Domain: "location", Key: locationKey, Leaf: &spatialCacheLeaf{}}, nil); err != nil || !retained {
		b.Fatal("failed to retain location proof", err)
	}
	if err = spool.retainGeoLayout(ctx, &bucket, identity, source); err != nil {
		b.Fatal(err)
	}
	// This benchmark times only the optional load plus normal current collection.
	b.ReportAllocs()
	for b.Loop() {
		bucket.geoReplay, err = spool.loadGeoLayout(ctx, &bucket, identity)
		if err != nil || bucket.geoReplay == nil || bucket.geoReplay.entry.Leaf.GeoLayout.GeoRecords != geoRecords {
			b.Fatal("expected persisted geographic layout", err)
		}
		current, err := spool.collect(ctx, &bucket, true)
		if err != nil || len(current.Sources[0].Records) != nonGeoRecords {
			b.Fatal("current retained rows missing", err)
		}
		bucket.geoReplay = nil
	}
}
