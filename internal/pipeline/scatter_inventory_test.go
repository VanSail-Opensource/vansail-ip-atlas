package pipeline

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// Every source partition has a different exact row in every /8. Keeping one
// private output per input at every descent would require 65*256 distinct
// terminal files, already above the 16,384-file store limit before ancestry.
func TestSpatialScatterKeepsDenseInputFrontierWithinInventory(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	contract := [32]byte{1}
	clock := time.Unix(1700000000, 0).UTC()
	spool, err := newBulkSpool(workspace, clock, contract, 1<<30, func() uint64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(spool.root)
	if err = spool.refresh(); err != nil {
		t.Fatal(err)
	}
	spool.reuse, err = openSpatialCache(ctx, workspace, contract, 64<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer spool.reuse.Abort()
	const inputs = 65
	spool.batchRecords = inputs
	root := &bulkBucket{prefix: netip.MustParsePrefix("::/0"), active: true}
	spool.all = append(spool.all, root)
	for i := 0; i < inputs; i++ {
		writer := spool.store.Writer(ctx)
		for key := 0; key < 256; key++ {
			address := netip.AddrFrom16([16]byte{byte(key), byte(i), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
			record := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Prefix: netip.PrefixFrom(address, 128), Family: "scatter-fixture", PhysicalCountry: "US", Current: true}}
			if err := writer.Append(record); err != nil {
				_ = writer.Abort()
				t.Fatal(err)
			}
		}
		parts, err := spool.finish(writer)
		if err != nil || len(parts) != 1 {
			t.Fatal("seed shape differs", len(parts), err)
		}
		root.parts = append(root.parts, parts...)
	}
	leaves, err := spool.leaves(ctx, []*bulkBucket{root}, false, func(bucket *bulkBucket, state intelligence.BuildState) error {
		if bucket.prefix.Bits() != 8 || len(state.Sources[0].Records) != inputs {
			t.Fatal("leaf population differs", bucket.prefix)
		}
		seen := [inputs]bool{}
		for _, record := range state.Sources[0].Records {
			address := record.Geo.Prefix.Addr()
			i := int(address.As16()[1])
			if !bucket.prefix.Contains(address) || i >= inputs || seen[i] {
				t.Fatal("duplicate or misplaced spatial record")
			}
			seen[i] = true
		}
		return nil
	})
	if err != nil || len(leaves) != 256 {
		t.Fatalf("full first-pass frontier did not fit: %d leaves, %v", len(leaves), err)
	}
	objects, err := os.ReadDir(filepath.Join(spool.root, ".atlas-private", "records-v2"))
	if err != nil || len(objects) != 256 {
		t.Fatal("expected one file per final scope", len(objects), err)
	}
}
