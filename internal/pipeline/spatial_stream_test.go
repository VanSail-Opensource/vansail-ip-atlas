package pipeline

import (
	"context"
	"io"
	"math"
	"net/netip"
	"os"
	"testing"
	"time"
)

func spatialReplayFixture(t *testing.T) (*bulkSpool, *spatialStreamWriter, spatialCacheStream) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	spool, err := newBulkSpool(root, time.Unix(1700000000, 0).UTC(), [32]byte{1}, DefaultLimits().ScratchBytes, func() uint64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(spool.root) })
	if err = spool.refresh(); err != nil {
		t.Fatal(err)
	}
	cache, err := openSpatialCache(ctx, root, [32]byte{2}, 256<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	spool.reuse = cache
	t.Cleanup(func() { _ = cache.Abort() })
	writer, err := spool.newSpatialStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.abort() })
	for i, risk := range []float64{0.1, 1e-17, 0.2, 0.9999999999999999, 0.00000000000003} {
		err = writer.appendRisk(spatialRiskEvent{Address: netip.AddrFrom4([4]byte{8, 8, 8, byte(i + 1)}), Risk: risk, Families: []string{"b", "a"}, Origins: []uint32{15169, 13335}})
		if err != nil {
			t.Fatal(err)
		}
	}
	stream, retained, err := writer.finish()
	if err != nil || !retained {
		t.Fatal("stream was not retained", err)
	}
	entry := spatialCacheEntry{Domain: "risk", Key: [32]byte{3}, Leaf: &spatialCacheLeaf{Stream: stream}}
	if retained, err = cache.Retain(ctx, entry, map[[32]byte]string{stream.SHA256: writer.path}); err != nil || !retained {
		t.Fatal("entry was not retained", err)
	}
	if err := cache.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cache.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cache.Abort(); err != nil {
		t.Fatal(err)
	}
	cache, err = openSpatialCache(ctx, root, [32]byte{2}, 256<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	spool.reuse = cache
	t.Cleanup(func() { _ = cache.Abort() })
	return spool, writer, stream
}

func TestSpatialRiskReplayPreservesExactEventAndFloatingOrder(t *testing.T) {
	spool, _, stream := spatialReplayFixture(t)
	var total float64
	count := 0
	err := spool.replayRisk(context.Background(), stream, func(event spatialRiskEvent) error {
		if event.Address != netip.AddrFrom4([4]byte{8, 8, 8, byte(count + 1)}) || len(event.Families) != 2 || event.Families[0] != "b" || event.Families[1] != "a" || len(event.Origins) != 2 || event.Origins[0] != 15169 || event.Origins[1] != 13335 {
			t.Fatal("event sequence or ordered members changed")
		}
		total += event.Risk
		count++
		return nil
	})
	var expected float64
	for _, risk := range []float64{0.1, 1e-17, 0.2, 0.9999999999999999, 0.00000000000003} {
		expected += risk
	}
	if err != nil || count != 5 || math.Float64bits(total) != math.Float64bits(expected) {
		t.Fatalf("ordered accumulation differs: %x/%x count=%d err=%v", math.Float64bits(total), math.Float64bits(expected), count, err)
	}
}

func TestSpatialReplayBindsActuallyConsumedObjectBytes(t *testing.T) {
	spool, writer, stream := spatialReplayFixture(t)
	ctx := context.Background()
	reader, err := spool.openSpatialStream(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	// Replace the cache object after opening with another internally valid
	// compressed stream. Per-frame CRC/SHA checks alone cannot bind that stream
	// to the authenticated generation's original object digest.
	other, err := spool.newSpatialStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer other.abort()
	if err = other.appendRisk(spatialRiskEvent{Address: netip.MustParseAddr("9.9.9.9"), Risk: 0.5, Families: []string{"changed"}, Origins: []uint32{13335}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = other.finish(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(other.path)
	if err != nil {
		t.Fatal(err)
	}
	path, err := spool.reuse.ObjectPath(stream.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, reader.reader)
	if readErr == nil && reader.verify() == nil {
		t.Fatal("changed stream passed actual-consumption integrity")
	}
	if writer.reserved == 0 {
		t.Fatal("fixture unexpectedly lost scratch accounting")
	}
}

func TestSpatialRiskEventRejectsNoncanonicalAndInvalidData(t *testing.T) {
	for _, data := range []string{
		`{"Address":"8.8.8.8","Risk":0.5,"Families":[],"Origins":[],"Risk":0.1}`,
		`{"Address":"8.8.8.8","Risk":0.5,"Families":[],"Origins":[],"Extra":1}`,
		`{"Address":"8.8.8.8","Risk":2,"Families":[],"Origins":[]}`,
		`{"Address":"8.8.8.8","Risk":0.5,"Families":[],"Origins":[0]}`,
	} {
		var event spatialRiskEvent
		if err := strictDecodeSpatialRisk([]byte(data), &event); err == nil {
			t.Fatal("invalid cached event accepted", data)
		}
	}
}
