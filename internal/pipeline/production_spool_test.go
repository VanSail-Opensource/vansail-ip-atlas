package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func spatialTestSpool(t *testing.T, prefixes ...string) (*bulkSpool, []*bulkBucket) {
	t.Helper()
	root := t.TempDir()
	clock := time.Unix(1794096000, 0).UTC()
	spool, err := newBulkSpool(root, clock, [32]byte{1}, DefaultLimits().ScratchBytes, func() uint64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	var records []intelligence.NormalizedRecord
	for _, prefix := range prefixes {
		records = append(records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Prefix: netip.MustParsePrefix(prefix), Family: "synthetic", PhysicalCountry: "US", Current: true, Weight: 70}})
	}
	state := intelligence.BuildState{Version: 1, PolicyHash: [32]byte{1}, EvaluatedAt: clock, Sources: []intelligence.StoredSource{{ID: "synthetic", Fingerprint: [32]byte{1}, ExpiresAt: clock.Add(time.Hour), Records: records}}}
	spatial, _, err := spool.seed(context.Background(), root, state)
	if err != nil {
		t.Fatal(err)
	}
	return spool, spatial
}

func TestBulkSpoolSkipsEmptySpatialLevelsAndPreservesRecords(t *testing.T) {
	for _, tc := range []struct {
		prefixes []string
		family   int
		scope    string
	}{
		{[]string{"8.8.8.0/24", "8.8.9.0/24"}, 0, "8.8.8.0/23"},
		{[]string{"8.8.8.8/32", "8.8.8.9/32"}, 0, "8.8.8.0/24"},
		{[]string{"2001:4860:1::/64", "2001:4860:2::/64"}, 1, "2001:4860::/46"},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			spool, roots := spatialTestSpool(t, tc.prefixes...)
			left, right, err := spool.split(context.Background(), roots[tc.family])
			if err != nil {
				t.Fatal(err)
			}
			child := left
			if len(child.parts) == 0 {
				child = right
			}
			if child.prefix.String() != tc.scope {
				t.Fatal("empty spatial chain retained or /24 boundary narrowed", child.prefix)
			}
			seen := map[string]bool{}
			if err = spool.walk(context.Background(), child.parts, func(record intelligence.NormalizedRecord) error { seen[record.Geo.Prefix.String()] = true; return nil }); err != nil {
				t.Fatal(err)
			}
			if len(seen) != len(tc.prefixes) {
				t.Fatal("spatial narrowing discarded observations")
			}
			for _, p := range tc.prefixes {
				if !seen[p] {
					t.Fatal("spatial narrowing changed a prefix")
				}
			}
		})
	}
}

func TestBulkSpoolBroadAncestorPreventsUnsafeNarrowing(t *testing.T) {
	spool, roots := spatialTestSpool(t, "8.0.0.0/8", "8.8.8.0/24")
	left, right, err := spool.split(context.Background(), roots[0])
	if err != nil {
		t.Fatal(err)
	}
	child := left
	if len(child.parts) == 0 {
		child = right
	}
	if child.prefix.String() != "8.0.0.0/8" {
		t.Fatal("descendant narrowed its ancestor", child.prefix)
	}
	left, right, err = spool.split(context.Background(), child)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []*bulkBucket{left, right} {
		if part.prefix.Bits() != 9 || len(part.parts) == 0 {
			t.Fatal("inherited ancestor disappeared from one child", part.prefix)
		}
		inherited := false
		if err = spool.walk(context.Background(), part.parts, func(record intelligence.NormalizedRecord) error {
			inherited = inherited || record.Geo.Prefix.String() == "8.0.0.0/8"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !inherited {
			t.Fatal("inherited ancestor lost")
		}
	}
}

func TestBulkSpatialScatterRetainsAdaptiveBinaryScopesAndPublicBytes(t *testing.T) {
	for _, prefix := range []string{"8.0.0.0/8", "2001:4860::/32"} {
		t.Run(prefix, func(t *testing.T) {
			t.Run("records", func(t *testing.T) { testBulkSpatialScatterParity(t, netip.MustParsePrefix(prefix), false) })
			t.Run("bytes", func(t *testing.T) { testBulkSpatialScatterParity(t, netip.MustParsePrefix(prefix), true) })
		})
	}
}

func testBulkSpatialScatterParity(t *testing.T, broad netip.Prefix, byteLimit bool) {
	t.Helper()
	state, policy, _, _, _ := intelligenceFixture(t)
	state.Sources = state.Sources[:1]
	state.Sources[0].Records = []intelligence.NormalizedRecord{
		{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Prefix: broad, Scope: intelligence.ExplicitPrefix, Family: "broad-risk", Signal: "abuse", Weight: 70, Current: true, SourcePublishedAt: state.EvaluatedAt}},
		{Version: 3, Kind: intelligence.RecordCoverage, Coverage: &intelligence.Coverage{Prefix: broad, Layer: intelligence.ExplicitPrefix, Family: "broad-risk", PublishedAt: state.EvaluatedAt, Current: true, Complete: true}},
	}
	for i := 0; i < 32; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{8, byte(i * 8), 0, 0}), 24)
		if broad.Addr().Is6() {
			address := broad.Addr().As16()
			address[4] = byte(i * 8)
			p = netip.PrefixFrom(netip.AddrFrom16(address), 48)
		}
		state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Prefix: p, Family: "synthetic", PhysicalCountry: "US", Weight: 70, Current: true}})
	}
	// Duplicate inherited rows must not change the fitting predicate or votes.
	state.Sources[0].Records = append(state.Sources[0].Records, state.Sources[0].Records[0])
	byteBudget := 0
	if byteLimit {
		left, right, err := bulkChildren(&bulkBucket{prefix: broad})
		if err != nil {
			t.Fatal(err)
		}
		for _, child := range []*bulkBucket{left, right} {
			seen := map[string]bool{}
			cost := 0
			for _, record := range state.Sources[0].Records {
				prefix, err := spatialPrefix(record)
				if err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				if !seen[string(data)] && (prefix.Contains(child.prefix.Addr()) || child.prefix.Contains(prefix.Addr())) {
					cost += 2*len(data) + 1024
					seen[string(data)] = true
				}
			}
			byteBudget = max(byteBudget, cost)
		}
	}
	var outputs [2][]string
	var scopes [2][]string
	for method := range outputs {
		root := t.TempDir()
		spool, err := newBulkSpool(root, state.EvaluatedAt, state.PolicyHash, DefaultLimits().ScratchBytes, func() uint64 { return 0 })
		if err != nil {
			t.Fatal(err)
		}
		spool.batchRecords = 20
		if byteLimit {
			spool.batchRecords, spool.batchBytes = 1000, byteBudget
		}
		roots, _, err := spool.seed(context.Background(), root, state)
		if err != nil {
			t.Fatal(err)
		}
		var walk func(*bulkBucket) error
		walk = func(bucket *bulkBucket) error {
			if len(bucket.parts) == 0 {
				return nil
			}
			part, err := spool.collect(context.Background(), bucket, false)
			if errors.Is(err, errBulkPartition) {
				var left, right *bulkBucket
				if method == 0 {
					left, right, err = spool.split(context.Background(), bucket)
				} else {
					left, right, err = spool.splitSpatial(context.Background(), bucket)
				}
				if err != nil {
					return err
				}
				if err = walk(left); err != nil {
					return err
				}
				return walk(right)
			}
			if err != nil {
				return err
			}
			scopes[method] = append(scopes[method], bucket.prefix.String())
			return IntelligenceProducer(part, policy, state.EvaluatedAt, MaterializationInputs{scope: bucket.prefix})(context.Background(), func(record via3.PublicRecord) error {
				data, err := json.Marshal(record)
				if err == nil {
					outputs[method] = append(outputs[method], string(data))
				}
				return err
			})
		}
		for _, root := range roots {
			if err = walk(root); err != nil {
				t.Fatal(err)
			}
		}
		sort.Strings(outputs[method])
	}
	first := netip.PrefixFrom(broad.Addr(), broad.Bits()+1).String()
	if len(scopes[0]) != 2 || len(scopes[1]) != 2 || scopes[0][0] != first || scopes[1][0] != scopes[0][0] || scopes[1][1] != scopes[0][1] {
		t.Fatal("scatter changed first-fitting binary scopes", scopes)
	}
	if len(outputs[0]) != len(outputs[1]) {
		t.Fatal("scatter changed public row population", len(outputs[0]), len(outputs[1]))
	}
	for i := range outputs[0] {
		if outputs[0][i] != outputs[1][i] {
			t.Fatal("scatter changed canonical public record bytes", i)
		}
	}
}

func TestBulkSpatialScatterHiddenChildrenSurviveFrontierGC(t *testing.T) {
	spool, roots := spatialTestSpool(t, "8.0.0.0/8", "8.8.0.0/24", "8.200.0.0/24")
	left, right, err := spool.splitSpatial(context.Background(), roots[0])
	if err != nil {
		t.Fatal(err)
	}
	child := left
	if len(child.parts) == 0 {
		child = right
	}
	left, right, err = spool.splitSpatial(context.Background(), child)
	if err != nil {
		t.Fatal(err)
	}
	if left.scattered[0] == nil || right.scattered[0] == nil {
		t.Fatal("scatter did not retain hidden adaptive children")
	}
	left.active = false
	if err = spool.gc(context.Background()); err != nil {
		t.Fatal(err)
	}
	var check func(*bulkBucket)
	check = func(node *bulkBucket) {
		if node == nil {
			return
		}
		if err := spool.walk(context.Background(), node.parts, func(intelligence.NormalizedRecord) error { return nil }); err != nil {
			t.Fatal("active group lost hidden child object", err)
		}
		for _, child := range node.scattered {
			check(child)
		}
	}
	check(right)
	part, err := spool.collect(context.Background(), right, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(part.Sources[0].Records) != 2 {
		t.Fatal("shared broad observations were dropped or counted repeatedly")
	}
}

func TestBulkSpatialScatterNarrowingRetainsInheritedSubtree(t *testing.T) {
	spool, roots := spatialTestSpool(t, "64.0.0.0/2", "64.1.0.0/24", "80.1.0.0/24", "96.1.0.0/24", "112.1.0.0/24")
	left, _, err := spool.splitSpatial(context.Background(), roots[0])
	if err != nil {
		t.Fatal(err)
	}
	if left.prefix.String() != "64.0.0.0/2" || left.scattered[0] == nil {
		t.Fatal("narrowing discarded the cached inherited subtree", left.prefix)
	}
	before := spool.store.DiskBytes()
	for _, child := range left.scattered {
		for _, terminal := range child.scattered {
			count := 0
			if err := spool.walk(context.Background(), terminal.parts, func(intelligence.NormalizedRecord) error {
				count++
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if count != 2 {
				t.Fatal("inherited observation multiplied within a terminal", count)
			}
		}
	}
	left, right, err := spool.splitSpatial(context.Background(), left)
	if err != nil {
		t.Fatal(err)
	}
	if left.prefix.Bits() != 3 || right.prefix.Bits() != 3 || spool.store.DiskBytes() != before {
		t.Fatal("cached subdivision rewrote inherited rows")
	}
}

type cancelOnSpoolPartial struct {
	context.Context
	root  string
	fired bool
}

func (c *cancelOnSpoolPartial) Err() error {
	if !c.fired {
		entries, _ := filepath.Glob(filepath.Join(c.root, ".atlas-private", "records-v2", "*.partial"))
		c.fired = len(entries) > 0
	}
	if c.fired {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestBulkSpatialScatterCancellationRemovesOpenWriters(t *testing.T) {
	spool, roots := spatialTestSpool(t, "8.0.0.0/8", "8.8.0.0/24", "8.200.0.0/24")
	ctx := &cancelOnSpoolPartial{Context: context.Background(), root: spool.root}
	if _, _, err := spool.splitSpatial(ctx, roots[0]); !errors.Is(err, context.Canceled) || !ctx.fired {
		t.Fatal("scatter did not cancel after writers opened", err)
	}
	entries, err := os.ReadDir(filepath.Join(spool.root, ".atlas-private", "records-v2"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".partial" {
			t.Fatal("canceled scatter left an open writer")
		}
	}
	if err = spool.walk(context.Background(), roots[0].parts, func(intelligence.NormalizedRecord) error { return nil }); err != nil {
		t.Fatal("cancellation removed the active parent", err)
	}
}

func TestBulkSpatialScatterWritersShareScratchBudget(t *testing.T) {
	spool, roots := spatialTestSpool(t, "0.0.0.0/0")
	const externalBytes = uint64(1 << 20)
	capacity := uint64(intelligence.DefaultRecordStoreLimits().PartitionBytes)
	spool.maximum = capacity + externalBytes
	spool.external = func() uint64 { return externalBytes }
	// A sparse reservation leaves room for eight stream headers, not all16.
	// Every live writer must charge the same store before writing its bytes.
	padding := filepath.Join(spool.root, ".atlas-private", "records-v2", "reserved.records")
	file, err := os.OpenFile(padding, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = file.Truncate(int64(capacity - spool.store.DiskBytes() - 64))
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	if _, _, err = spool.splitSpatial(context.Background(), roots[0]); err == nil {
		t.Fatal("concurrent scatter writers exceeded the shared scratch budget")
	}
	if spool.store.DiskBytes()+externalBytes > spool.maximum || !roots[0].active {
		t.Fatal("failed scatter exceeded its budget or released its parent")
	}
	partials, err := filepath.Glob(filepath.Join(spool.root, ".atlas-private", "records-v2", "*.partial"))
	if err != nil || len(partials) != 0 {
		t.Fatal("budget failure retained open writers", partials, err)
	}
	if err = spool.walk(context.Background(), roots[0].parts, func(intelligence.NormalizedRecord) error { return nil }); err != nil {
		t.Fatal("budget failure damaged the active parent", err)
	}
}
