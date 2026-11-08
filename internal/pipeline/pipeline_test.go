package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func testOptions(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	limits := DefaultLimits()
	limits.RecordBytes = 2048
	limits.SortBytes = 4096
	limits.PartitionBytes = 8192
	limits.PartitionRecords = 6
	limits.MergeFanIn = 2
	return Options{Workspace: root, Output: filepath.Join(root, "build-private", "candidate"), Mode: "synthetic", Clock: 1794096000, ValidUntil: 1794099600, Limits: limits}
}
func producer(records []via3.PublicRecord) Producer {
	return func(ctx context.Context, emit func(via3.PublicRecord) error) error {
		for _, r := range records {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := emit(r); err != nil {
				return err
			}
		}
		return nil
	}
}
func fusedFixture() []via3.PublicRecord {
	parent := netip.MustParsePrefix("203.0.0.0/16")
	child := netip.MustParsePrefix("203.0.113.0/24")
	yes := true
	out := []via3.PublicRecord{
		{Version: 3, Kind: 2, Prefix: parent, Geo: &via3.GeoData{Country: "US", City: "Parent City"}},
		{Version: 3, Kind: 3, Prefix: parent, Coordinates: &via3.CoordinateData{Latitude: 10, Longitude: 20, Precision: 3}},
		{Version: 3, Kind: 2, Prefix: child, Geo: &via3.GeoData{Country: "US"}},
		{Version: 3, Kind: 3, Prefix: child, Coordinates: &via3.CoordinateData{Unknown: true}},
		{Version: 3, Kind: 5, Prefix: child, Usage: &via3.UsageData{Anycast: &yes}},
		{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("2001:db8::/32"), Geo: &via3.GeoData{Country: "DE"}},
		{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("2001:db8:1::/48"), Geo: &via3.GeoData{Country: "FR"}},
		{Version: 3, Kind: 8, ASN: 13335, ASNAggregate: &via3.ASNData{Name: "First Network"}},
		{Version: 3, Kind: 8, ASN: 15169, ASNAggregate: &via3.ASNData{Name: "Second Network"}},
	}
	for i := 0; i < 32; i++ {
		out = append(out, via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(fmt.Sprintf("203.0.%d.1/32", i)), Exact: true, Geo: &via3.GeoData{Country: "US", City: "Exact City"}})
	}
	return out
}

func TestExternalSortRepackInheritedTombstonesAndCanonicalRelease(t *testing.T) {
	records := fusedFixture()
	records = append(records, records[5], records[5])
	opts := testOptions(t)
	result, err := Build(context.Background(), opts, producer(records))
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.InputRecords != int64(len(records)) || result.Stats.UniqueRecords != int64(len(records)-2) || result.Stats.SortRuns < 2 || result.Stats.Partitions < 2 || !result.Stats.ProcessRSSMeasured || result.Stats.ProcessRSSPeak == 0 {
		t.Fatalf("missing streaming/resource evidence: %+v", result.Stats)
	}
	if result.Stats.SortBufferPeak > uint64(opts.Limits.SortBytes) || result.Stats.PartitionBufferPeak > uint64(opts.Limits.PartitionBytes) || result.Stats.ScratchPeak > opts.Limits.ScratchBytes {
		t.Fatal("compiler exceeded declared logical budgets")
	}
	reader, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		q, country, city string
		coordinate       bool
	}{{"203.0.112.2", "US", "Parent City", true}, {"203.0.113.1", "US", "", false}, {"203.0.31.1", "US", "Exact City", true}, {"2001:db8:1::2", "FR", "", false}, {"2001:db8:2::1", "DE", "", false}} {
		answer, err := reader.Lookup(context.Background(), tc.q)
		if err != nil {
			t.Fatal(tc.q, err)
		}
		if answer.Geo == nil || answer.Geo.Country == nil || *answer.Geo.Country != tc.country {
			t.Fatal("inherited country changed", tc.q, answer.Geo)
		}
		if tc.city == "" && answer.Geo.City != nil || tc.city != "" && (answer.Geo.City == nil || *answer.Geo.City != tc.city) {
			t.Fatal("tombstone or exact override changed", tc.q, answer.Geo)
		}
		if (answer.Geo.Latitude != nil) != tc.coordinate {
			t.Fatal("coordinate tombstone changed", tc.q, answer.Geo)
		}
	}
	for _, q := range []string{"AS13335", "AS15169"} {
		answer, err := reader.Lookup(context.Background(), q)
		if err != nil || len(answer.ASNs) != 1 || answer.ASNs[0].Name == nil {
			t.Fatal("ASN routing lost", q, err)
		}
	}
	second := testOptions(t)
	second.Limits.SortBytes = 8192
	slices.Reverse(records)
	again, err := Build(context.Background(), second, producer(records))
	if err != nil {
		t.Fatal(err)
	}
	if again.Pointer != result.Pointer {
		t.Fatal("record order or sort-run boundaries changed immutable release")
	}
	assertClean(t, opts.Workspace)
	assertClean(t, second.Workspace)
}

func assertClean(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, ".atlas-private"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("temporary runs survived completion/cancellation", entries)
	}
}
func TestConflictingFusedIdentityAndCancellationCleanScratch(t *testing.T) {
	base := via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("203.0.113.0/24"), Geo: &via3.GeoData{Country: "US"}}
	conflict := base
	conflict.Geo = &via3.GeoData{Country: "DE"}
	for _, test := range []struct {
		name    string
		produce Producer
	}{{"conflict", producer([]via3.PublicRecord{base, conflict})}, {"cancel", func(ctx context.Context, emit func(via3.PublicRecord) error) error {
		if err := emit(base); err != nil {
			return err
		}
		return context.Canceled
	}}} {
		t.Run(test.name, func(t *testing.T) {
			opts := testOptions(t)
			if _, err := Build(context.Background(), opts, test.produce); err == nil {
				t.Fatal("bad producer accepted")
			}
			if _, err := os.Stat(opts.Output); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed candidate published")
			}
			assertClean(t, opts.Workspace)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := testOptions(t)
	_, err := Build(ctx, opts, func(ctx context.Context, emit func(via3.PublicRecord) error) error {
		if err := emit(base); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("parent cancellation was not propagated", err)
	}
	assertClean(t, opts.Workspace)
}

func TestProductionGateBeforeWorkAndBeforeAtomicPublication(t *testing.T) {
	opts := testOptions(t)
	opts.Mode = "production"
	if _, err := Build(context.Background(), opts, producer(fusedFixture())); via3.ErrorCode(err) != "production_blocked" {
		t.Fatal("missing production gate accepted", err)
	}
	calls := 0
	opts.ProductionGate = func(context.Context) error {
		calls++
		if calls == 2 {
			return errors.New("approval withdrawn")
		}
		return nil
	}
	if _, err := Build(context.Background(), opts, producer(fusedFixture())); err == nil || calls != 2 {
		t.Fatal("withdrawn candidate published", err, calls)
	}
	if _, err := os.Stat(opts.Output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("output exists after gate withdrawal")
	}
	assertClean(t, opts.Workspace)
}

func TestScratchLimitAndIndivisibleASNFailWithoutTruncation(t *testing.T) {
	opts := testOptions(t)
	opts.Limits.ScratchBytes = 1024
	if _, err := Build(context.Background(), opts, producer(fusedFixture())); err == nil {
		t.Fatal("scratch ceiling ignored")
	}
	assertClean(t, opts.Workspace)
	opts = testOptions(t)
	opts.Limits.PartitionRecords = 1
	rows := []via3.PublicRecord{{Version: 3, Kind: 8, ASN: 13335, ASNAggregate: &via3.ASNData{Name: "Network"}}, {Version: 3, Kind: 13, ASN: 13335, Tier1: &via3.TierData{NetworkClass: 0, Stability: 0}}}
	if _, err := Build(context.Background(), opts, producer(rows)); err == nil {
		t.Fatal("single-ASN records silently truncated")
	}
	assertClean(t, opts.Workspace)
}

func TestProcessRSSAndPhysicalFreeSpaceGuardsAbortBeforePublication(t *testing.T) {
	for _, kind := range []string{"rss", "free-space"} {
		t.Run(kind, func(t *testing.T) {
			opts := testOptions(t)
			if kind == "rss" {
				opts.Limits.RSSBytes = 1
			} else {
				opts.Limits.MinimumFreeBytes = ^uint64(0)
			}
			if _, err := Build(context.Background(), opts, producer(fusedFixture())); err == nil {
				t.Fatal("resource abort was ignored")
			}
			if _, err := os.Stat(opts.Output); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("resource-failed candidate published")
			}
			assertClean(t, opts.Workspace)
		})
	}
}

func TestPrivateRunFramingAndPathGuards(t *testing.T) {
	opts := testOptions(t)
	opts.Output = filepath.Join(opts.Workspace, "web", "public", "atlas")
	if _, err := Build(context.Background(), opts, producer(fusedFixture())); err == nil {
		t.Fatal("public scratch destination accepted")
	}
	data, _ := json.Marshal(fusedFixture()[0])
	data = append(data, []byte(" {}")...)
	if _, err := decode(data); err == nil {
		t.Fatal("trailing run bytes accepted")
	}
	r := fusedFixture()[0]
	r.Inherited = true
	if _, err := normalize(r); err == nil {
		t.Fatal("caller forged inherited overlay")
	}
}

func TestPlannerRepacksActualCompressedBytesWithoutRecordCountTrigger(t *testing.T) {
	opts := testOptions(t)
	opts.Limits = DefaultLimits()
	opts.Limits.ObjectBytes = 1024
	var records []via3.PublicRecord
	for i := 0; i < 64; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("synthetic independent city %d", i)))
		records = append(records, via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(fmt.Sprintf("203.0.%d.0/24", i)), Geo: &via3.GeoData{Country: "US", City: hex.EncodeToString(sum[:])}})
	}
	result, err := Build(context.Background(), opts, producer(records))
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.BinaryByteRepacks == 0 || result.Stats.Partitions < 2 {
		t.Fatal("actual binary byte target did not trigger repacking", result.Stats)
	}
	for _, object := range result.Manifest.Objects {
		if object.Bytes > 1024 {
			t.Fatal("binary target exceeded", object)
		}
	}
}

func TestCanonicalUnorderedOriginsDeduplicateAndInputUnionIsBounded(t *testing.T) {
	opts := testOptions(t)
	one := via3.PublicRecord{Version: 3, Kind: 4, Prefix: netip.MustParsePrefix("203.0.113.0/24"), Network: &via3.NetworkData{Origins: []uint32{15169, 13335, 13335}}}
	two := one
	two.Network = &via3.NetworkData{Origins: []uint32{13335, 15169}}
	result, err := Build(context.Background(), opts, producer([]via3.PublicRecord{one, two}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.UniqueRecords != 1 {
		t.Fatal("semantically equal unordered facts did not dedupe")
	}
	bad := one
	bad.Geo = &via3.GeoData{}
	if _, err := normalize(bad); err == nil {
		t.Fatal("mismatched tagged union accepted")
	}
	bad = one
	bad.Network = &via3.NetworkData{Origins: make([]uint32, 4097)}
	if _, err := normalize(bad); err == nil {
		t.Fatal("huge origin vector reached JSON encoding")
	}
}
