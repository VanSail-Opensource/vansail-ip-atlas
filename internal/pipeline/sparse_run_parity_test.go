package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

// These public bytes are captured from the dense private-run implementation at
// 34ebd97fae5129c2c64ddb2c7a582baddc549b9e. The fixture uses baseline-stable APIs
// so the same test can independently run against that implementation.
type sparseRunParityGolden struct {
	Release, Manifest, Inventory, Answers string
	Files, SortRuns, Partitions           int64
	SortPeak, PartitionPeak               uint64
}

var sparseRunParityGoldens = map[string]sparseRunParityGolden{
	"count": {
		Release: "e88fa258330f656c5fb241b44023e2b33ce120d32ad9108314b62e3931d2f5bd", Manifest: "7fcd9874c41b1ed3c061052526a5998a28db6ab22a76d241338cce255c18b4bc",
		Inventory: "73c1a93d1a1b1d738e2b083557ae6122ff44c1113d51376126045a3b0e9e4c76", Answers: "fbf7510a505d535d41f68e183fd442980bedf151ffd1dc5d64d71671e6750784",
		Files: 138, SortRuns: 43, Partitions: 84, SortPeak: 8176, PartitionPeak: 15360,
	},
	"bytes": {
		Release: "6968f644a5d519894e4395cb4e1e202dffa8ed12238a3930758436d8780ff42d", Manifest: "7d59add09a44d266685c7cef481d515b5f4e4ea064dc6b72fc7c202bbfd7a406",
		Inventory: "16ab961a70b7f3363e0c514e1f4f2d59f75dce410e0b6eb89ab3dc514eba788c", Answers: "c39e2f5251e1032a13b02a05e3dc687c7de37680249024e894b2888fa8775d8a",
		Files: 154, SortRuns: 43, Partitions: 100, SortPeak: 8176, PartitionPeak: 9432,
	},
}

func sparseRunParityRows() []via3.PublicRecord {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	zero, positive, exactRisk := 0.0, 0.11, 0.2
	score, cone, no := uint8(11), uint32(1), false
	rows := []via3.PublicRecord{
		{Version: 3, Kind: 2, Prefix: prefix, Geo: &via3.GeoData{Country: "US", Region: "St. Louis", City: "Example City"}},
		{Version: 3, Kind: 3, Prefix: prefix, Coordinates: &via3.CoordinateData{Latitude: 10.125, Longitude: -20.125, Precision: 3}},
		{Version: 3, Kind: 4, Prefix: prefix, Network: &via3.NetworkData{Name: "Example Network", Organization: "Example", Origins: []uint32{13335, 13335}}},
		{Version: 3, Kind: 5, Prefix: prefix, Usage: &via3.UsageData{Type: 1, Assignment: 1, Anycast: &no, DirectedBroadcast: &no}},
		{Version: 3, Kind: 6, Prefix: netip.MustParsePrefix("203.0.113.1/32"), Exact: true, Quality: &via3.QualityData{Score: &score, Confidence: 2, Reasons: 1, Exact: &positive, Prefix: &zero, ASN: &zero, Neighbors: &zero}},
		{Version: 3, Kind: 7, Prefix: prefix, Profile: &via3.ProfileData{Cells: []via3.CellData{{Address: netip.MustParseAddr("203.0.113.1"), Usage: 1, Score: &score, Confidence: 2, Reasons: 1, ExactRisk: &exactRisk, AttachNetwork: true}}}},
		{Version: 3, Kind: 8, ASN: 13335, ASNAggregate: &via3.ASNData{Name: "Example Network", Country: "US", Risk: &zero, Confidence: 2, Prefixes: []netip.Prefix{prefix}, CustomerCone: &cone, NetworkClass: 2, Stability: 2}},
		{Version: 3, Kind: 9, Prefix: prefix, ASN: 13335, RPKI: &via3.RPKIData{Status: 1, MaximumLength: 24}},
		{Version: 3, Kind: 10, Prefix: prefix, Origins: &via3.OriginsData{ASNs: []uint32{13335}}},
		{Version: 3, Kind: 11, ASN: 13335, Path: &via3.PathData{GraphEligible: true, Visibility: 2, Segments: []via3.SegmentData{{Type: 1, ASNs: []uint32{13335, 3356}}}}},
		{Version: 3, Kind: 12, ASN: 13335, Relationship: &via3.RelationshipData{To: 3356, Relation: 1, Observed: true, Inferred: true}},
		{Version: 3, Kind: 13, ASN: 13335, Tier1: &via3.TierData{NetworkClass: 2, Stability: 2}},
		{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("11.0.0.0/8"), Geo: &via3.GeoData{Country: "US", City: "IPv4 Parent"}},
		{Version: 3, Kind: 3, Prefix: netip.MustParsePrefix("11.0.0.0/8"), Coordinates: &via3.CoordinateData{Latitude: 10, Longitude: 20, Precision: 3}},
		{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("2001:4860::/32"), Geo: &via3.GeoData{Country: "DE", City: "IPv6 Parent"}},
		{Version: 3, Kind: 3, Prefix: netip.MustParsePrefix("2001:4860::/32"), Coordinates: &via3.CoordinateData{Latitude: 30, Longitude: 40, Precision: 3}},
		{Version: 3, Kind: 3, Prefix: netip.MustParsePrefix("2001:4860:7::/48"), Coordinates: &via3.CoordinateData{Unknown: true}},
	}
	for i := 0; i < 128; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, 0, byte(i), 0}), 24)
		rows = append(rows,
			via3.PublicRecord{Version: 3, Kind: 2, Prefix: p, Geo: &via3.GeoData{Country: "US", City: fmt.Sprintf("IPv4 City %d", i)}},
			via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.PrefixFrom(p.Addr().Next(), 32), Exact: true, Geo: &via3.GeoData{Country: "FR", City: "Exact City"}},
			via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(fmt.Sprintf("2001:4860:%x::/48", i)), Geo: &via3.GeoData{Country: "US", City: fmt.Sprintf("IPv6 City %d", i)}},
		)
	}
	for i := 0; i < 256; i++ {
		var prefixes []netip.Prefix
		if i%2 == 0 {
			prefixes = []netip.Prefix{}
		}
		rows = append(rows, via3.PublicRecord{Version: 3, Kind: 8, ASN: 14000 + uint32(i), ASNAggregate: &via3.ASNData{Name: "Synthetic Network", Prefixes: prefixes}})
	}
	return append(rows, rows[0], rows[7], rows[14])
}

func sparseRunPublicInventory(t *testing.T, root string) (string, int64) {
	t.Helper()
	h := sha256.New()
	var files int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("nonregular public inventory entry")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s\x00%d\x00%s\n", filepath.ToSlash(relative), len(data), via3.Hash(data))
		files++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil)), files
}

func sparseRunPublicAnswers(t *testing.T, options Options) string {
	t.Helper()
	reader, err := via3.OpenRelease(options.Output, func() int64 { return options.Clock })
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	encoder := json.NewEncoder(h)
	for _, query := range []string{"203.0.113.1", "203.0.113.2", "11.0.63.1", "11.0.100.2", "11.128.0.1", "2001:4860:7::1", "2001:4860:70::1", "2001:4860:8000::1", "AS13335", "AS14000", "AS14001", "192.0.2.1"} {
		answer, err := reader.Lookup(context.Background(), query)
		if err != nil {
			t.Fatal(query, err)
		}
		if err = encoder.Encode(answer); err != nil {
			t.Fatal(err)
		}
	}
	profile, err := reader.ClassC(context.Background(), "203.0.113.1")
	if err != nil || profile == nil || len(profile.Cells) != 256 || profile.Cells[1].Score == nil || *profile.Cells[1].Score != 11 || profile.Cells[2].Score != nil || profile.AggregateScore == nil || *profile.AggregateScore != 11 {
		t.Fatal("scored and unknown Class-C cells changed", err)
	}
	if err = encoder.Encode(profile); err != nil {
		t.Fatal(err)
	}
	page, err := reader.Prefixes(context.Background(), "AS13335", 0)
	if err != nil || len(page.Prefixes) != 1 || page.Prefixes[0] != "203.0.113.0/24" {
		t.Fatal("ASN prefix page changed", err)
	}
	if err = encoder.Encode(page); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestSparseRunPublicReleaseParity(t *testing.T) {
	for _, mode := range []string{"count", "bytes"} {
		for _, reversed := range []bool{false, true} {
			name := fmt.Sprintf("%s/reversed=%t", mode, reversed)
			t.Run(name, func(t *testing.T) {
				rows := sparseRunParityRows()
				if reversed {
					slices.Reverse(rows)
				}
				options := testOptions(t)
				options.Limits.SortBytes = 8192
				options.Limits.PartitionRecords = 16
				options.Limits.PartitionBytes = 16384
				if mode == "bytes" {
					options.Limits.PartitionRecords = DefaultLimits().PartitionRecords
					options.Limits.PartitionBytes = 12288
				}
				candidate, err := Build(context.Background(), options, producer(rows))
				if err != nil {
					t.Fatal(err)
				}
				if candidate.Stats.InputRecords != int64(len(rows)) || candidate.Stats.UniqueRecords != int64(len(rows)-3) || candidate.Stats.SortRuns < 2 || candidate.Stats.Partitions < 2 {
					t.Fatal("fixture did not exercise merge, deduplication and partitioning")
				}
				inventory, files := sparseRunPublicInventory(t, options.Output)
				if files != int64(len(candidate.Manifest.Objects)+2) {
					t.Fatal("public inventory does not exactly match objects, manifest and pointer")
				}
				got := sparseRunParityGolden{candidate.Pointer.ReleaseID, candidate.Pointer.ManifestSHA256, inventory, sparseRunPublicAnswers(t, options), files, candidate.Stats.SortRuns, candidate.Stats.Partitions, candidate.Stats.SortBufferPeak, candidate.Stats.PartitionBufferPeak}
				if candidate.Pointer.FormatVersion != 3 || candidate.Pointer.ManifestPath != "/_atlas/releases/"+got.Release+"/manifest.json" {
					t.Fatal("immutable pointer shape changed")
				}
				want := sparseRunParityGoldens[mode]
				if reversed {
					want.SortPeak = 8163
				}
				if got != want {
					t.Fatalf("public release or original logical partitioning changed:\n got %+v\nwant %+v", got, want)
				}
				assertClean(t, options.Workspace)
			})
		}
	}
}

func sparseRunBoundaryRow(t *testing.T) (via3.PublicRecord, int64) {
	t.Helper()
	var prefixes []netip.Prefix
	for i := 0; i < 128; i++ {
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{11, 0, byte(i), 0}), 24))
	}
	row, err := normalize(via3.PublicRecord{Version: 3, Kind: 8, ASN: 13335, ASNAggregate: &via3.ASNData{Name: "Synthetic Network", Prefixes: prefixes}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(row)
	if err != nil || len(data) <= 1024 {
		t.Fatal("boundary fixture must exceed the minimum configurable record limit", err)
	}
	return row, int64(len(data))
}

func TestSparseRunRetainsOriginalRecordByteLimit(t *testing.T) {
	row, denseBytes := sparseRunBoundaryRow(t)
	for _, delta := range []int64{0, -1} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			options := testOptions(t)
			options.Limits.RecordBytes = denseBytes + delta
			options.Limits.SortBytes = denseBytes + 128
			options.Limits.PartitionBytes = denseBytes + 512
			candidate, err := Build(context.Background(), options, producer([]via3.PublicRecord{row}))
			if delta == 0 {
				if err != nil || candidate.Stats.SortBufferPeak != uint64(denseBytes+128) || candidate.Stats.PartitionBufferPeak != uint64(denseBytes+512) {
					t.Fatal("exact original byte boundary changed", err)
				}
			} else if err == nil {
				t.Fatal("sparse wire size admitted a record above the original byte ceiling")
			} else if _, statErr := os.Stat(options.Output); !os.IsNotExist(statErr) {
				t.Fatal("rejected record published output", statErr)
			}
		})
	}
}

func TestSparseRunRetainsOriginalSortByteBoundary(t *testing.T) {
	row, denseBytes := sparseRunBoundaryRow(t)
	var previous via3.Pointer
	for _, delta := range []int64{0, -1} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			options := testOptions(t)
			options.Limits.RecordBytes = denseBytes
			options.Limits.SortBytes = 2*(denseBytes+128) + delta
			options.Limits.PartitionBytes = denseBytes + 512
			candidate, err := Build(context.Background(), options, producer([]via3.PublicRecord{row, row}))
			if err != nil {
				t.Fatal(err)
			}
			wantRuns, wantPeak := int64(1), uint64(2*(denseBytes+128))
			if delta == -1 {
				wantRuns, wantPeak = 2, uint64(denseBytes+128)
				if candidate.Pointer != previous {
					t.Fatal("sort-run boundary changed deduplication or immutable output")
				}
			}
			if candidate.Stats.SortRuns != wantRuns || candidate.Stats.SortBufferPeak != wantPeak || candidate.Stats.InputRecords != 2 || candidate.Stats.UniqueRecords != 1 {
				t.Fatal("sparse wire size changed the original sort boundary")
			}
			previous = candidate.Pointer
		})
	}
}

func TestSparseRunRetainsOriginalPartitionByteBoundary(t *testing.T) {
	row, denseBytes := sparseRunBoundaryRow(t)
	tier := via3.PublicRecord{Version: 3, Kind: 13, ASN: row.ASN, Tier1: &via3.TierData{}}
	data, err := json.Marshal(tier)
	if err != nil {
		t.Fatal(err)
	}
	logicalBytes := denseBytes + int64(len(data)) + 2*512
	for _, delta := range []int64{0, -1} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			options := testOptions(t)
			options.Limits.RecordBytes = denseBytes
			options.Limits.SortBytes = logicalBytes
			options.Limits.PartitionBytes = logicalBytes + delta
			candidate, err := Build(context.Background(), options, producer([]via3.PublicRecord{row, tier}))
			if delta == 0 {
				if err != nil || candidate.Stats.Partitions != 1 || candidate.Stats.PartitionBufferPeak != uint64(logicalBytes) {
					t.Fatal("exact original partition boundary changed", err)
				}
			} else if err == nil {
				t.Fatal("sparse wire size admitted an oversized indivisible ASN partition")
			} else if _, statErr := os.Stat(options.Output); !os.IsNotExist(statErr) {
				t.Fatal("rejected indivisible partition published output", statErr)
			}
		})
	}
}
