package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func groupedFactRows(count int) []via3.PublicRecord {
	var rows []via3.PublicRecord
	score, risk := uint8(17), 0.17
	for i := 0; i < count; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i >> 8), byte(i), 0}), 24)
		rows = append(rows,
			via3.PublicRecord{Version: 3, Kind: 2, Prefix: p, Geo: &via3.GeoData{Country: "US", City: fmt.Sprintf("Synthetic City %d", i%17)}},
			via3.PublicRecord{Version: 3, Kind: 3, Prefix: p, Coordinates: &via3.CoordinateData{Latitude: 1, Longitude: 2, Precision: 3}},
			via3.PublicRecord{Version: 3, Kind: 4, Prefix: p, Network: &via3.NetworkData{Origins: []uint32{13335}}},
			via3.PublicRecord{Version: 3, Kind: 5, Prefix: p, Usage: &via3.UsageData{Type: 4}},
			via3.PublicRecord{Version: 3, Kind: 6, Prefix: p, Quality: &via3.QualityData{Score: &score, Confidence: 1, Reasons: 1, Exact: &risk}},
			via3.PublicRecord{Version: 3, Kind: 7, Prefix: p, Profile: &via3.ProfileData{Cells: []via3.CellData{{Address: p.Addr(), Score: &score, Confidence: 1, Reasons: 1, ExactRisk: &risk, AttachNetwork: true}}}},
			via3.PublicRecord{Version: 3, Kind: 9, Prefix: p, ASN: 13335, RPKI: &via3.RPKIData{Status: 1, MaximumLength: 24, ObservedAt: 1794096000, ValidUntil: 1794099600}},
			via3.PublicRecord{Version: 3, Kind: 10, Prefix: p, Origins: &via3.OriginsData{ASNs: []uint32{13335}}})
	}
	return rows
}

func TestGroupedFactLookupMatchesUnpartitionedReference(t *testing.T) {
	rows := fusedFixture()
	parent, child := netip.MustParsePrefix("203.0.0.0/16"), netip.MustParsePrefix("203.0.113.0/24")
	score, risk := uint8(17), 0.17
	rows = append(rows,
		via3.PublicRecord{Version: 3, Kind: 4, Prefix: parent, Network: &via3.NetworkData{Origins: []uint32{13335, 15169}}},
		via3.PublicRecord{Version: 3, Kind: 4, Prefix: child, Network: &via3.NetworkData{Origins: []uint32{13335}}},
		via3.PublicRecord{Version: 3, Kind: 10, Prefix: parent, Origins: &via3.OriginsData{ASNs: []uint32{13335, 15169}}},
		via3.PublicRecord{Version: 3, Kind: 10, Prefix: child, Origins: &via3.OriginsData{ASNs: []uint32{13335}}},
		via3.PublicRecord{Version: 3, Kind: 6, Prefix: parent, Quality: &via3.QualityData{Score: &score, Confidence: 1, Reasons: 1, Exact: &risk}},
		via3.PublicRecord{Version: 3, Kind: 6, Prefix: child, Quality: &via3.QualityData{}},
		via3.PublicRecord{Version: 3, Kind: 7, Prefix: child, Profile: &via3.ProfileData{Cells: []via3.CellData{{Address: child.Addr(), AttachNetwork: true}}}},
		via3.PublicRecord{Version: 3, Kind: 9, Prefix: parent, ASN: 13335, RPKI: &via3.RPKIData{Status: 1, MaximumLength: 16, ObservedAt: 1794095000, ValidUntil: 1794095900}},
		via3.PublicRecord{Version: 3, Kind: 9, Prefix: parent, ASN: 15169, RPKI: &via3.RPKIData{Status: 2, ObservedAt: 1794095000, ValidUntil: 1794095900}},
		via3.PublicRecord{Version: 3, Kind: 11, ASN: 13335, Path: &via3.PathData{GraphEligible: true, Visibility: 2, Segments: []via3.SegmentData{{Type: 1, ASNs: []uint32{13335, 3356}}}}},
		via3.PublicRecord{Version: 3, Kind: 11, ASN: 3356, Path: &via3.PathData{GraphEligible: true, Visibility: 1, Segments: []via3.SegmentData{{Type: 1, ASNs: []uint32{3356, 174}}}}},
		via3.PublicRecord{Version: 3, Kind: 12, ASN: 13335, Relationship: &via3.RelationshipData{To: 3356, Relation: 1, Observed: true, Inferred: true}},
		via3.PublicRecord{Version: 3, Kind: 12, ASN: 3356, Relationship: &via3.RelationshipData{To: 174, Relation: 1, Observed: true, Inferred: true}},
		via3.PublicRecord{Version: 3, Kind: 13, ASN: 3356, Tier1: &via3.TierData{NetworkClass: 2, Stability: 2}})
	for i := 40; i < 56; i++ {
		p := netip.MustParsePrefix(fmt.Sprintf("203.0.%d.0/24", i))
		rows = append(rows, via3.PublicRecord{Version: 3, Kind: 9, Prefix: p, ASN: 13335, RPKI: &via3.RPKIData{Status: 3, ObservedAt: 1794095000, ValidUntil: 1794095900}})
	}
	// An explicit empty origin list is a real boundary, not an absent group.
	empty := netip.MustParsePrefix("203.0.115.0/24")
	rows = append(rows,
		via3.PublicRecord{Version: 3, Kind: 4, Prefix: empty, Network: &via3.NetworkData{Origins: []uint32{}}},
		via3.PublicRecord{Version: 3, Kind: 10, Prefix: empty, Origins: &via3.OriginsData{ASNs: []uint32{}}})
	opts := testOptions(t)
	opts.Limits.PartitionRecords = 8
	baseline, err := via3.Build(context.Background(), via3.CompileInput{Mode: opts.Mode, Clock: opts.Clock, ValidUntil: opts.ValidUntil, Partitions: []via3.PartitionInput{{Partition: "all", PrefixRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, ASNRoutes: []uint32{3356, 13335, 15169}, Records: rows}}})
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{}
	for _, object := range baseline.Objects {
		objects[object.Info.SHA256] = object.Bytes
	}
	pointer, _ := canonical(baseline.Pointer)
	manifest, _ := canonical(baseline.Manifest)
	want, err := via3.NewRelease(pointer, manifest, func(hash string) ([]byte, error) { return objects[hash], nil }, func() int64 { return opts.Clock })
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := Build(context.Background(), opts, producer(rows))
	if err != nil {
		t.Fatal(err)
	}
	got, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{"203.0.1.1", "203.0.40.1", "203.0.55.1", "203.0.112.2", "203.0.113.0", "203.0.113.1", "203.0.114.1", "203.0.115.1", "2001:db8:1::1", "2001:db8:2::1", "AS13335", "AS15169", "AS3356", "AS174", "8.8.8.8"}
	for _, q := range queries {
		a, err := got.Lookup(context.Background(), q)
		if err != nil {
			t.Fatal(q, err)
		}
		b, err := want.Lookup(context.Background(), q)
		if err != nil {
			t.Fatal(q, err)
		}
		a.ReleaseID = b.ReleaseID
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("grouped lookup changed %s\ngot %+v\nwant %+v", q, a, b)
		}
	}
	a, err := got.ClassC(context.Background(), child.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := want.ClassC(context.Background(), child.Addr().String())
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("grouped profile/network references changed", err)
	}
	slices.Reverse(rows)
	again := testOptions(t)
	again.Limits.PartitionRecords = opts.Limits.PartitionRecords
	again.Limits.SortBytes *= 2
	reordered, err := Build(context.Background(), again, producer(rows))
	if err != nil || reordered.Pointer != candidate.Pointer {
		t.Fatal("grouped inventory depends on input/sort-run order", err)
	}
	verifyGroupedWorkerFixture(t, candidate, opts, got, queries)
}

func verifyGroupedWorkerFixture(t *testing.T, candidate Candidate, opts Options, reader *via3.Release, queries []string) {
	t.Helper()
	type object struct {
		Info  via3.ObjectInfo `json:"info"`
		Bytes []byte          `json:"base64"`
	}
	type vector struct {
		Query  string             `json:"q"`
		Answer via3.LookupAnswer  `json:"answer"`
		ClassC *via3.ClassCAnswer `json:"classC"`
	}
	fixture := struct {
		Clock    int64         `json:"clock"`
		Pointer  via3.Pointer  `json:"pointer"`
		Manifest via3.Manifest `json:"manifest"`
		Objects  []object      `json:"objects"`
		Vectors  []vector      `json:"vectors"`
	}{Clock: opts.Clock, Pointer: candidate.Pointer, Manifest: candidate.Manifest}
	for _, info := range candidate.Manifest.Objects {
		data, err := os.ReadFile(filepath.Join(opts.Output, "objects", info.SHA256+".via3"))
		if err != nil {
			t.Fatal(err)
		}
		fixture.Objects = append(fixture.Objects, object{info, data})
	}
	for _, q := range queries {
		a, err := reader.Lookup(context.Background(), q)
		if err != nil {
			t.Fatal(q, err)
		}
		profile, err := reader.ClassC(context.Background(), q)
		if err != nil {
			t.Fatal(q, err)
		}
		fixture.Vectors = append(fixture.Vectors, vector{q, a, profile})
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := "../../fixtures/bin/grouped-via3.json"
	if os.Getenv("ATLAS_EXPORT_GROUPED_CORPUS") == "1" {
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(want, data) {
		t.Fatal("grouped Go/worker fixture differs; regenerate only after semantic parity review", err)
	}
}

func TestGroupedAnycastValidationRetainsCrossKindGuard(t *testing.T) {
	opts := testOptions(t)
	parent, child := netip.MustParsePrefix("203.0.0.0/16"), netip.MustParsePrefix("203.0.113.0/24")
	yes := true
	rows := []via3.PublicRecord{
		{Version: 3, Kind: 2, Prefix: parent, Geo: &via3.GeoData{Country: "US", City: "Parent City"}},
		{Version: 3, Kind: 3, Prefix: parent, Coordinates: &via3.CoordinateData{Latitude: 1, Longitude: 2, Precision: 3}},
		{Version: 3, Kind: 5, Prefix: child, Usage: &via3.UsageData{Anycast: &yes}},
	}
	if _, err := Build(context.Background(), opts, producer(rows)); via3.ErrorCode(err) != "record" {
		t.Fatal("separate packing bypassed cross-kind anycast validation", err)
	}
}

func TestIndependentFactGroupsAvoidCrossKindObjectFanout(t *testing.T) {
	opts := testOptions(t)
	opts.Limits = DefaultLimits()
	opts.Limits.PartitionRecords = 16
	opts.Limits.MaxObjects = 180
	candidate, err := Build(context.Background(), opts, producer(groupedFactRows(128)))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Manifest.Objects) > opts.Limits.MaxObjects || candidate.Stats.UniqueRecords != 1024 {
		t.Fatal("packing dropped facts or exceeded unchanged fixture ceiling", candidate.Stats)
	}
	reader, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 128; i++ {
		q := fmt.Sprintf("11.0.%d.0", i)
		a, err := reader.Lookup(context.Background(), q)
		if err != nil || a.Geo == nil || a.Geo.City == nil || a.Usage == nil || a.Quality == nil || a.Network == nil || len(a.BGP.RPKI) != 1 || a.BGP.RPKI[0].Status != "valid" {
			t.Fatalf("fact lost at %s: %+v %v", q, a, err)
		}
		profile, err := reader.ClassC(context.Background(), q)
		if err != nil || profile == nil || len(profile.Cells[0].Origins) != 1 || profile.Cells[0].Origins[0] != 13335 {
			t.Fatal("profile network ordinal changed", err)
		}
	}
}
