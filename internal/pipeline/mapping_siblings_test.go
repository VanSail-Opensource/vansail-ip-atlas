package pipeline

import (
	"context"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestLocationSiblingsPreserveOverridesUnknownsAndScopedRoots(t *testing.T) {
	p := netip.MustParsePrefix
	// Four /26 siblings promote twice, with a more-specific override below
	// the leftmost child. The /25s in a separate block have no equal sibling.
	rows := []locationRow[string]{
		{p("192.0.2.0/26"), "unknown"}, {p("192.0.2.0/32"), "city"}, {p("192.0.2.64/26"), "unknown"},
		{p("192.0.2.128/26"), "unknown"}, {p("192.0.2.192/26"), "unknown"}, {p("198.51.100.128/25"), "country"},
		{p("2001:db8::/127"), "geo"}, {p("2001:db8::1/128"), "unknown"}, {p("2001:db8::2/127"), "geo"},
	}
	global := []locationRow[string]{{p("192.0.2.0/24"), "unknown"}, rows[1], rows[5], {p("2001:db8::/126"), "geo"}, rows[7]}
	got := foldLocationSiblings(slices.Clone(rows), netip.Prefix{}, equalLocationValue[string])
	if !slices.Equal(got, global) {
		t.Fatalf("global siblings changed overrides or order: %v", got)
	}
	scoped := []locationRow[string]{{p("192.0.2.0/25"), "unknown"}, rows[1], rows[3], rows[4], rows[5], rows[6], rows[7], rows[8]}
	got = foldLocationSiblings(slices.Clone(rows), p("192.0.2.0/25"), equalLocationValue[string])
	if !slices.Equal(got, scoped) {
		t.Fatalf("fold escaped the materialization scope: %v", got)
	}
	// An existing different parent must survive even when fully covered.
	different := append([]locationRow[string]{{p("192.0.2.0/24"), "parent"}}, rows[:5]...)
	got = foldLocationSiblings(slices.Clone(different), netip.Prefix{}, equalLocationValue[string])
	want := []locationRow[string]{different[0], {p("192.0.2.0/25"), "unknown"}, rows[1], {p("192.0.2.128/25"), "unknown"}}
	if !slices.Equal(got, want) {
		t.Fatalf("replaced an explicit different parent: %v", got)
	}
}

func TestLocationSiblingsRetainTriStateAndNativeLookups(t *testing.T) {
	p := netip.MustParsePrefix
	yes, no := true, false
	var raw []via3.PublicRecord
	add := func(prefix string, g via3.GeoData, c via3.CoordinateData, u via3.UsageData) {
		raw = append(raw, via3.PublicRecord{Version: 3, Kind: 2, Prefix: p(prefix), Geo: &g}, via3.PublicRecord{Version: 3, Kind: 3, Prefix: p(prefix), Coordinates: &c}, via3.PublicRecord{Version: 3, Kind: 5, Prefix: p(prefix), Usage: &u})
	}
	coords := via3.CoordinateData{Latitude: 1, Longitude: 2, Precision: 3}
	add("203.0.112.0/24", via3.GeoData{Country: "US"}, coords, via3.UsageData{Anycast: &no})
	add("203.0.112.128/25", via3.GeoData{}, via3.CoordinateData{Unknown: true}, via3.UsageData{Anycast: &yes})
	add("203.0.113.0/24", via3.GeoData{Country: "US"}, coords, via3.UsageData{})
	add("2001:db8::/127", via3.GeoData{}, via3.CoordinateData{Unknown: true}, via3.UsageData{})
	add("2001:db8::2/127", via3.GeoData{}, via3.CoordinateData{Unknown: true}, via3.UsageData{Anycast: &no})
	var buffer locationRows
	for _, r := range raw {
		if err := buffer.collect(r); err != nil {
			t.Fatal(err)
		}
	}
	var folded []via3.PublicRecord
	if err := buffer.emit(context.Background(), netip.Prefix{}, func(r via3.PublicRecord) error { folded = append(folded, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(folded) != len(raw)-4 {
		t.Fatalf("remaining rows %d/%d", len(folded), len(raw))
	}
	for i, r := range folded {
		if i > 0 {
			prev := folded[i-1]
			if prev.Prefix.Addr().Compare(r.Prefix.Addr()) > 0 || prev.Prefix.Addr() == r.Prefix.Addr() && (prev.Prefix.Bits() > r.Prefix.Bits() || prev.Prefix == r.Prefix && prev.Kind >= r.Kind) {
				t.Fatal("materializer order changed")
			}
		}
	}
	build := func(rows []via3.PublicRecord) *via3.Release {
		t.Helper()
		opts := testOptions(t)
		opts.Limits.PartitionRecords = 7
		if _, err := Build(context.Background(), opts, func(ctx context.Context, emit func(via3.PublicRecord) error) error {
			for _, r := range rows {
				if err := emit(r); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		release, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
		if err != nil {
			t.Fatal(err)
		}
		return release
	}
	dense, sparse := build(raw), build(folded)
	for _, q := range []string{"203.0.111.255", "203.0.112.0", "203.0.112.127", "203.0.112.128", "203.0.112.255", "203.0.113.0", "203.0.113.255", "203.0.114.0", "2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4"} {
		want, err := dense.Lookup(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		got, err := sparse.Lookup(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		want.ReleaseID = got.ReleaseID
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("lookup differs at %s", q)
		}
	}
}
