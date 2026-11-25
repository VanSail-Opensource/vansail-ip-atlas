package via3

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestIPv4CoverageUsesSelectedRouterAndNetworkIndexes(t *testing.T) {
	prefix := netip.MustParsePrefix
	network := func(cidr string, inherited bool) PublicRecord {
		return PublicRecord{Version: 3, Kind: 4, Prefix: prefix(cidr), Inherited: inherited, Network: &NetworkData{Name: "Network"}}
	}
	partition := func(route string, records ...PublicRecord) PartitionInput {
		return PartitionInput{Partition: "all", PrefixRoutes: []netip.Prefix{prefix(route)}, Records: records}
	}
	const domain = uint64(1) << 32
	defaults := partition("0.0.0.0/0", network("0.0.0.0/0", false))
	for _, tc := range []struct {
		name    string
		parts   []PartitionInput
		covered uint64
		gap     string
	}{
		{"default and more specific overrides", []PartitionInput{defaults, partition("192.0.2.0/24", network("0.0.0.0/0", true), network("192.0.2.128/25", false))}, domain, ""},
		{"complete union without a default", []PartitionInput{partition("0.0.0.0/0", network("0.0.0.0/1", false), network("128.0.0.0/1", false))}, domain, ""},
		{"router gap despite child default", []PartitionInput{partition("0.0.0.0/1", network("0.0.0.0/0", false))}, domain / 2, "128.0.0.0"},
		{"more specific router masks broad default", []PartitionInput{defaults, partition("255.255.255.255/32", PublicRecord{Version: 3, Kind: 2, Prefix: prefix("255.255.255.255/32"), Geo: &GeoData{Country: "US"}})}, domain - 1, "255.255.255.255"},
		{"more specific destination has a partial network index", []PartitionInput{defaults, partition("255.255.255.254/31", network("255.255.255.254/32", false))}, domain - 1, "255.255.255.255"},
		{"unselected default cannot fill first gap", []PartitionInput{partition("128.0.0.0/1", network("0.0.0.0/0", false))}, 0, "0.0.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const clock = 1700000000
			b, err := Build(t.Context(), CompileInput{Mode: "synthetic", Clock: clock, ValidUntil: clock + 3600, Partitions: tc.parts})
			if err != nil {
				t.Fatal(err)
			}
			objects := map[string][]byte{}
			for _, obj := range b.Objects {
				objects[obj.Info.SHA256] = obj.Bytes
			}
			open := func() *Release {
				r, err := NewRelease(canonical(b.Pointer), canonical(b.Manifest), func(hash string) ([]byte, error) { return objects[hash], nil }, func() int64 { return clock })
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			r := open()
			counts, gap, err := r.IPv4NetworkCoverage(t.Context())
			if err != nil || counts.CoveredAddresses != tc.covered || gap.IsValid() != (tc.gap != "") || gap.IsValid() && gap.String() != tc.gap {
				t.Fatalf("counts %+v gap %v err %v", counts, gap, err)
			}
			if tc.gap != "" {
				a, err := r.Lookup(t.Context(), tc.gap)
				if err != nil || a.Network != nil {
					t.Fatalf("coverage gap has network %v, %v", a.Network, err)
				}
			} else if counts.NetworkObjects < 1 || counts.RouterIntervals < counts.NetworkObjects {
				t.Fatal(counts)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, _, err = r.IPv4NetworkCoverage(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation: %v", err)
			}
			if tc.name == "complete union without a default" {
				r = open()
				for _, obj := range b.Objects {
					if obj.Info.Kind == 4 {
						delete(objects, obj.Info.SHA256)
					}
				}
				if _, _, err = r.IPv4NetworkCoverage(t.Context()); err == nil {
					t.Fatal("missing selected object received a coverage certificate")
				}
			}
		})
	}
}
