package pipeline

import (
	"net/netip"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestCatalogLabelCollisionRedactsOnlyMatchingPublicFields(t *testing.T) {
	c := &compiler{options: Options{Limits: DefaultLimits(), PrivateLabelValues: []string{"x4b", "strasse"}}}
	prefix := netip.MustParsePrefix("8.8.8.0/24")
	records := []via3.PublicRecord{
		{Version: 3, Kind: 2, Prefix: prefix, Geo: &via3.GeoData{Country: "DE", Region: "Bavaria", City: "Straße"}},
		{Version: 3, Kind: 4, Prefix: prefix, Network: &via3.NetworkData{Name: "DNMC-NET-0x4b", Organization: "Independent", ISP: "X4B", Origins: []uint32{15169}}},
		{Version: 3, Kind: 8, ASN: 15169, ASNAggregate: &via3.ASNData{Name: "X4B-AS-AP", Organization: "Independent", Country: "US"}},
	}
	for _, input := range records {
		frame, err := c.newCanonicalRunFrame(input)
		if err != nil {
			t.Fatal(err)
		}
		_, r, err := decodeCompactRunPayload(frame.row.data, c.options.Limits.RecordBytes)
		if err != nil {
			t.Fatal(err)
		}
		switch input.Kind {
		case 2:
			if r.Geo.Country != "DE" || r.Geo.Region != "Bavaria" || r.Geo.City != "" || input.Geo.City != "Straße" {
				t.Fatal(r.Geo)
			}
		case 4:
			if r.Network.Name != "" || r.Network.ISP != "" || r.Network.Organization != "Independent" || len(r.Network.Origins) != 1 || r.Network.Origins[0] != 15169 || input.Network.ISP != "X4B" {
				t.Fatal(r.Network)
			}
		case 8:
			if r.ASNAggregate.Name != "" || r.ASNAggregate.Organization != "Independent" || r.ASNAggregate.Country != "US" || input.ASNAggregate.Name != "X4B-AS-AP" {
				t.Fatal(r.ASNAggregate)
			}
		}
	}
	opts := testOptions(t)
	opts.PrivateLabelValues = c.options.PrivateLabelValues
	if _, err := Build(t.Context(), opts, producer(records)); err != nil {
		t.Fatal(err)
	}
	reader, err := via3.OpenRelease(opts.Output, func() int64 { return opts.Clock })
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ip, err := reader.Lookup(t.Context(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if ip.Geo == nil || ip.Geo.City != nil || !matchesOptionalLabel(ip.Geo.Country, "DE") || !matchesOptionalLabel(ip.Geo.Region, "Bavaria") {
		t.Fatal(ip.Geo)
	}
	if ip.Network == nil || ip.Network.Name != nil || ip.Network.ISP != nil || !matchesOptionalLabel(ip.Network.Organization, "Independent") || len(ip.BGP.Origins) != 1 || ip.BGP.Origins[0] != 15169 {
		t.Fatal(ip.Network, ip.BGP.Origins)
	}
	asn, err := reader.Lookup(t.Context(), "AS15169")
	if err != nil {
		t.Fatal(err)
	}
	if len(asn.ASNs) != 1 || asn.ASNs[0].Name != nil || !matchesOptionalLabel(asn.ASNs[0].Organization, "Independent") || !matchesOptionalLabel(asn.ASNs[0].Country, "US") {
		t.Fatal(asn.ASNs)
	}
}
