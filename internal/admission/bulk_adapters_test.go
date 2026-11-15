package admission

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func bulkSource(id, schema string) Source {
	s := Source{Family: "fixture-family", Category: "geolocation", Scope: "prefix", Coverage: "mapping", Format: "range-csv", Weight: 75, Parser: Parser{ID: id, Schema: schema, Version: 1}, Fields: []string{"country_code"}, PublicFields: []string{"physical_country"}, FieldMappings: map[string][]string{"country_code": {"physical_country"}}}
	if id == "city-range-csv" {
		s.Format = "csv"
		s.Fields = []string{"country_code", "region", "city", "latitude", "longitude"}
		s.PublicFields = []string{"physical_country", "region", "city", "latitude", "longitude"}
		for _, v := range s.Fields[1:] {
			s.FieldMappings[v] = []string{v}
		}
	}
	return s
}
func parseBulkTest(t *testing.T, s Source, input string, maximum int) ([]intelligence.NormalizedRecord, error) {
	t.Helper()
	var out []intelligence.NormalizedRecord
	err := parseBulkPayload(context.Background(), strings.NewReader(input), s, time.Unix(1800000000, 0).UTC(), maximum, func(r intelligence.NormalizedRecord) error { out = append(out, r); return r.Validate() })
	return out, err
}
func TestCountryRangeMinimalCover(t *testing.T) {
	s := bulkSource("country-range-csv", "start-end-country-csv-v1")
	rows, err := parseBulkTest(t, s, "8.8.8.1,8.8.8.6,US\n", 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.8.1/32", "8.8.8.2/31", "8.8.8.4/31", "8.8.8.6/32"}
	if len(rows) != len(want) {
		t.Fatal(len(rows))
	}
	for i, v := range rows {
		if v.Geo.Prefix.String() != want[i] || v.Geo.PhysicalCountry != "US" {
			t.Fatal(v)
		}
	}
	var v6 []netip.Prefix
	if err = rangePrefixes(netip.MustParseAddr("2001:4860::"), netip.MustParseAddr("2001:4860::ffff"), func(p netip.Prefix) error { v6 = append(v6, p); return nil }); err != nil || len(v6) != 1 || v6[0].Bits() != 112 {
		t.Fatal(v6, err)
	}
}
func TestCitySchemasDropNonPublicColumns(t *testing.T) {
	for _, tc := range []struct{ schema, input string }{{"dbip-city-eight-columns-v1", "8.8.8.0,8.8.8.255,NA,US,Example,City,37.1,-122.2\n"}, {"sapics-city-ten-columns-v1", "8.8.8.0,8.8.8.255,US,Example,county,City,private-postal,37.1,-122.2,private-zone\n"}} {
		rows, err := parseBulkTest(t, bulkSource("city-range-csv", tc.schema), tc.input, 100)
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		g := rows[0].Geo
		if g.Region != "Example" || g.City != "City" || g.Coordinates == nil || g.Coordinates.Precision != 3 {
			t.Fatal(g)
		}
	}
}
func TestBulkRejectsMalformedAndBoundedInputs(t *testing.T) {
	s := bulkSource("country-range-csv", "start-end-country-csv-v1")
	for _, input := range []string{"8.8.8.2,8.8.8.1,US\n", "8.8.8.1,2001:4860::1,US\n", "8.8.8.1,8.8.8.1,USA\n", "8.8.8.1,8.8.8.1,US,extra\n", "\"unterminated\n" + strings.Repeat("x", 1<<20), "8.8.8.1,8.8.8.1,\xff\n"} {
		if _, err := parseBulkTest(t, s, input, 100); err == nil {
			t.Fatal("accepted malformed input")
		}
	}
	if _, err := parseBulkTest(t, s, "8.8.8.1,8.8.8.6,US\n", 3); err == nil {
		t.Fatal("normalized expansion unbounded")
	}
	s.Parser.Schema = "guessed-schema"
	if _, ok := selectAdapter(s); ok {
		t.Fatal("uncertified schema accepted")
	}
}

func TestBulkCSVPhysicalRowsStrictQuotesAndOwnedLabels(t *testing.T) {
	source := bulkSource("city-range-csv", "dbip-city-eight-columns-v1")
	input := "8.8.8.0,8.8.8.255,NA,US,\"First, Region\",\"A \"\"quoted\"\" city\",37.1,-122.2\r\n8.8.4.0,8.8.4.255,NA,US,Second,Other,38,-123\r\n"
	rows, err := parseBulkTest(t, source, input, 100)
	if err != nil || len(rows) != 2 || rows[0].Geo.Region != "First, Region" || rows[0].Geo.City != "A \"quoted\" city" || rows[1].Geo.City != "Other" {
		t.Fatal("quoted commas, escaped quotes, CRLF or retained label ownership changed", rows, err)
	}
	for _, input := range []string{
		"8.8.8.0,8.8.8.255,NA,US,Region,\"multi\nline\",37,-122\n",
		"8.8.8.0,8.8.8.255,NA,US,Region,Cit\"y,37,-122\n",
		"8.8.8.0,8.8.8.255,NA,US,Region,\"unterminated\n" + strings.Repeat("x", 2<<20),
		"8.8.8.0,8.8.8.255,NA,US,Region,\"" + strings.Repeat("x", 1<<20) + "\",37,-122\n",
	} {
		if _, err = parseBulkTest(t, source, input, 100); err == nil {
			t.Fatal("accepted malformed or over-limit physical CSV record")
		}
	}
}
func TestLiteralListNeverResolvesAndKeepsExactScope(t *testing.T) {
	s := Source{Family: "fixture", Category: "abuse", Scope: "prefix", Coverage: "positive_only", Format: "cidr-text", Parser: Parser{ID: "literal-prefix-text", Schema: "one-literal-ip-or-prefix-per-line-v1", Version: 1}, Signals: []string{"abuse"}, Fields: []string{"abuse"}, PublicFields: []string{"reason_flags"}, FieldMappings: map[string][]string{"abuse": {"reason_flags"}}}
	rows, err := parseBulkTest(t, s, "# ignored\n10.1.2.3\n8.8.8.8\n8.8.4.0/24\n", 100)
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	if rows[0].Evidence.Scope != intelligence.Exact || rows[1].Evidence.Scope != intelligence.ExplicitPrefix {
		t.Fatal("scope conflated")
	}
	for _, v := range []string{"host.example", "https://host.example/8.8.8.8", "8.8.8.8:443", "8.8.8.1/24", "8.8.8.8 comment"} {
		if _, err := parseBulkTest(t, s, v, 100); err == nil {
			t.Fatal("nonliteral accepted")
		}
	}
}
func TestRelationshipProviderDirection(t *testing.T) {
	s := Source{Category: "bgp", Scope: "asn_edge", Coverage: "mapping", Format: "text", Parser: Parser{ID: "caida-relationships", Schema: "asn-asn-relation-pipe-v1", Version: 1}, Fields: []string{"as_relationship"}, PublicFields: []string{"as_relationships"}, FieldMappings: map[string][]string{"as_relationship": {"as_relationships"}}}
	rows, err := parseBulkTest(t, s, "13335|15169|-1|ignored\n", 100)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	index := intelligence.NewRelationships(true)
	v := rows[0].Relationship
	if err = index.Add(v.From, v.To, v.Relation); err != nil {
		t.Fatal(err)
	}
	if index.Relation(13335, 15169) != intelligence.Customer || index.Relation(15169, 13335) != intelligence.TransitUpstream {
		t.Fatal("provider direction reversed")
	}
}
