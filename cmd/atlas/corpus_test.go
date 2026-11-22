package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestProductionCorpusRetainsTruthfulSubsetAndUnknowns(t *testing.T) {
	root := t.TempDir()
	prefix := netip.MustParsePrefix("8.8.8.0/24")
	built, err := via3.Build(context.Background(), via3.CompileInput{Mode: "production", Clock: 1700000000, ValidUntil: 1700003600,
		ProductionGate: func(context.Context) error { return nil }, Partitions: []via3.PartitionInput{{Partition: "all", PrefixRoutes: []netip.Prefix{prefix}, ASNRoutes: []uint32{13335}, Records: []via3.PublicRecord{
			{Version: 3, Kind: 2, Prefix: prefix, Geo: &via3.GeoData{Country: "US"}},
			{Version: 3, Kind: 8, ASN: 13335, ASNAggregate: &via3.ASNData{Name: "Observed metadata"}},
		}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = built.Write(filepath.Join(root, "atlas")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(root, ".atlas-private"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = buildProductionCorpus(context.Background(), []string{"-workspace", root, "-atlas", "atlas", "-clock", "1700000001"}); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(filepath.Join(root, ".atlas-private/production-browser-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus productionCorpus
	if err = json.Unmarshal(bytes, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.FormatVersion != 3 || corpus.ReleaseID != built.Manifest.ReleaseID || corpus.GraphQuery != nil || corpus.MapQuery != nil || corpus.InteractionQuery != "8.8.8.1" || len(corpus.Queries) != 10000 {
		t.Fatalf("incorrect subset corpus: %+v", corpus)
	}
	if corpus.UnknownQueries.IPv4 == nil || corpus.IPv4Coverage != nil || corpus.UnknownQueries.IPv6 == "" || corpus.UnknownQueries.ASN == "" {
		t.Fatal("actual unknown coverage missing")
	}
	for _, row := range corpus.Availability {
		want := row.Stratum == "ipv4_lpm" || row.Stratum == "sparse_asn" || row.Stratum == "unknown"
		if (row.Status == "observed") != want || (row.SampledQueries > 0) != want {
			t.Fatalf("fabricated or missing stratum: %+v", row)
		}
	}
	for _, q := range corpus.Queries {
		if q.Stratum != "ipv4_lpm" && q.Stratum != "sparse_asn" && q.Stratum != "unknown" {
			t.Fatalf("borrowed absent stratum: %+v", q)
		}
	}
}

func TestCorpusMapAndUnknownClassificationsUseActualFacts(t *testing.T) {
	coordinate := 1.0
	precision := "area"
	answer := via3.LookupAnswer{Kind: "ip", Geo: &via3.GeoAnswer{Latitude: &coordinate, Longitude: &coordinate, Precision: &precision}}
	if !corpusHasMap(answer) || corpusUnknown(answer) {
		t.Fatal("finer area coordinates misclassified")
	}
	precision = "country"
	if corpusHasMap(answer) {
		t.Fatal("country coordinates became a city map")
	}
	precision = "city_centroid"
	yes := true
	answer.Usage = &via3.UsageAnswer{Anycast: &yes}
	if corpusHasMap(answer) {
		t.Fatal("anycast became a location")
	}
	unknown := via3.LookupAnswer{Kind: "asn", BGP: via3.BGPAnswer{Origins: []uint32{4199999999}, RPKI: []via3.RPKIAnswer{{Status: "unavailable"}}}}
	if !corpusUnknown(unknown) {
		t.Fatal("requested ASN context became an observed fact")
	}
	unknown.BGP.RPKI[0].Status = "valid"
	if corpusUnknown(unknown) {
		t.Fatal("observed RPKI classified as unknown")
	}
	if (&productionCorpus{}).selectQueries(map[string][]string{"unknown": {"192.0.2.1"}}) == nil {
		t.Fatal("unknown-only corpus accepted")
	}
}

func TestCorpusLabelsOnlySelectedIndexRow(t *testing.T) {
	parent := via3.PrefixKey(netip.MustParsePrefix("8.8.0.0/16"), false, 0)
	child := via3.PrefixKey(netip.MustParsePrefix("8.8.8.0/24"), false, 1)
	host := via3.PrefixKey(netip.MustParsePrefix("8.8.8.1/32"), false, 2)
	exact := via3.PrefixKey(netip.MustParsePrefix("8.8.8.1/32"), true, 3)
	localParent := via3.PrefixKey(netip.MustParsePrefix("8.8.0.0/16"), false, 4)
	newShard := func(local, inherited [][]byte) *via3.Shard {
		return &via3.Shard{Kind: 4, Sections: []via3.Section{
			{ID: 1, Data: via3.Vector(32, local...)},
			{ID: 3, Data: via3.Vector(40, make([]byte, 40), make([]byte, 40), make([]byte, 40), make([]byte, 40), make([]byte, 40))},
			{ID: 8, Data: via3.Vector(32, inherited...)},
		}}
	}
	shard := newShard([][]byte{child, host, exact}, [][]byte{parent})
	for _, test := range []struct {
		name    string
		section uint16
		row     []byte
		address string
		want    bool
	}{
		{"inherited survives", 8, parent, "8.8.9.1", true},
		{"inherited shadowed", 8, parent, "8.8.8.1", false},
		{"child selected", 1, child, "8.8.8.2", true},
		{"child shadowed", 1, child, "8.8.8.1", false},
		{"host shadowed by exact", 1, host, "8.8.8.1", false},
		{"exact selected", 1, exact, "8.8.8.1", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := corpusRowSelected(shard, test.section, test.row, netip.MustParseAddr(test.address)); got != test.want {
				t.Fatalf("selected=%v want=%v", got, test.want)
			}
		})
	}
	shard = newShard([][]byte{localParent}, [][]byte{parent})
	if corpusRowSelected(shard, 8, parent, netip.MustParseAddr("8.8.9.1")) || !corpusRowSelected(shard, 1, localParent, netip.MustParseAddr("8.8.9.1")) {
		t.Fatal("local replacement mislabeled as inherited")
	}
	shard = newShard([][]byte{child, host, exact}, [][]byte{parent})
	address, selected := corpusSelectedAddress(shard, 8, parent, netip.MustParseAddr("8.8.8.1"), netip.MustParsePrefix("8.8.0.0/16"))
	if !selected || address.String() != "8.8.9.0" {
		t.Fatalf("shadowed first address hid inherited population: %v %v", address, selected)
	}
	if _, selected := corpusSelectedAddress(shard, 8, parent, netip.MustParseAddr("8.8.8.1"), netip.MustParsePrefix("8.8.8.0/24")); selected {
		t.Fatal("query witness escaped its actual router partition")
	}
}

func TestCorpusNetworkMOASUsesRecordOrdinalAndOriginCount(t *testing.T) {
	row := via3.PrefixKey(netip.MustParsePrefix("8.8.8.0/24"), false, 1)
	record := make([]byte, 40)
	binary.LittleEndian.PutUint32(record[4:8], 99) // Origin offset is not its count.
	binary.LittleEndian.PutUint32(record[8:12], 2)
	shard := &via3.Shard{Kind: 4, Sections: []via3.Section{{ID: 3, Data: via3.Vector(40, make([]byte, 40), record)}}}
	if !corpusNetworkMOAS(shard, row) {
		t.Fatal("second network record with two origins not detected")
	}
	binary.LittleEndian.PutUint32(row[20:24], 0)
	if corpusNetworkMOAS(shard, row) {
		t.Fatal("origin count read from wrong record")
	}
	binary.LittleEndian.PutUint32(row[20:24], 99)
	if corpusNetworkMOAS(shard, row) {
		t.Fatal("out of bounds record accepted")
	}
	shard.Kind = 2
	if corpusNetworkMOAS(shard, row) {
		t.Fatal("non-network record accepted")
	}
}

func TestCorpusPrefixRejectsNonCanonicalRows(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(row []byte) { row[19] = 1 },
		func(row []byte) { row[2] = 1 },
		func(row []byte) { row[2] = 2 },
		func(row []byte) { row[4] = 1 },
		func(row []byte) { row[24] = 1 },
	} {
		row := via3.PrefixKey(netip.MustParsePrefix("8.8.8.0/24"), false, 0)
		mutate(row)
		if _, _, err := corpusPrefix(row); err == nil {
			t.Fatal("malformed corpus row accepted")
		}
	}
}

func TestCorpusParsesActualInheritedPartitionKeys(t *testing.T) {
	for encoded, want := range map[string]string{"4:00000000000000000000000008080800/24": "8.8.8.0/24", "6:20014860000000000000000000000000/32": "2001:4860::/32"} {
		got, err := corpusPartitionPrefix(encoded)
		if err != nil || got.String() != want {
			t.Fatalf("partition %s: %v %v", encoded, got, err)
		}
	}
	for _, invalid := range []string{"8.8.8.0/24", "4:00000000000000000000000008080801/24", "6:20014860000000000000000000000000/129", "all"} {
		if _, err := corpusPartitionPrefix(invalid); err == nil {
			t.Fatalf("invalid partition accepted: %s", invalid)
		}
	}
}

func TestProductionCorpusCertifiesCoveredIPv4AndPreservesRealUnknowns(t *testing.T) {
	root := t.TempDir()
	prefix := netip.MustParsePrefix("0.0.0.0/0")
	built, err := via3.Build(t.Context(), via3.CompileInput{Mode: "production", Clock: 1700000000, ValidUntil: 1700003600,
		ProductionGate: func(context.Context) error { return nil }, Partitions: []via3.PartitionInput{{Partition: "all", PrefixRoutes: []netip.Prefix{prefix},
			Records: []via3.PublicRecord{{Version: 3, Kind: 4, Prefix: prefix, Network: &via3.NetworkData{Name: "Default network", Origins: []uint32{13335}}},
				{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("8.8.8.0/24"), Geo: &via3.GeoData{Country: "US"}}},
		}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = built.Write(filepath.Join(root, "atlas")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(root, ".atlas-private"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = buildProductionCorpus(t.Context(), []string{"-workspace", root, "-atlas", "atlas", "-clock", "1700000001"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, ".atlas-private", "production-browser-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c productionCorpus
	if err = json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Queries) != 10000 || c.UnknownQueries.IPv4 != nil || c.UnknownQueries.IPv6 == "" || c.UnknownQueries.ASN == "" || !c.IPv4Coverage.Valid(built.Manifest.ReleaseID) {
		t.Fatal("missing evidence for covered IPv4 population")
	}
	if c.IPv4Coverage.NetworkObjects != 1 || c.IPv4Coverage.RouterIntervals != 1 || c.IPv4Coverage.Lookup.Network.Prefix != "0.0.0.0/0" || c.IPv4Coverage.ClassC != nil {
		t.Fatal("covered witness changed")
	}
	r, err := via3.OpenRelease(filepath.Join(root, "atlas"), func() int64 { return 1700000001 })
	if err != nil {
		t.Fatal(err)
	}
	if err = c.IPv4Coverage.Verify(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	for _, q := range c.Queries {
		if a, err := netip.ParseAddr(q.Q); err == nil && a.Is4() && q.Stratum == "unknown" {
			t.Fatal("covered IPv4 labelled unknown")
		}
	}
	c.IPv4Coverage.RouterIntervals++
	if err = c.IPv4Coverage.Verify(t.Context(), r); err == nil {
		t.Fatal("invented coverage evidence accepted")
	}
}
