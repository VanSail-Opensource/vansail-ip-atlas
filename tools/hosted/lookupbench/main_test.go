package main

import (
	"strings"
	"testing"

	corpusproof "vansail-ip-atlas/internal/corpus"
	"vansail-ip-atlas/internal/via3"
)

func subsetCorpus() corpus {
	c := corpus{FormatVersion: 3, Mode: "production", ReleaseID: strings.Repeat("a", 64), InteractionQuery: "8.8.8.1"}
	v4 := "192.0.2.1"
	c.UnknownQueries.IPv4 = &v4
	c.UnknownQueries.IPv6 = "2001:db8::1"
	c.UnknownQueries.ASN = "AS4199999999"
	for _, stratum := range []string{"ipv4_exact", "ipv4_lpm", "ipv6_exact", "ipv6_lpm", "moas", "sparse_asn", "dense_asn", "inherited", "unknown"} {
		c.Availability = append(c.Availability, struct {
			Stratum        string `json:"stratum"`
			Status         string `json:"status"`
			SampledQueries int    `json:"sampled_queries"`
		}{stratum, "absent", 0})
	}
	c.Availability[1].Status = "observed"
	c.Availability[1].SampledQueries = 1
	c.Availability[8].Status = "observed"
	c.Availability[8].SampledQueries = 3
	for i := 0; i < 2500; i++ {
		c.Queries = append(c.Queries, query{"8.8.8.1", "ipv4_lpm"}, query{*c.UnknownQueries.IPv4, "unknown"}, query{c.UnknownQueries.IPv6, "unknown"}, query{c.UnknownQueries.ASN, "unknown"})
	}
	return c
}

func TestSubsetCorpusRetainsPopulationAndRejectsInventedCoverage(t *testing.T) {
	if err := validateCorpus(subsetCorpus()); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*corpus){
		func(c *corpus) { c.FormatVersion = 1 }, func(c *corpus) { c.ReleaseID = "invalid" }, func(c *corpus) { c.Queries = c.Queries[:9999] },
		func(c *corpus) { c.Availability[4].Status = "observed" }, func(c *corpus) { c.Queries[0].Stratum = "moas" },
		func(c *corpus) { c.Availability[1].SampledQueries = 0 }, func(c *corpus) { c.UnknownQueries.ASN = "AS4199999997" },
		func(c *corpus) { q := "AS13335"; c.MapQuery = &q }, func(c *corpus) { q := "8.8.8.1"; c.GraphQuery = &q },
		func(c *corpus) { c.Queries[0].Q = "example.test" },
	} {
		c := subsetCorpus()
		mutation(&c)
		if validateCorpus(c) == nil {
			t.Fatal("invalid subset corpus accepted")
		}
	}
}

func TestCoveredCorpusBindsWitnessAndRejectsUnknownIPv4Labels(t *testing.T) {
	c := subsetCorpus()
	c.UnknownQueries.IPv4 = nil
	for i, q := range c.Queries {
		if q.Q == "192.0.2.1" {
			c.Queries[i].Q = c.UnknownQueries.IPv6
		}
	}
	c.IPv4Coverage = &corpusproof.IPv4Coverage{IPv4NetworkCoverage: via3.IPv4NetworkCoverage{CoveredAddresses: corpusproof.IPv4Addresses, RouterIntervals: 2, NetworkObjects: 1}, Lookup: via3.LookupAnswer{Q: "0.0.0.0", Kind: "ip", ReleaseID: c.ReleaseID, Network: &via3.NetworkAnswer{Prefix: "0.0.0.0/0"}}}
	if err := validateCorpus(c); err != nil {
		t.Fatal(err)
	}
	c.Queries[1].Q = "0.0.0.0"
	if validateCorpus(c) == nil {
		t.Fatal("covered IPv4 counted as unknown")
	}
	c.Queries[1].Q = c.UnknownQueries.IPv6
	q := "192.0.2.1"
	c.UnknownQueries.IPv4 = &q
	if validateCorpus(c) == nil {
		t.Fatal("incompatible IPv4 populations accepted")
	}
	c.UnknownQueries.IPv4 = nil
	for _, mutate := range []func(*corpusproof.IPv4Coverage){
		func(p *corpusproof.IPv4Coverage) { p.Lookup.ReleaseID = "wrong" },
		func(p *corpusproof.IPv4Coverage) { p.Lookup.Network = nil },
		func(p *corpusproof.IPv4Coverage) { p.Lookup.Synthetic = true },
		func(p *corpusproof.IPv4Coverage) { p.CoveredAddresses-- },
		func(p *corpusproof.IPv4Coverage) { p.NetworkObjects = 3 },
		func(p *corpusproof.IPv4Coverage) { p.ClassC = &via3.ClassCAnswer{} },
	} {
		bad := *c.IPv4Coverage
		mutate(&bad)
		if bad.Valid(c.ReleaseID) {
			t.Fatal("invalid covered witness accepted")
		}
	}
}
