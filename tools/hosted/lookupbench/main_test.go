package main

import (
	"strings"
	"testing"
)

func subsetCorpus() corpus {
	c := corpus{FormatVersion: 2, Mode: "production", ReleaseID: strings.Repeat("a", 64), InteractionQuery: "8.8.8.1"}
	c.UnknownQueries.IPv4 = "192.0.2.1"
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
		c.Queries = append(c.Queries, query{"8.8.8.1", "ipv4_lpm"}, query{c.UnknownQueries.IPv4, "unknown"}, query{c.UnknownQueries.IPv6, "unknown"}, query{c.UnknownQueries.ASN, "unknown"})
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
