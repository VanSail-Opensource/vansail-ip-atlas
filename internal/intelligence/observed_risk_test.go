package intelligence

import (
	"net/netip"
	"testing"
)

func TestObservedRiskIPv6AndZeroEvidence(t *testing.T) {
	p := testPolicy(t)
	address := netip.MustParseAddr("2001:db8::1")
	positive := riskEvidence(address.String(), "independent-a", "malware")
	engine, err := NewEngine(p, []Evidence{positive}, nil, nil, clock())
	if err != nil {
		t.Fatal(err)
	}
	value, err := engine.Lookup(address)
	if err != nil || value.Score == nil || *value.Score != 48 || value.CoverageComplete || value.Contributions[3] != nil || value.Confidence != "low" {
		t.Fatalf("IPv6 observed risk: %+v %v", value, err)
	}
	unknown, _ := engine.Lookup(netip.MustParseAddr("2001:db8::2"))
	if unknown.Score != nil || unknown.Reasons != 0 {
		t.Fatalf("unlisted became a score: %+v", unknown)
	}
	positive.Weight = 0
	engine, err = NewEngine(p, []Evidence{positive}, nil, nil, clock())
	if err != nil {
		t.Fatal(err)
	}
	value, _ = engine.Lookup(address)
	if value.Score != nil || value.Confidence != "unrated" || value.Reasons != 0 || value.Contributions[0] != nil {
		t.Fatalf("zero-weight became evidence: %+v", value)
	}
}

func TestObservedRiskConfidenceUsesWeakestContributingLayer(t *testing.T) {
	p := testPolicy(t)
	address := netip.MustParseAddr("192.0.2.1")
	var records []Evidence
	for _, family := range []string{"a", "b", "c", "d"} {
		v := riskEvidence(address.String(), family, "malware")
		v.Scope, v.Prefix = ExplicitPrefix, netip.MustParsePrefix("192.0.2.0/24")
		records = append(records, v)
	}
	engine, err := NewEngine(p, records, nil, nil, clock())
	if err != nil {
		t.Fatal(err)
	}
	value, _ := engine.Lookup(address)
	if value.Confidence != "high" || value.CoverageComplete {
		t.Fatalf("independent support: %+v", value)
	}
	records = append(records, riskEvidence(address.String(), "a", "proxy"))
	engine, err = NewEngine(p, records, nil, nil, clock())
	if err != nil {
		t.Fatal(err)
	}
	value, _ = engine.Lookup(address)
	if value.Confidence != "low" {
		t.Fatalf("weak exact layer falsely gained prefix votes: %+v", value)
	}
}

func TestObservedRiskTinyPositiveAndExplicitASNOnly(t *testing.T) {
	p := testPolicy(t)
	positive := riskEvidence("192.0.2.1", "a", "proxy")
	positive.Weight = 0.00001
	engine, err := NewEngine(p, []Evidence{positive}, nil, nil, clock())
	if err != nil {
		t.Fatal(err)
	}
	value, _ := engine.Lookup(positive.Address)
	if value.Score == nil || *value.Score != 0 || value.Reasons == 0 {
		t.Fatalf("tiny supported contribution lost: %+v", value)
	}
	positive.Scope, positive.ASN, positive.Weight = ASN, 100, 100
	engine, err = NewEngine(p, []Evidence{positive}, nil, mapping(), clock())
	if err != nil {
		t.Fatal(err)
	}
	value, _ = engine.Lookup(positive.Address)
	if value.Score != nil || engine.ASNContext(100).Risk <= 0 || engine.ASNContext(100).Contribution != 0 {
		t.Fatal("explicit ASN risk bypassed unchanged host-support cap")
	}
}
