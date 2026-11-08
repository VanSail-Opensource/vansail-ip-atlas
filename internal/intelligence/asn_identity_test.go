package intelligence

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestASNIdentityCSVStreamsSanitizesAndCountsReserved(t *testing.T) {
	input := "asn,handle,description,country-code\r\n13335,EDGE,\"Example, Incorporated\",us\r\n0,RESERVED,Unknown,ZZ\r\n23456,TRANS,Unknown,ZZ\r\n64512,PRIVATE,Unknown,ZZ\r\n15169,SAFE,\"unsafe@example.com\",XX\r\n174,TRANSIT,\"Multi\nLine\",US\r\n"
	var out []ASNIdentityEvidence
	stats, err := ParseASNIdentityCSV(context.Background(), strings.NewReader(input), ParseLimits{Bytes: 4096, Records: 10, LineBytes: 1024}, func(v ASNIdentityEvidence) error { out = append(out, v); return nil })
	if err != nil || stats.ReadRows != 6 || stats.AcceptedRows != 3 || stats.SkippedReservedASNs != 3 || len(out) != 3 {
		t.Fatal("ASN identity row accounting changed", stats, err)
	}
	if out[0].ASN != 13335 || out[0].Name != "EDGE" || out[0].Organization != "Example, Incorporated" || out[0].Country != "US" || out[1].Organization != "" || out[1].Country != "" || out[2].Organization != "" {
		t.Fatal("identity fields were inferred or unsafe values retained", out)
	}
	if out[0].Current || out[0].Family != "" {
		t.Fatal("parser manufactured source admission")
	}
}

func TestASNIdentityCSVRejectsSchemaUTF8BudgetsAndCancellation(t *testing.T) {
	for _, input := range []string{"asn,name,org,country\n13335,X,Y,US\n", "asn,handle,description,country-code\nAS13335,X,Y,US\n", "asn,handle,description,country-code\n13335,X,Y,US,extra\n", "asn,handle,description,country-code\n13335,X,\"unterminated\n", "asn,handle,description,country-code\n13335,X,\xff,US\n"} {
		if _, err := ParseASNIdentityCSV(context.Background(), strings.NewReader(input), ParseLimits{Bytes: 4096, Records: 10, LineBytes: 1024}, func(ASNIdentityEvidence) error { return nil }); err == nil {
			t.Fatal("invalid ASN identity input accepted")
		}
	}
	input := "asn,handle,description,country-code\n13335,X,Y,US\n15169,A,B,US\n"
	for _, limits := range []ParseLimits{{Bytes: 40, Records: 10, LineBytes: 1024}, {Bytes: 4096, Records: 1, LineBytes: 1024}, {Bytes: 4096, Records: 10, LineBytes: 20}} {
		if _, err := ParseASNIdentityCSV(context.Background(), strings.NewReader(input), limits, func(ASNIdentityEvidence) error { return nil }); err == nil {
			t.Fatal("ASN identity parser exceeded bound")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseASNIdentityCSV(ctx, strings.NewReader(input), ParseLimits{Bytes: 4096, Records: 10, LineBytes: 1024}, func(ASNIdentityEvidence) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("ASN parser lost cancellation", err)
	}
}

func TestASNIdentityFusionIndependentFieldsAndFamilyConflicts(t *testing.T) {
	values := []ASNIdentityEvidence{{ASN: 13335, Family: "alpha", Weight: 90, Current: true, Name: "Edge A", Organization: "Operator A", Country: "US"}, {ASN: 13335, Family: "alpha", Weight: 90, Current: true, Name: "Edge B", Country: "US"}, {ASN: 13335, Family: "bravo", Weight: 80, Current: true, Name: "Other Edge", Organization: "Operator B", Country: "DE"}}
	got, err := FuseASNIdentities(values)
	if err != nil || got.Name != "Other Edge" || got.Organization != "Operator A" || got.Country != "US" {
		t.Fatal("field/family fusion changed", got, err)
	}
	values = append(values, ASNIdentityEvidence{ASN: 13335, Family: "charlie", Weight: 90, Current: true, Organization: "Conflicting Operator", Country: "DE"})
	got, err = FuseASNIdentities(values)
	if err != nil || got.Organization != "" || got.Country != "" || got.Name != "Other Edge" {
		t.Fatal("equal reliability conflict did not remain unknown", got, err)
	}
	values = append(values, ASNIdentityEvidence{ASN: 0, Family: "stale", Weight: 100, Current: false, Name: "Stale Winner", Organization: "Stale Operator", Country: "DE"})
	stale, err := FuseASNIdentities(values)
	if err != nil || stale != got {
		t.Fatal("stale ASN identity did not abstain", stale, err)
	}
	values[len(values)-1].Current = true
	if _, err := FuseASNIdentities(values); err == nil {
		t.Fatal("invalid current ASN identity accepted")
	}
}
