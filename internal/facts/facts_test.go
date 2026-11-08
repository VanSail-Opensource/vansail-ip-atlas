package facts

import (
	"strings"
	"testing"
)

func TestCountryAndASNFrozenEnums(t *testing.T) {
	codes := strings.Fields(countryCodes)
	if len(codes) != 249 {
		t.Fatalf("got %d assigned countries", len(codes))
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if seen[code] || !CountryValid(code) {
			t.Fatal("country enum duplicate or invalid")
		}
		seen[code] = true
	}
	for _, code := range []string{"AA", "ZZ", "XK", "us", "USA", "", "U ", "\x00U"} {
		if CountryValid(code) {
			t.Fatalf("nonassigned country accepted: %q", code)
		}
	}
	for _, asn := range []uint32{0, 23456, 64496, 64512, 65535, 65552, 131071, 4200000000, 4294967295} {
		if PublicASN(asn) {
			t.Fatalf("reserved ASN accepted: %d", asn)
		}
	}
	for _, asn := range []uint32{1, 23455, 23457, 64495, 131072, 4199999999} {
		if !PublicASN(asn) {
			t.Fatalf("public ASN rejected: %d", asn)
		}
	}
}
