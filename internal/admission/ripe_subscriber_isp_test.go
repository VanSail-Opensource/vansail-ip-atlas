package admission

import (
	"os"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

const customer = `inet6num: 2a02:1808::/32
netname: INSTITUTIONAL-NET
country: BE
mnt-by: TELENET-DBM
descr: Telenet N.V. Fixed Residential Broadband
status: AGGREGATED-BY-LIR
last-modified: 2026-11-01T01:02:03Z
source: RIPE
`

func TestRIPESubscriberRequiresFullUnambiguousOriginal(t *testing.T) {
	clock := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	check := func(t *testing.T, input string, want intelligence.RIPESubscriberISP) ripeNamesInventory {
		t.Helper()
		var row *intelligence.NetworkNameRecord
		v, _, err := readRIPENames(t.Context(), strings.NewReader(input), clock, 10, 1<<20, true, func(r intelligence.NormalizedRecord) error {
			row = r.NetworkName
			return r.Validate()
		})
		if err != nil || row == nil || row.Name != "INSTITUTIONAL-NET" || row.SubscriberISP != want {
			t.Fatalf("got %+v, error %v", row, err)
		}
		return v
	}
	original := check(t, customer, intelligence.RIPETelenet)
	for _, pair := range [][2]string{
		{"mnt-by: TELENET-DBM", "mnt-by: OTHER-MNT"},
		{"mnt-by: TELENET-DBM", "mnt-by: TELENET-DBM\nmnt-by: OTHER-MNT"},
		{"country: BE", "country: PL"},
		{"country: BE", "country: BE\ncountry: BE"},
		{"status: AGGREGATED-BY-LIR", "status: ASSIGNED"},
		{"status: AGGREGATED-BY-LIR", "status: AGGREGATED-BY-LIR\n  OTHER"},
		{"Telenet N.V. Fixed Residential Broadband", "Telenet N.V. Backbone"},
		{"Telenet N.V. Fixed Residential Broadband", "Telenet N.V. Fixed Residential Broadband\n+ except customer addresses"},
		{"Telenet N.V. Fixed Residential Broadband", "Telenet N.V. Fixed Residential Broadband\ndescr: infrastructure"},
		{"descr:", "remarks:"},
		{"country: BE", ""},
	} {
		t.Run(pair[1], func(t *testing.T) {
			input := strings.Replace(customer, pair[0], pair[1], 1)
			// Removing an attribute must not introduce a new RPSL object boundary.
			input = strings.Replace(input, "\n\n", "\n", 1)
			other := check(t, input, intelligence.RIPEUnknownISP)
			if original.projection == other.projection {
				t.Fatal("ISP disappeared without changing the projection proof")
			}
		})
	}
}

func TestObservedRIPESubscriberFixture(t *testing.T) {
	f, err := os.Open("../../fixtures/source-certification/observed-ripe-inet6num.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	expected := map[string]intelligence.RIPESubscriberISP{
		"2a00:9f00::/34":     intelligence.RIPEVectra,
		"2a02:2028::/40":     intelligence.RIPEWilhelmTel,
		"2a02:1808::/32":     intelligence.RIPETelenet,
		"2001:16a2:200::/39": intelligence.RIPESTC,
		"2a00:9f00::/48":     intelligence.RIPEUnknownISP,
	}
	_, _, err = readRIPENames(t.Context(), f, time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC), 256, 1<<20, false, func(r intelligence.NormalizedRecord) error {
		n := r.NetworkName
		p := n.Prefix.String()
		if n.SubscriberISP != expected[p] {
			t.Fatalf("%s ISP %v, expected %v", p, n.SubscriberISP, expected[p])
		}
		delete(expected, p)
		return r.Validate()
	})
	if err != nil || len(expected) != 0 {
		t.Fatal("incomplete fixture", expected, err)
	}
}
