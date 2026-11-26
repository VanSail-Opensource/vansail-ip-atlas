package admission

import (
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func TestGeoFieldMaskMatchesPreviousPublicFieldPredicates(t *testing.T) {
	names := []string{"registration_country", "physical_country", "region", "city", "latitude", "longitude"}
	for allowed := range 1 << len(names) {
		fields := []string{"unknown-field"}
		for i, name := range names {
			if allowed&(1<<i) != 0 {
				fields = append(fields, name)
			}
		}
		m := allowedGeoFields(fields)
		for have := range 64 {
			x := intelligence.GeoEvidence{Current: have&32 != 0}
			if have&1 != 0 {
				x.RegistrationCountry = "US"
			}
			if have&2 != 0 {
				x.PhysicalCountry = "US"
			}
			if have&4 != 0 {
				x.Region = "CA"
			}
			if have&8 != 0 {
				x.City = "Example"
			}
			if have&16 != 0 {
				x.Coordinates = &intelligence.Coordinates{}
			}
			want := !(!x.Current || x.RegistrationCountry != "" && !contains(fields, "registration_country") || x.PhysicalCountry != "" && !contains(fields, "physical_country") || x.Region != "" && !contains(fields, "region") || x.City != "" && !contains(fields, "city") || x.Coordinates != nil && (!contains(fields, "latitude") || !contains(fields, "longitude")))
			if m.allows(&x) != want {
				t.Fatalf("allowed=%06b present=%06b exact predicate changed", allowed, have)
			}
		}
	}
}
