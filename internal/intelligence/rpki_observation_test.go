package intelligence

import (
	"net/netip"
	"testing"
	"time"
)

func TestRPKIObservationUsesPublisherClockAndMatchingAuthorizationDeadline(t *testing.T) {
	observed := time.Unix(1700000000, 0).UTC()
	coverage := observed.Add(time.Hour)
	for _, prefixes := range [][4]string{{"203.0.0.0/16", "203.0.113.0/24", "203.0.113.128/25", "8.8.8.0/24"}, {"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1:1::/64", "2001:4860::/32"}} {
		parent, exact := netip.MustParsePrefix(prefixes[0]), netip.MustParsePrefix(prefixes[1])
		rows := []VRP{
			{Prefix: parent, MaxLength: uint8(exact.Bits()), ASN: 13335, ValidUntil: observed.Add(2 * time.Hour)},
			{Prefix: exact, MaxLength: uint8(exact.Bits()), ASN: 13335, ValidUntil: observed.Add(3 * time.Hour)},
			{Prefix: exact, MaxLength: uint8(exact.Bits()), ASN: 15169, ValidUntil: coverage},
		}
		index, err := NewVRPObservationIndex(rows, observed, coverage)
		if err != nil {
			t.Fatal(err)
		}
		if index.Validate(exact, 13335) != RPKIUnknown {
			t.Fatal("historical snapshot escaped through legacy current-status API")
		}
		for _, tc := range []struct {
			prefix string
			asn    uint32
			status RPKIStatus
			until  time.Time
		}{
			{prefixes[1], 13335, RPKIValid, observed.Add(3 * time.Hour)},
			{prefixes[1], 15169, RPKIValid, coverage},
			{prefixes[1], 3356, RPKIInvalid, coverage},
			{prefixes[2], 13335, RPKIInvalid, coverage},
			{prefixes[3], 13335, RPKINotFound, coverage},
		} {
			got := index.Observe(netip.MustParsePrefix(tc.prefix), tc.asn)
			if got.Status != tc.status || !got.ObservedAt.Equal(observed) || !got.ValidUntil.Equal(tc.until) || got.Status == RPKIValid && got.MaximumLength != uint8(exact.Bits()) {
				t.Fatalf("wrong per-announcement observation: got=%+v want=%+v", got, tc)
			}
		}
		rows[0].ValidUntil = observed
		if _, err := NewVRPObservationIndex(rows, observed, coverage); err == nil {
			t.Fatal("authorization already expired at publisher observation accepted")
		}
	}
	legacy, err := NewVRPIndex(nil, true)
	if err != nil || legacy.Observe(netip.MustParsePrefix("8.8.8.0/24"), 13335).Status != RPKIUnknown {
		t.Fatal("legacy completeness invented publisher observation", err)
	}
	for _, clock := range []time.Time{{}, observed.Add(time.Nanosecond), time.Unix(9007199254740992, 0)} {
		if _, err := NewVRPObservationIndex(nil, clock, coverage); err == nil {
			t.Fatal("invalid observation clock accepted")
		}
	}
}
