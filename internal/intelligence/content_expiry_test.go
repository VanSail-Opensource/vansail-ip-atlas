package intelligence

import (
	"net/netip"
	"testing"
	"time"
)

func TestVRPContentExpiryBoundsTheWholeSnapshot(t *testing.T) {
	policy, snapshot, binding := stateFixture()
	until := clock().Add(90 * time.Minute)
	snapshot.ContentValidUntil = until
	snapshot.Records = []NormalizedRecord{{Version: 3, Kind: RecordVRP, VRP: &VRP{Prefix: netip.MustParsePrefix("8.8.8.0/24"), MaxLength: 24, ASN: 65037, ValidUntil: until}}}
	plan, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil || len(plan.State.Sources) != 1 {
		t.Fatal(err)
	}
	source := plan.State.Sources[0]
	if !source.ExpiresAt.Equal(until) || source.Receipt == nil || !source.Receipt.ContentValidUntil.Equal(until) {
		t.Fatal("cryptographic content expiry extended to source max_age")
	}
	expired, err := Reconcile(plan.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, until, binding)
	if err != nil || len(expired.State.Sources) != 0 || !expired.FullRebuild {
		t.Fatal("expired VRP snapshot survived", err)
	}
	snapshot.ContentValidUntil = until.Add(time.Hour)
	if _, err = Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding); err == nil {
		t.Fatal("source expiry exceeded an included authorization expiry")
	}
}
func TestPrivateAuthorizationASNStillInvalidatesPublicOrigin(t *testing.T) {
	prefix := netip.MustParsePrefix("8.8.8.0/24")
	index, err := NewVRPIndex([]VRP{{Prefix: prefix, MaxLength: 24, ASN: 65037}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := index.Validate(prefix, 13335); got != RPKIInvalid {
		t.Fatal("dropping a private authorization incorrectly produced not_found", got)
	}
	if IsPublicASN(65037) {
		t.Fatal("VRP support must not broaden public query/BGP ASN eligibility")
	}
}
