package intelligence

import (
	"testing"
	"time"
)

func TestASNUsageItemClockCannotBeRenewedByContainer(t *testing.T) {
	policy, snapshot, hash := stateFixture()
	current := ScopedUsage{ASN: 13335, ObservedAt: clock().Add(-719 * time.Hour), Evidence: UsageEvidence{Family: "input", Type: "hosting", Current: true}}
	stale := current
	stale.ASN = 15169
	stale.ObservedAt = clock().Add(-721 * time.Hour)
	snapshot.Records = []NormalizedRecord{{Version: 3, Kind: RecordUsage, Usage: &current}, {Version: 3, Kind: RecordUsage, Usage: &stale}}
	first, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash)
	if err != nil || len(first.State.Sources) != 1 || len(first.State.Sources[0].Records) != 1 {
		t.Fatal("stale usage survived", first, err)
	}
	if !first.State.Sources[0].ExpiresAt.Equal(clock().Add(time.Hour)) {
		t.Fatal("usage expiry extended")
	}
	expired, err := Reconcile(first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock().Add(time.Hour), hash)
	if err != nil || len(expired.State.Sources) != 1 || len(expired.State.Sources[0].Records) != 0 {
		t.Fatal("old usage renewed", expired, err)
	}
	future := current
	future.ObservedAt = clock().Add(25 * time.Hour)
	snapshot.Records[0].Usage = &future
	if _, err = Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash); err == nil {
		t.Fatal("future usage accepted")
	}
}
