package intelligence

import (
	"net/netip"
	"testing"
	"time"
)

func TestDatedThreatItemDoesNotRenewWithFreshContainer(t *testing.T) {
	policy := testPolicy(t)
	evidence := riskEvidence("8.8.8.8", "dated-threat", "c2")
	evidence.SourcePublishedAt = clock()
	evidence.ItemPublishedAt = clock().Add(-721 * time.Hour)
	engine, err := NewEngine(policy, []Evidence{evidence}, nil, nil, clock())
	if err != nil {
		t.Fatal(err)
	}
	answer, err := engine.Lookup(netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatal(err)
	}
	if answer.Reasons != 0 {
		t.Fatal("old dated IOC acquired a current reason from a new wrapper")
	}
	p, s, binding := stateFixture()
	s.Records = []NormalizedRecord{{Version: 3, Kind: RecordEvidence, Evidence: &evidence}}
	plan, err := Reconcile(BuildState{}, []SourcePolicy{p}, []SourceSnapshot{s}, clock(), binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range plan.State.Sources {
		if len(source.Records) > 0 {
			t.Fatal("expired dated item remained in current normalized state")
		}
	}
}
