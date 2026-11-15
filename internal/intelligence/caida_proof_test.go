package intelligence

import (
	"crypto/sha256"
	"testing"
	"time"
)

func caidaProofFixture() (SourcePolicy, SourceSnapshot, [32]byte) {
	p, s, binding := stateFixture()
	p.ProofKind, s.ProofKind = "embedded", "embedded"
	s.PublishedAt = clock().Add(-24 * time.Hour)
	s.PublishedAt = time.Date(s.PublishedAt.Year(), s.PublishedAt.Month(), s.PublishedAt.Day(), 0, 0, 0, 0, time.UTC)
	s.CAIDAProof = &CAIDASourceProof{Version: 1, AssetURL: CAIDASerial2Index + s.PublishedAt.Format("200601") + "01.as-rel2.txt.bz2", IndexSHA256: sha256.Sum256([]byte("index")), PayloadSHA256: s.PayloadHash, Rows: 1, Headers: 2, BGPHeaders: 1, FirstObservedAt: s.PublishedAt, LastObservedAt: s.PublishedAt}
	s.Records = []NormalizedRecord{{Version: 3, Kind: RecordRelationship, Relationship: &RelationshipRecord{From: 174, To: 209, Relation: Peer}}}
	return p, s, binding
}

func TestCAIDAProofIsClonedAndFingerprintBound(t *testing.T) {
	p, s, binding := caidaProofFixture()
	first, err := Reconcile(BuildState{}, []SourcePolicy{p}, []SourceSnapshot{s}, clock(), binding)
	if err != nil || len(first.State.Sources) != 1 {
		t.Fatal(first, err)
	}
	s.CAIDAProof.Rows++
	if first.State.Sources[0].Receipt.CAIDAProof.Rows != 1 {
		t.Fatal("receipt aliases caller proof")
	}
	s.CAIDAProof.Rows--
	s.CAIDAProof.IndexSHA256 = sha256.Sum256([]byte("changed discovery index"))
	changed, err := Reconcile(first.State, []SourcePolicy{p}, []SourceSnapshot{s}, clock(), binding)
	if err != nil || !changed.FullRebuild || changed.State.Sources[0].Fingerprint == first.State.Sources[0].Fingerprint {
		t.Fatal("discovery evidence escaped fingerprint", changed, err)
	}
}

func TestCAIDAProofRejectsTamperedClockURLAndPayload(t *testing.T) {
	for name, mutate := range map[string]func(*SourceSnapshot){
		"newer publication": func(s *SourceSnapshot) { s.PublishedAt = s.PublishedAt.Add(time.Hour) },
		"future header":     func(s *SourceSnapshot) { s.CAIDAProof.LastObservedAt = clock().Add(48 * time.Hour) },
		"non UTC date":      func(s *SourceSnapshot) { s.CAIDAProof.FirstObservedAt = s.CAIDAProof.FirstObservedAt.Add(time.Second) },
		"wrong payload":     func(s *SourceSnapshot) { s.CAIDAProof.PayloadSHA256 = sha256.Sum256([]byte("other")) },
		"missing index":     func(s *SourceSnapshot) { s.CAIDAProof.IndexSHA256 = [32]byte{} },
		"missing BGP":       func(s *SourceSnapshot) { s.CAIDAProof.BGPHeaders = 0 },
		"offhost URL":       func(s *SourceSnapshot) { s.CAIDAProof.AssetURL = "https://evil.test/20261101.as-rel2.txt.bz2" },
		"URL query":         func(s *SourceSnapshot) { s.CAIDAProof.AssetURL += "?fresh=1" },
		"wrong proof kind":  func(s *SourceSnapshot) { s.ProofKind = "github_commit" },
	} {
		t.Run(name, func(t *testing.T) {
			p, s, binding := caidaProofFixture()
			mutate(&s)
			plan, err := Reconcile(BuildState{}, []SourcePolicy{p}, []SourceSnapshot{s}, clock(), binding)
			if err != nil || len(plan.State.Sources) != 0 {
				t.Fatal("bad proof admitted", plan, err)
			}
		})
	}
	for _, count := range []uint64{0, 2} {
		p, s, binding := caidaProofFixture()
		s.CAIDAProof.Rows = count
		plan, err := Reconcile(BuildState{}, []SourcePolicy{p}, []SourceSnapshot{s}, clock(), binding)
		if err == nil && len(plan.State.Sources) != 0 {
			t.Fatal("row count escaped proof", count)
		}
	}
}
