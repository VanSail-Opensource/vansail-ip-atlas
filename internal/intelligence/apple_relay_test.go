package intelligence

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAppleRelayReceiptRequiresDatedSubstantiveTransition(t *testing.T) {
	now := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	edition := now.Add(-96 * time.Hour)
	preceding := AppleRelayWitness{Commit: strings.Repeat("a", 40), CapturedAt: edition.Add(-10 * time.Hour), CommittedAt: edition.Add(-9 * time.Hour), FileHash: [32]byte{1}, PrefixHash: [32]byte{2}, Prefixes: 2}
	following := AppleRelayWitness{Commit: strings.Repeat("b", 40), CapturedAt: edition.Add(8 * time.Hour), CommittedAt: edition.Add(9 * time.Hour), FileHash: [32]byte{3}, PrefixHash: [32]byte{4}, Prefixes: 3}
	proof := AppleRelayProof{Edition: edition, ETag: fmt.Sprintf("\"%x-64\"", edition.Unix()), Bytes: 100, PayloadHash: [32]byte{1}, Before: preceding, After: following}
	if proof.Validate(now, edition, proof.PayloadHash) != nil || proof.Validate(now, edition.Add(-time.Hour), proof.PayloadHash) != nil {
		t.Fatal("rejected dated transition or earliest retained projection clock")
	}
	if deadline := proof.ContentDeadline(720 * time.Hour); !deadline.Equal(preceding.CapturedAt.Add(720*time.Hour)) || !deadline.Before(edition.Add(720*time.Hour)) {
		t.Fatal("projection clock was renewed by the representation")
	}
	for name, change := range map[string]func(*AppleRelayProof){
		"retagged identical prefixes": func(p *AppleRelayProof) { p.Before.PrefixHash = p.After.PrefixHash },
		"same witness bytes":          func(p *AppleRelayProof) { p.Before.FileHash = p.After.FileHash },
		"same immutable commit":       func(p *AppleRelayProof) { p.Before.Commit = p.After.Commit },
		"reversed source change":      func(p *AppleRelayProof) { p.Before.CommittedAt = edition.Add(time.Minute) },
		"future witness": func(p *AppleRelayProof) {
			p.After.CapturedAt = now.Add(time.Minute)
			p.After.CommittedAt = p.After.CapturedAt
		},
		"new view before publisher": func(p *AppleRelayProof) { p.After.CapturedAt = edition.Add(-time.Minute) },
		"invalid commit token":      func(p *AppleRelayProof) { p.Before.Commit = strings.Repeat("!", 40) },
		"changed payload":           func(p *AppleRelayProof) { p.PayloadHash[3]++ },
		"missing raw data":          func(p *AppleRelayProof) { p.Bytes = 0 },
		"strong tag changed":        func(p *AppleRelayProof) { p.ETag = "W/" + p.ETag },
		"empty projection":          func(p *AppleRelayProof) { p.After.Prefixes = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			p := proof
			change(&p)
			if p.Validate(now, edition, proof.PayloadHash) == nil {
				t.Fatal("invalid edition accepted")
			}
		})
	}
}
