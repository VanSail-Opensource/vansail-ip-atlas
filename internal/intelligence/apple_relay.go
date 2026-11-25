package intelligence

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"vansail-ip-atlas/internal/subscription"
)

const AppleRelaySourceID = "apple-private-relay"
const AppleRelayMaxPrefixes = 500_000

var ErrAppleRelay = errors.New("invalid witnessed Apple relay prefix edition")

type AppleRelayWitness struct {
	Commit                  string
	CommittedAt, CapturedAt time.Time
	FileHash, PrefixHash    [32]byte
	Prefixes                int
}

type AppleRelayProof struct {
	Edition       time.Time
	ETag          string
	Bytes         int64
	PayloadHash   [32]byte
	Before, After AppleRelayWitness
}

func (p *AppleRelayProof) Validate(now, published time.Time, payload [32]byte) error {
	if p == nil || published.Year() < 1970 || published.After(p.Edition) || p.Edition.Nanosecond() != 0 || p.Bytes <= 0 || p.Bytes > 32<<20 || p.ETag != fmt.Sprintf("\"%x-%x\"", p.Edition.Unix(), p.Bytes) || payload == ([32]byte{}) || p.PayloadHash != payload {
		return ErrAppleRelay
	}
	for _, w := range []AppleRelayWitness{p.Before, p.After} {
		if len(w.Commit) != 40 || w.CapturedAt.Year() < 1970 || w.CommittedAt.Before(w.CapturedAt) || w.CommittedAt.Sub(w.CapturedAt) > 24*time.Hour || w.CommittedAt.After(now) || w.FileHash == ([32]byte{}) || w.PrefixHash == ([32]byte{}) || w.Prefixes <= 0 || w.Prefixes > AppleRelayMaxPrefixes {
			return ErrAppleRelay
		}
		for _, c := range w.Commit {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return ErrAppleRelay
			}
		}
	}
	if !p.Before.CommittedAt.Before(p.Edition) || p.After.CapturedAt.Before(p.Edition) || p.Before.Commit == p.After.Commit || p.Before.FileHash == p.After.FileHash || p.Before.PrefixHash == p.After.PrefixHash {
		return ErrAppleRelay
	}
	return nil
}

// The distinct preceding capture bounds the age of the selected prefix set even
// when the server updates the CSV's unselected geographic columns later.
func (p *AppleRelayProof) ContentDeadline(maxAge time.Duration) time.Time {
	return p.Before.CapturedAt.Truncate(time.Second).Add(maxAge)
}

func cloneAppleRelayProof(p *AppleRelayProof) *AppleRelayProof {
	if p == nil {
		return nil
	}
	clone := *p
	return &clone
}

// The private set binds the observed prefixes across differently ordered whole
// files. It retains prefix lengths, including /32 and /128 claims as CIDRs.
type ApplePrefixSet map[netip.Prefix]struct{}

func (s ApplePrefixSet) Insert(prefix netip.Prefix) error {
	if len(s) >= AppleRelayMaxPrefixes || !subscription.PublicPrefix(prefix) || prefix != prefix.Masked() {
		return ErrAppleRelay
	}
	if _, dup := s[prefix]; dup {
		return ErrAppleRelay
	}
	s[prefix] = struct{}{}
	return nil
}

func (s ApplePrefixSet) Add(r NormalizedRecord, at time.Time, weight float64) error {
	e := r.Evidence
	if r.Kind != RecordEvidence || e == nil || e.Scope != ExplicitPrefix || e.Family != AppleRelaySourceID || e.Signal != "proxy" || !e.Current || e.SubscriptionLiteral || e.Address.IsValid() || e.ASN != 0 || !e.ItemPublishedAt.IsZero() || !e.SourcePublishedAt.Equal(at) || e.Weight != weight {
		return ErrAppleRelay
	}
	return s.Insert(e.Prefix)
}

func (s ApplePrefixSet) Hash() [32]byte {
	rows := make([]netip.Prefix, 0, len(s))
	for prefix := range s {
		rows = append(rows, prefix)
	}
	slices.SortFunc(rows, netip.Prefix.Compare)
	h := sha256.New()
	h.Write([]byte("vansail-apple-relay-prefix-set-v1\x00"))
	var frame [18]byte
	for _, p := range rows {
		addr := p.Addr()
		ip := addr.As16()
		copy(frame[:16], ip[:])
		frame[16], frame[17] = byte(addr.BitLen()), byte(p.Bits())
		h.Write(frame[:])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
