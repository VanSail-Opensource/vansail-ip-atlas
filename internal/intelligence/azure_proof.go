package intelligence

import (
	"crypto/sha256"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"time"

	"vansail-ip-atlas/internal/subscription"
)

// AzureServiceEdition binds a publisher's dated Azure Public service-tag file to
// its exact global AppService host declarations. These sets remain private.
type AzureServiceEdition struct {
	Day, LastModified             time.Time
	PayloadHash                   [32]byte
	ChangeNumber, TagChangeNumber uint32
	Hosts                         []netip.Addr
}

type AzureServiceProof struct {
	Version   uint16
	IndexHash [32]byte
	Editions  []AzureServiceEdition // newest first, separated by one week
}

const AzureServiceSourceID = "azure-appservice-public"
const MaxAzureServiceHosts = 16384

func (p *AzureServiceProof) Eligible(now, published time.Time, payload [32]byte) (map[netip.Addr]bool, error) {
	deny := errors.New("invalid Azure service edition proof")
	if p == nil || p.Version != 1 || p.IndexHash == ([32]byte{}) || len(p.Editions) < 2 || len(p.Editions) > 3 || published.IsZero() || now.IsZero() {
		return nil, deny
	}
	latest := p.Editions[0]
	if latest.PayloadHash != payload || published.After(latest.Day) {
		return nil, deny
	}
	var eligible map[netip.Addr]bool
	for n, e := range p.Editions {
		if e.Day.Year() < 1970 || !e.Day.Equal(e.Day.UTC().Truncate(24*time.Hour)) || e.Day.After(now) || e.LastModified.IsZero() || e.LastModified.After(now) || e.ChangeNumber == 0 || e.TagChangeNumber == 0 || e.PayloadHash == ([32]byte{}) || len(e.Hosts) == 0 || len(e.Hosts) > MaxAzureServiceHosts {
			return nil, deny
		}
		if n > 0 {
			newer := p.Editions[n-1]
			if !newer.Day.Equal(e.Day.Add(7*24*time.Hour)) || newer.ChangeNumber < e.ChangeNumber || newer.TagChangeNumber < e.TagChangeNumber {
				return nil, deny
			}
		}
		observed := make(map[netip.Addr]bool, len(e.Hosts))
		for i, a := range e.Hosts {
			if a.Is4In6() || !subscription.Public(a) || i > 0 && !e.Hosts[i-1].Less(a) {
				return nil, deny
			}
			observed[a] = true
		}
		if n == 0 {
			eligible = observed
		} else {
			for a := range eligible {
				if !observed[a] {
					delete(eligible, a)
				}
			}
		}
	}
	prior := p.Editions[len(p.Editions)-1]
	if prior.Day.Add(7*24*time.Hour).After(now) || prior.LastModified.Add(7*24*time.Hour).After(now) || len(eligible) == 0 {
		return nil, deny
	}
	return eligible, nil
}
func cloneAzureProof(p *AzureServiceProof) *AzureServiceProof {
	if p == nil {
		return nil
	}
	c := *p
	c.Editions = slices.Clone(p.Editions)
	for i := range c.Editions {
		c.Editions[i].Hosts = slices.Clone(c.Editions[i].Hosts)
	}
	return &c
}

// AzureHostObservation accepts only the exact neutral hosting observation covered
// by the two publisher editions. No per-item date or adverse signal is inferred.
func AzureHostObservation(record NormalizedRecord) bool {
	x := record.Evidence
	return record.Kind == RecordEvidence && x != nil && x.Scope == Exact && x.Signal == "hosting" && x.Address.IsValid() && !x.Address.Is4In6() && subscription.Public(x.Address) && !x.Prefix.IsValid() && x.ASN == 0 && !x.SubscriptionLiteral && x.ItemPublishedAt.IsZero()
}

func AzureHostSetHash(hosts map[netip.Addr]bool) [32]byte {
	h := sha256.New()
	for _, a := range slices.SortedFunc(maps.Keys(hosts), netip.Addr.Compare) {
		raw := a.As16()
		h.Write(raw[:])
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
