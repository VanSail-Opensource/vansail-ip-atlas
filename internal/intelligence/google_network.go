package intelligence

import (
	"crypto/sha256"
	"errors"
	"hash"
	"net/netip"
	"time"

	"vansail-ip-atlas/internal/subscription"
)

const GoogleNetworkSourceID = "google-network-organization"
const GoogleNetworkMaxPrefixes = 10000

// A publisher's network organization is independent of the announcing ASN.
type NetworkOrganizationRecord struct {
	Prefix       netip.Prefix
	Organization string
}

type GoogleNetworkProof struct {
	PublishedAt             time.Time
	PayloadHash, Projection [32]byte
	Prefixes, IPv4, IPv6    uint64
}

func (p *GoogleNetworkProof) Validate(now, published time.Time, payload [32]byte) error {
	if p == nil || p.PublishedAt.Year() < 1970 || !p.PublishedAt.Equal(published) || !published.Equal(published.Truncate(time.Millisecond)) || p.PublishedAt.After(now) || payload == ([32]byte{}) || p.PayloadHash != payload || p.Projection == ([32]byte{}) || p.Prefixes > GoogleNetworkMaxPrefixes || p.IPv4 == 0 || p.IPv4 >= p.Prefixes || p.IPv6 != p.Prefixes-p.IPv4 {
		return errors.New("invalid complete Google-owned network range proof")
	}
	return nil
}

func cloneGoogleNetworkProof(p *GoogleNetworkProof) *GoogleNetworkProof {
	if p == nil {
		return nil
	}
	clone := *p
	return &clone
}

// GoogleNetworkDigest verifies every original prefix in parser order. The
// organization is fixed by the publisher's description of this entire report.
type GoogleNetworkDigest struct {
	stream     hash.Hash
	ipv4, ipv6 uint64
}

func (d *GoogleNetworkDigest) Add(r NormalizedRecord) error {
	v := r.NetworkOrganization
	if r.Kind != RecordNetworkOrganization || v == nil || v.Organization != "Google" || !subscription.PublicPrefix(v.Prefix) || d.ipv4+d.ipv6 >= GoogleNetworkMaxPrefixes {
		return errors.New("invalid Google network organization record")
	}
	if d.stream == nil {
		d.stream = sha256.New()
	}
	var entry [18]byte
	address := v.Prefix.Addr()
	addr := address.As16()
	copy(entry[:16], addr[:])
	entry[16], entry[17] = byte(address.BitLen()), byte(v.Prefix.Bits())
	d.stream.Write(entry[:])
	if address.Is4() {
		d.ipv4++
	} else {
		d.ipv6++
	}
	return nil
}
func (d *GoogleNetworkDigest) Sum() (uint64, [32]byte) {
	var projection [32]byte
	if d.stream != nil {
		copy(projection[:], d.stream.Sum(nil))
	}
	return d.ipv4 + d.ipv6, projection
}
func (d *GoogleNetworkDigest) Matches(p *GoogleNetworkProof) bool {
	count, projection := d.Sum()
	return p != nil && count == p.Prefixes && projection == p.Projection && d.ipv4 == p.IPv4 && d.ipv6 == p.IPv6
}
