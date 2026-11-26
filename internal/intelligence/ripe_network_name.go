package intelligence

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"net/netip"
	"strings"
	"time"

	"vansail-ip-atlas/internal/subscription"
)

const RIPENetworkNameSourceID = "ripe-ipv6-network-names"
const RIPENetworkNameMaxRecords = 5000000

// A matching registry object can have an unpublished name. Retaining its
// boundary prevents an enclosing allocation's label from reaching that child.
type NetworkNameRecord struct {
	Prefix        netip.Prefix
	Name          string
	ModifiedAt    time.Time
	SubscriberISP RIPESubscriberISP `json:",omitempty"`
}

// RIPESubscriberISP is a reviewed operator identity supported by an explicit
// subscriber description in the same registry object. Zero is unknown.
type RIPESubscriberISP uint8

const (
	RIPEUnknownISP RIPESubscriberISP = iota
	RIPEWilhelmTel
	RIPETelenet
	RIPESTC
	RIPEVectra
)

func (s RIPESubscriberISP) Label() string {
	switch s {
	case RIPEWilhelmTel:
		// Public labels omit hostname-shaped tokens. Retain both brand words.
		return "wilhelm tel GmbH"
	case RIPETelenet:
		return "Telenet"
	case RIPESTC:
		return "stc"
	case RIPEVectra:
		return "Vectra"
	}
	return ""
}

func (r *NetworkNameRecord) validSubscriberISP() bool {
	return r.SubscriberISP == RIPEUnknownISP || r.SubscriberISP.Label() != "" && r.Name != "" && !r.ModifiedAt.IsZero()
}

// ValidRIPENetworkName enforces the registry's published inet6num netname
// grammar. Every permitted ASCII spelling is already a safe label and the
// length bound is below SafeLabel's truncation limit. Contact handles of the
// form AA123-RIPE cannot become network labels.
func ValidRIPENetworkName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	letter := func(b byte) bool { return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' }
	digit := func(b byte) bool { return b >= '0' && b <= '9' }
	if !letter(name[0]) || !letter(name[len(name)-1]) && !digit(name[len(name)-1]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		b := name[i]
		if !letter(b) && !digit(b) && b != '-' && b != '_' {
			return false
		}
	}
	if len(name) > 5 && strings.EqualFold(name[len(name)-5:], "-RIPE") {
		local := name[:len(name)-5]
		i := 0
		for i < len(local) && letter(local[i]) {
			i++
		}
		if i > 0 && i < len(local) {
			j := i
			for j < len(local) && digit(local[j]) {
				j++
			}
			if j == len(local) {
				return false
			}
		}
	}
	return true
}

type RIPEIPv6NetworkProof struct {
	PublishedAt                           time.Time
	PayloadHash, UTF8Hash, Projection     [32]byte
	Records, Prefixes, NamedPrefixes      uint64
	PrimaryDecodedBytes, UTF8DecodedBytes int64
}

func (p *RIPEIPv6NetworkProof) Validate(now, published time.Time, payload [32]byte) error {
	if p == nil || published.Year() < 1970 || !p.PublishedAt.Equal(published) || published.Nanosecond() != 0 || published.After(now) || payload == ([32]byte{}) || p.PayloadHash != payload || p.UTF8Hash == ([32]byte{}) || p.Projection == ([32]byte{}) || p.NamedPrefixes == 0 || p.NamedPrefixes > p.Prefixes || p.Prefixes > p.Records || p.Records > RIPENetworkNameMaxRecords || p.PrimaryDecodedBytes <= 0 || p.UTF8DecodedBytes <= 0 || p.UTF8DecodedBytes > 3<<30 || p.PrimaryDecodedBytes > (3<<30)-p.UTF8DecodedBytes {
		return errors.New("invalid complete RIPE IPv6 network name proof")
	}
	return nil
}
func cloneRIPENetworkProof(p *RIPEIPv6NetworkProof) *RIPEIPv6NetworkProof {
	if p == nil {
		return nil
	}
	q := *p
	return &q
}

type RIPENetworkNameDigest struct {
	stream       hash.Hash
	count, named uint64
	newest       time.Time
}

func (d *RIPENetworkNameDigest) Add(r NormalizedRecord) error {
	x := r.NetworkName
	if r.Kind != RecordNetworkName || x == nil || !x.validSubscriberISP() || !x.Prefix.Addr().Is6() || !subscription.PublicPrefix(x.Prefix) || d.count >= RIPENetworkNameMaxRecords || x.Name != "" && (!ValidRIPENetworkName(x.Name) || x.ModifiedAt.IsZero()) || !x.ModifiedAt.IsZero() && (x.ModifiedAt.Year() < 1970 || x.ModifiedAt.Nanosecond() != 0) {
		return errors.New("invalid RIPE IPv6 network name record")
	}
	if d.stream == nil {
		d.stream = sha256.New()
	}
	var entry [27]byte
	ip := x.Prefix.Addr().As16()
	copy(entry[:16], ip[:])
	entry[16] = byte(x.Prefix.Bits())
	entry[17] = byte(len(x.Name))
	binary.BigEndian.PutUint64(entry[18:26], uint64(x.ModifiedAt.Unix()))
	entry[26] = byte(x.SubscriberISP)
	d.stream.Write(entry[:])
	d.stream.Write([]byte(x.Name))
	d.count++
	if x.Name != "" {
		d.named++
		if d.newest.Before(x.ModifiedAt) {
			d.newest = x.ModifiedAt
		}
	}
	return nil
}
func (d *RIPENetworkNameDigest) Sum() (uint64, [32]byte) {
	var h [32]byte
	if d.stream != nil {
		copy(h[:], d.stream.Sum(nil))
	}
	return d.count, h
}
func (d *RIPENetworkNameDigest) Matches(p *RIPEIPv6NetworkProof) bool {
	n, h := d.Sum()
	return p != nil && n == p.Prefixes && h == p.Projection && d.named == p.NamedPrefixes && d.newest.Equal(p.PublishedAt)
}
