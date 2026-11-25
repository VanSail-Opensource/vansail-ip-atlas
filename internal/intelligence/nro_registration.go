package intelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"time"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/subscription"
)

const NRORegistrationID = "nro-delegated-registration"

// NRORegistrationProof binds the complete authenticated publisher body to precisely
// its derived registration-country CIDRs. No opaque resource-holder IDs are retained.
type NRORegistrationProof struct {
	Day                                   time.Time
	PayloadHash, ChecksumHash, Projection [32]byte
	Records, Prefixes                     uint64
}

func (p *NRORegistrationProof) Validate(now, published time.Time, payload [32]byte) error {
	if p == nil || now.IsZero() || p.Day.Year() < 1970 || p.PayloadHash == ([32]byte{}) || p.ChecksumHash != sha256.Sum256([]byte(hex.EncodeToString(payload[:])+"  nro-delegated-stats\n")) || p.Projection == ([32]byte{}) || p.PayloadHash != payload || !p.Day.Equal(published) || !p.Day.Equal(p.Day.UTC().Truncate(24*time.Hour)) || p.Day.After(now) || p.Records == 0 || p.Records > 2000000 || p.Prefixes == 0 || p.Prefixes > 5000000 {
		return errors.New("invalid complete NRO report proof")
	}
	return nil
}
func cloneNROProof(p *NRORegistrationProof) *NRORegistrationProof {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

type NRORegistrationDigest struct {
	stream hash.Hash
	count  uint64
}

func (d *NRORegistrationDigest) Add(record NormalizedRecord) error {
	x := record.Geo
	if record.Kind != RecordGeo || x == nil || !x.Current || x.Family != "nro-rir-delegation" || !subscription.PublicPrefix(x.Prefix) || !facts.CountryValid(x.RegistrationCountry) || x.PhysicalCountry != "" || x.Region != "" || x.City != "" || x.Coordinates != nil {
		return errors.New("invalid scoped registration country mapping")
	}
	if d.stream == nil {
		d.stream = sha256.New()
	}
	var entry [20]byte
	addr := x.Prefix.Addr().As16()
	copy(entry[:16], addr[:])
	entry[16] = byte(x.Prefix.Addr().BitLen())
	entry[17] = byte(x.Prefix.Bits())
	copy(entry[18:], x.RegistrationCountry)
	d.stream.Write(entry[:])
	d.count++
	return nil
}
func (d *NRORegistrationDigest) Sum() (uint64, [32]byte) {
	var h [32]byte
	if d.stream != nil {
		copy(h[:], d.stream.Sum(nil))
	}
	return d.count, h
}
