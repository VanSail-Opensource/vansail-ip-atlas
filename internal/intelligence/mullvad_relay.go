package intelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"hash"
	"math"
	"net/netip"
	"strings"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/subscription"
)

const MullvadRelaySourceID = "mullvad-relay-geolocation"
const MullvadMaxEnvelope = 16 << 10
const MullvadMaxHosts = 8192

// These publisher Ed25519 keys are from Mullvad's verified key-set commit
// f670df13c9f584316434ab8af689f8ce7fa5b089. The bundled Sigsum policy
// verifies both inclusion in a trusted log and its independent witness quorum.
const mullvadSigningKeys = `
61fd2d3cfda421356d793c4b395f115d9565a9370fcc66085cc2fa3152adab9e
7858620cfb0b2394519ed224ff288ad9fec90ee90ff44c89c31e7440ce9ab21f
430de613e04f4731cfd20778abb8fc759ecdd4a53c8febce0ed492015c4908a6
f33220d0d2dc2107eb2af2dec61f76fcbecb1d26c7316a7c06d5a2bb0f4faa37
729823ccd58055f075fa36b1eaae4f8f62f5258c856f1d0fc68189a9fbf2ad0d
32a79f73d040603c6055e8ddcdd4d1bb9d7f7787aa5e5fe300b861ce58549f9c
d535cc7d82e67c70d91c5daf7f53c6d14847e0f477585bb0ea7d59019c79ed10
46d2d364788ad00879c80ce4d19aa2f97d3ecd7029fd78b37a4ca7da66fbdcf1
3c350820d318b9e1444cdcf9364907bcfe6d01ec8ce4dc5b0bb8c02e321edc06
bbd3c114e169f7c8b18c552ae655629e7a4ff08482de2d30e0fe22ff86d1454c
`

var errMullvadProof = errors.New("invalid signed relay location proof")

// VerifyMullvadEnvelope authenticates the timestamp and digest before either
// can select a URL or influence freshness. Proof parsing accepts only v2.
func VerifyMullvadEnvelope(envelope string) ([32]byte, time.Time, error) {
	var digest [32]byte
	if len(envelope) == 0 || len(envelope) > MullvadMaxEnvelope {
		return digest, time.Time{}, errMullvadProof
	}
	line, raw, ok := strings.Cut(envelope, "\n\n")
	if !ok || !strings.HasPrefix(raw, "version=2\n") || strings.ContainsAny(line, "\r\n") {
		return digest, time.Time{}, errMullvadProof
	}
	var signature proof.SigsumProof
	if err := signature.FromASCII(strings.NewReader(raw)); err != nil {
		return digest, time.Time{}, errMullvadProof
	}
	trust, err := policy.BuiltinByName("sigsum-generic-2025-1")
	if err != nil {
		return digest, time.Time{}, errMullvadProof
	}
	keys := make(map[crypto.Hash]crypto.PublicKey)
	for key := range strings.FieldsSeq(mullvadSigningKeys) {
		var k crypto.PublicKey
		if _, err := hex.Decode(k[:], []byte(key)); err != nil {
			return digest, time.Time{}, errMullvadProof
		}
		keys[k.Hash()] = k
	}
	message := crypto.HashBytes([]byte(line + "\n"))
	if signature.Verify(&message, keys, trust) != nil {
		return digest, time.Time{}, errMullvadProof
	}
	var stamp struct {
		Digest    string    `json:"digest"`
		Timestamp time.Time `json:"timestamp"`
	}
	if jsonv2.Unmarshal([]byte(line), &stamp, jsonv2.RejectUnknownMembers(true)) != nil || len(stamp.Digest) != 64 || strings.ToLower(stamp.Digest) != stamp.Digest || stamp.Timestamp.Year() < 1970 {
		return digest, time.Time{}, errMullvadProof
	}
	if _, err = hex.Decode(digest[:], []byte(stamp.Digest)); err != nil || digest == ([32]byte{}) {
		return digest, time.Time{}, errMullvadProof
	}
	return digest, stamp.Timestamp.UTC(), nil
}

// The signed object stays private. AcquiredAt binds the 24-hour envelope
// freshness test at intake, separately from the source's content age.
type MullvadRelayProof struct {
	Envelope   string
	AcquiredAt time.Time
	Hosts      uint64
	Projection [32]byte
}

func (p *MullvadRelayProof) Validate(now, published time.Time, payload [32]byte) error {
	if p == nil || p.AcquiredAt.After(now) || published.IsZero() || p.Hosts == 0 || p.Hosts > MullvadMaxHosts || p.Projection == ([32]byte{}) {
		return errMullvadProof
	}
	h, signed, err := VerifyMullvadEnvelope(p.Envelope)
	if err != nil || h != payload || published.After(signed) || p.AcquiredAt.Before(signed) || !p.AcquiredAt.Before(signed.Add(24*time.Hour)) {
		return errMullvadProof
	}
	return nil
}

func cloneMullvadProof(p *MullvadRelayProof) *MullvadRelayProof {
	if p == nil {
		return nil
	}
	cloned := *p
	return &cloned
}

// Canonical address order makes asset reorderings or changes to unused private
// routing fields irrelevant to the age of an identical geographic projection.
type MullvadRelayDigest struct {
	stream   hash.Hash
	previous netip.Addr
	count    uint64
}

func (d *MullvadRelayDigest) Add(r NormalizedRecord) error {
	g := r.Geo
	if r.Kind != RecordGeo || g == nil || !g.Current || !facts.CountryValid(g.PhysicalCountry) ||
		g.RegistrationCountry != "" || g.City == "" || g.Region != "" && g.PhysicalCountry != "US" {
		return errMullvadProof
	}
	c := g.Coordinates
	if c == nil || c.Precision != 3 || !finite(c.Latitude) || !finite(c.Longitude) ||
		math.Abs(c.Latitude) > 90 || math.Abs(c.Longitude) > 180 {
		return errMullvadProof
	}
	addr := g.Prefix.Addr()
	if !subscription.Public(addr) || addr.Is4In6() || addr.Zone() != "" || g.Prefix.Bits() != addr.BitLen() || d.count >= MullvadMaxHosts || d.previous.Compare(addr) >= 0 {
		return errMullvadProof
	}
	if d.stream == nil {
		d.stream = sha256.New()
		d.stream.Write([]byte("atlas-mullvad-geo-v1\x00"))
	}
	// JSON's newline record separator cannot occur in an encoded string.
	err := json.NewEncoder(d.stream).Encode([]any{addr.String(), g.PhysicalCountry, g.Region, g.City, g.Coordinates.Latitude, g.Coordinates.Longitude})
	if err != nil {
		return errMullvadProof
	}
	d.previous = addr
	d.count++
	return nil
}

func (d *MullvadRelayDigest) Sum() (uint64, [32]byte) {
	var sum [32]byte
	if d.stream != nil {
		copy(sum[:], d.stream.Sum(nil))
	}
	return d.count, sum
}

func (d *MullvadRelayDigest) Matches(p *MullvadRelayProof) bool {
	n, h := d.Sum()
	return p != nil && n == p.Hosts && h == p.Projection
}
