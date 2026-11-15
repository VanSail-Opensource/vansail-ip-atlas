package intelligence

import (
	"crypto/sha256"
	"errors"
	"time"
)

// GeoSourceProof is private publisher evidence for a complete downloaded asset.
// CSV identity prevents archive repacking from renewing previously seen data.
// None of these fields has a public lookup or VIA3 representation.
type GeoSourceProof struct {
	Version                                  uint16
	AssetURL, CSVMember                      string
	DecodedSHA256, PageSHA256, LicenseSHA256 [32]byte
	UpstreamClock                            time.Time
	DecodedBytes                             int64
}

func (p *GeoSourceProof) ContentHash() ([32]byte, error) {
	if p == nil || p.Version != 1 || p.DecodedSHA256 == ([32]byte{}) || p.DecodedBytes <= 0 || p.DecodedBytes > 3<<30 || p.UpstreamClock.IsZero() {
		return [32]byte{}, errors.New("decoded geolocation proof invalid")
	}
	data := append([]byte("atlas-decoded-geo-v1\x00"), p.DecodedSHA256[:]...)
	return sha256.Sum256(data), nil
}
func cloneGeoProof(p *GeoSourceProof) *GeoSourceProof {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}
