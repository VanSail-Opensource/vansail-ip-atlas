package intelligence

import (
	"errors"
	"time"
)

// VRPSourceProof is private complete-body evidence from the dedicated exporter
// adapter. A positive authorization row is not proof of complete coverage.
type VRPSourceProof struct {
	Version                          uint16
	Rows, AcceptedRows, ExpiredRows  uint64
	BuiltAt, EvaluatedAt, ValidUntil time.Time
}

func (p *VRPSourceProof) Validate(clock, published, contentUntil time.Time) error {
	if p == nil || p.Version != 1 || p.Rows == 0 || p.Rows > 100_000_000 || p.AcceptedRows == 0 || p.AcceptedRows > p.Rows || p.ExpiredRows > p.Rows || p.AcceptedRows+p.ExpiredRows != p.Rows || p.BuiltAt.IsZero() || p.BuiltAt.After(clock.Add(24*time.Hour)) || published.After(p.BuiltAt) || !p.EvaluatedAt.Equal(clock) || !p.ValidUntil.Equal(contentUntil) || !clock.Before(p.ValidUntil) {
		return errors.New("complete VRP snapshot proof invalid")
	}
	return nil
}
func cloneVRPProof(p *VRPSourceProof) *VRPSourceProof {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}
