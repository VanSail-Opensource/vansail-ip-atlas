package intelligence

import (
	"errors"
	"time"
)

// VRPSourceProof is private complete-body evidence from the dedicated exporter
// adapter. Version 1 certifies live-at-intake authorizations. Version 2 retains
// the complete publisher snapshot as observations, including authorizations that
// expired after ObservedAt. Neither proof alone asserts current authorization.
type VRPSourceProof struct {
	Version                          uint16
	Rows, AcceptedRows, ExpiredRows  uint64
	BuiltAt, EvaluatedAt, ValidUntil time.Time
	// New fields are omitted when zero to preserve authenticated v1 encodings.
	RetainedRows       uint64    `json:",omitempty"`
	ObservedAt         time.Time `json:",omitzero"`
	CoverageValidUntil time.Time `json:",omitzero"`
}

func (p *VRPSourceProof) Validate(clock, published, contentUntil time.Time) error {
	if p != nil {
		switch p.Version {
		case 1:
			if p.RetainedRows == 0 && p.ObservedAt.IsZero() && p.CoverageValidUntil.IsZero() && p.Rows > 0 && p.Rows <= 100_000_000 && p.AcceptedRows > 0 && p.AcceptedRows <= p.Rows && p.ExpiredRows <= p.Rows && p.AcceptedRows+p.ExpiredRows == p.Rows && !p.BuiltAt.IsZero() && !p.BuiltAt.After(clock.Add(24*time.Hour)) && !published.After(p.BuiltAt) && p.EvaluatedAt.Equal(clock) && p.ValidUntil.Equal(contentUntil) && clock.Before(p.ValidUntil) {
				return nil
			}
		case 2:
			if p.Rows > 0 && p.Rows <= 100_000_000 && p.RetainedRows == p.Rows && p.AcceptedRows == 0 && p.ExpiredRows == 0 && p.BuiltAt.IsZero() && p.ValidUntil.IsZero() && !p.ObservedAt.IsZero() && !published.IsZero() && !published.After(p.ObservedAt) && !p.ObservedAt.After(clock.Add(24*time.Hour)) && p.EvaluatedAt.Equal(clock) && p.CoverageValidUntil.After(p.ObservedAt) && contentUntil.IsZero() {
				return nil
			}
		}
	}
	return errors.New("complete VRP snapshot proof invalid")
}
func cloneVRPProof(p *VRPSourceProof) *VRPSourceProof {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}
