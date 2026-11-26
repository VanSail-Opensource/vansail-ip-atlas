package intelligence

import (
	"context"
	"net/netip"
)

type prefixScore struct {
	risk     float64
	reasons  uint32
	families int
}

const maxRetainedPrefixScores = 16 << 10
const maxPrefixScoreWork = 256 << 10

// PreparePrefixScores optionally computes, at the current engine clock, one
// exact layer per bounded evidence prefix. Prepare before querying the engine.
// An address's deepest matching evidence prefix determines its entire chain of
// ancestor inputs. Never retain finished answers or reuse across clocks.
func (e *Engine) PreparePrefixScores(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(e.prefix) == 0 || len(e.prefix) > maxRetainedPrefixScores || e.prefixScores != nil {
		return nil
	}
	scores := make(map[netip.Prefix]prefixScore, len(e.prefix))
	var gathered []Evidence
	remaining := maxPrefixScoreWork
	for target := range e.prefix {
		if err := ctx.Err(); err != nil {
			return err
		}
		addr := target.Addr()
		gathered = gathered[:0]
		for _, bits := range e.evidenceDepths.forAddress(addr) {
			if int(bits) > target.Bits() {
				continue
			}
			records := e.prefix[netip.PrefixFrom(addr, int(bits)).Masked()]
			if len(records) > remaining || len(records) > 8192-len(gathered) {
				return nil // Keep the complete ordinary path on pressure.
			}
			remaining -= len(records)
			gathered = append(gathered, records...)
		}
		score, err := e.scorePrefix(gathered)
		if err != nil {
			return nil // Do not cache an error for an unqueried prefix.
		}
		scores[target] = score
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.prefixScores = scores
	return nil
}

func (e *Engine) scorePrefix(records []Evidence) (prefixScore, error) {
	value, err := e.policy.layer(records, e.buildClock())
	return prefixScore{value.Risk, value.Reasons, len(value.Families)}, err
}

func (e *Engine) lookupPrefixScore(addr netip.Addr) (prefixScore, error) {
	depths := e.evidenceDepths.forAddress(addr)
	if e.prefixScores != nil {
		for _, depth := range depths {
			if score, ok := e.prefixScores[netip.PrefixFrom(addr, int(depth)).Masked()]; ok {
				return score, nil
			}
		}
		return prefixScore{}, nil
	}
	var records []Evidence
	for _, depth := range depths {
		records = append(records, e.prefix[netip.PrefixFrom(addr, int(depth)).Masked()]...)
	}
	return e.scorePrefix(records)
}
