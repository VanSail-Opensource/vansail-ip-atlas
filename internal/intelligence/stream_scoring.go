package intelligence

import (
	"context"
	"math"
	"net/netip"
	"sort"
)

// WalkExactRisks exposes only already fused exact facts for the offline global
// ASN aggregate. Sorted addresses preserve the canonical accumulation order.
// Families remain private and this helper does not create public observations.
func (e *Engine) WalkExactRisks(ctx context.Context, emit func(netip.Addr, float64, []string, []uint32) error) error {
	addresses := make([]netip.Addr, 0, len(e.exact))
	for addr := range e.exact {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	for _, addr := range addresses {
		if err := ctx.Err(); err != nil {
			return err
		}
		fact := e.exact[addr]
		if fact.layer.Risk > 0 {
			if err := emit(addr, fact.layer.Risk, fact.positiveFamilies, e.Origins(addr)); err != nil {
				return err
			}
		}
	}
	return nil
}

// UseASNContexts borrows an immutable complete offline aggregate for this
// engine's lifetime. Production materialization creates it from all spatial
// partitions before looking up any answer; no query/history cache is involved.
func (e *Engine) UseASNContexts(contexts map[uint32]ASNContext) { e.globalASN = contexts }

// AggregateASNContext is the exact existing ASN formula, shared by ordinary and
// streamed materializers. Counts are exact-IP positive observations; families
// count independent currently eligible families and saturate at three.
func (p Policy) AggregateASNContext(mass float64, count uint64, families int, explicitRisk float64) ASNContext {
	diversity := math.Min(1, float64(families)/3)
	confidence := diversity * math.Min(1, float64(count)/64)
	risk := math.Max(explicitRisk, (1-math.Exp(-mass/256))*diversity)
	return ASNContext{risk, confidence, p.Weights[2] * confidence * risk, true}
}
