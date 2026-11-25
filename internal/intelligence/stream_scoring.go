package intelligence

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"sort"
	"time"
)

type exactRiskVisitor struct {
	ctx  context.Context
	emit func(netip.Addr, float64, []string, []uint32) error
}

// newEngine has already validated policy, publication times and routes and
// sorted this bounded leaf's exact addresses in canonical accumulation order.
func (v *exactRiskVisitor) walk(policy Policy, observations map[netip.Addr][]Evidence, addresses []netip.Addr, engine *Engine, clock time.Time) error {
	for _, addr := range addresses {
		if err := v.ctx.Err(); err != nil {
			return err
		}
		layer, err := policy.layer(observations[addr], clock)
		if err != nil {
			return err
		}
		if layer.Risk <= 0 {
			continue
		}
		if origins := engine.Origins(addr); len(origins) > 0 {
			if err := v.emit(addr, layer.Risk, layer.Families, origins); err != nil {
				return err
			}
		}
	}
	return v.ctx.Err()
}

// WalkRoutedExactRisks uses the ordinary origin index, timestamp admission,
// independent-family scoring and canonical address order. It streams directly
// into the global ASN accumulator without constructing unrelated lookup tables.
func WalkRoutedExactRisks(ctx context.Context, policy Policy, evidence []Evidence, origins []OriginMapping, clock time.Time, emit func(netip.Addr, float64, []string, []uint32) error) error {
	if ctx == nil || emit == nil {
		return errors.New("exact risk sink is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, v := range evidence {
		if v.Scope != Exact || !v.Current || !v.Address.IsValid() || v.Address.Zone() != "" {
			return errors.New("routed exact risk requires current exact input")
		}
	}
	_, err := newEngine(policy, evidence, nil, origins, clock, &exactRiskVisitor{ctx: ctx, emit: emit})
	return err
}

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
	return ASNContext{risk, confidence, p.Weights[2] * confidence * risk, true, uint8(min(families, 4))}
}
