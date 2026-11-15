package admission

import (
	"context"
	"errors"

	"vansail-ip-atlas/internal/intelligence"
)

// SealPrivateState authenticates the completed intake index only while this
// engine owns the workspace writer lock. Consumers still recheck current rights,
// fixture/code bindings, source receipts, capability coverage and expiry.
func (e *Engine) SealPrivateState(ctx context.Context, binding [32]byte) error {
	if e == nil {
		return errors.New("admission engine unavailable")
	}
	e.lifecycle.RLock()
	defer e.lifecycle.RUnlock()
	if e.closed || e.lock == nil {
		return errors.New("admission writer lock required")
	}
	return intelligence.SealPrivateState(ctx, e.workspace, binding)
}
func (e *Engine) RetainPrivateStateSeal(ctx context.Context, binding [32]byte) error {
	if e == nil {
		return errors.New("admission engine unavailable")
	}
	e.lifecycle.RLock()
	defer e.lifecycle.RUnlock()
	if e.closed || e.lock == nil {
		return errors.New("admission writer lock required")
	}
	return intelligence.RetainPrivateStateSeal(ctx, e.workspace, binding)
}
