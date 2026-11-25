package pipeline

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// The immutable normalized source walk and ordinary leaf collector validate
// and size every input. Only these records can contribute routed exact risk.
func exactRiskInput(record intelligence.NormalizedRecord) bool {
	return record.Kind == intelligence.RecordOrigins || record.Kind == intelligence.RecordEvidence && record.Evidence != nil && record.Evidence.Scope == intelligence.Exact
}

// The full policy is validated by the builder. These are the inputs to the
// exact layer's risk and positive family set, including observation admission.
func exactRiskDependencies(policy intelligence.Policy, clock time.Time) ([32]byte, error) {
	type signal struct {
		Beta, HalfLifeHours, Severity float64
		MergeInto                     intelligence.Signal
	}
	signals := make(map[intelligence.Signal]signal, len(policy.Signals))
	for name, v := range policy.Signals {
		signals[name] = signal{v.Beta, v.HalfLifeHours, v.Severity, v.MergeInto}
	}
	return spatialReuseKey("exact-risk-dependencies", struct {
		Clock                                    time.Time
		Signals                                  map[intelligence.Signal]signal
		Order                                    []intelligence.Signal
		Specificity, SubscriptionSpecificity     float64
		MaxAge, SubscriptionAge, FutureTolerance time.Duration
	}{clock, signals, policy.Order, policy.Specificity[intelligence.Exact], policy.SubscriptionSpecificity, policy.MaxAge, policy.SubscriptionAge, policy.FutureTolerance})
}

// The normal collector charged the full input and role joins to its working
// bounds. The public pass separately validates and scores contextual inputs.
func walkRiskInputs(ctx context.Context, state intelligence.BuildState, policy intelligence.Policy, clock time.Time, emit func(netip.Addr, float64, []string, []uint32) error) error {
	if state.Version != 1 || len(state.Sources) != 1 || state.PolicyHash == ([32]byte{}) || !state.EvaluatedAt.Equal(clock) {
		return errors.New("invalid current exact risk leaf")
	}
	source := state.Sources[0]
	if source.ID == "" || len(source.ID) > 256 || source.Fingerprint == ([32]byte{}) || !clock.Before(source.ExpiresAt) {
		return errors.New("invalid exact risk source")
	}
	var evidence []intelligence.Evidence
	var origins []intelligence.OriginMapping
	for _, r := range source.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !exactRiskInput(r) {
			continue
		}
		if err := r.Validate(); err != nil {
			return err
		}
		switch r.Kind {
		case intelligence.RecordEvidence:
			evidence = append(evidence, *r.Evidence)
		case intelligence.RecordOrigins:
			origins = append(origins, *r.Origins)
		}
	}
	return intelligence.WalkRoutedExactRisks(ctx, policy, evidence, origins, clock, emit)
}

// visitRisk runs after the full bounded leaf has been authenticated. An edit
// to unrelated rows may miss the physical shortcut while preserving this key.
func (r *bulkLeafReuse) visitRisk(ctx context.Context, bucket *bulkBucket, state intelligence.BuildState, policy intelligence.Policy, clock time.Time) error {
	if bucket.riskDigest == ([32]byte{}) {
		return errors.New("missing collected exact risk inputs")
	}
	key, err := spatialReuseKey("exact-risk-inputs", struct {
		Policy, Inputs [32]byte
		Prefix         netip.Prefix
	}{r.riskPolicy, bucket.riskDigest, bucket.prefix})
	if err != nil {
		return err
	}
	r.riskInput = key
	entry, hit, err := r.spool.reuse.Lookup(ctx, "risk-input", key)
	if err != nil {
		return err
	}
	if hit {
		r.riskHit = entry.Leaf
		return r.spool.replayRisk(ctx, entry.Leaf.Stream, r.risk)
	}
	return walkRiskInputs(ctx, state, policy, clock, func(addr netip.Addr, score float64, families []string, origins []uint32) error {
		event := spatialRiskEvent{Address: addr, Risk: score, Families: families, Origins: origins}
		if err := r.recordRisk(event); err != nil {
			return err
		}
		return r.risk(event)
	})
}

// Retain the semantic entry even when the full physical scope was unchanged.
// A later edit can then recognize its current exact and route inputs. Supplying
// the verified physical object is required when creating either alias.
func (r *bulkLeafReuse) retainRiskInput(ctx context.Context, entry spatialCacheEntry, files map[[32]byte]string) error {
	if entry.Leaf.RiskInput == ([32]byte{}) {
		return nil
	}
	stream := entry.Leaf.Stream
	if stream != (spatialCacheStream{}) && len(files) == 0 {
		path, err := r.spool.reuse.ObjectPath(stream.SHA256)
		if err != nil {
			return err
		}
		files = map[[32]byte]string{stream.SHA256: path}
	}
	alias := spatialCacheEntry{Domain: "risk-input", Key: entry.Leaf.RiskInput, Leaf: &spatialCacheLeaf{Stream: stream}}
	_, err := r.spool.reuse.Retain(ctx, alias, files)
	return err
}
