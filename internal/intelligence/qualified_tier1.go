package intelligence

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"
)

const maxQualifiedRelationshipEdges = 4_000_000

// QualifyTier1State is the production compiler entry point. Its supplied state
// must match the independently authenticated complete state/chunk identity.
func QualifyTier1State(ctx context.Context, workspace string, state BuildState, binding [32]byte, now time.Time) (*QualifiedTier1, error) {
	qualified, err := ObserveTier1State(ctx, workspace, state, binding, now)
	if err != nil {
		return nil, err
	}
	if err = qualified.Validate(state, now); err != nil {
		return nil, err
	}
	return qualified, nil
}

// ObserveTier1State records the outcome of this authenticated source epoch
// before any unrelated release-capability or output gate. A fully evaluated
// ineligible epoch returns an object with nil error; Validate rejects it for
// production. Callers must hold the admission workspace writer lock.
func ObserveTier1State(ctx context.Context, workspace string, state BuildState, binding [32]byte, now time.Time) (*QualifiedTier1, error) {
	sealed, err := VerifyPrivateStateSeal(ctx, workspace, binding)
	if err != nil {
		return nil, err
	}
	expected, err := stateIdentity(sealed)
	if err != nil {
		return nil, err
	}
	actual, err := stateIdentity(state)
	if err != nil || actual != expected {
		return nil, errors.New("Tier-1 observation must match the authenticated complete state")
	}
	return observeTier1State(ctx, workspace, sealed, binding, now, 100_000_000)
}

// QualifiedTier1 is a read-only context derived from the exact sealed private
// state. Its unexported construction/binding cannot be replaced by a caller's
// eligibility boolean or an ASN allowlist. The global graph is bounded apart
// from the materializer's 96MiB per-partition working set: at most 200k endpoint
// ASNs and 4M directed edges (conservative 512MiB Go graph allowance). Full-run
// RSS remains a measured gate rather than a consequence of this count bound.
type QualifiedTier1 struct {
	stateHash, policyHash [32]byte
	observationHash       [32]byte
	clock, expires        time.Time
	relations             *RelationshipIndex
	snapshot              Tier1Snapshot
}

func stateIdentity(state BuildState) ([32]byte, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// BuildQualifiedTier1 authenticates all chunk roots before two streaming passes:
// relationships first, then path visibility. No whole-RIB path slice is built.
func BuildQualifiedTier1(ctx context.Context, workspace string, policyHash [32]byte, now time.Time, maxWork int) (*QualifiedTier1, error) {
	state, err := VerifyPrivateStateSeal(ctx, workspace, policyHash)
	if err != nil {
		return nil, err
	}
	return observeTier1State(ctx, workspace, state, policyHash, now, maxWork)
}

func observeTier1State(ctx context.Context, workspace string, state BuildState, policyHash [32]byte, now time.Time, maxWork int) (*QualifiedTier1, error) {
	if now.IsZero() || !state.EvaluatedAt.Equal(now) || maxWork <= 0 {
		return nil, errors.New("same-clock qualified Tier-1 inputs required")
	}
	identity, err := stateIdentity(state)
	if err != nil {
		return nil, err
	}
	history, err := loadTier1History(ctx, workspace, policyHash)
	if err != nil {
		return nil, err
	}
	prior := history
	// Persist the authenticated attempt first. A crash, cancellation or graph
	// budget error cannot make an intervening evaluation disappear. This marker
	// is a state identity, never a fabricated upstream observation timestamp.
	history.Pending = identity
	if err = writeTier1History(ctx, workspace, history); err != nil {
		return nil, err
	}
	qualified := &QualifiedTier1{stateHash: identity, policyHash: policyHash, clock: now, relations: NewRelationships(true)}
	var captured time.Time
	var relevantExpiry time.Time
	type relevantSource struct {
		ID          string
		Fingerprint [32]byte
		Observed    time.Time
	}
	var relevant []relevantSource
	for _, source := range state.Sources {
		receipt := source.Receipt
		if receipt == nil || !receipt.PayloadVerified || !receipt.SchemaVerified || receipt.PayloadHash == ([32]byte{}) || receipt.PayloadHash != receipt.ProofPayloadHash || receipt.PublishedAt.IsZero() || receipt.PublishedAt.After(now.Add(24*time.Hour)) || !now.Before(source.ExpiresAt) || source.ExpiresAt.After(receipt.PublishedAt.Add(720*time.Hour)) {
			return nil, errors.New("qualified Tier-1 requires current payload-bound source receipts")
		}
		observed := receipt.PublishedAt
		if receipt.MRTProof != nil {
			content, err := receipt.MRTProof.ContentHash()
			if err != nil || content != receipt.PayloadHash || receipt.MRTProof.Through.After(now.Add(24*time.Hour)) || receipt.MRTProof.CaptureEnd().After(now.Add(24*time.Hour)) || receipt.PublishedAt.After(receipt.MRTProof.CapturedAt) {
				return nil, errors.New("Tier-1 MRT content-set receipt invalid")
			}
			observed = receipt.MRTProof.Through
		}
		if qualified.expires.IsZero() || source.ExpiresAt.Before(qualified.expires) {
			qualified.expires = source.ExpiresAt
		}
		hasPaths, hasRelationships := false, false
		err = WalkStoredSource(ctx, workspace, source, func(record NormalizedRecord) error {
			switch record.Kind {
			case RecordRelationship:
				hasRelationships = true
				v := record.Relationship
				if err := qualified.relations.Add(v.From, v.To, v.Relation); err != nil {
					return err
				}
				if len(qualified.relations.nodes) > 200_000 || len(qualified.relations.edges) > maxQualifiedRelationshipEdges {
					return ErrGraphBudget
				}
			case RecordPath:
				if !record.Path.Observation.Current || len(record.Path.Observation.Family) == 0 || len(record.Path.Observation.Family) > 256 {
					return errors.New("noncurrent Tier-1 path receipt")
				}
				hasPaths = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if hasPaths && (captured.IsZero() || observed.Before(captured)) {
			captured = observed
		}
		if hasPaths || hasRelationships {
			if source.Fingerprint == ([32]byte{}) {
				return nil, errors.New("Tier-1 relevant source fingerprint missing")
			}
			relevant = append(relevant, relevantSource{source.ID, source.Fingerprint, observed})
			if relevantExpiry.IsZero() || source.ExpiresAt.Before(relevantExpiry) {
				relevantExpiry = source.ExpiresAt
			}
		}
	}
	sort.Slice(relevant, func(i, j int) bool { return relevant[i].ID < relevant[j].ID })
	encoded, err := json.Marshal(struct {
		Policy  [32]byte
		Sources []relevantSource
	}{policyHash, relevant})
	if err != nil {
		return nil, err
	}
	qualified.observationHash = sha256.Sum256(encoded)
	var previous *Tier1Snapshot
	var anchor *tier1HistoryEpoch
	var cached *tier1HistoryEpoch
	if len(prior.Epochs) != 0 {
		epoch := prior.Epochs[0]
		if !captured.IsZero() && !epoch.PublishedAt.IsZero() && captured.Before(epoch.PublishedAt) {
			return nil, errors.New("Tier-1 actual observation epoch cannot move backwards")
		}
		if prior.Pending == ([32]byte{}) && epoch.InputHash == qualified.observationHash && epoch.PublishedAt.Equal(captured) {
			cached = &epoch
		}
		separation := captured.Sub(epoch.PublishedAt)
		if cached == nil && prior.Pending == ([32]byte{}) && epoch.Eligible && epoch.Continuity && separation >= 24*time.Hour && separation <= 720*time.Hour && now.Before(epoch.ExpiresAt) {
			anchor = &epoch
			value := Tier1Snapshot{PublishedAt: epoch.PublishedAt, PolicyHash: hex.EncodeToString(policyHash[:]), Eligible: true, RawCandidates: map[uint32]bool{}}
			for _, asn := range epoch.Candidates {
				value.RawCandidates[asn] = true
			}
			previous = &value
		}
	}
	walk := func(visit func(PathObservation) error) error {
		for _, source := range state.Sources {
			if err := WalkStoredSource(ctx, workspace, source, func(record NormalizedRecord) error {
				if record.Kind == RecordPath {
					return visit(record.Path.Observation)
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}
	qualified.snapshot, err = deriveTier1(ctx, qualified.relations, walk, captured, now, hex.EncodeToString(policyHash[:]), previous, maxWork)
	if err != nil {
		return nil, err
	}
	epoch := tier1HistoryEpoch{PublishedAt: captured, ExpiresAt: relevantExpiry, StateHash: identity, InputHash: qualified.observationHash, Eligible: qualified.snapshot.Eligible, Continuity: qualified.snapshot.Eligible, Candidates: tier1Candidates(qualified.snapshot), Stable: []uint32{}}
	if anchor != nil {
		epoch.Anchor = &tier1HistoryAnchor{PublishedAt: anchor.PublishedAt, ExpiresAt: anchor.ExpiresAt, InputHash: anchor.InputHash, StateHash: anchor.StateHash, Candidates: append([]uint32(nil), anchor.Candidates...)}
	}
	if cached != nil {
		if cached.Eligible != epoch.Eligible || !equalTier1Candidates(cached.Candidates, epoch.Candidates) {
			return nil, errors.New("identical Tier-1 input identity changed its evaluated predicates")
		}
		stable := make(map[uint32]bool, len(cached.Stable))
		if cached.Anchor != nil && now.Before(cached.Anchor.ExpiresAt) {
			epoch.Anchor = cached.Anchor
			for _, asn := range cached.Stable {
				stable[asn] = true
			}
		}
		for i := range qualified.snapshot.Results {
			r := &qualified.snapshot.Results[i]
			if qualified.snapshot.RawCandidates[r.ASN] && stable[r.ASN] {
				r.Class, r.Stability = "tier1_candidate", "stable"
			}
		}
		epoch.Continuity = cached.Continuity
	} else if prior.Pending != ([32]byte{}) && len(prior.Epochs) > 0 && prior.Epochs[0].InputHash == epoch.InputHash {
		// Reusing the same old source epoch after an interrupted critical
		// evaluation cannot resurrect that epoch as a fresh continuity anchor.
		epoch.Continuity = false
	}
	for _, r := range qualified.snapshot.Results {
		if r.Stability == "stable" {
			epoch.Stable = append(epoch.Stable, r.ASN)
		}
	}
	if len(epoch.Stable) > 0 && epoch.Anchor != nil && (qualified.expires.IsZero() || epoch.Anchor.ExpiresAt.Before(qualified.expires)) {
		qualified.expires = epoch.Anchor.ExpiresAt
	}
	history.Pending = [32]byte{}
	history.Epochs = []tier1HistoryEpoch{epoch}
	if err = writeTier1History(ctx, workspace, history); err != nil {
		return nil, err
	}
	return qualified, nil
}

func (q *QualifiedTier1) Validate(state BuildState, now time.Time) error {
	if err := q.ValidateObservation(state, now); err != nil {
		return err
	}
	if !q.snapshot.Eligible {
		return errors.New("qualified Tier-1 observations unavailable")
	}
	return nil
}

// ValidateObservation authenticates the complete state and lifetime without
// asserting enough observations for a Tier-1 classification. An unavailable
// observation remains unknown and still records an intervening failed epoch.
func (q *QualifiedTier1) ValidateObservation(state BuildState, now time.Time) error {
	if q == nil || q.stateHash == ([32]byte{}) || q.policyHash == ([32]byte{}) || q.policyHash != state.PolicyHash || !state.EvaluatedAt.Equal(q.clock) || now.Before(q.clock) || !now.Before(q.expires) {
		return errors.New("authenticated Tier-1 observation binding or lifetime invalid")
	}
	identity, err := stateIdentity(state)
	if err != nil || identity != q.stateHash {
		return errors.New("authenticated Tier-1 observation does not match the complete state")
	}
	return nil
}

// MaterializationIdentity binds every derived classification, including real
// history-dependent stability. The normalized state alone cannot distinguish
// those outcomes. This private digest is not source or release qualification;
// callers must still validate the observation against the complete state.
func (q *QualifiedTier1) MaterializationIdentity() ([32]byte, error) {
	if q == nil || q.stateHash == ([32]byte{}) || q.policyHash == ([32]byte{}) || q.observationHash == ([32]byte{}) || q.clock.IsZero() || !q.clock.Before(q.expires) {
		return [32]byte{}, errors.New("authenticated Tier-1 materialization identity required")
	}
	data, err := json.Marshal(struct {
		Version         uint16
		StateHash       [32]byte
		PolicyHash      [32]byte
		ObservationHash [32]byte
		Clock, Expires  time.Time
		Snapshot        Tier1Snapshot
	}{1, q.stateHash, q.policyHash, q.observationHash, q.clock, q.expires, q.snapshot})
	if err != nil {
		return [32]byte{}, err
	}
	// Relationships are already bound by the complete state and compiler code.
	return sha256.Sum256(append([]byte("tier1-materialization-v1\x00"), data...)), nil
}

func (q *QualifiedTier1) Result(asn uint32) Tier1Result {
	if q != nil && q.snapshot.Eligible {
		i := sort.Search(len(q.snapshot.Results), func(i int) bool { return q.snapshot.Results[i].ASN >= asn })
		if i < len(q.snapshot.Results) && q.snapshot.Results[i].ASN == asn {
			return q.snapshot.Results[i]
		}
	}
	return Tier1Result{ASN: asn, Class: "unknown", Stability: "unavailable"}
}

// ValidUntil includes the authenticated prior anchor's actual source expiry
// whenever a stable candidacy depends on that anchor.
func (q *QualifiedTier1) ValidUntil() time.Time {
	if q == nil {
		return time.Time{}
	}
	return q.expires
}

func (q *QualifiedTier1) Relation(from, to uint32) Relation {
	if q == nil {
		return UnknownRelation
	}
	return q.relations.Relation(from, to)
}

type tier1HistoryEpoch struct {
	PublishedAt          time.Time
	ExpiresAt            time.Time
	StateHash            [32]byte
	InputHash            [32]byte
	Eligible, Continuity bool
	Candidates           []uint32
	Stable               []uint32
	Anchor               *tier1HistoryAnchor `json:",omitempty"`
}
type tier1HistoryAnchor struct {
	PublishedAt, ExpiresAt time.Time
	InputHash, StateHash   [32]byte
	Candidates             []uint32
}
type tier1History struct {
	Version    uint16
	PolicyHash [32]byte
	Epochs     []tier1HistoryEpoch
	Pending    [32]byte
	MAC        [32]byte
}

const tier1HistoryName = "tier1-history-v2.json"
const maxTier1HistoryBytes = 8 << 20 // raw/stable/actual-anchor sets, each <=200k ASNs

func tier1Candidates(snapshot Tier1Snapshot) []uint32 {
	out := make([]uint32, 0, len(snapshot.RawCandidates))
	for asn := range snapshot.RawCandidates {
		out = append(out, asn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func equalTier1Candidates(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func validTier1Candidates(values []uint32) bool {
	if len(values) > 200_000 {
		return false
	}
	var last uint32
	for _, asn := range values {
		if !IsPublicASN(asn) || asn <= last {
			return false
		}
		last = asn
	}
	return true
}
func tier1StableCandidates(snapshot Tier1Snapshot) []uint32 {
	var out []uint32
	for _, r := range snapshot.Results {
		if r.Stability == "stable" {
			out = append(out, r.ASN)
		}
	}
	return out
}

func tier1HistoryMAC(key []byte, history tier1History) [32]byte {
	history.MAC = [32]byte{}
	data, _ := json.Marshal(history)
	h := hmac.New(sha256.New, key)
	h.Write([]byte("VanSail/Tier1-history/v2\x00"))
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func loadTier1History(ctx context.Context, workspace string, policyHash [32]byte) (tier1History, error) {
	blank := tier1History{Version: 2, PolicyHash: policyHash}
	// Legacy v1 only recorded successfully published epochs and lacks an
	// idempotent outcome. Keep that audit file, but never import it as evidence.
	data, err := readPrivateBounded(ctx, workspace, tier1HistoryName, maxTier1HistoryBytes)
	if os.IsNotExist(err) {
		return blank, nil
	}
	if err != nil {
		return blank, err
	}
	var history tier1History
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&history); err != nil || history.Version != 2 || len(history.Epochs) > 1 {
		return blank, errors.New("private Tier-1 history invalid")
	}
	canonical, err := json.Marshal(history)
	if err != nil || !bytes.Equal(canonical, data) {
		return blank, errors.New("private Tier-1 history serialization invalid")
	}
	key, err := readPrivateBounded(ctx, workspace, "state-seal.key", 32)
	if err != nil || len(key) != 32 {
		return blank, errors.New("private Tier-1 history key invalid")
	}
	expected := tier1HistoryMAC(key, history)
	if !hmac.Equal(expected[:], history.MAC[:]) {
		return blank, errors.New("private Tier-1 history authentication failed")
	}
	for _, epoch := range history.Epochs {
		if epoch.StateHash == ([32]byte{}) || epoch.InputHash == ([32]byte{}) || epoch.Eligible && (epoch.PublishedAt.IsZero() || !epoch.ExpiresAt.After(epoch.PublishedAt)) || epoch.Continuity && !epoch.Eligible || !epoch.Eligible && (len(epoch.Candidates) > 0 || len(epoch.Stable) > 0 || epoch.Anchor != nil) || !epoch.Continuity && len(epoch.Stable) > 0 || !validTier1Candidates(epoch.Candidates) || len(epoch.Stable) > len(epoch.Candidates) {
			return blank, errors.New("private Tier-1 history epoch invalid")
		}
		if a := epoch.Anchor; a != nil {
			separation := epoch.PublishedAt.Sub(a.PublishedAt)
			if !epoch.Eligible || a.PublishedAt.IsZero() || !a.ExpiresAt.After(a.PublishedAt) || a.InputHash == ([32]byte{}) || a.StateHash == ([32]byte{}) || a.InputHash == epoch.InputHash || separation < 24*time.Hour || separation > 720*time.Hour || !validTier1Candidates(a.Candidates) {
				return blank, errors.New("private Tier-1 actual anchor invalid")
			}
		}
		if len(epoch.Stable) > 0 && epoch.Anchor == nil {
			return blank, errors.New("private Tier-1 stable result has no actual anchor")
		}
		var last uint32
		for _, asn := range epoch.Stable {
			i := sort.Search(len(epoch.Candidates), func(i int) bool { return epoch.Candidates[i] >= asn })
			if asn <= last || i == len(epoch.Candidates) || epoch.Candidates[i] != asn {
				return blank, errors.New("private Tier-1 stable result invalid")
			}
			a := epoch.Anchor
			j := sort.Search(len(a.Candidates), func(i int) bool { return a.Candidates[i] >= asn })
			if j == len(a.Candidates) || a.Candidates[j] != asn {
				return blank, errors.New("private Tier-1 stable result absent from actual anchor")
			}
			last = asn
		}
	}
	if history.PolicyHash != policyHash {
		return blank, nil // A policy/code/catalog change cannot borrow old stability.
	}
	return history, nil
}

// SaveQualifiedTier1History is an idempotent compatibility integrity check.
// ObserveTier1State already persisted the actual outcome before release gates;
// publication success must never advance or replace the source-epoch history.
func SaveQualifiedTier1History(ctx context.Context, workspace string, qualified *QualifiedTier1) error {
	if qualified == nil || !qualified.snapshot.Eligible {
		return errors.New("qualified Tier-1 context required")
	}
	return VerifyTier1ObservationHistory(ctx, workspace, qualified)
}

// VerifyTier1ObservationHistory checks the persisted outcome, including a
// truthful unavailable observation, without advancing or rewriting history.
func VerifyTier1ObservationHistory(ctx context.Context, workspace string, qualified *QualifiedTier1) error {
	if qualified == nil {
		return errors.New("authenticated Tier-1 observation required")
	}
	state, err := VerifyPrivateStateSeal(ctx, workspace, qualified.policyHash)
	if err != nil {
		return err
	}
	if err = qualified.ValidateObservation(state, qualified.clock); err != nil {
		return err
	}
	history, err := loadTier1History(ctx, workspace, qualified.policyHash)
	if err != nil {
		return err
	}
	if history.Pending != ([32]byte{}) || len(history.Epochs) != 1 || history.Epochs[0].StateHash != qualified.stateHash || history.Epochs[0].InputHash != qualified.observationHash || !history.Epochs[0].PublishedAt.Equal(qualified.snapshot.PublishedAt) || history.Epochs[0].Eligible != qualified.snapshot.Eligible || !equalTier1Candidates(history.Epochs[0].Candidates, tier1Candidates(qualified.snapshot)) || !equalTier1Candidates(history.Epochs[0].Stable, tier1StableCandidates(qualified.snapshot)) {
		return errors.New("Tier-1 evaluation outcome changed before publication")
	}
	return nil
}

func writeTier1History(ctx context.Context, workspace string, history tier1History) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := readPrivateBounded(ctx, workspace, "state-seal.key", 32)
	if err != nil || len(key) != 32 {
		return errors.New("private Tier-1 history key invalid")
	}
	history.MAC = tier1HistoryMAC(key, history)
	data, err := json.Marshal(history)
	if err != nil || len(data) > maxTier1HistoryBytes {
		return errors.New("bounded Tier-1 history bytes exceeded")
	}
	return atomicPrivateBytes(workspace, tier1HistoryName, data)
}
