package intelligence

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type RecordKind uint8

const (
	RecordEvidence RecordKind = iota + 1
	RecordCoverage
	RecordOrigins
	RecordGeo
	RecordUsage
	RecordVRP
	RecordPath
	RecordRelationship
	RecordASNIdentity
)

type ScopedUsage struct {
	Prefix   netip.Prefix
	Evidence UsageEvidence
}
type ScopedPath struct {
	Prefix      netip.Prefix
	Observation PathObservation
}
type RelationshipRecord struct {
	From, To uint32
	Relation Relation
}

// NormalizedRecord is a versioned tagged union; exactly one payload is allowed.
// It has no URI, port, protocol, credential, source URL, or raw publisher field.
type NormalizedRecord struct {
	Version      uint16
	Kind         RecordKind
	Evidence     *Evidence            `json:",omitempty"`
	Coverage     *Coverage            `json:",omitempty"`
	Origins      *OriginMapping       `json:",omitempty"`
	Geo          *GeoEvidence         `json:",omitempty"`
	Usage        *ScopedUsage         `json:",omitempty"`
	VRP          *VRP                 `json:",omitempty"`
	Path         *ScopedPath          `json:",omitempty"`
	Relationship *RelationshipRecord  `json:",omitempty"`
	ASNIdentity  *ASNIdentityEvidence `json:",omitempty"`
}

func (r NormalizedRecord) Validate() error {
	present := [9]bool{r.Evidence != nil, r.Coverage != nil, r.Origins != nil, r.Geo != nil, r.Usage != nil, r.VRP != nil, r.Path != nil, r.Relationship != nil, r.ASNIdentity != nil}
	count := 0
	for _, yes := range present {
		if yes {
			count++
		}
	}
	if r.Version != 3 || r.Kind < 1 || r.Kind > 9 || count != 1 || !present[int(r.Kind)-1] {
		return errors.New("normalized record union invalid")
	}
	return nil
}

type SourcePolicy struct {
	ID, Family, Admission, ProofKind string
	FixtureTested, RightsReviewed    bool
	AttributionRequired              *bool
	Attribution                      *DatasetAttribution
	ParserVersion, SchemaVersion     uint32
	MaxAge                           time.Duration
	Subscription, CompleteCoverage   bool
	Weight                           float64
	Dependencies                     []string
}
type SourceSnapshot struct {
	ID                                                    string
	PayloadHash, ProofPayloadHash                         [32]byte
	NormalizationPolicyHash                               [32]byte
	ParserVersion, SchemaVersion                          uint32
	PublishedAt                                           time.Time
	ProofKind                                             string
	PayloadVerified, SchemaVerified, ImmutableCommitBound bool
	Records                                               []NormalizedRecord
	ASNIdentityStats                                      *ASNIdentityStats `json:",omitempty"`
}
type SourceDecision struct{ ID, State, Reason string }
type StoredSource struct {
	ID          string
	Fingerprint [32]byte
	ExpiresAt   time.Time
	Records     []NormalizedRecord
	Attribution *DatasetAttribution `json:",omitempty"`
}
type BuildState struct {
	Version     uint16
	PolicyHash  [32]byte
	EvaluatedAt time.Time
	Sources     []StoredSource
}
type ReconcilePlan struct {
	State          BuildState
	Decisions      []SourceDecision
	ChangedSources []string
	FullRebuild    bool
	NextExpiry     time.Time
}

// Reconcile reevaluates unchanged payloads against clocks, rights, dependencies
// and policy before considering a cache hit. A changed source invalidates every
// dependent fact family: full rebuild is the safe initial incremental strategy.
// Time-dependent decay also requires recompilation; it is never hidden by a
// byte-identical download or HTTP 304. Object hashing can still dedupe output.
func Reconcile(previous BuildState, policies []SourcePolicy, snapshots []SourceSnapshot, now time.Time, policyHash [32]byte) (ReconcilePlan, error) {
	plan := ReconcilePlan{State: BuildState{Version: 1, PolicyHash: policyHash, EvaluatedAt: now}}
	if now.IsZero() || policyHash == ([32]byte{}) || len(policies) > 1000 || len(snapshots) > 1000 {
		return plan, errors.New("bounded explicit reconciliation inputs required")
	}
	byID := map[string]SourcePolicy{}
	for _, policy := range policies {
		if policy.ID == "" || policy.Family == "" {
			return plan, errors.New("source identity required")
		}
		if _, ok := byID[policy.ID]; ok {
			return plan, errors.New("duplicate source policy")
		}
		byID[policy.ID] = policy
	}
	payloads := map[string]SourceSnapshot{}
	for _, snapshot := range snapshots {
		if _, ok := payloads[snapshot.ID]; ok {
			return plan, errors.New("duplicate source snapshot")
		}
		payloads[snapshot.ID] = snapshot
	}
	states := map[string]SourceDecision{}
	visiting := map[string]bool{}
	expiry := map[string]time.Time{}
	var decide func(string) (SourceDecision, error)
	decide = func(id string) (SourceDecision, error) {
		if decision, ok := states[id]; ok {
			return decision, nil
		}
		policy, ok := byID[id]
		if !ok {
			return SourceDecision{id, "quarantined", "dependency_removed"}, nil
		}
		if visiting[id] {
			return SourceDecision{}, errors.New("source dependency cycle")
		}
		visiting[id] = true
		defer delete(visiting, id)
		decision := SourceDecision{id, "current", ""}
		deny := func(state, reason string) {
			if decision.State == "current" {
				decision.State, decision.Reason = state, reason
			}
		}
		if policy.Admission != "active" {
			deny("quarantined", "not_active")
		}
		creditReady := policy.AttributionRequired != nil && (!*policy.AttributionRequired || policy.Attribution != nil) && (policy.Attribution == nil || policy.Attribution.Validate() == nil)
		if !policy.FixtureTested || !policy.RightsReviewed || !creditReady || policy.ParserVersion == 0 || policy.SchemaVersion != 3 {
			deny("quarantined", "certification_or_rights_incomplete")
		}
		if policy.MaxAge <= 0 || policy.MaxAge > 720*time.Hour || !finite(policy.Weight) || policy.Weight < 0 || policy.Weight > 100 {
			deny("quarantined", "invalid_policy")
		}
		snapshot, exists := payloads[id]
		if !exists {
			deny("missing", "payload_missing")
		} else {
			if !snapshot.PayloadVerified || !snapshot.SchemaVerified {
				deny("invalid", "payload_or_schema_invalid")
			}
			if snapshot.ParserVersion != policy.ParserVersion || snapshot.SchemaVersion != policy.SchemaVersion || snapshot.NormalizationPolicyHash != policyHash {
				deny("invalid", "cached_parser_schema_or_policy_mismatch")
			}
			if snapshot.PayloadHash == ([32]byte{}) || snapshot.PayloadHash != snapshot.ProofPayloadHash || snapshot.ProofKind != policy.ProofKind {
				deny("quarantined", "publication_not_payload_bound")
			}
			switch snapshot.ProofKind {
			case "embedded", "github_release", "snapshot_metadata":
			case "github_commit":
				if !snapshot.ImmutableCommitBound {
					deny("quarantined", "mutable_commit")
				}
			default:
				deny("quarantined", "unapproved_clock")
			}
			if snapshot.PublishedAt.IsZero() || snapshot.PublishedAt.After(now.Add(24*time.Hour)) {
				deny("quarantined", "publication_clock_invalid")
			}
			deadline := snapshot.PublishedAt.Add(policy.MaxAge)
			if policy.Subscription && snapshot.PublishedAt.Add(168*time.Hour).Before(deadline) {
				deadline = snapshot.PublishedAt.Add(168 * time.Hour)
			}
			expiry[id] = deadline
			if !now.Before(deadline) {
				deny("stale", "publication_expired")
			}
		}
		for _, dependency := range policy.Dependencies {
			dependencyDecision, err := decide(dependency)
			if err != nil {
				return SourceDecision{}, err
			}
			if dependencyDecision.State != "current" {
				deny("quarantined", "dependency_not_current")
			}
		}
		states[id] = decision
		return decision, nil
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		decision, err := decide(id)
		if err != nil {
			return plan, err
		}
		plan.Decisions = append(plan.Decisions, decision)
	}
	// Identical downloaded bytes cannot become independent observations by
	// changing their configured family label. Merge the connected family groups
	// before binding any record: a family bridging two hashes also correlates all
	// of those snapshots. Only currently eligible sources participate.
	parents := make(map[string]string)
	var familyRoot func(string) string
	familyRoot = func(family string) string {
		parent, ok := parents[family]
		if !ok {
			parents[family] = family
			return family
		}
		if parent != family {
			parents[family] = familyRoot(parent)
		}
		return parents[family]
	}
	hashFamily := make(map[[32]byte]string)
	for _, id := range ids {
		if states[id].State != "current" {
			continue
		}
		family, digest := byID[id].Family, payloads[id].PayloadHash
		left := familyRoot(family)
		if previous, ok := hashFamily[digest]; ok {
			right := familyRoot(previous)
			if left < right {
				parents[right] = left
			} else {
				parents[left] = right
			}
		} else {
			hashFamily[digest] = family
		}
	}
	total := 0
	hasDecay := false
	for _, id := range ids {
		if states[id].State != "current" {
			continue
		}
		policy, snapshot := byID[id], payloads[id]
		family := familyRoot(policy.Family)
		records := make([]NormalizedRecord, 0, len(snapshot.Records))
		for _, record := range snapshot.Records {
			total++
			if total > 2_000_000 {
				return plan, errors.New("normalized record partition budget exceeded")
			}
			if err := record.Validate(); err != nil {
				return plan, err
			}
			clone, err := cloneRecord(record)
			if err != nil {
				return plan, err
			}
			switch clone.Kind {
			case RecordEvidence:
				v := clone.Evidence
				var canonical bool
				v.Signal, canonical = CanonicalSignal(v.Signal)
				if !canonical {
					return plan, errors.New("normalized signal not supported")
				}
				v.Family = family
				v.Weight = policy.Weight
				v.Current = true
				v.SourcePublishedAt = snapshot.PublishedAt
				v.SubscriptionLiteral = policy.Subscription
				// A publisher's fresh wrapper cannot date an endpoint copied from an
				// older subscription. Only a verified upstream item clock qualifies.
				if policy.Subscription && v.ItemPublishedAt.IsZero() {
					continue
				}
				if v.ItemPublishedAt.After(now.Add(24 * time.Hour)) {
					return plan, errors.New("normalized item publication is in future")
				}
				itemClock := snapshot.PublishedAt
				if !v.ItemPublishedAt.IsZero() && v.ItemPublishedAt.Before(itemClock) {
					itemClock = v.ItemPublishedAt
				}
				if policy.Subscription {
					itemExpiry := itemClock.Add(168 * time.Hour)
					if !now.Before(itemExpiry) {
						continue
					}
					if itemExpiry.Before(expiry[id]) {
						expiry[id] = itemExpiry
					}
				}
				hasDecay = true
			case RecordCoverage:
				v := clone.Coverage
				v.Family = family
				v.Current = true
				v.Complete = policy.CompleteCoverage
				v.PublishedAt = snapshot.PublishedAt
			case RecordGeo:
				v := clone.Geo
				v.Family = family
				v.Weight = policy.Weight
				v.Current = true
				v.PhysicalCountry = country(v.PhysicalCountry)
				v.RegistrationCountry = country(v.RegistrationCountry)
				v.Region = SafeLabel(v.Region)
				v.City = SafeLabel(v.City)
			case RecordUsage:
				v := clone.Usage.Evidence
				switch v.Type {
				case "", "unknown", "residential", "business", "mobile", "datacenter", "hosting", "education", "government":
				default:
					return plan, errors.New("normalized usage enum invalid")
				}
				switch v.Assignment {
				case "", "unknown", "native", "broadcast_or_routed":
				default:
					return plan, errors.New("normalized assignment enum invalid")
				}
				clone.Usage.Evidence.Family = family
				clone.Usage.Evidence.Current = true
			case RecordPath:
				clone.Path.Observation.Family = family
				clone.Path.Observation.Current = true
			case RecordASNIdentity:
				v := clone.ASNIdentity
				if !IsPublicASN(v.ASN) {
					return plan, errors.New("normalized ASN identity invalid")
				}
				v.Family = family
				v.Weight = policy.Weight
				v.Current = true
				v.Name = SafeLabel(v.Name)
				v.Organization = SafeLabel(v.Organization)
				v.Country = country(v.Country)
			}
			records = append(records, clone)
		}
		encoded, err := json.Marshal(struct {
			Policy   SourcePolicy
			Snapshot SourceSnapshot
			Records  []NormalizedRecord
		}{policy, SourceSnapshot{ID: id, PayloadHash: snapshot.PayloadHash, ProofPayloadHash: snapshot.ProofPayloadHash, NormalizationPolicyHash: snapshot.NormalizationPolicyHash, ParserVersion: snapshot.ParserVersion, SchemaVersion: snapshot.SchemaVersion, PublishedAt: snapshot.PublishedAt, ProofKind: snapshot.ProofKind, PayloadVerified: true, SchemaVerified: true, ImmutableCommitBound: snapshot.ImmutableCommitBound}, records})
		if err != nil {
			return plan, err
		}
		stored := StoredSource{ID: id, Fingerprint: sha256.Sum256(encoded), ExpiresAt: expiry[id], Records: records}
		if policy.Attribution != nil {
			credit := *policy.Attribution
			stored.Attribution = &credit
		}
		plan.State.Sources = append(plan.State.Sources, stored)
		if plan.NextExpiry.IsZero() || stored.ExpiresAt.Before(plan.NextExpiry) {
			plan.NextExpiry = stored.ExpiresAt
		}
	}
	old := map[string][32]byte{}
	for _, source := range previous.Sources {
		old[source.ID] = source.Fingerprint
	}
	current := map[string][32]byte{}
	for _, source := range plan.State.Sources {
		current[source.ID] = source.Fingerprint
		if old[source.ID] != source.Fingerprint {
			plan.ChangedSources = append(plan.ChangedSources, source.ID)
		}
	}
	for id := range old {
		if _, ok := current[id]; !ok {
			plan.ChangedSources = append(plan.ChangedSources, id)
		}
	}
	sort.Strings(plan.ChangedSources)
	plan.FullRebuild = previous.Version != 1 || previous.PolicyHash != policyHash || len(plan.ChangedSources) > 0 || hasDecay && !previous.EvaluatedAt.Equal(now)
	return plan, nil
}
func cloneRecord(input NormalizedRecord) (NormalizedRecord, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return NormalizedRecord{}, err
	}
	var output NormalizedRecord
	err = json.Unmarshal(data, &output)
	return output, err
}

// SavePrivateState has a fixed private destination and an atomic replacement;
// callers cannot accidentally choose web/public as the state-file location.
func SavePrivateState(workspace string, state BuildState) error {
	for _, source := range state.Sources {
		if source.Attribution != nil && source.Attribution.Validate() != nil {
			return errors.New("private dataset attribution invalid")
		}
	}
	root, err := filepath.Abs(workspace)
	if err != nil {
		return err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	directory := filepath.Join(root, ".atlas-private")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || relative != ".atlas-private" {
		return errors.New("private state directory escaped workspace")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > 64<<20 {
		return errors.New("private state partition exceeds 64 MiB")
	}
	file, err := os.CreateTemp(directory, "state-*.partial")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(directory, "state-v1.json"))
}
func LoadPrivateState(workspace string) (BuildState, error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return BuildState{}, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return BuildState{}, err
	}
	path := filepath.Join(root, ".atlas-private", "state-v1.json")
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return BuildState{}, err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative != filepath.Join(".atlas-private", "state-v1.json") {
		return BuildState{}, errors.New("private state file escaped workspace")
	}
	stat, err := os.Stat(resolved)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 64<<20 {
		return BuildState{}, errors.New("invalid private state file")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return BuildState{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<20+1))
	decoder.DisallowUnknownFields()
	var state BuildState
	if err := decoder.Decode(&state); err != nil {
		return BuildState{}, err
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return BuildState{}, errors.New("private state trailing data")
	}
	if state.Version != 1 {
		return BuildState{}, errors.New("unsupported private state version")
	}
	for _, source := range state.Sources {
		if source.Attribution != nil && source.Attribution.Validate() != nil {
			return BuildState{}, errors.New("private dataset attribution invalid")
		}
		for _, record := range source.Records {
			if err := record.Validate(); err != nil {
				return BuildState{}, err
			}
		}
	}
	return state, nil
}
