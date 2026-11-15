package intelligence

import (
	"context"
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
	Prefix     netip.Prefix
	ASN        uint32    `json:",omitempty"`
	ObservedAt time.Time `json:",omitzero"`
	Evidence   UsageEvidence
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
	Version         uint16
	Kind            RecordKind
	Evidence        *Evidence            `json:",omitempty"`
	Coverage        *Coverage            `json:",omitempty"`
	Origins         *OriginMapping       `json:",omitempty"`
	Geo             *GeoEvidence         `json:",omitempty"`
	Usage           *ScopedUsage         `json:",omitempty"`
	VRP             *VRP                 `json:",omitempty"`
	Path            *ScopedPath          `json:",omitempty"`
	Relationship    *RelationshipRecord  `json:",omitempty"`
	ASNIdentity     *ASNIdentityEvidence `json:",omitempty"`
	MRTOriginatedAt *time.Time           `json:",omitempty"` // private route-heard clock, never a public fact
	MRT             *MRTRouteIdentity    `json:",omitempty"`
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
	if r.MRTOriginatedAt != nil && (r.MRTOriginatedAt.IsZero() || r.Kind != RecordOrigins && r.Kind != RecordPath) {
		return errors.New("private MRT originated clock invalid")
	}
	if r.MRT != nil && (r.Kind != RecordOrigins && r.Kind != RecordPath || r.MRT.PeerTable == 0 || r.MRT.CapturedAt.IsZero() || !r.MRT.AddPath && r.MRT.PathID != 0) {
		return errors.New("private MRT route identity invalid")
	}
	if u := r.Usage; u != nil {
		if u.ASN != 0 {
			if !IsPublicASN(u.ASN) || u.Prefix.IsValid() || u.ObservedAt.IsZero() || u.Evidence.Contextual {
				return errors.New("ASN usage requires an exclusive ASN and observed clock")
			}
		} else if !u.Prefix.IsValid() {
			return errors.New("prefix usage requires a prefix")
		}
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
	ContentValidUntil                                     time.Time `json:",omitzero"`
	ProofKind                                             string
	PayloadVerified, SchemaVerified, ImmutableCommitBound bool
	Records                                               []NormalizedRecord
	RecordPartitions                                      []RecordPartition `json:",omitempty"`
	ASNIdentityStats                                      *ASNIdentityStats `json:",omitempty"`
	MRTProof                                              *MRTSourceProof   `json:",omitempty"`
	GeoProof                                              *GeoSourceProof   `json:",omitempty"`
	VRPProof                                              *VRPSourceProof   `json:",omitempty"`
}
type SourceDecision struct{ ID, State, Reason string }
type StoredSource struct {
	ID               string
	Fingerprint      [32]byte
	ExpiresAt        time.Time
	Records          []NormalizedRecord
	RecordPartitions []RecordPartition   `json:",omitempty"`
	Attribution      *DatasetAttribution `json:",omitempty"`
	Receipt          *SourceReceipt      `json:",omitempty"`
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
	return reconcile(context.Background(), previous, policies, snapshots, now, policyHash, nil)
}

func reconcile(ctx context.Context, previous BuildState, policies []SourcePolicy, snapshots []SourceSnapshot, now time.Time, policyHash [32]byte, storage *reconcileStorage) (ReconcilePlan, error) {
	plan := ReconcilePlan{State: BuildState{Version: 1, PolicyHash: policyHash, EvaluatedAt: now}}
	if storage != nil {
		plan.State.Version = 2
	}
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
			if snapshot.MRTProof != nil {
				content, err := snapshot.MRTProof.ContentHash()
				if err != nil || content != snapshot.PayloadHash || snapshot.ProofKind != "embedded" || snapshot.PublishedAt.After(snapshot.MRTProof.CapturedAt) || snapshot.MRTProof.Through.After(now.Add(24*time.Hour)) || snapshot.MRTProof.CaptureEnd().After(now.Add(24*time.Hour)) {
					deny("quarantined", "mrt_content_set_not_bound")
				}
			}
			if snapshot.GeoProof != nil {
				if _, err := snapshot.GeoProof.ContentHash(); err != nil || snapshot.PublishedAt.After(snapshot.GeoProof.UpstreamClock) || snapshot.GeoProof.UpstreamClock.After(now.Add(24*time.Hour)) {
					deny("invalid", "geolocation_payload_or_clock_invalid")
				}
			}
			if snapshot.VRPProof != nil && snapshot.VRPProof.Validate(now, snapshot.PublishedAt, snapshot.ContentValidUntil) != nil {
				deny("quarantined", "complete_vrp_snapshot_not_bound")
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
			if !snapshot.ContentValidUntil.IsZero() && snapshot.ContentValidUntil.Before(deadline) {
				deadline = snapshot.ContentValidUntil
			}
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
		family := byID[id].Family
		snapshot := payloads[id]
		identities := [][32]byte{snapshot.PayloadHash}
		if snapshot.GeoProof != nil {
			digest, err := snapshot.GeoProof.ContentHash()
			if err != nil {
				return plan, err
			}
			identities = append(identities, digest)
		}
		for _, digest := range identities {
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
		var writer *RecordWriter
		var parts []RecordPartition
		var vrpCount uint64
		var vrpMinimumExpiry time.Time
		if storage != nil {
			writer = storage.store.Writer(ctx)
			defer writer.Abort()
		}
		process := func(record NormalizedRecord) error {
			total++
			if storage == nil && total > 2_000_000 {
				return errors.New("normalized record partition budget exceeded")
			}
			if err := record.Validate(); err != nil {
				return err
			}
			if snapshot.VRPProof != nil && snapshot.VRPProof.Version == 2 && record.Kind != RecordVRP {
				return errors.New("complete VRP observation snapshot contains another record kind")
			}
			clone, err := cloneRecord(record)
			if err != nil {
				return err
			}
			switch clone.Kind {
			case RecordEvidence:
				v := clone.Evidence
				var canonical bool
				v.Signal, canonical = CanonicalSignal(v.Signal)
				if !canonical {
					return errors.New("normalized signal not supported")
				}
				v.Family = family
				v.Weight = policy.Weight
				v.Current = true
				v.SourcePublishedAt = snapshot.PublishedAt
				v.SubscriptionLiteral = policy.Subscription
				// A publisher's fresh wrapper cannot date an endpoint copied from an
				// older subscription. Only a verified upstream item clock qualifies.
				if policy.Subscription && v.ItemPublishedAt.IsZero() {
					return nil
				}
				if v.ItemPublishedAt.After(now.Add(24 * time.Hour)) {
					return errors.New("normalized item publication is in future")
				}
				itemClock := snapshot.PublishedAt
				if !v.ItemPublishedAt.IsZero() && v.ItemPublishedAt.Before(itemClock) {
					itemClock = v.ItemPublishedAt
				}
				{
					maximum := policy.MaxAge
					if policy.Subscription && maximum > 168*time.Hour {
						maximum = 168 * time.Hour
					}
					itemExpiry := itemClock.Add(maximum)
					if !now.Before(itemExpiry) {
						return nil
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
				if observed := clone.Usage.ObservedAt; !observed.IsZero() {
					if observed.After(now.Add(24 * time.Hour)) {
						return errors.New("usage observation is in future")
					}
					deadline := observed.Add(policy.MaxAge)
					if !now.Before(deadline) {
						return nil
					}
					if deadline.Before(expiry[id]) {
						expiry[id] = deadline
					}
				}
				v := clone.Usage.Evidence
				switch v.Type {
				case "", "unknown", "residential", "business", "mobile", "datacenter", "hosting", "education", "government":
				default:
					return errors.New("normalized usage enum invalid")
				}
				switch v.Assignment {
				case "", "unknown", "native", "broadcast_or_routed":
				default:
					return errors.New("normalized assignment enum invalid")
				}
				clone.Usage.Evidence.Family = family
				clone.Usage.Evidence.Current = true
			case RecordPath:
				clone.Path.Observation.Family = family
				clone.Path.Observation.Current = true
			case RecordASNIdentity:
				v := clone.ASNIdentity
				if !IsPublicASN(v.ASN) {
					return errors.New("normalized ASN identity invalid")
				}
				v.Family = family
				v.Weight = policy.Weight
				v.Current = true
				v.Name = SafeLabel(v.Name)
				v.Organization = SafeLabel(v.Organization)
				v.Country = country(v.Country)
			case RecordVRP:
				vrpCount++
				until := clone.VRP.ValidUntil
				if proof := snapshot.VRPProof; proof != nil && proof.Version == 2 {
					// The row describes the original publisher snapshot, not a
					// renewed authorization at intake or materialization time.
					if !until.After(proof.ObservedAt) || until.Before(proof.CoverageValidUntil) {
						return errors.New("VRP observation expiry does not bind the publisher snapshot")
					}
					if vrpMinimumExpiry.IsZero() || until.Before(vrpMinimumExpiry) {
						vrpMinimumExpiry = until
					}
				} else if !until.IsZero() {
					if snapshot.ContentValidUntil.IsZero() || until.Before(snapshot.ContentValidUntil) || !now.Before(until) {
						return errors.New("VRP expiry is missing, expired or exceeds its source bound")
					}
				}
			}
			if writer != nil {
				return writer.Append(clone)
			}
			records = append(records, clone)
			return nil
		}
		if storage != nil {
			if err := WalkStoredSource(ctx, storage.workspace, StoredSource{Records: snapshot.Records, RecordPartitions: snapshot.RecordPartitions}, process); err != nil {
				return plan, err
			}
			var err error
			parts, err = writer.Finish()
			if err != nil {
				return plan, err
			}
		} else {
			if len(snapshot.RecordPartitions) > 0 {
				return plan, errors.New("partitioned input requires streamed reconciliation")
			}
			for _, record := range snapshot.Records {
				if err := process(record); err != nil {
					return plan, err
				}
			}
		}
		if proof := snapshot.VRPProof; proof != nil {
			if proof.Version == 2 {
				if vrpCount != proof.RetainedRows || !vrpMinimumExpiry.Equal(proof.CoverageValidUntil) {
					return plan, errors.New("complete VRP observation proof differs from retained rows or expiry")
				}
			} else if vrpCount != proof.AcceptedRows {
				return plan, errors.New("complete VRP proof differs from retained record count")
			}
		}
		encoded, err := json.Marshal(struct {
			Policy           SourcePolicy
			Snapshot         SourceSnapshot
			Records          []NormalizedRecord
			RecordPartitions []RecordPartition `json:",omitempty"`
		}{policy, SourceSnapshot{ID: id, PayloadHash: snapshot.PayloadHash, ProofPayloadHash: snapshot.ProofPayloadHash, NormalizationPolicyHash: snapshot.NormalizationPolicyHash, ParserVersion: snapshot.ParserVersion, SchemaVersion: snapshot.SchemaVersion, PublishedAt: snapshot.PublishedAt, ContentValidUntil: snapshot.ContentValidUntil, ProofKind: snapshot.ProofKind, PayloadVerified: true, SchemaVerified: true, ImmutableCommitBound: snapshot.ImmutableCommitBound, MRTProof: cloneMRTProof(snapshot.MRTProof), GeoProof: cloneGeoProof(snapshot.GeoProof), VRPProof: cloneVRPProof(snapshot.VRPProof)}, records, parts})
		if err != nil {
			return plan, err
		}
		stored := StoredSource{ID: id, Fingerprint: sha256.Sum256(encoded), ExpiresAt: expiry[id], Records: records, RecordPartitions: parts, Receipt: receipt(policy, snapshot)}
		if policy.Attribution != nil {
			credit := *policy.Attribution
			if credit.Logo != nil {
				logo := *credit.Logo
				credit.Logo = &logo
			}
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
	plan.FullRebuild = previous.Version != plan.State.Version || previous.PolicyHash != policyHash || len(plan.ChangedSources) > 0 || hasDecay && !previous.EvaluatedAt.Equal(now)
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
	if state.Version != 1 && state.Version != 2 {
		return BuildState{}, errors.New("unsupported private state version")
	}
	for _, source := range state.Sources {
		if len(source.RecordPartitions) > maxRecordPartitions || len(source.Records) > 0 && len(source.RecordPartitions) > 0 {
			return BuildState{}, errors.New("invalid private record storage")
		}
		for _, part := range source.RecordPartitions {
			if !validPartition(part) {
				return BuildState{}, errors.New("invalid private partition descriptor")
			}
		}
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
