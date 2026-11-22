package intelligence

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SourceReceipt is private admission evidence, bound by the state seal and the
// source fingerprint. It is never a public provenance record or self-approval.
type SourceReceipt struct {
	PayloadHash, ProofPayloadHash, NormalizationPolicyHash              [32]byte
	ParserVersion, SchemaVersion                                        uint32
	PublishedAt                                                         time.Time
	ContentValidUntil                                                   time.Time `json:",omitzero"`
	ProofKind                                                           string
	PayloadVerified, SchemaVerified, ImmutableCommitBound, Subscription bool
	MRTProof                                                            *MRTSourceProof       `json:",omitempty"`
	GeoProof                                                            *GeoSourceProof       `json:",omitempty"`
	VRPProof                                                            *VRPSourceProof       `json:",omitempty"`
	CAIDAProof                                                          *CAIDASourceProof     `json:",omitempty"`
	AzureProof                                                          *AzureServiceProof    `json:",omitempty"`
	NROProof                                                            *NRORegistrationProof `json:",omitempty"`
}

func receipt(policy SourcePolicy, snapshot SourceSnapshot) *SourceReceipt {
	return &SourceReceipt{PayloadHash: snapshot.PayloadHash, ProofPayloadHash: snapshot.ProofPayloadHash, NormalizationPolicyHash: snapshot.NormalizationPolicyHash, ParserVersion: snapshot.ParserVersion, SchemaVersion: snapshot.SchemaVersion, PublishedAt: snapshot.PublishedAt, ContentValidUntil: snapshot.ContentValidUntil, ProofKind: snapshot.ProofKind, PayloadVerified: snapshot.PayloadVerified, SchemaVerified: snapshot.SchemaVerified, ImmutableCommitBound: snapshot.ImmutableCommitBound, Subscription: policy.Subscription, MRTProof: cloneMRTProof(snapshot.MRTProof), GeoProof: cloneGeoProof(snapshot.GeoProof), VRPProof: cloneVRPProof(snapshot.VRPProof), CAIDAProof: cloneCAIDAProof(snapshot.CAIDAProof), AzureProof: cloneAzureProof(snapshot.AzureProof), NROProof: cloneNROProof(snapshot.NROProof)}
}

type reconcileStorage struct {
	workspace string
	store     *RecordStore
}

// ReconcilePartitioned runs the same admission/family/record-binding logic as
// Reconcile, replacing only its storage strategy. No source is promoted here.
func ReconcilePartitioned(ctx context.Context, workspace string, previous BuildState, policies []SourcePolicy, snapshots []SourceSnapshot, now time.Time, policyHash [32]byte, limits ...RecordStoreLimits) (ReconcilePlan, error) {
	if len(limits) > 1 {
		return ReconcilePlan{}, errors.New("one private storage policy required")
	}
	bound := DefaultRecordStoreLimits()
	if len(limits) == 1 {
		bound = limits[0]
	}
	store, err := NewRecordStore(workspace, bound)
	if err != nil {
		return ReconcilePlan{}, err
	}
	return reconcile(ctx, previous, policies, snapshots, now, policyHash, &reconcileStorage{workspace, store})
}

// SavePartitionedState atomically replaces the current index and retains at
// most one still-eligible previous generation. Data objects are immutable.
func SavePartitionedState(ctx context.Context, workspace string, state, previous BuildState) error {
	if state.Version != 2 {
		return errors.New("partitioned state version required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if previous.Version == 2 {
		if _, err := VerifyPrivateStateSeal(ctx, workspace, previous.PolicyHash); err == nil {
			if err = RetainPrivateStateSeal(ctx, workspace, previous.PolicyHash); err != nil {
				return err
			}
		}
	}
	if err := SavePrivateState(workspace, state); err != nil {
		return err
	}
	retained := BuildState{Version: 2, PolicyHash: state.PolicyHash, EvaluatedAt: previous.EvaluatedAt}
	current := map[string]bool{}
	for _, source := range state.Sources {
		current[source.ID] = true
	}
	if previous.PolicyHash == state.PolicyHash && !previous.EvaluatedAt.After(state.EvaluatedAt) && state.EvaluatedAt.Sub(previous.EvaluatedAt) <= 48*time.Hour {
		for _, source := range previous.Sources {
			if current[source.ID] && state.EvaluatedAt.Before(source.ExpiresAt) {
				retained.Sources = append(retained.Sources, source)
			}
		}
	}
	data, err := json.Marshal(retained)
	if err != nil {
		return err
	}
	if len(data) > 64<<20 {
		return errors.New("retained state metadata exceeded")
	}
	return atomicPrivateBytes(workspace, "state-previous-v2.json", data)
}
func LoadRetainedPrivateState(ctx context.Context, workspace string) (BuildState, error) {
	data, err := readPrivateBounded(ctx, workspace, "state-previous-v2.json", 64<<20)
	if err != nil {
		return BuildState{}, err
	}
	var state BuildState
	err = json.Unmarshal(data, &state)
	if err != nil {
		return BuildState{}, err
	}
	if state.Version != 2 {
		return BuildState{}, errors.New("retained private state version invalid")
	}
	return state, nil
}

// PruneRecordStore removes only hash-named objects in the checked private tree.
// The current state is authoritative. A previous source may survive only while
// still eligible under the exact same policy and still present in the current
// source set; withdrawn/expired source objects never wait for a retention TTL.
func PruneRecordStore(ctx context.Context, workspace string, current, previous BuildState, now time.Time) error {
	root, err := recordDirectory(workspace, false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	currentIDs := map[string]bool{}
	for _, source := range current.Sources {
		if !now.Before(source.ExpiresAt) {
			continue
		}
		currentIDs[source.ID] = true
		for _, part := range source.RecordPartitions {
			if !validPartition(part) {
				return errors.New("invalid current partition")
			}
			keep[partitionName(part)] = true
		}
	}
	if previous.PolicyHash == current.PolicyHash && !previous.EvaluatedAt.IsZero() && !previous.EvaluatedAt.After(now) && now.Sub(previous.EvaluatedAt) <= 48*time.Hour {
		for _, source := range previous.Sources {
			if currentIDs[source.ID] && now.Before(source.ExpiresAt) {
				for _, part := range source.RecordPartitions {
					if !validPartition(part) {
						return errors.New("invalid retained partition")
					}
					keep[partitionName(part)] = true
				}
			}
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) > maxRecordPartitions {
		return errors.New("private partition inventory exceeded")
	}
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("invalid private partition entry")
		}
		if len(name) != 72 || filepath.Ext(name) != ".records" {
			if strings.HasPrefix(name, "record-") && strings.HasSuffix(name, ".partial") {
				if err = os.Remove(filepath.Join(root, name)); err != nil {
					return err
				}
				continue
			}
			return errors.New("unknown private record-store entry")
		}
		decoded, err := hex.DecodeString(name[:64])
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != name[:64] {
			return errors.New("invalid private partition name")
		}
		if !keep[name] {
			if err = os.Remove(filepath.Join(root, name)); err != nil {
				return err
			}
		}
	}
	return nil
}
