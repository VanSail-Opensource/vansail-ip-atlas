package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/admission"
	"vansail-ip-atlas/internal/intelligence"
)

// These intentionally unqualified engineering sources can authenticate a real
// unavailable Tier-1 observation, but cannot pass production source controls.
func benchmarkObservationFixture(t *testing.T) (string, intelligence.BuildState) {
	t.Helper()
	root, state := stateCommandFixture(t)
	state.Version = 2
	store, err := intelligence.NewRecordStore(root, intelligence.DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	for i := range state.Sources {
		source := &state.Sources[i]
		writer := store.Writer(context.Background())
		for _, record := range source.Records {
			if err = writer.Append(record); err != nil {
				t.Fatal(err)
			}
		}
		source.RecordPartitions, err = writer.Finish()
		if err != nil {
			t.Fatal(err)
		}
		source.Records = nil
		payload := sha256.Sum256([]byte(source.ID))
		source.Receipt = &intelligence.SourceReceipt{PayloadHash: payload, ProofPayloadHash: payload, NormalizationPolicyHash: state.PolicyHash, PublishedAt: state.EvaluatedAt, PayloadVerified: true, SchemaVerified: true}
	}
	if err = intelligence.SavePrivateState(root, state); err != nil {
		t.Fatal(err)
	}
	engine, err := admission.New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if err = engine.SealPrivateState(context.Background(), state.PolicyHash); err != nil {
		t.Fatal(err)
	}
	return root, state
}

func benchmarkTestArguments(root string, clock time.Time) []string {
	return []string{"-workspace", root, "-out", "build-private/isolated", "-scenario", "cold_full", "-clock", strconv.FormatInt(clock.Unix(), 10)}
}

func assertBenchmarkLockReleased(t *testing.T, root string) {
	t.Helper()
	engine, err := admission.New(root)
	if err != nil {
		t.Fatal("benchmark retained the source writer lock", err)
	}
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBenchmarkSetupRequiresExclusiveSourceWriter(t *testing.T) {
	root, state := benchmarkObservationFixture(t)
	owner, err := admission.New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err = benchmarkState(context.Background(), benchmarkTestArguments(root, state.EvaluatedAt)); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatal("benchmark did not reject the competing source writer", err)
	}
	if _, err = os.Stat(filepath.Join(root, ".atlas-private", "tier1-history-v2.json")); !os.IsNotExist(err) {
		t.Fatal("competing benchmark changed observation history", err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal("benchmark changed the other writer's lock", err)
	}
	assertBenchmarkLockReleased(t, root)
}

func TestBenchmarkSetupRecordsObservationBeforeQualificationFailure(t *testing.T) {
	root, state := benchmarkObservationFixture(t)
	private := filepath.Join(root, ".atlas-private")
	before := map[string]string{}
	for _, name := range []string{"state-v1.json", "state-seal-v2.json", "state-seal.key"} {
		data, err := os.ReadFile(filepath.Join(private, name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = string(data)
	}
	// This fixture deliberately lacks the complete production configuration and
	// capabilities. The authenticated epoch must be observed before that gate.
	if err := benchmarkState(context.Background(), benchmarkTestArguments(root, state.EvaluatedAt)); err == nil || !strings.Contains(err.Error(), "closed configuration contracts") {
		t.Fatal("unqualified source fixture escaped its production controls", err)
	}
	data, err := os.ReadFile(filepath.Join(private, "tier1-history-v2.json"))
	if err != nil {
		t.Fatal("later qualification failure suppressed the source observation", err)
	}
	var history struct {
		Pending [32]byte
		Epochs  []struct {
			StateHash          [32]byte
			Eligible           bool
			Candidates, Stable []uint32
		}
	}
	stateBytes, _ := json.Marshal(state)
	if err = json.Unmarshal(data, &history); err != nil || history.Pending != ([32]byte{}) || len(history.Epochs) != 1 || history.Epochs[0].StateHash != sha256.Sum256(stateBytes) || history.Epochs[0].Eligible || len(history.Epochs[0].Candidates) != 0 || len(history.Epochs[0].Stable) != 0 {
		t.Fatal("failed benchmark did not preserve the exact unavailable epoch", err)
	}
	for name, original := range before {
		data, err := os.ReadFile(filepath.Join(private, name))
		if err != nil || string(data) != original {
			t.Fatal("benchmark changed authenticated baseline files", name, err)
		}
	}
	for _, name := range []string{"build-private/isolated", ".atlas-private/production-receipt.json"} {
		if _, err = os.Stat(filepath.Join(root, filepath.FromSlash(name))); !os.IsNotExist(err) {
			t.Fatal("failed qualification emitted benchmark or production output", err)
		}
	}
	assertBenchmarkLockReleased(t, root)
}

func TestBenchmarkSetupRejectsChangedBaselineBeforeObservation(t *testing.T) {
	for _, mutation := range []string{"clock", "policy", "key", "chunk", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			root, state := benchmarkObservationFixture(t)
			clock := state.EvaluatedAt
			ctx := context.Background()
			path := ""
			switch mutation {
			case "clock":
				clock = clock.Add(time.Second)
			case "policy":
				path = filepath.Join(root, "SOURCES_AUDIT.md")
			case "key":
				path = filepath.Join(root, ".atlas-private", "state-seal.key")
			case "chunk":
				part := state.Sources[0].RecordPartitions[0]
				path = filepath.Join(root, ".atlas-private", "records-v2", hex.EncodeToString(part.SHA256[:])+".records")
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if path != "" {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := benchmarkState(ctx, benchmarkTestArguments(root, clock)); err == nil {
				t.Fatal("changed or canceled baseline reached materialization")
			}
			if _, err := os.Stat(filepath.Join(root, ".atlas-private", "tier1-history-v2.json")); !os.IsNotExist(err) {
				t.Fatal("invalid baseline changed observation history", err)
			}
			assertBenchmarkLockReleased(t, root)
		})
	}
}

func TestBenchmarkMutationPreservesAuthenticatedSourceBytes(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := intelligence.NewRecordStore(root, intelligence.DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(ctx)
	for _, prefix := range []string{"8.8.8.0/24", "9.9.9.0/24", "1.1.1.0/24"} {
		if err := writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo,
			Geo: &intelligence.GeoEvidence{Prefix: netip.MustParsePrefix(prefix), PhysicalCountry: "US", City: "Original", Family: "fixture", Weight: 70, Current: true}}); err != nil {
			t.Fatal(err)
		}
	}
	parts, err := writer.Finish()
	if err != nil {
		t.Fatal(err)
	}
	baseline := intelligence.BuildState{Sources: []intelligence.StoredSource{{ID: "fixture", RecordPartitions: parts}}}
	before, _ := json.Marshal(baseline)
	isolated := filepath.Join(root, "build-private", "isolated")
	if err = cloneBenchmarkRecords(ctx, root, isolated, baseline); err != nil {
		t.Fatal(err)
	}
	changed := baseline
	changed.Sources = append([]intelligence.StoredSource(nil), baseline.Sources...)
	if err = mutateBenchmarkGeo(ctx, isolated, &changed, 2); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(baseline)
	if string(before) != string(after) {
		t.Fatal("baseline metadata mutated")
	}
	for _, population := range []struct {
		root     string
		state    intelligence.BuildState
		expected int
	}{{root, baseline, 0}, {isolated, changed, 2}} {
		mutations, total := 0, 0
		err = intelligence.WalkStoredSource(ctx, population.root, population.state.Sources[0], func(record intelligence.NormalizedRecord) error {
			total++
			if record.Geo.City != "Original" {
				mutations++
			}
			return nil
		})
		if err != nil || total != 3 || mutations != population.expected {
			t.Fatalf("records=%d changed=%d err=%v", total, mutations, err)
		}
	}
	if err = mutateBenchmarkGeo(ctx, isolated, &changed, 4); err == nil {
		t.Fatal("unavailable mutation population accepted")
	}
}

func TestBenchmarkDestinationRejectsEscapeAndLink(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"build-private", "../escape", ".atlas-private", "build-private/../../escape"} {
		if _, err := benchmarkDestination(root, path); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	if _, err := benchmarkDestination(root, "build-private/case/one"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		// Windows paths are case insensitive. The ancestor walk must terminate
		// when an absolute caller path spells the workspace differently.
		if _, err := benchmarkDestination(root, filepath.Join(strings.ToUpper(root), "build-private", "case")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "build-private"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "build-private", "linked")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Log("symlink creation unavailable on this host")
		return
	}
	if _, err := benchmarkDestination(root, filepath.Join(link, "case")); err == nil {
		t.Fatal("followed external link")
	}
}
