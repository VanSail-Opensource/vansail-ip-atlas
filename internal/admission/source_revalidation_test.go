package admission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func preparedSourceValidation(t *testing.T) (*Engine, Source, time.Time, [32]byte, intelligence.BuildState, CapabilityReport, *sourceValidation) {
	t.Helper()
	ctx := context.Background()
	engine, source, _, now, binding := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
	source.Rights.Identifier = "CC0-1.0"
	result, err := engine.IngestPartitioned(ctx, source, now, binding)
	if err != nil || result.Snapshot == nil {
		t.Fatal(err)
	}
	plan, err := intelligence.ReconcilePartitioned(ctx, engine.workspace, intelligence.BuildState{}, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = intelligence.SavePartitionedState(ctx, engine.workspace, plan.State, intelligence.BuildState{}); err != nil {
		t.Fatal(err)
	}
	if err = engine.SealPrivateState(ctx, binding); err != nil {
		t.Fatal(err)
	}
	state, report, validation, err := validateSourceSet(ctx, engine.workspace, []Source{source}, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	return engine, source, now, binding, state, report, validation
}

func TestSourceRevalidationRetainsSemanticsWithoutMintingMissingCapabilities(t *testing.T) {
	engine, source, now, binding, state, report, validation := preparedSourceValidation(t)
	actual, repeated, err := validation.revalidate(context.Background(), engine.workspace, []Source{source}, now, binding)
	if err != nil || !reflect.DeepEqual(actual, state) || !reflect.DeepEqual(repeated, report) {
		t.Fatal("unchanged authenticated inputs changed semantic statistics", err)
	}
	if repeated.RequireProduction() == nil {
		t.Fatal("semantic reuse manufactured absent core capabilities")
	}
	if _, err := QualifyProductionState(context.Background(), engine.workspace, []Source{source}, now, binding); err == nil {
		t.Fatal("incomplete sources minted production qualification")
	}
	if err := (&ProductionQualification{}).RevalidateCurrent(context.Background(), engine.workspace, []Source{source}, now, binding); err == nil {
		t.Fatal("zero qualification reused statistics")
	}
}

func TestSourceRevalidationRejectsChangedControlsClockAndWorkspace(t *testing.T) {
	for _, mutation := range []string{"rights", "admission", "dependencies", "public-fields", "family", "clock", "binding", "workspace"} {
		t.Run(mutation, func(t *testing.T) {
			engine, source, now, binding, _, _, validation := preparedSourceValidation(t)
			root := engine.workspace
			switch mutation {
			case "rights":
				source.Rights.Distribution = "deny"
			case "admission":
				source.Admission = "retired"
			case "dependencies":
				source.Dependencies = []string{"missing"}
			case "public-fields":
				source.PublicFields = nil
			case "family":
				source.Family = "different-family"
			case "clock":
				now = now.Add(time.Second)
			case "binding":
				binding[0] ^= 1
			case "workspace":
				root = t.TempDir()
			}
			if _, _, err := validation.revalidate(context.Background(), root, []Source{source}, now, binding); err == nil {
				t.Fatal("changed validation identity accepted")
			}
		})
	}
}

func TestSourceRevalidationRechecksActualBytesAndCurrentCertification(t *testing.T) {
	for _, mutation := range []string{"partition", "state", "seal", "fixture", "ledger", "code", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			engine, source, now, binding, state, _, validation := preparedSourceValidation(t)
			ctx := context.Background()
			var path string
			switch mutation {
			case "partition":
				part := state.Sources[0].RecordPartitions[0]
				path = filepath.Join(engine.workspace, ".atlas-private", "records-v2", hex.EncodeToString(part.SHA256[:])+".records")
			case "state":
				path = filepath.Join(engine.workspace, ".atlas-private", "state-v1.json")
			case "seal":
				path = filepath.Join(engine.workspace, ".atlas-private", "state-seal-v2.json")
			case "fixture":
				path = filepath.Join(engine.workspace, filepath.FromSlash(source.Fixture.Path))
			case "ledger":
				path = filepath.Join(engine.workspace, "fixtures", "source-certification", "adapter-certifications.json")
			case "code":
				path = filepath.Join(engine.workspace, "internal", "adapter.go")
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
			if _, _, err := validation.revalidate(ctx, engine.workspace, []Source{source}, now, binding); err == nil {
				t.Fatal("mutation bypassed byte or certification revalidation")
			}
		})
	}
}

func TestSourceRevalidationCannotRenewExpiredOrResealedSources(t *testing.T) {
	engine, source, now, binding, state, _, validation := preparedSourceValidation(t)
	if _, _, err := validation.revalidate(context.Background(), engine.workspace, []Source{source}, state.Sources[0].ExpiresAt, binding); err == nil {
		t.Fatal("cached statistics renewed source expiry")
	}
	state.Sources[0].ExpiresAt = state.Sources[0].ExpiresAt.Add(time.Second)
	data, err := json.Marshal(state)
	if err != nil || os.WriteFile(filepath.Join(engine.workspace, ".atlas-private", "state-v1.json"), data, 0600) != nil {
		t.Fatal("state fixture mutation failed")
	}
	if err := engine.SealPrivateState(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validation.revalidate(context.Background(), engine.workspace, []Source{source}, now, binding); err == nil {
		t.Fatal("new valid seal reused an earlier state's semantic approval")
	}
}

// Four small, synthetic publisher assets pass the actual admission adapters,
// fixture checks and partitioned reconciliation. No capabilities are injected.
func preparedCoreQualification(t *testing.T) (*Engine, []Source, time.Time, [32]byte, *ProductionQualification) {
	t.Helper()
	ctx := context.Background()
	engine, template, fetch, now, binding := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
	geo := bulkSource("city-range-csv", "sapics-city-ten-columns-v1")
	risk := Source{Category: "abuse", Scope: "exact_ip", Coverage: "positive_only", Format: "txt", Parser: Parser{"literal-prefix-text", "one-literal-ip-or-prefix-per-line-v1", 1}, Signals: []string{"abuse"}, Fields: []string{"abuse"}, PublicFields: []string{"reason_flags"}, FieldMappings: map[string][]string{"abuse": {"reason_flags"}}}
	usage := Source{Category: "asn", Scope: "asn", Coverage: "mapping", Format: "json", Parser: Parser{"ipverse-asn-usage-json", "ipverse-as-category-json-v1", 1}, Fields: []string{"metadata.category"}, PublicFields: []string{"usage_type"}, FieldMappings: map[string][]string{"metadata.category": {"usage_type"}}}
	entries := []struct {
		id, payload string
		source      Source
	}{
		{"core-city-one", "8.8.8.0,8.8.8.255,US,Example,county,City,ignored,37.1,-122.2,ignored\n", geo},
		{"core-city-two", "8.8.8.0,8.8.8.255,US,Example,county,Other,ignored,37.1,-122.2,ignored\n", geo},
		{"core-risk", "8.8.8.8\n", risk},
		{"core-usage", `[{"asn":13335,"metadata":{"category":"hosting","lastModified":"2026-11-07"}}]`, usage},
	}
	implementation, err := implementationHash(ctx, engine.workspace)
	if err != nil {
		t.Fatal(err)
	}
	reviews := ledger{Version: 1}
	var catalog []Source
	for _, entry := range entries {
		s := entry.source
		s.ID, s.Family, s.Admission = entry.id, entry.id+"-family", "active"
		s.URL = "https://github.com/unit/" + entry.id + "/releases/download/v1/data"
		s.Publication = Publication{"github_release", "https://api.github.com/repos/unit/" + entry.id + "/releases/latest", "published_at"}
		s.MaxCompressedBytes, s.MaxAge, s.Weight = template.MaxCompressedBytes, template.MaxAge, template.Weight
		s.Rights = template.Rights
		s.Rights.Identifier = "CC0-1.0"
		s.Fixture = template.Fixture
		s.Fixture.Path = "fixtures/source-certification/" + entry.id + ".csv"
		s.Fixture.Parser, s.Fixture.Schema = s.Parser.ID, s.Parser.Schema
		s.Fixture.SHA256 = hashString(sha256.Sum256([]byte(entry.payload)))
		if err := os.WriteFile(filepath.Join(engine.workspace, filepath.FromSlash(s.Fixture.Path)), []byte(entry.payload), 0600); err != nil {
			t.Fatal(err)
		}
		reviews.Certifications = append(reviews.Certifications, certification{s.ID, s.Parser.ID, s.Parser.Schema, s.Parser.Version, s.Fixture.SHA256, s.Fixture.TestedAt, hashString(implementation)})
		fetch.assets[s.URL] = []byte(entry.payload)
		fetch.assets[s.Publication.Locator] = metadataFor(t, s.URL, []byte(entry.payload), now.Add(-time.Hour), now.Add(-2*time.Hour))
		catalog = append(catalog, s)
	}
	data, err := json.Marshal(reviews)
	if err != nil || os.WriteFile(filepath.Join(engine.workspace, "fixtures", "source-certification", "adapter-certifications.json"), data, 0600) != nil {
		t.Fatal("fixture review write failed", err)
	}
	var policies []intelligence.SourcePolicy
	var snapshots []intelligence.SourceSnapshot
	for _, source := range catalog {
		result, err := engine.IngestPartitioned(ctx, source, now, binding)
		if err != nil || result.Snapshot == nil {
			t.Fatal("core fixture failed actual admission", source.ID, result.Decision, err)
		}
		policies = append(policies, result.Policy)
		snapshots = append(snapshots, *result.Snapshot)
	}
	plan, err := intelligence.ReconcilePartitioned(ctx, engine.workspace, intelligence.BuildState{}, policies, snapshots, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = intelligence.SavePartitionedState(ctx, engine.workspace, plan.State, intelligence.BuildState{}); err != nil {
		t.Fatal(err)
	}
	if err = engine.SealPrivateState(ctx, binding); err != nil {
		t.Fatal(err)
	}
	qualified, err := QualifyProductionState(ctx, engine.workspace, catalog, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	return engine, catalog, now, binding, qualified
}

func TestSourceRevalidationQualifiesActualCoreAndRejectsCallerAliases(t *testing.T) {
	for _, mutation := range []string{"unchanged", "state-alias", "report-alias", "later-clock"} {
		t.Run(mutation, func(t *testing.T) {
			engine, catalog, now, binding, q := preparedCoreQualification(t)
			if err := q.RevalidateCurrent(context.Background(), engine.workspace, catalog, now, binding); err != nil {
				t.Fatal("unchanged source set lost qualification", err)
			}
			switch mutation {
			case "state-alias":
				state := q.State()
				state.Sources[0].Receipt.PublishedAt = now
			case "report-alias":
				report := q.Report()
				for i := range report.Capabilities {
					if len(report.Capabilities[i].Families) != 0 {
						report.Capabilities[i].Families[0] = "caller-edited"
						break
					}
				}
			case "later-clock":
				now = now.Add(time.Second)
			}
			err := q.RevalidateCurrent(context.Background(), engine.workspace, catalog, now, binding)
			if (mutation == "unchanged") != (err == nil) {
				t.Fatal("mutable caller state or clock bypassed qualification identity", err)
			}
		})
	}
}

func TestSourceRevalidationDoesNotReplaceIndependentCurrentTimeQualification(t *testing.T) {
	engine, catalog, now, binding, q := preparedCoreQualification(t)
	current, err := QualifyProductionStateAtHash(context.Background(), engine.workspace, catalog, now.Add(time.Second), binding, q.stateHash)
	if err != nil || !reflect.DeepEqual(current.Report(), q.Report()) {
		t.Fatal("independent current-time qualification changed", err)
	}
	if err := current.RevalidateCurrent(context.Background(), engine.workspace, catalog, now, binding); err == nil {
		t.Fatal("independent verification silently acquired a compile reuse handle")
	}
	if _, err := QualifyProductionStateAtHash(context.Background(), engine.workspace, catalog, q.ValidUntil(), binding, q.stateHash); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatal("independent verification reused an earlier freshness decision", err)
	}
}

func TestSourceRevalidationVerifiedQualificationRequiresMatchingHandle(t *testing.T) {
	engine, catalog, now, binding, q := preparedCoreQualification(t)
	verified, _, err := intelligence.VerifyPrivateState(context.Background(), engine.workspace, binding)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := QualifyProductionStateVerified(context.Background(), engine.workspace, catalog, now, binding, verified)
	if err != nil || !reflect.DeepEqual(actual.Report(), q.Report()) || actual.stateHash != q.stateHash {
		t.Fatal("opaque initial validation changed source qualification", err)
	}
	for _, mutation := range []string{"nil", "zero", "copied", "policy", "root"} {
		t.Run(mutation, func(t *testing.T) {
			handle, root, policy := verified, engine.workspace, binding
			switch mutation {
			case "nil":
				handle = nil
			case "zero":
				handle = new(intelligence.VerifiedPrivateState)
			case "copied":
				copy := *verified
				handle = &copy
			case "policy":
				policy[0] ^= 1
			case "root":
				root = t.TempDir()
			}
			if _, err := QualifyProductionStateVerified(context.Background(), root, catalog, now, policy, handle); err == nil {
				t.Fatal("unbound opaque handle qualified sources")
			}
		})
	}
}

func TestSourceRevalidationCapabilityFailureCannotSuppressTier1History(t *testing.T) {
	engine, source, now, binding, _, _, _ := preparedSourceValidation(t)
	ctx := context.Background()
	verified, _, err := intelligence.VerifyPrivateState(ctx, engine.workspace, binding)
	if err != nil {
		t.Fatal(err)
	}
	tier1, err := verified.ObserveTier1State(ctx, engine.workspace, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(engine.workspace, ".atlas-private", "tier1-history-v2.json")
	before, err := os.ReadFile(path)
	if err != nil || len(before) == 0 {
		t.Fatal("authenticated unavailable epoch did not reach history", err)
	}
	if _, err := QualifyProductionStateVerified(ctx, engine.workspace, []Source{source}, now, binding, verified); err == nil {
		t.Fatal("missing core observations qualified production")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("unrelated capability failure altered observed history", err)
	}
	if err = verified.VerifyTier1ObservationHistory(ctx, engine.workspace, tier1); err != nil {
		t.Fatal("unavailable observation lost authentication", err)
	}
}
