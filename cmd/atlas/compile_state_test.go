package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"vansail-ip-atlas/internal/admission"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func stateCommandFixture(t *testing.T) (string, intelligence.BuildState) {
	t.Helper()
	root := t.TempDir()
	// Deactivate the copied source controls: these handcrafted records are
	// engineering state and can only produce a visibly synthetic candidate.
	for _, relative := range []string{"configs/sources.yaml", "configs/scoring.yaml", "configs/tier1.yaml", "configs/web.yaml", "configs/release-approval.yaml", "SOURCES_AUDIT.md", "fixtures/source-certification/adapter-certifications.json"} {
		data, err := os.ReadFile(filepath.Join("../..", filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		if relative == "configs/sources.yaml" {
			var document yaml.Node
			if err = yaml.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			var walk func(*yaml.Node)
			walk = func(n *yaml.Node) {
				if n.Kind == yaml.MappingNode {
					for i := 0; i < len(n.Content); i += 2 {
						if n.Content[i].Value == "admission" {
							n.Content[i+1].Value = "candidate"
						}
					}
				}
				for _, child := range n.Content {
					walk(child)
				}
			}
			walk(&document)
			data, err = yaml.Marshal(&document)
			if err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "internal"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "internal", "fixture.go"), []byte("package fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configHash, sourceBytes, err := intakeConfigHash(root)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := admission.DecodeCatalog(bytes.NewReader(sourceBytes))
	if err != nil {
		t.Fatal(err)
	}
	certificationHash, err := admission.CertificationFingerprint(context.Background(), root, sources)
	if err != nil {
		t.Fatal(err)
	}
	policyHash := sha256.Sum256(append(append([]byte("intake-policy-v1\x00"), configHash[:]...), certificationHash[:]...))
	clock := time.Unix(1794096000, 0).UTC()
	state := intelligence.BuildState{Version: 1, PolicyHash: policyHash, EvaluatedAt: clock, Sources: []intelligence.StoredSource{
		{ID: "engineering-risk", Fingerprint: sha256.Sum256([]byte("risk")), ExpiresAt: clock.Add(time.Hour), Records: []intelligence.NormalizedRecord{
			{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Family: "private-test", Signal: "malware", Scope: intelligence.Exact, Address: netip.MustParseAddr("203.0.113.0"), SourcePublishedAt: clock, Weight: 100, Current: true}},
		}},
		{ID: "engineering-mapping", Fingerprint: sha256.Sum256([]byte("mapping")), ExpiresAt: clock.Add(time.Hour), Records: []intelligence.NormalizedRecord{
			{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Origins: []uint32{13335}}},
		}},
	}}
	if err := intelligence.SavePrivateState(root, state); err != nil {
		t.Fatal(err)
	}
	return root, state
}

func TestCompileStateCommandRoundTripAndWithdrawal(t *testing.T) {
	root, state := stateCommandFixture(t)
	if err := run(context.Background(), []string{"compile-state", "-workspace", root, "-clock", "1794096000"}); err != nil {
		t.Fatal(err)
	}
	reader, err := via3.OpenRelease(filepath.Join(root, "build-private", "compiled-state"), func() int64 { return 1794096000 })
	if err != nil {
		t.Fatal(err)
	}
	answer, err := reader.Lookup(context.Background(), "203.0.113.0")
	if err != nil || !answer.Synthetic || answer.ValidUntil != 1794099600 || answer.Quality == nil || answer.Quality.Score == nil || *answer.Quality.Score == 0 || answer.Quality.Confidence != "low" || answer.Quality.Coverage.Status != "incomplete" || !slices.Contains(answer.Quality.Reasons, "malware") {
		t.Fatalf("private-state command changed supported observed risk: %+v %v", answer, err)
	}
	state.Sources = state.Sources[1:]
	if err := intelligence.SavePrivateState(root, state); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"compile-state", "-workspace", root, "-clock", "1794096000", "-out", "build-private/withdrawn"}); err != nil {
		t.Fatal(err)
	}
	reader, err = via3.OpenRelease(filepath.Join(root, "build-private", "withdrawn"), func() int64 { return 1794096000 })
	if err != nil {
		t.Fatal(err)
	}
	answer, err = reader.Lookup(context.Background(), "203.0.113.0")
	if err != nil || answer.Quality == nil || answer.Quality.Score == nil || *answer.Quality.Score != 0 ||
		answer.Quality.Confidence != "unrated" || answer.Quality.Coverage.Layers.Exact != "unassessed" || len(answer.Quality.Reasons) != 0 {
		t.Fatal("withdrawn evidence survived recompilation", answer.Quality, err)
	}
	profile, err := reader.ClassC(context.Background(), "203.0.113.0")
	if err != nil {
		t.Fatal(err)
	}
	requireUnobservedIPv4Profile(t, profile, "203.0.113.0/24")
}

func requireUnobservedIPv4Profile(t *testing.T, profile *via3.ClassCAnswer, prefix string) {
	t.Helper()
	if profile == nil || profile.Prefix != prefix || profile.Unit != "ipv4-address" || profile.TotalUnits != 256 || len(profile.Cells) != 256 ||
		profile.ObservedCount != 0 || profile.AssessedCount != 0 || profile.PositiveCount != 0 || profile.ScoredCount != 0 ||
		profile.ScoreSum != 0 || profile.AggregateScore == nil || *profile.AggregateScore != 0 {
		t.Fatal("incorrect unobserved IPv4 profile")
	}
	for _, cell := range profile.Cells {
		if cell.Observed || cell.Score == nil || *cell.Score != 0 || cell.Confidence != "unrated" || cell.Coverage != "incomplete" || len(cell.Reasons) != 0 {
			t.Fatal("an unobserved grid cell acquired evidence or assessment", cell)
		}
	}
}

func TestCompileStateCommandRejectsChangedPolicyClockExpiryAndProduction(t *testing.T) {
	for _, kind := range []string{"policy", "clock", "expiry", "production", "empty"} {
		t.Run(kind, func(t *testing.T) {
			root, state := stateCommandFixture(t)
			args := []string{"compile-state", "-workspace", root, "-clock", "1794096000"}
			switch kind {
			case "policy":
				if err := os.WriteFile(filepath.Join(root, "SOURCES_AUDIT.md"), []byte("review withdrawn\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "clock":
				args = append(args, "-clock", "1794096001")
			case "expiry":
				state.Sources[0].ExpiresAt = state.EvaluatedAt
				if err := intelligence.SavePrivateState(root, state); err != nil {
					t.Fatal(err)
				}
			case "production":
				args = append(args, "-mode", "production")
			case "empty":
				state.Sources = nil
				if err := intelligence.SavePrivateState(root, state); err != nil {
					t.Fatal(err)
				}
			}
			if err := run(context.Background(), args); err == nil {
				t.Fatal("ineligible state materialized")
			}
			if _, err := os.Stat(filepath.Join(root, "build-private", "compiled-state")); !os.IsNotExist(err) {
				t.Fatal("failed state left candidate", err)
			}
		})
	}
}
