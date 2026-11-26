package pipeline

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func TestSemanticMappingAliasAcrossPrefixEvidenceWithdrawal(t *testing.T) {
	for _, name := range []string{"parity", "tamper"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			state, policy, _, _, _ := intelligenceFixture(t)
			removed := intelligence.StoredSource{ID: "prefix-risk", Fingerprint: [32]byte{91}, ExpiresAt: state.Sources[0].ExpiresAt}
			prefix := netip.MustParsePrefix("203.0.113.128/25")
			removed.Records = []intelligence.NormalizedRecord{{
				Version: 3, Kind: intelligence.RecordEvidence,
				Evidence: &intelligence.Evidence{Family: "test-prefix-source", Signal: "proxy", Scope: intelligence.ExplicitPrefix, Prefix: prefix, Weight: 90, Current: true, SourcePublishedAt: state.EvaluatedAt},
			}}
			state.Sources = append(state.Sources, removed)
			opt := testOptions(t)
			opt.Limits = DefaultLimits()
			initial, err := BuildStreamedIntelligence(ctx, opt, partitionSpatialFixture(t, opt.Workspace, state), policy)
			if err != nil {
				t.Fatal(err)
			}
			cacheRoot := filepath.Join(opt.Workspace, ".atlas-private", "spatial-cache-v1")
			data, err := os.ReadFile(filepath.Join(cacheRoot, "index.json"))
			if err != nil {
				t.Fatal(err)
			}
			var index spatialCacheIndex
			if err := json.Unmarshal(data, &index); err != nil {
				t.Fatal(err)
			}
			targets := map[[32]byte]spatialCacheStream{}
			var aliases int
			for _, e := range index.Entries {
				if e.Domain == mappingDomain && e.Leaf.MappingInput != ([32]byte{}) && e.Leaf.Stream.Records > 0 {
					targets[e.Leaf.MappingInput] = e.Leaf.Stream
				}
			}
			for _, e := range index.Entries {
				if target, ok := targets[e.Key]; ok {
					if e.Domain != mappingDomain || e.Leaf.MappingInput != ([32]byte{}) || e.Leaf.Stream != target {
						t.Fatal("physical proof did not lead to the same target")
					}
					aliases++
					if name == "tamper" {
						p := filepath.Join(cacheRoot, "objects", spatialCacheFileName(e.Leaf.Stream.SHA256))
						content, err := os.ReadFile(p)
						if err != nil {
							t.Fatal(err)
						}
						content[len(content)-1] ^= 1
						if err = os.WriteFile(p, content, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if aliases != 2 {
				t.Fatalf("expected checked location and network aliases, got %d", aliases)
			}
			state.Sources = state.Sources[:len(state.Sources)-1]
			opt.Output = filepath.Join(opt.Workspace, "build-private", "withdrawn")
			warm, err := BuildStreamedIntelligence(ctx, opt, partitionSpatialFixture(t, opt.Workspace, state), policy)
			if name == "tamper" {
				if err == nil {
					t.Fatal("withdrawal accepted a damaged mapping alias")
				}
				if _, err = os.Lstat(opt.Output); !os.IsNotExist(err) {
					t.Fatal("damaged alias produced a candidate")
				}
				return
			}
			if err != nil || warm.Pointer == initial.Pointer || warm.Stats.MaterializationCacheHits != 0 {
				t.Fatal("withdrawal did not rebuild the changed risk", err)
			}
			compareCold := func(current intelligence.BuildState, warm Candidate) {
				t.Helper()
				cold := testOptions(t)
				cold.Clock, cold.ValidUntil, cold.Limits = opt.Clock, opt.ValidUntil, opt.Limits
				want, err := BuildStreamedIntelligence(ctx, cold, partitionSpatialFixture(t, cold.Workspace, current), policy)
				if err != nil || want.Pointer != warm.Pointer {
					t.Fatal("reused mapping differs from a cold rebuild", err)
				}
			}
			compareCold(state, warm)

			// A real city edit using the unchanged source identity must still
			// dirty the location alias, as in the changed-input measurement.
			changed := cloneSpatialFixture(t, state)
			changed.Sources[0].Records[0].Geo.City = "Edited City"
			opt.Output = filepath.Join(opt.Workspace, "build-private", "edited-location")
			edited, err := BuildStreamedIntelligence(ctx, opt, partitionSpatialFixture(t, opt.Workspace, changed), policy)
			if err != nil || edited.Pointer == warm.Pointer {
				t.Fatal("edited geographic evidence falsely retained an old mapping", err)
			}
			compareCold(changed, edited)
		})
	}
}

func TestMappingAliasMetadataIsLocalAndNonrecursive(t *testing.T) {
	for _, e := range []spatialCacheEntry{
		{Domain: "public", Key: [32]byte{1}, Leaf: &spatialCacheLeaf{MappingInput: [32]byte{2}}},
		{Domain: mappingDomain, Key: [32]byte{1}, Leaf: &spatialCacheLeaf{MappingInput: [32]byte{1}}},
		{Domain: mappingDomain, Key: [32]byte{1}, Leaf: &spatialCacheLeaf{MappingInput: [32]byte{2}, Split: true}},
	} {
		if _, err := spatialCacheFiles(e); err == nil {
			t.Fatal("invalid mapping proof was accepted")
		}
	}
}
