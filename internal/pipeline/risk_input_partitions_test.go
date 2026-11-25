package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func TestExactRiskLeafReuseBindsOnlyRiskInputs(t *testing.T) {
	for _, mode := range []string{"role", "geo", "coverage", "vrp", "prefix-risk", "exact", "origin", "clock"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			state, policy, _, _, _ := intelligenceFixture(t)
			state.Sources = append(state.Sources, intelligence.StoredSource{ID: "asn-roles", Fingerprint: [32]byte{8}, ExpiresAt: state.Sources[0].ExpiresAt, Records: []intelligence.NormalizedRecord{{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{ASN: 13335, ObservedAt: state.EvaluatedAt, Evidence: intelligence.UsageEvidence{Family: "asn-roles", Type: "hosting", Current: true}}}}})
			opt := testOptions(t)
			opt.Limits = DefaultLimits()
			build := func(s intelligence.BuildState, dir string) (Candidate, map[[32]byte]spatialCacheStream) {
				t.Helper()
				opt.Clock = s.EvaluatedAt.Unix()
				opt.Output = filepath.Join(opt.Workspace, "build-private", dir)
				v, e := BuildStreamedIntelligence(ctx, opt, partitionSpatialFixture(t, opt.Workspace, s), policy)
				if e != nil {
					t.Fatal(e)
				}
				b, e := os.ReadFile(filepath.Join(opt.Workspace, ".atlas-private", "spatial-cache-v1", "index.json"))
				if e != nil {
					t.Fatal(e)
				}
				var i spatialCacheIndex
				if e = json.Unmarshal(b, &i); e != nil {
					t.Fatal(e)
				}
				keys := map[[32]byte]spatialCacheStream{}
				for _, e := range i.Entries {
					if e.Domain == "risk-input" && e.Leaf != nil && !e.Leaf.Split {
						keys[e.Key] = e.Leaf.Stream
					}
				}
				if len(keys) == 0 {
					t.Fatal("missing risk leaf")
				}
				return v, keys
			}
			_, baseline := build(state, "before")
			changed := cloneSpatialFixture(t, state)
			apply := false
			for _, s := range changed.Sources {
				for _, r := range s.Records {
					switch mode {
					case "geo":
						if r.Geo != nil {
							r.Geo.City = "New region city"
							apply = true
						}
					case "coverage":
						if r.Coverage != nil {
							r.Coverage.Family = "new-coverage"
							apply = true
						}
					case "vrp":
						if r.VRP != nil {
							r.VRP.MaxLength = 24
							apply = true
						}
					case "prefix-risk":
						if r.Evidence != nil && r.Evidence.Scope == intelligence.ExplicitPrefix {
							r.Evidence.Weight = 40
							apply = true
						}
					case "exact":
						if r.Evidence != nil && r.Evidence.Scope == intelligence.Exact {
							r.Evidence.Weight = 5
							apply = true
						}
					case "origin":
						if r.Origins != nil {
							r.Origins.Origins = []uint32{15169}
							apply = true
						}
					}
				}
			}
			switch mode {
			case "role":
				changed.Sources = changed.Sources[:len(changed.Sources)-1]
				apply = true
			case "clock":
				changed.EvaluatedAt = changed.EvaluatedAt.Add(time.Minute)
				apply = true
			}
			if !apply {
				t.Fatal("fixture failed to change requested input")
			}
			warm, keys := build(changed, "after")
			same := mode != "exact" && mode != "origin" && mode != "clock"
			if reflect.DeepEqual(baseline, keys) != same {
				t.Fatal("risk leaf dependency mismatch", mode)
			}
			cold := testOptions(t)
			cold.Limits = opt.Limits
			cold.Clock = opt.Clock
			cold.ValidUntil = opt.ValidUntil
			want, e := BuildStreamedIntelligence(ctx, cold, changed, policy)
			if e != nil || want.Pointer != warm.Pointer {
				t.Fatal("warm risk projection differs from independent full-input rebuild", e)
			}
		})
	}
}

func TestExactRiskDependencyKeyTracksScoringInputs(t *testing.T) {
	state, policy := mappingFixture(t)
	key := func(p intelligence.Policy, clock time.Time) [32]byte {
		t.Helper()
		v, e := exactRiskDependencies(p, clock)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	baseline := key(policy, state.EvaluatedAt)
	unrelated := policy
	unrelated.GeoMargin += 0.01
	unrelated.GeoSupport[0]++
	unrelated.Weights[2] += 0.01
	unrelated.MinimumFamilies++
	unrelated.Specificity[intelligence.ExplicitPrefix] += 0.01
	if key(unrelated, state.EvaluatedAt) != baseline {
		t.Fatal("unrelated public/coverage policy invalidated exact events")
	}
	changes := map[string]func(*intelligence.Policy){
		"max age":                  func(p *intelligence.Policy) { p.MaxAge++ },
		"subscription age":         func(p *intelligence.Policy) { p.SubscriptionAge++ },
		"future tolerance":         func(p *intelligence.Policy) { p.FutureTolerance++ },
		"specificity":              func(p *intelligence.Policy) { p.Specificity[intelligence.Exact] += 0.01 },
		"subscription specificity": func(p *intelligence.Policy) { p.SubscriptionSpecificity += 0.01 },
		"signal order": func(p *intelligence.Policy) {
			p.Order = append([]intelligence.Signal(nil), p.Order...)
			p.Order[0], p.Order[1] = p.Order[1], p.Order[0]
		},
	}
	for name, change := range map[string]func(*intelligence.SignalPolicy){
		"half life":    func(s *intelligence.SignalPolicy) { s.HalfLifeHours++ },
		"beta":         func(s *intelligence.SignalPolicy) { s.Beta += 0.01 },
		"severity":     func(s *intelligence.SignalPolicy) { s.Severity -= 0.01 },
		"merge target": func(s *intelligence.SignalPolicy) { s.MergeInto = "malware" },
	} {
		changes[name] = func(p *intelligence.Policy) {
			signals := make(map[intelligence.Signal]intelligence.SignalPolicy, len(p.Signals))
			for signal, config := range p.Signals {
				if signal == "proxy" {
					change(&config)
				}
				signals[signal] = config
			}
			p.Signals = signals
		}
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := policy
			change(&changed)
			if key(changed, state.EvaluatedAt) == baseline {
				t.Fatal("changed score policy reused exact events")
			}
		})
	}
	if key(policy, state.EvaluatedAt.Add(time.Nanosecond)) == baseline {
		t.Fatal("changed clock reused decayed exact events")
	}
}

func TestExactRiskAliasRejectsForeignOrRecursiveCacheEntries(t *testing.T) {
	key, input := [32]byte{1}, [32]byte{2}
	for _, d := range []string{"location", "public", "risk-input", "raw-split"} {
		if _, err := spatialCacheFiles(spatialCacheEntry{Domain: d, Key: key, Leaf: &spatialCacheLeaf{RiskInput: input}}); err == nil {
			t.Fatalf("%s accepted physical risk metadata", d)
		}
	}
	for _, e := range []spatialCacheEntry{
		{Domain: "risk", Key: key, Leaf: &spatialCacheLeaf{RiskInput: key}},
		{Domain: "risk", Key: key, Leaf: &spatialCacheLeaf{RiskInput: input, Split: true}},
		{Domain: "risk-input", Key: input, Leaf: &spatialCacheLeaf{Split: true}},
		{Domain: "risk-input", Key: input, Leaf: &spatialCacheLeaf{Stream: spatialCacheStream{SHA256: [32]byte{4}, Bytes: 100, DecodedBytes: 1000000, Records: 200001}}},
	} {
		if _, err := spatialCacheFiles(e); err == nil {
			t.Fatal("invalid risk alias accepted", e.Domain)
		}
	}
}

func TestExactRiskAliasChecksCurrentStreamObjectAfterUnrelatedEdit(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	opts := testOptions(t)
	opts.Limits = DefaultLimits()
	ctx := context.Background()
	before := partitionSpatialFixture(t, opts.Workspace, state)
	if _, err := BuildStreamedIntelligence(ctx, opts, before, policy); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(opts.Workspace, ".atlas-private", "spatial-cache-v1")
	data, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx spatialCacheIndex
	if err = json.Unmarshal(data, &idx); err != nil {
		t.Fatal(err)
	}
	var damaged bool
	for _, e := range idx.Entries {
		if e.Domain != "risk-input" || e.Leaf.Stream == (spatialCacheStream{}) {
			continue
		}
		path := filepath.Join(root, "objects", spatialCacheFileName(e.Leaf.Stream.SHA256))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw[0] ^= 0xff
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		damaged = true
		break
	}
	if !damaged {
		t.Fatal("missing authenticated routed risk stream")
	}
	input := cloneSpatialFixture(t, state)
	for _, source := range input.Sources {
		for _, r := range source.Records {
			if r.Geo != nil {
				r.Geo.City = "Another city"
			}
		}
	}
	opts.Output = filepath.Join(opts.Workspace, "build-private", "after-invalid-risk")
	if _, err = BuildStreamedIntelligence(ctx, opts, partitionSpatialFixture(t, opts.Workspace, input), policy); err == nil {
		t.Fatal("damaged semantic stream accepted")
	}
	if _, err = os.Stat(filepath.Join(opts.Output, "current.json")); !os.IsNotExist(err) {
		t.Fatal("failed risk replay published a candidate", err)
	}
}
