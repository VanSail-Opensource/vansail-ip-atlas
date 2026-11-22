package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func originSeedFixture(t *testing.T, workspace string, singletonParts bool) (intelligence.BuildState, intelligence.Policy, []intelligence.OriginMapping, []intelligence.OriginMapping, int) {
	t.Helper()
	state, policy := mappingFixture(t)
	source := state.Sources[0]
	source.Records = nil
	state.Sources = nil
	state.Version = 2
	a := intelligence.OriginMapping{Prefix: netip.MustParsePrefix("11.0.0.0/16"), Origins: []uint32{13335}}
	m := intelligence.OriginMapping{Prefix: a.Prefix, Origins: []uint32{13335, 15169}}
	r := intelligence.OriginMapping{Prefix: a.Prefix, Origins: []uint32{15169, 13335}}
	n := intelligence.OriginMapping{Prefix: netip.MustParsePrefix("11.0.1.0/24"), Origins: nil}
	e := intelligence.OriginMapping{Prefix: n.Prefix, Origins: []uint32{}}
	child := intelligence.OriginMapping{Prefix: netip.MustParsePrefix("11.0.2.0/24"), Origins: []uint32{13335}}
	var peer uint16
	origin := func(mapping intelligence.OriginMapping) intelligence.NormalizedRecord {
		peer++
		return intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &mapping, MRT: &intelligence.MRTRouteIdentity{PeerKey: [32]byte{byte(peer)}, PeerIndex: peer, PeerTable: 1, CapturedAt: state.EvaluatedAt}}
	}
	path := func(set bool) intelligence.NormalizedRecord {
		segments := []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{13335, 32934}}}
		if set {
			segments = append(segments, intelligence.PathSegment{Type: intelligence.ASSet, ASNs: []uint32{15169, 13335}})
		}
		return intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordPath, Path: &intelligence.ScopedPath{Prefix: a.Prefix, Observation: intelligence.PathObservation{Origin: 13335, Family: "synthetic-peer", Current: true, OriginOutward: true, Segments: segments}}, MRT: &intelligence.MRTRouteIdentity{PeerKey: [32]byte{byte(peer)}, PeerIndex: peer, PeerTable: 1, CapturedAt: state.EvaluatedAt}}
	}
	first := []intelligence.NormalizedRecord{origin(a), path(false), origin(a), path(false), origin(m), path(true), origin(m), path(true), origin(r), origin(n), origin(n), origin(e), origin(e), origin(child), origin(child), origin(a), {Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Prefix: a.Prefix, Family: "synthetic", PhysicalCountry: "US", Weight: 70, Current: true}}, origin(a)}
	second := []intelligence.NormalizedRecord{origin(a), path(false), origin(a)}
	third := []intelligence.NormalizedRecord{origin(a)}
	store, err := intelligence.NewRecordStore(workspace, intelligence.DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	for i, groups := range [][][]intelligence.NormalizedRecord{{first, second}, {third}} {
		value := source
		value.ID = []string{"peer-source-a", "peer-source-b"}[i]
		value.Fingerprint = [32]byte{byte(i + 1)}
		value.RecordPartitions = nil
		if singletonParts {
			var separate [][]intelligence.NormalizedRecord
			for _, records := range groups {
				for _, record := range records {
					separate = append(separate, []intelligence.NormalizedRecord{record})
				}
			}
			groups = separate
		}
		for _, records := range groups {
			writer := store.Writer(context.Background())
			for _, record := range records {
				if err := writer.Append(record); err != nil {
					t.Fatal(err)
				}
			}
			parts, err := writer.Finish()
			if err != nil || len(parts) != 1 {
				t.Fatal("fixture input partition changed", err, len(parts))
			}
			value.RecordPartitions = append(value.RecordPartitions, parts...)
		}
		state.Sources = append(state.Sources, value)
	}
	return state, policy, []intelligence.OriginMapping{a, m, r, n, e, child, a, a, a, a}, []intelligence.OriginMapping{a, m, r, n, e, child, a, a, a}, 5
}

func TestOriginSeedDedupeRetainsBoundariesOrderedValuesAndPaths(t *testing.T) {
	for _, stable := range []bool{false, true} {
		t.Run(map[bool]string{false: "coalesced", true: "per-input"}[stable], func(t *testing.T) {
			workspace := t.TempDir()
			state, _, wantSpatial, wantPrefixes, wantPaths := originSeedFixture(t, workspace, false)
			sourceBefore, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			spool, err := newBulkSpool(workspace, state.EvaluatedAt, state.PolicyHash, DefaultLimits().ScratchBytes, func() uint64 { return 0 })
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(spool.root)
			var roots []*bulkBucket
			if stable {
				roots, _, err = spool.seedStable(context.Background(), workspace, state)
			} else {
				roots, _, err = spool.seedCold(context.Background(), workspace, state)
			}
			if err != nil {
				t.Fatal(err)
			}
			var spatial, prefixes []intelligence.OriginMapping
			geo, paths := 0, 0
			if err := spool.walk(context.Background(), roots[0].parts, func(record intelligence.NormalizedRecord) error {
				if record.Origins != nil {
					spatial = append(spatial, *record.Origins)
				}
				if record.Geo != nil {
					geo++
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := spool.walk(context.Background(), spool.prefixParts, func(record intelligence.NormalizedRecord) error {
				prefixes = append(prefixes, *record.Origins)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := spool.walk(context.Background(), spool.pathParts, func(record intelligence.NormalizedRecord) error {
				paths++
				if record.Path == nil || record.MRT != nil {
					t.Fatal("path category or metadata changed")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(spatial, wantSpatial) || !reflect.DeepEqual(prefixes, wantPrefixes) || geo != 1 || paths != wantPaths {
				t.Fatalf("dedupe crossed a category/partition boundary or changed origin identity: spatial=%+v prefix=%+v geo=%d paths=%d", spatial, prefixes, geo, paths)
			}
			if !reflect.DeepEqual(sortedASNs(spool.known), []uint32{13335, 15169}) {
				t.Fatal("ASN side index changed", sortedASNs(spool.known))
			}
			sourceAfter, _ := json.Marshal(state)
			if string(sourceBefore) != string(sourceAfter) {
				t.Fatal("seed mutated original source ownership")
			}
			count := 0
			for _, source := range state.Sources {
				if err := intelligence.WalkStoredSource(context.Background(), workspace, source, func(intelligence.NormalizedRecord) error { count++; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			if count != 22 {
				t.Fatal("original peer observation population changed", count)
			}
		})
	}
}

func TestOriginSeedWindowOwnsIdentityAndPreservesVersion(t *testing.T) {
	var rows []intelligence.NormalizedRecord
	appender := seedOriginAppender{emit: func(_ int, record intelligence.NormalizedRecord) error { rows = append(rows, record); return nil }}
	origin := func(version uint16, asns []uint32) intelligence.NormalizedRecord {
		return intelligence.NormalizedRecord{Version: version, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("11.0.0.0/24"), Origins: asns}}
	}
	values := []uint32{13335}
	if err := appender.append(0, origin(3, values)); err != nil {
		t.Fatal(err)
	}
	values[0] = 15169
	if err := appender.append(0, origin(3, []uint32{13335})); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatal("mutated caller slice altered remembered identity")
	}
	if err := appender.append(0, origin(4, []uint32{13335})); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatal("different version was suppressed")
	}
}

func TestOriginSeedDedupeColdReleaseParity(t *testing.T) {
	options := testOptions(t)
	options.Limits = DefaultLimits()
	state, policy, _, _, _ := originSeedFixture(t, options.Workspace, false)
	candidate, err := BuildStreamedIntelligence(context.Background(), options, state, policy)
	if err != nil {
		t.Fatal(err)
	}
	// Isolating every observation in its own input partition makes
	// adjacent suppression impossible. This checks the complete inventory
	// and release against a fresh build of the same data without suppression.
	reference := testOptions(t)
	reference.Limits = options.Limits
	separate, _, _, _, _ := originSeedFixture(t, reference.Workspace, true)
	expected, err := BuildStreamedIntelligence(context.Background(), reference, separate, policy)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Pointer != expected.Pointer {
		t.Fatal("cold release differs from build retaining all peer observations", candidate.Pointer, expected.Pointer)
	}
	reader, err := via3.OpenRelease(options.Output, func() int64 { return options.Clock })
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip, prefix string
		origins    []uint32
	}{{"11.0.1.1", "11.0.1.0/24", nil}, {"11.0.2.1", "11.0.2.0/24", []uint32{13335}}, {"11.0.3.1", "11.0.0.0/16", []uint32{13335, 15169}}} {
		answer, err := reader.Lookup(context.Background(), tc.ip)
		if err != nil || answer.Network == nil || answer.Network.Prefix != tc.prefix || !slices.Equal(answer.Network.Origins, tc.origins) {
			t.Fatal("observed/unsupported origin boundary changed", tc.ip, answer.Network, err)
		}
	}
	// A second unchanged build exercises the derived cache, with the same bytes.
	options.Output = filepath.Join(options.Workspace, "build-private", "again")
	again, err := BuildStreamedIntelligence(context.Background(), options, state, policy)
	if err != nil || again.Pointer != candidate.Pointer {
		t.Fatal("warm parity differs", err)
	}
}

func TestOriginSeedWindowDoesNotRetainFailedEmission(t *testing.T) {
	sentinel := errors.New("sink failed")
	calls := 0
	appender := seedOriginAppender{emit: func(int, intelligence.NormalizedRecord) error {
		calls++
		return sentinel
	}}
	record := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix("11.0.0.0/24"), Origins: []uint32{13335}}}
	for i := 0; i < 2; i++ {
		if err := appender.append(0, record); !errors.Is(err, sentinel) {
			t.Fatal("failed emission became a successful duplicate", err)
		}
	}
	if calls != 2 {
		t.Fatal("failed row was retained in adjacency window", calls)
	}
}
