package intelligence

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestMRTReplayUnknownBaseBoundaryFallsBackBeforeUpdatesOrOutput(t *testing.T) {
	for _, scenario := range []string{"nil_origins", "empty_origins", "unsupported_path"} {
		t.Run(scenario, func(t *testing.T) {
			base, records, captured := streamReplayFixture(t, false)
			boundary := NormalizedRecord{Version: 3, Kind: RecordOrigins, MRT: records[0].MRT, MRTOriginatedAt: records[0].MRTOriginatedAt, Origins: &OriginMapping{Prefix: netip.MustParsePrefix("192.0.2.128/25")}}
			if scenario == "empty_origins" {
				boundary.Origins.Origins = []uint32{}
			} else if scenario == "unsupported_path" {
				boundary = records[0]
				path := *boundary.Path
				path.Prefix, path.Observation.Origin = netip.MustParsePrefix("192.0.2.128/25"), 65000
				boundary.Path = &path
			}
			base.Walk = func(_ context.Context, visit func(NormalizedRecord) error) error {
				if err := visit(records[0]); err != nil {
					return err
				}
				return visit(boundary)
			}
			attrs := updateAttributes(4, PathSegment{ASSequence, []uint32{100, 420001}})
			archive := streamArchive(base, bgp4mpFrame(4, false, false, bgpUpdate(attrs, nil, bgpNLRI("192.0.1.0/24", false, 0))), captured)
			scan, scans, emitted := archive.Scan, 0, 0
			archive.Scan = func(ctx context.Context, limit int, visit func(MRTUpdate) error, observe func(MRTPeerSession) error) (MRTSnapshotClock, error) {
				scans++
				return scan(ctx, limit, visit, observe)
			}
			budget := NewMRTReplayBudget(context.Background())
			defer budget.Close()
			result, err := StreamMRTReplay(context.Background(), base, []MRTStreamArchive{archive}, captured.Add(6*time.Minute), budget, func(NormalizedRecord) error { emitted++; return nil })
			if err != nil || !result.ColdFallback || result.Proof != nil || scans != 0 || emitted != 0 {
				t.Fatalf("unsupported base touched replay/output: result=%+v scans=%d output=%d err=%v", result, scans, emitted, err)
			}
		})
	}
}

func TestMRTReplayUnsupportedUpdateFallsBackBeforeApplyOrOutput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		segments []PathSegment
	}{
		{"private_origin", []PathSegment{{ASSequence, []uint32{100, 65000}}}},
		{"as_trans", []PathSegment{{ASSequence, []uint32{100, 23456}}}},
		{"terminal_set", []PathSegment{{ASSequence, []uint32{100}}, {ASSet, []uint32{13335, 15169}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, _, captured := streamReplayFixture(t, false)
			attrs := updateAttributes(4, tc.segments...)
			archive := streamArchive(base, bgp4mpFrame(4, false, false, bgpUpdate(attrs, nil, bgpNLRI("192.0.1.0/24", false, 0))), captured)
			scan, scans, emitted := archive.Scan, 0, 0
			archive.Scan = func(ctx context.Context, limit int, visit func(MRTUpdate) error, observe func(MRTPeerSession) error) (MRTSnapshotClock, error) {
				scans++
				return scan(ctx, limit, visit, observe)
			}
			budget := NewMRTReplayBudget(context.Background())
			defer budget.Close()
			result, err := StreamMRTReplay(context.Background(), base, []MRTStreamArchive{archive}, captured.Add(6*time.Minute), budget, func(NormalizedRecord) error { emitted++; return nil })
			if err != nil || !result.ColdFallback || result.Proof != nil || scans != 1 || emitted != 0 {
				t.Fatalf("unsupported update reached apply/output: result=%+v scans=%d output=%d err=%v", result, scans, emitted, err)
			}
		})
	}
}

func TestMRTReplayApplyRechecksUnsupportedOriginBeforeOutput(t *testing.T) {
	base, _, captured := streamReplayFixture(t, false)
	attrs := updateAttributes(4, PathSegment{ASSequence, []uint32{100, 420001}})
	archive := streamArchive(base, bgp4mpFrame(4, false, false, bgpUpdate(attrs, nil, bgpNLRI("192.0.1.0/24", false, 0))), captured)
	scan, scans, emitted := archive.Scan, 0, 0
	archive.Scan = func(ctx context.Context, limit int, visit func(MRTUpdate) error, observe func(MRTPeerSession) error) (MRTSnapshotClock, error) {
		scans++
		return scan(ctx, limit, func(event MRTUpdate) error {
			if scans == 2 && event.Kind == MRTAnnounce {
				event.Origin = 65000
			}
			return visit(event)
		}, observe)
	}
	budget := NewMRTReplayBudget(context.Background())
	defer budget.Close()
	result, err := StreamMRTReplay(context.Background(), base, []MRTStreamArchive{archive}, captured.Add(6*time.Minute), budget, func(NormalizedRecord) error { emitted++; return nil })
	if err != nil || !result.ColdFallback || result.Proof != nil || result.Reason != "update_apply_failed_or_deadline" || emitted != 0 {
		t.Fatalf("changed unsupported origin reached materialization: result=%+v output=%d err=%v", result, emitted, err)
	}
}
