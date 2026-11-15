package intelligence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func streamReplayFixture(t *testing.T, addPath bool) (MRTStreamBase, []NormalizedRecord, time.Time) {
	t.Helper()
	data := mrtFixture(false, addPath, []PathSegment{{ASSequence, []uint32{100, 420000}}})
	captured := time.Unix(int64(binary.BigEndian.Uint32(data)), 0).UTC()
	var records []NormalizedRecord
	_, err := ParseMRTSnapshot(context.Background(), bytes.NewReader(data), mrtLimits(), captured, 720*time.Hour, func(v MRTSnapshotRecord) error {
		r := v.Record
		originated := r.ObservedAt
		records = append(records, NormalizedRecord{Version: 3, Kind: RecordPath, MRTOriginatedAt: &originated, MRT: &MRTRouteIdentity{PeerKey: r.PeerKey, PeerIndex: r.PeerIndex, PeerTable: r.PeerTable, PathID: r.PathID, AddPath: r.AddPath, PeerAmbiguous: r.PeerAmbiguous, CapturedAt: v.CapturedAt}, Path: &ScopedPath{Prefix: r.Prefix, Observation: PathObservation{Origin: r.Origin, Segments: r.Segments, Family: "synthetic-ris", Current: true}}})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	base := MRTStreamBase{Family: "synthetic-ris", Proof: &MRTSourceProof{Version: 1, Collector: sha256.Sum256([]byte("synthetic collector")), BasePayloadHash: sha256.Sum256(data), BaseBytes: int64(len(data)), CapturedAt: captured, Through: captured}}
	base.Walk = func(ctx context.Context, visit func(NormalizedRecord) error) error {
		for _, r := range records {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := visit(r); err != nil {
				return err
			}
		}
		return nil
	}
	return base, records, captured
}

func streamArchive(base MRTStreamBase, raw []byte, captured time.Time) MRTStreamArchive {
	setMRTCapture(raw, captured.Add(time.Minute))
	proof := MRTArchiveProof{PayloadHash: sha256.Sum256(raw), From: captured, Until: captured.Add(5 * time.Minute)}
	return MRTStreamArchive{Collector: base.Proof.Collector, Proof: proof, Scan: func(ctx context.Context, limit int, sink func(MRTUpdate) error, observe func(MRTPeerSession) error) (MRTSnapshotClock, error) {
		limits := mrtLimits()
		limits.Records = limit
		return ParseMRTUpdatesSnapshot(ctx, bytes.NewReader(raw), limits, captured.Add(6*time.Minute), 720*time.Hour, sink, observe)
	}}
}

func TestStreamMRTReplayBootstrapsUniquePeerSessionAndMergesPrefixes(t *testing.T) {
	base, originals, captured := streamReplayFixture(t, false)
	attrs := updateAttributes(4, PathSegment{ASSequence, []uint32{100, 420001}})
	archive := streamArchive(base, bgp4mpFrame(4, false, false, bgpUpdate(attrs, nil, bgpNLRI("192.0.1.0/24", false, 0))), captured)
	budget := NewMRTReplayBudget(context.Background())
	defer budget.Close()
	var output []NormalizedRecord
	result, err := StreamMRTReplay(context.Background(), base, []MRTStreamArchive{archive}, captured.Add(6*time.Minute), budget, func(r NormalizedRecord) error { output = append(output, r); return nil })
	if err != nil || result.ColdFallback || result.Proof == nil || len(output) != 4 || result.Updates != 1 || len(result.Proof.Peers) != 1 {
		t.Fatal("unique verified peer join failed", result, err, len(output))
	}
	if output[0].Origins.Prefix.String() != "192.0.1.0/24" || output[2].Origins.Prefix.String() != "192.0.2.0/24" || output[3].MRTOriginatedAt == nil || !output[3].MRTOriginatedAt.Equal(*originals[0].MRTOriginatedAt) {
		t.Fatal("merge reordered prefixes or erased original route time")
	}
	content, err := result.Proof.ContentHash()
	if err != nil || content == base.Proof.BasePayloadHash {
		t.Fatal("updated raw content set was not independently hash bound", err)
	}
	mirror := *result.Proof
	mirror.Collector = sha256.Sum256([]byte("different label, same exact bytes"))
	same, err := mirror.ContentHash()
	if err != nil || same != content {
		t.Fatal("collector/source labels manufactured independent content hashes")
	}
}

func TestStreamMRTReplayUnsafeJoinsAlwaysColdFallback(t *testing.T) {
	for _, scenario := range []string{"duplicate_peer", "duplicate_path_key", "ambiguous_transport", "different_collector", "missing_peer", "wrong_peer_asn", "gap", "addpath_mode", "malformed_tail", "deadline", "update_limit", "multiple_capture_clocks"} {
		t.Run(scenario, func(t *testing.T) {
			base, records, captured := streamReplayFixture(t, false)
			attrs := updateAttributes(4, PathSegment{ASSequence, []uint32{100, 420000}})
			raw := bgp4mpFrame(4, false, false, bgpUpdate(attrs, nil, bgpNLRI("192.0.2.0/24", false, 0)))
			switch scenario {
			case "multiple_capture_clocks":
				base.Proof.CaptureUntil = captured.Add(time.Second)
			case "duplicate_peer":
				records[0].MRT.PeerAmbiguous = true
			case "duplicate_path_key":
				copy := records[0]
				base.Walk = func(_ context.Context, visit func(NormalizedRecord) error) error {
					if err := visit(records[0]); err != nil {
						return err
					}
					return visit(copy)
				}
			case "ambiguous_transport":
				other := append([]byte(nil), raw...)
				other[31] = 3
				raw = append(raw, other...)
			case "missing_peer":
				raw = bgp4mpFrame(7, false, false, bgpMessage(4, nil))
			case "wrong_peer_asn":
				binary.BigEndian.PutUint32(raw[12:], 101)
			case "addpath_mode":
				raw = bgp4mpFrame(9, false, false, bgpUpdate(attrs, nil, bgpNLRI("192.0.2.0/24", true, 1)))
			case "malformed_tail":
				raw = append(append([]byte(nil), raw...), raw[:len(raw)-1]...)
			}
			archive := streamArchive(base, raw, captured)
			if scenario == "different_collector" {
				archive.Collector[0] ^= 1
			}
			if scenario == "gap" {
				archive.Proof.From = captured.Add(time.Minute)
			}
			budget := NewMRTReplayBudget(context.Background())
			defer budget.Close()
			if scenario == "deadline" {
				budget.deadline = time.Now().Add(-time.Second)
			}
			if scenario == "update_limit" {
				budget.updates = maxMRTReplayUpdates
			}
			result, err := StreamMRTReplay(context.Background(), base, []MRTStreamArchive{archive}, captured.Add(6*time.Minute), budget, func(NormalizedRecord) error { return nil })
			if err != nil || !result.ColdFallback || result.Proof != nil {
				t.Fatal("unsafe source/session mapping produced a candidate", scenario, result, err)
			}
		})
	}
}

func TestStreamMRTReplayAddPathWithdrawalKeepsOtherObservedPath(t *testing.T) {
	base, records, captured := streamReplayFixture(t, true)
	other := records[0]
	meta := *other.MRT
	meta.PathID = 124
	other.MRT = &meta
	base.Walk = func(_ context.Context, visit func(NormalizedRecord) error) error {
		if err := visit(records[0]); err != nil {
			return err
		}
		return visit(other)
	}
	withdraw := bgp4mpFrame(9, false, false, bgpUpdate(nil, bgpNLRI("192.0.2.0/24", true, 123), nil))
	archive := streamArchive(base, withdraw, captured)
	budget := NewMRTReplayBudget(context.Background())
	defer budget.Close()
	var output []NormalizedRecord
	result, err := StreamMRTReplay(context.Background(), base, []MRTStreamArchive{archive}, captured.Add(6*time.Minute), budget, func(r NormalizedRecord) error { output = append(output, r); return nil })
	if err != nil || result.ColdFallback || len(output) != 2 || output[1].MRT.PathID != 124 {
		t.Fatal("ADDPATH withdrawal erased another path or retained withdrawn data", result, err, len(output))
	}
}

func TestStreamMRTReplaySessionResetRetractsOnlyMatchingPeer(t *testing.T) {
	base, records, captured := streamReplayFixture(t, false)
	other := records[0]
	meta := *other.MRT
	meta.PeerKey = mrtPeerKey([]byte{192, 0, 2, 3}, 101)
	meta.PeerIndex = 1
	other.MRT = &meta
	path := *other.Path
	path.Prefix = netip.MustParsePrefix("192.0.3.0/24")
	other.Path = &path
	base.Walk = func(_ context.Context, visit func(NormalizedRecord) error) error {
		if err := visit(records[0]); err != nil {
			return err
		}
		return visit(other)
	}
	reset := bgp4mpFrame(5, false, false, []byte{0, 6, 0, 1})
	quiet := bgp4mpFrame(4, false, false, bgpMessage(4, nil))
	binary.BigEndian.PutUint32(quiet[12:], 101)
	quiet[27] = 3
	archive := streamArchive(base, append(reset, quiet...), captured)
	budget := NewMRTReplayBudget(context.Background())
	defer budget.Close()
	var output []NormalizedRecord
	result, err := StreamMRTReplay(context.Background(), base, []MRTStreamArchive{archive}, captured.Add(6*time.Minute), budget, func(r NormalizedRecord) error { output = append(output, r); return nil })
	if err != nil || result.ColdFallback || len(output) != 2 || output[1].MRT.PeerKey != other.MRT.PeerKey || len(result.Proof.Peers) != 1 {
		t.Fatal("session reset retained stale routes or erased another peer", result, err, len(output))
	}
}
