package admission

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// The fixture retains a real observed route boundary even when its terminal
// AS_PATH cannot establish a public scalar origin. Its originated clock is old;
// the independently checked complete RIB capture supplies current observation.
func boundaryMRTFixture(captured time.Time, prefix netip.Prefix, segments []intelligence.PathSegment) []byte {
	frame := func(subtype uint16, body []byte) []byte {
		header := binary.BigEndian.AppendUint32(nil, uint32(captured.Unix()))
		header = binary.BigEndian.AppendUint16(header, 13)
		header = binary.BigEndian.AppendUint16(header, subtype)
		header = binary.BigEndian.AppendUint32(header, uint32(len(body)))
		return append(header, body...)
	}
	peer := []byte{0, 0, 0, 1, 0, 0, 0, 1, 2, 0, 0, 0, 2, 192, 0, 2, 1}
	peer = binary.BigEndian.AppendUint32(peer, 100)
	var path []byte
	for _, segment := range segments {
		kind := byte(2)
		if segment.Type == intelligence.ASSet {
			kind = 1
		}
		path = append(path, kind, byte(len(segment.ASNs)))
		for _, asn := range segment.ASNs {
			path = binary.BigEndian.AppendUint32(path, asn)
		}
	}
	attributes := append([]byte{0x40, 2, byte(len(path))}, path...)
	rib := binary.BigEndian.AppendUint32(nil, 1)
	rib = append(rib, byte(prefix.Bits()))
	rib = append(rib, prefix.Addr().AsSlice()[:(prefix.Bits()+7)/8]...)
	rib = binary.BigEndian.AppendUint16(rib, 1)
	rib = binary.BigEndian.AppendUint16(rib, 0)
	rib = binary.BigEndian.AppendUint32(rib, uint32(captured.Add(-1000*time.Hour).Unix()))
	rib = binary.BigEndian.AppendUint16(rib, uint16(len(attributes)))
	rib = append(rib, attributes...)
	subtype := uint16(2)
	if prefix.Addr().Is6() {
		subtype = 4
	}
	return append(frame(1, peer), frame(subtype, rib)...)
}

func parseBoundaryMRT(t *testing.T, data []byte, now time.Time) ([]intelligence.NormalizedRecord, intelligence.MRTSnapshotClock, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snapshot.mrt")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	source := Source{Format: "mrt", Family: "synthetic", MaxCompressedBytes: int64(len(data) + 1024), MaxAge: 720 * time.Hour}
	var records []intelligence.NormalizedRecord
	clock, err := parseMRTCapturePayload(context.Background(), file, int64(len(data)), source, now, 100, func(record intelligence.NormalizedRecord) error {
		records = append(records, record)
		return nil
	})
	return records, clock, err
}

func TestMRTCaptureUnsupportedOriginsRetainUnknownBoundaries(t *testing.T) {
	captured := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	for _, prefix := range []string{"11.0.1.0/24", "2001:4860:1::/48"} {
		for _, tc := range []struct {
			name     string
			segments []intelligence.PathSegment
			origin   uint32
		}{
			{"public", []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{100, 13335}}}, 13335},
			{"empty_path", nil, 0},
			{"private", []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{100, 65000}}}, 0},
			{"as_trans", []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{100, 23456}}}, 0},
			{"terminal_set", []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{100}}, {Type: intelligence.ASSet, ASNs: []uint32{13335, 15169}}}, 0},
		} {
			t.Run(prefix+"/"+tc.name, func(t *testing.T) {
				p := netip.MustParsePrefix(prefix)
				records, clock, err := parseBoundaryMRT(t, boundaryMRTFixture(captured, p, tc.segments), captured.Add(time.Hour))
				want := 1
				if tc.origin != 0 {
					want = 2
				}
				if err != nil || len(records) != want || clock.Frames != 2 || !clock.First.Equal(captured) || !clock.Last.Equal(captured) {
					t.Fatalf("complete capture rejected or changed: records=%d clock=%+v err=%v", len(records), clock, err)
				}
				for _, record := range records {
					if err := record.Validate(); err != nil || record.MRT == nil || !record.MRT.CapturedAt.Equal(captured) || record.MRTOriginatedAt == nil || !record.MRTOriginatedAt.Equal(captured.Add(-1000*time.Hour)) {
						t.Fatal("lost observed route identity or original audit clock", err)
					}
				}
				origins := records[0].Origins
				if origins == nil || origins.Prefix != p || origins.Origins == nil {
					t.Fatal("missing explicit observed prefix boundary")
				}
				if tc.origin == 0 && len(origins.Origins) != 0 || tc.origin != 0 && (len(origins.Origins) != 1 || origins.Origins[0] != tc.origin) {
					t.Fatal("unsupported observation invented a scalar origin or MOAS", origins)
				}
			})
		}
	}
}

func TestMRTCaptureUnknownBoundaryStillRequiresCompleteFreshFrames(t *testing.T) {
	captured := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	for _, scenario := range []string{"truncated", "trailing_header", "future_originated", "expired_capture", "future_capture", "invalid_zero_asn"} {
		t.Run(scenario, func(t *testing.T) {
			data := boundaryMRTFixture(captured, netip.MustParsePrefix("11.0.1.0/24"), []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{100, 65000}}})
			now := captured.Add(time.Hour)
			switch scenario {
			case "truncated":
				data = data[:len(data)-1]
			case "trailing_header":
				data = append(data, 0)
			case "future_originated":
				rib := 12 + int(binary.BigEndian.Uint32(data[8:12]))
				binary.BigEndian.PutUint32(data[rib+12+12:], uint32(captured.Add(25*time.Hour).Unix()))
			case "expired_capture":
				now = captured.Add(720 * time.Hour)
			case "future_capture":
				now = captured.Add(-25 * time.Hour)
			case "invalid_zero_asn":
				data = boundaryMRTFixture(captured, netip.MustParsePrefix("11.0.1.0/24"), []intelligence.PathSegment{{Type: intelligence.ASSequence, ASNs: []uint32{100, 0}}})
			}
			_, clock, err := parseBoundaryMRT(t, data, now)
			if err == nil || clock != (intelligence.MRTSnapshotClock{}) {
				t.Fatal("invalid complete capture gained a proof", clock, err)
			}
		})
	}
}

func TestUnknownOriginBoundariesCannotQualifyRoutingCapabilities(t *testing.T) {
	stats := []SourceStatistics{{ID: "one", Family: "one"}, {ID: "two", Family: "two"}}
	for i := range stats {
		stats[i].Kinds[intelligence.RecordOrigins-1] = 1
		stats[i].Kinds[intelligence.RecordPath-1] = 1
	}
	for _, capability := range deriveCapabilities(stats, time.Unix(1800000000, 0)).Capabilities {
		if (capability.Capability == "asn_prefix" || capability.Capability == "bgp_origins_paths") && capability.Qualified {
			t.Fatal("empty observed prefix qualified positive origin capability", capability.Capability)
		}
	}
	stats[0].OriginObservations = 1
	for _, capability := range deriveCapabilities(stats, time.Unix(1800000000, 0)).Capabilities {
		if (capability.Capability == "asn_prefix" || capability.Capability == "bgp_origins_paths") && !capability.Qualified {
			t.Fatal("positive public origin lost capability", capability.Capability)
		}
	}
}

func TestMRTQualificationCountsPositiveAndUnknownObservationsSeparately(t *testing.T) {
	e, sources, fetch, now, binding := preparedMRTCoordinator(t)
	for i := range sources {
		sources[i].Rights.Identifier = "CC0-1.0"
	}
	fetch.assets[sources[0].URL] = coordinatorMRTFixture(now.Add(-2*time.Hour), 65000, 2)
	result, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
	if err != nil || len(result.Results) != 2 {
		t.Fatal(result, err)
	}
	var snapshots []intelligence.SourceSnapshot
	var policies []intelligence.SourcePolicy
	for _, intake := range result.Results {
		if intake.Snapshot == nil {
			t.Fatal("valid complete capture denied", intake.Decision)
		}
		snapshots = append(snapshots, *intake.Snapshot)
		policies = append(policies, intake.Policy)
	}
	plan, err := intelligence.ReconcilePartitioned(context.Background(), e.workspace, intelligence.BuildState{}, policies, snapshots, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	_, stats, err := RevalidateStoredSources(context.Background(), e.workspace, sources, plan.State, now, binding)
	if err != nil || len(stats) != 2 {
		t.Fatal(stats, err)
	}
	for _, stat := range stats {
		if stat.ID == sources[0].ID {
			if stat.Records != 1 || stat.OriginObservations != 0 || stat.UnknownOriginBoundaries != 1 || stat.Kinds[intelligence.RecordPath-1] != 0 {
				t.Fatal("unknown boundary counted as positive routing", stat)
			}
		} else if stat.Records != 2 || stat.OriginObservations != 1 || stat.UnknownOriginBoundaries != 0 || stat.Kinds[intelligence.RecordPath-1] != 1 {
			t.Fatal("positive observation statistics changed", stat)
		}
	}
}
