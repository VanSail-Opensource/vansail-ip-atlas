package admission

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func coordinatorMRTFixture(now time.Time, origin uint32, subnet byte) []byte {
	frame := func(subtype uint16, body []byte) []byte {
		header := binary.BigEndian.AppendUint32(nil, uint32(now.Unix()))
		header = binary.BigEndian.AppendUint16(header, 13)
		header = binary.BigEndian.AppendUint16(header, subtype)
		header = binary.BigEndian.AppendUint32(header, uint32(len(body)))
		return append(header, body...)
	}
	peer := []byte{0, 0, 0, 1, 0, 0, 0, 1, 2, 0, 0, 0, 2, 192, 0, 2, 1}
	peer = binary.BigEndian.AppendUint32(peer, 100)
	path := []byte{2, 2}
	path = binary.BigEndian.AppendUint32(path, 100)
	path = binary.BigEndian.AppendUint32(path, origin)
	attributes := append([]byte{0x40, 2, byte(len(path))}, path...)
	rib := []byte{0, 0, 0, 1, 24, 192, 0, subnet, 0, 1, 0, 0}
	rib = binary.BigEndian.AppendUint32(rib, uint32(now.Add(-1000*time.Hour).Unix()))
	rib = binary.BigEndian.AppendUint16(rib, uint16(len(attributes)))
	rib = append(rib, attributes...)
	return append(frame(1, peer), frame(2, rib)...)
}

func preparedMRTCoordinator(t *testing.T) (*Engine, []Source, *fixtureFetch, time.Time, [32]byte) {
	t.Helper()
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	payloads := [][]byte{coordinatorMRTFixture(now.Add(-2*time.Hour), 200, 2), coordinatorMRTFixture(now.Add(-2*time.Hour), 300, 3)}
	e, base, fetch, _, binding := prepared(t, payloads[0], "mrt")
	var sources []Source
	var reviews []certification
	code, err := implementationHash(context.Background(), e.workspace)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"unit-ris", "unit-views"} {
		source := base
		source.ID, source.Family, source.Category, source.Scope, source.Coverage = id, id, "bgp", "path", "mapping"
		source.Parser = Parser{"mrt-table-dump-v2", "mrt-table-dump-v2-unicast-v1", 1}
		source.URL = "https://example.com/" + id + ".mrt"
		source.Publication = Publication{"embedded", source.URL, "mrt_frame_capture_timestamp"}
		source.PublicFields = []string{"bgp_origins", "bgp_paths"}
		source.Fields = []string{"asn", "as_path"}
		source.FieldMappings = map[string][]string{"asn": {"bgp_origins"}, "as_path": {"bgp_paths"}}
		source.Fixture.Parser, source.Fixture.Schema = source.Parser.ID, source.Parser.Schema
		source.Fixture.Path = "fixtures/source-certification/" + id + ".mrt"
		source.Fixture.SHA256 = hashString(sha256.Sum256(payloads[i]))
		if err = os.WriteFile(filepath.Join(e.workspace, filepath.FromSlash(source.Fixture.Path)), payloads[i], 0600); err != nil {
			t.Fatal(err)
		}
		reviews = append(reviews, certification{source.ID, source.Parser.ID, source.Parser.Schema, 1, source.Fixture.SHA256, source.Fixture.TestedAt, hashString(code)})
		fetch.assets[source.URL] = payloads[i]
		sources = append(sources, source)
	}
	data, _ := json.Marshal(ledger{1, reviews})
	if err = os.WriteFile(filepath.Join(e.workspace, "fixtures/source-certification/adapter-certifications.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return e, sources, fetch, now, binding
}

func TestMRTCoordinatorBindsTwoCompleteIndependentCapturePayloads(t *testing.T) {
	e, sources, fetch, now, binding := preparedMRTCoordinator(t)
	result, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
	if err != nil || fetch.calls != 2 || len(result.CaptureClocks) != 2 {
		t.Fatal("coordinator did not acquire exactly two complete payloads", result, err, fetch.calls)
	}
	for _, intake := range result.Results {
		if intake.Snapshot == nil || intake.Snapshot.MRTProof == nil || intake.Decision.State != "current" || intake.Snapshot.ProofKind != "embedded" || !intake.Snapshot.PublishedAt.Equal(now.Add(-2*time.Hour)) || len(intake.Snapshot.Records) != 0 {
			t.Fatal("snapshot clock was not capture/payload bound", intake)
		}
		count := 0
		err = intelligence.WalkStoredSource(context.Background(), e.workspace, intelligence.StoredSource{RecordPartitions: intake.Snapshot.RecordPartitions}, func(record intelligence.NormalizedRecord) error {
			count++
			if record.MRTOriginatedAt == nil || now.Sub(*record.MRTOriginatedAt) <= 720*time.Hour {
				t.Fatal("fresh RIB erased or incorrectly expired a route's private originated time")
			}
			return nil
		})
		if err != nil || count != 2 {
			t.Fatal("typed streaming snapshot changed", count, err)
		}
	}
}

func TestMRTCoordinatorRejectsDisabledIncompleteAndCorrelatedInputs(t *testing.T) {
	for _, scenario := range []string{"disabled", "same_family", "uncertified", "same_payload", "bad_second_capture"} {
		t.Run(scenario, func(t *testing.T) {
			e, sources, fetch, now, binding := preparedMRTCoordinator(t)
			enabled := true
			switch scenario {
			case "disabled":
				enabled = false
			case "same_family":
				sources[1].Family = sources[0].Family
			case "uncertified":
				sources[1].Fixture.Status = "missing"
			case "same_payload":
				fetch.assets[sources[1].URL] = fetch.assets[sources[0].URL]
			case "bad_second_capture":
				bad := append([]byte(nil), fetch.assets[sources[1].URL]...)
				binary.BigEndian.PutUint32(bad, uint32(now.Add(25*time.Hour).Unix()))
				fetch.assets[sources[1].URL] = bad
			}
			result, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: enabled})
			if err != nil {
				t.Fatal(err)
			}
			for _, intake := range result.Results {
				if intake.Snapshot != nil || intake.Decision.State == "current" {
					t.Fatal("partial or correlated family set was published", intake)
				}
			}
			if (scenario == "disabled" || scenario == "same_family" || scenario == "uncertified") && fetch.calls != 0 {
				t.Fatal("control/fixture failure performed network IO")
			}
		})
	}
}

func TestMRTCoordinatorRunBudgetCannotResetAcrossCalls(t *testing.T) {
	e, sources, fetch, now, binding := preparedMRTCoordinator(t)
	remaining := int64(len(fetch.assets[sources[0].URL]) + len(fetch.assets[sources[1].URL]) - 1)
	e.mrt = &mrtAcquisitionState{sources: map[string]bool{sources[0].ID: true, sources[1].ID: true}, bytes: 1<<30 - remaining, fetch: fetch}
	first, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
	if err != nil || e.mrt.bytes != 1<<30 {
		t.Fatal("shared run budget did not stop at its exact ceiling", err, e.mrt.bytes)
	}
	for _, intake := range first.Results {
		if intake.Snapshot != nil {
			t.Fatal("partially acquired family set survived budget failure")
		}
	}
	calls := fetch.calls
	if _, err = e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true}); err != nil || fetch.calls != calls {
		t.Fatal("another call reset the exhausted MRT run ceiling", err)
	}
}

func TestMRTGenericColdProofPreservesActualCaptureIntervalWithoutReplayPrivileges(t *testing.T) {
	e, sources, fetch, now, binding := preparedMRTCoordinator(t)
	first := now.Add(-2 * time.Hour)
	for _, source := range sources {
		data := append([]byte(nil), fetch.assets[source.URL]...)
		rib := 12 + int(binary.BigEndian.Uint32(data[8:12]))
		binary.BigEndian.PutUint32(data[rib:], uint32(first.Add(5*time.Second).Unix()))
		fetch.assets[source.URL] = data
	}
	result, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
	if err != nil || result.Mode != "cold_rib" {
		t.Fatal(result, err)
	}
	for i, row := range result.Results {
		if row.Snapshot == nil || row.Snapshot.MRTProof == nil {
			t.Fatal("generic complete cold source lost its proof", row)
		}
		p := row.Snapshot.MRTProof
		if !p.CapturedAt.Equal(first) || !p.Through.Equal(first) || !p.CaptureEnd().Equal(first.Add(5*time.Second)) || !row.Snapshot.PublishedAt.Equal(first) {
			t.Fatal("multi-frame cold capture invented or renewed an epoch", p)
		}
		hash, err := p.ContentHash()
		if err != nil || hash != row.Snapshot.PayloadHash || hash != sha256.Sum256(fetch.assets[sources[i].URL]) {
			t.Fatal("cold metadata changed exact raw payload identity", err)
		}
		if _, _, err = nextMRTUpdateURL(sources[i].URL, p.Through); err == nil {
			t.Fatal("generic publisher acquired recognized-provider replay privileges")
		}
	}
}
