package admission

import (
	"bytes"
	"compress/gzip"
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

func replayUpdateFixture(captured time.Time, origin uint32, subnet byte) []byte {
	path := []byte{2, 2}
	path = binary.BigEndian.AppendUint32(path, 100)
	path = binary.BigEndian.AppendUint32(path, origin)
	attrs := []byte{0x40, 1, 1, 0, 0x40, 2, byte(len(path))}
	attrs = append(attrs, path...)
	attrs = append(attrs, 0x40, 3, 4, 192, 0, 2, 1)
	body := []byte{0, 0}
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(body, attrs...)
	body = append(body, 24, 192, 0, subnet)
	message := bytes.Repeat([]byte{0xff}, 16)
	message = binary.BigEndian.AppendUint16(message, uint16(len(body)+19))
	message = append(message, 2)
	message = append(message, body...)
	transport := binary.BigEndian.AppendUint32(nil, 100)
	transport = binary.BigEndian.AppendUint32(transport, 200)
	transport = append(transport, 0, 0, 0, 1, 192, 0, 2, 1, 192, 0, 2, 2)
	transport = append(transport, message...)
	header := binary.BigEndian.AppendUint32(nil, uint32(captured.Unix()))
	header = binary.BigEndian.AppendUint16(header, 16)
	header = binary.BigEndian.AppendUint16(header, 4)
	header = binary.BigEndian.AppendUint32(header, uint32(len(transport)))
	return append(header, transport...)
}

func gzipMRTFixture(t *testing.T, input []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, err := z.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func preparedReplayCoordinator(t *testing.T) (*Engine, []Source, *fixtureFetch, time.Time, [32]byte, map[string][]string) {
	t.Helper()
	e, sources, fetch, now, binding := preparedMRTCoordinator(t)
	var reviews []certification
	code, err := implementationHash(context.Background(), e.workspace)
	if err != nil {
		t.Fatal(err)
	}
	plans := map[string][]string{}
	for i := range sources {
		source := &sources[i]
		collector := []string{"rrc01", "rrc03"}[i]
		source.URL = "https://data.ris.ripe.net/" + collector + "/" + now.Format("2006.01") + "/bview." + now.Format("20060102.1504") + ".gz"
		source.Publication = Publication{"embedded", source.URL, "mrt_frame_capture_timestamp"}
		source.Format = "mrt-gz"
		payload := gzipMRTFixture(t, coordinatorMRTFixture(now, uint32(200+i), byte(2+i)))
		fetch.assets[source.URL] = payload
		source.Fixture.Path = "fixtures/source-certification/" + source.ID + "-base.gz"
		source.Fixture.SHA256 = hashString(sha256.Sum256(payload))
		if err = os.WriteFile(filepath.Join(e.workspace, filepath.FromSlash(source.Fixture.Path)), payload, 0600); err != nil {
			t.Fatal(err)
		}
		reviews = append(reviews, certification{source.ID, source.Parser.ID, source.Parser.Schema, 1, source.Fixture.SHA256, source.Fixture.TestedAt, hashString(code)})
		updates := gzipMRTFixture(t, replayUpdateFixture(now.Add(time.Minute), uint32(300+i), byte(4+i)))
		fixture := source.Fixture
		fixture.Path = "fixtures/source-certification/" + source.ID + "-updates.gz"
		fixture.Parser, fixture.Schema = "mrt-bgp4mp", "mrt-bgp4mp-unicast-v1"
		fixture.SHA256 = hashString(sha256.Sum256(updates))
		source.MRTUpdatesFixture = &fixture
		if err = os.WriteFile(filepath.Join(e.workspace, filepath.FromSlash(fixture.Path)), updates, 0600); err != nil {
			t.Fatal(err)
		}
		reviews = append(reviews, certification{source.ID + "-updates", fixture.Parser, fixture.Schema, 1, fixture.SHA256, fixture.TestedAt, hashString(code)})
		url := "https://data.ris.ripe.net/" + collector + "/" + now.Format("2006.01") + "/updates." + now.Format("20060102.1504") + ".gz"
		fetch.assets[url] = updates
		plans[source.ID] = []string{url}
	}
	data, _ := json.Marshal(ledger{1, reviews})
	if err = os.WriteFile(filepath.Join(e.workspace, "fixtures/source-certification/adapter-certifications.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return e, sources, fetch, now, binding, plans
}

func sealMRTResult(t *testing.T, e *Engine, result MRTIntakeResult, now time.Time, binding [32]byte) {
	t.Helper()
	var policies []intelligence.SourcePolicy
	var snapshots []intelligence.SourceSnapshot
	for _, value := range result.Results {
		if value.Snapshot == nil {
			t.Fatal("cannot seal missing MRT snapshot", value.Decision)
		}
		policies = append(policies, value.Policy)
		snapshots = append(snapshots, *value.Snapshot)
	}
	plan, err := intelligence.ReconcilePartitioned(context.Background(), e.workspace, intelligence.BuildState{}, policies, snapshots, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = intelligence.SavePrivateState(e.workspace, plan.State); err != nil {
		t.Fatal(err)
	}
	if err = e.SealPrivateState(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
}

func TestMRTCoordinatorActuallyReplaysVerifiedSameCollectorArchives(t *testing.T) {
	e, sources, fetch, now, binding, plans := preparedReplayCoordinator(t)
	base, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	sealMRTResult(t, e, base, now, binding)
	for _, source := range sources {
		delete(fetch.assets, source.URL)
	} // Successful replay cannot secretly fetch a cold RIB.
	before := fetch.calls
	result, err := e.IngestMRT(context.Background(), sources, now.Add(6*time.Minute), binding, MRTIntakeOptions{Enabled: true, ReplayArchives: plans})
	if err != nil || result.Mode != "replayed_updates" || result.ReplayFallbackReason != "" || result.ReplayUpdates != 2 || fetch.calls-before != 2 {
		t.Fatal("verified replay did not replace cold acquisition", result, err, fetch.calls-before)
	}
	for i, intake := range result.Results {
		if intake.Snapshot == nil || intake.Snapshot.MRTProof == nil || len(intake.Snapshot.MRTProof.Archives) != 1 || !intake.Snapshot.PublishedAt.Equal(base.Results[i].Snapshot.PublishedAt) || !intake.Snapshot.MRTProof.Through.Equal(now.Add(5*time.Minute)) {
			t.Fatal("replay was not base-age/hash/window bound", intake)
		}
		paths := 0
		err = intelligence.WalkStoredSource(context.Background(), e.workspace, intelligence.StoredSource{RecordPartitions: intake.Snapshot.RecordPartitions}, func(r intelligence.NormalizedRecord) error {
			if r.Kind == intelligence.RecordPath {
				paths++
			}
			return nil
		})
		if err != nil || paths != 2 {
			t.Fatal("replay dropped the unchanged RIB or new observed prefix", paths, err)
		}
	}
	sealMRTResult(t, e, result, now.Add(6*time.Minute), binding)
}

func TestMRTReplayMissingCompanionOrDifferentCollectorFallsBackBeforeUpdateIO(t *testing.T) {
	for _, scenario := range []string{"missing_companion", "different_collector"} {
		t.Run(scenario, func(t *testing.T) {
			e, sources, fetch, now, binding, plans := preparedReplayCoordinator(t)
			base, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			sealMRTResult(t, e, base, now, binding)
			if scenario == "missing_companion" {
				sources[0].MRTUpdatesFixture = nil
			} else {
				plans[sources[0].ID][0] = "https://data.ris.ripe.net/rrc99/" + now.Format("2006.01") + "/updates." + now.Format("20060102.1504") + ".gz"
			}
			before := fetch.calls
			result, err := e.IngestMRT(context.Background(), sources, now.Add(6*time.Minute), binding, MRTIntakeOptions{Enabled: true, ReplayArchives: plans})
			if err != nil || result.Mode != "cold_rib" || result.ReplayFallbackReason == "" || fetch.calls-before != 2 {
				t.Fatal("unsafe update plan did not take the verified cold path", result, err)
			}
			for _, intake := range result.Results {
				if intake.Snapshot == nil {
					t.Fatal("cold fallback failed", intake.Decision)
				}
			}
		})
	}
}

func TestMRTCompanionFixtureBytesParticipateInRevocationFingerprint(t *testing.T) {
	e, sources, _, _, _, _ := preparedReplayCoordinator(t)
	before, err := CertificationFingerprint(context.Background(), e.workspace, sources)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.workspace, filepath.FromSlash(sources[0].MRTUpdatesFixture.Path))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	after, err := CertificationFingerprint(context.Background(), e.workspace, sources)
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("UPDATE fixture revocation did not invalidate the certified candidate identity")
	}
}

func TestMRTAutomaticClosedArchivePlanAndNoChangeReuse(t *testing.T) {
	e, sources, fetch, now, binding, _ := preparedReplayCoordinator(t)
	base, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	sealMRTResult(t, e, base, now, binding)
	for _, source := range sources {
		delete(fetch.assets, source.URL)
	}
	result, err := e.IngestMRT(context.Background(), sources, now.Add(6*time.Minute), binding, MRTIntakeOptions{Enabled: true})
	if err != nil || result.Mode != "replayed_updates" || result.ReplayUpdates != 2 {
		t.Fatal("automatic provider interval plan did not replay", result, err)
	}
	sealMRTResult(t, e, result, now.Add(6*time.Minute), binding)
	before := fetch.calls
	unchanged, err := e.IngestMRT(context.Background(), sources, now.Add(7*time.Minute), binding, MRTIntakeOptions{Enabled: true})
	if err != nil || unchanged.Mode != "unchanged_mrt" || fetch.calls != before {
		t.Fatal("no new closed interval triggered network acquisition", unchanged, err)
	}
	for i, intake := range unchanged.Results {
		if intake.Snapshot == nil || intake.Snapshot.PayloadHash != result.Results[i].Snapshot.PayloadHash || !intake.Snapshot.PublishedAt.Equal(base.Results[i].Snapshot.PublishedAt) {
			t.Fatal("no-change receipt renewed age or changed content")
		}
	}
}
