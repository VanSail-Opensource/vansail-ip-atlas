package admission

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func googleNetworkTestSource() Source {
	return Source{ID: intelligence.GoogleNetworkSourceID, Family: "google-network-owner", Category: "network_identity", URL: googleNetworkURL,
		Format: "json", Scope: "prefix", Coverage: "positive_only", MaxCompressedBytes: googleNetworkLimit, MaxAge: 720 * time.Hour, Weight: 100,
		Parser: Parser{intelligence.GoogleNetworkSourceID, "google-owned-ip-ranges-v1", 1}, Publication: Publication{"embedded", googleNetworkURL, "syncToken"},
		Fields: []string{"syncToken", "creationTime", "ipv4Prefix", "ipv6Prefix"}, PublicFields: []string{"network_organization"}, FieldMappings: map[string][]string{"ipv4Prefix": {"network_organization"}, "ipv6Prefix": {"network_organization"}}}
}

func TestGoogleNetworkStrictOriginalAndPublication(t *testing.T) {
	const payload = `{"syncToken":"1795572521387","creationTime":"2026-11-24T18:08:41.387493","prefixes":[{"ipv4Prefix":"8.8.8.0/24"},{"ipv6Prefix":"2001:4860::/32"}]}`
	ctx := t.Context()
	source := googleNetworkTestSource()
	clock := time.Date(2026, 11, 25, 2, 8, 41, 387000000, time.UTC)
	impl, ok := selectAdapter(source)
	if !ok || impl != googleNetwork || !publicationSupported(source) {
		t.Fatal("Google source contract rejected")
	}
	var values []string
	proof, err := parseGoogleNetwork(ctx, strings.NewReader(payload), source, clock, 2, func(r intelligence.NormalizedRecord) error {
		values = append(values, r.NetworkOrganization.Prefix.String())
		if r.NetworkOrganization.Organization != "Google" || r.Origins != nil || r.Geo != nil || r.Usage != nil || r.Evidence != nil {
			t.Fatal("unexpected additional classification")
		}
		return r.Validate()
	})
	if err != nil || !proof.PublishedAt.Equal(clock) || proof.Prefixes != 2 || proof.IPv4 != 1 || proof.IPv6 != 1 || len(values) != 2 || values[0] != "8.8.8.0/24" || values[1] != "2001:4860::/32" || proof.PayloadHash != sha256.Sum256([]byte(payload)) {
		t.Fatal("complete source projection", proof, values, err)
	}
	for _, bad := range []string{
		payload + `[]`,
		strings.Replace(payload, `"prefixes"`, `"PREFIXES"`, 1),
		strings.Replace(payload, `"ipv4Prefix"`, `"IPV4PREFIX"`, 1),
		strings.Replace(payload, `"creationTime":`, `"creationTime":"2026-11-24T18:08:41.387493","creationTime":`, 1),
		strings.Replace(payload, "1795572521387", "1795572521388", 1),
		strings.Replace(payload, "T18:", "T02:", 1),
		strings.Replace(payload, `{"ipv6Prefix"`, `{"ipv4Prefix":"8.8.8.0/24"},{"ipv6Prefix"`, 1),
		strings.Replace(payload, `"ipv6Prefix"`, `"ipv4Prefix"`, 1),
		strings.Replace(payload, "8.8.8.0/24", "8.8.8.1/24", 1),
		strings.Replace(payload, "8.8.8.0/24", "0.0.0.0/0", 1),
		strings.Replace(payload, "2001:4860::/32", "2001:db8::/32", 1),
		strings.Replace(payload, "2001:4860::/32", "::ffff:8.8.8.8/128", 1),
		strings.Replace(payload, `,{"ipv6Prefix":"2001:4860::/32"}`, "", 1),
		strings.Replace(payload, `"ipv4Prefix":`, `"service":"Google Cloud","ipv4Prefix":`, 1),
	} {
		if _, err := parseGoogleNetwork(ctx, strings.NewReader(bad), source, clock, 3, nil); err == nil {
			t.Errorf("invalid report accepted: %s", bad)
		}
	}
	if _, err := parseGoogleNetwork(ctx, strings.NewReader(payload), source, clock.Add(-time.Millisecond), 2, nil); err == nil {
		t.Fatal("future publication")
	}
	if _, err := parseGoogleNetwork(ctx, strings.NewReader(payload), source, clock, 1, nil); err == nil {
		t.Fatal("row budget exceeded")
	}
	source.MaxCompressedBytes = 12
	if _, err := parseGoogleNetwork(ctx, strings.NewReader(payload), source, clock, 2, nil); err == nil {
		t.Fatal("input byte budget exceeded")
	}
}

func TestGoogleNetworkClockAtBothPacificOffsets(t *testing.T) {
	for _, tc := range []struct{ utc, local string }{
		{"2026-07-11T07:30:00.123Z", "2026-07-11T00:30:00.123456"},
		{"2026-11-01T08:30:00.123Z", "2026-11-01T01:30:00.123456"},
		{"2026-11-01T09:30:00.123Z", "2026-11-01T01:30:00.123456"},
	} {
		clock, err := time.Parse(time.RFC3339Nano, tc.utc)
		if err != nil {
			t.Fatal(err)
		}
		observed, err := googleNetworkClock(fmt.Sprint(clock.UnixMilli()), tc.local)
		if err != nil || !observed.Equal(clock) {
			t.Fatalf("publication clock %s: %v", tc.utc, err)
		}
	}
}

func TestGoogleNetworkAdmissionAndRetraction(t *testing.T) {
	ctx := t.Context()
	data := []byte(`{"syncToken":"1794096000000","creationTime":"2026-11-07T16:00:00.000","prefixes":[{"ipv4Prefix":"8.8.8.0/24"},{"ipv6Prefix":"2001:4860::/32"}]}`)
	eng, orig, fetch, now, binding := prepared(t, data, "json")
	s := googleNetworkTestSource()
	s.Fixture, s.Rights, s.Admission = orig.Fixture, orig.Rights, "active"
	s.Fixture.Parser, s.Fixture.Schema, s.Fixture.PayloadFormat = s.Parser.ID, s.Parser.Schema, "original"
	s.Fixture.TestedAt = now.Format(time.RFC3339)
	certifyGeoTestSource(t, eng, s)
	fetch.assets = map[string][]byte{googleNetworkURL: data}
	result, err := eng.IngestPartitioned(ctx, s, now, binding)
	if err != nil || result.Snapshot == nil || result.Snapshot.GoogleNetworkProof == nil {
		t.Fatalf("partitioned intake: %v, %#v", err, result.Decision)
	}
	policy := []intelligence.SourcePolicy{result.Policy}
	plan, err := intelligence.ReconcilePartitioned(ctx, eng.workspace, intelligence.BuildState{}, policy, []intelligence.SourceSnapshot{*result.Snapshot}, now, binding)
	if err != nil || len(plan.State.Sources) != 1 {
		t.Fatal("reconcile", err)
	}
	_, stats, err := RevalidateStoredSources(ctx, eng.workspace, []Source{s}, plan.State, now, binding)
	if err != nil || len(stats) != 1 || stats[0].Records != 2 || stats[0].googleProjection != result.Snapshot.GoogleNetworkProof.Projection {
		t.Fatal("independent record qualification", err)
	}
	expired, err := eng.Ingest(ctx, s, now.Add(720*time.Hour), binding)
	if err != nil || expired.Snapshot != nil || expired.Decision.State != "stale" {
		t.Fatal("unchanged original renewed outside its validity", err, expired.Decision)
	}
}
