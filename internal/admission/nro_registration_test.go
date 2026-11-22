package admission

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

func nroTestSource() Source {
	return Source{ID: intelligence.NRORegistrationID, Family: "nro-rir-delegation", Category: "geolocation", Format: "text", Scope: "prefix", Coverage: "positive_only", URL: nroURL, MaxCompressedBytes: nroLimit, Weight: 100, MaxAge: 30 * 24 * time.Hour, Parser: Parser{"nro-delegated-registration", "nro-global-extended-v2", 1}, Publication: Publication{"embedded", nroURL, "header.serial"}, Fields: []string{"registry", "cc", "type", "start", "value", "status"}, PublicFields: []string{"registration_country"}, FieldMappings: map[string][]string{"cc": {"registration_country"}}}
}

const nroTestReport = `2|nro|20261108|7|19821213|20261108|+0000
nro|*|asn|*|1|summary
nro|*|ipv4|*|5|summary
nro|*|ipv6|*|1|summary
arin|US|asn|1|1|20010920|assigned|holder|e-stats
apnic|AU|ipv4|1.0.0.1|3|20110811|assigned|holder|e-stats
ripencc|EU|ipv4|8.0.0.0|256|20110811|assigned|holder|e-stats
arin|US|ipv4|10.0.0.0|16777216|00000000|assigned|holder|e-stats
iana|ZZ|ipv4|0.0.0.0|16777216|19810901|reserved|holder|iana
apnic|AU|ipv4|11.0.0.0|256|20110811|available|holder|e-stats
apnic|JP|ipv6|2001:200::|35|19990813|assigned|holder|e-stats`

func TestNRODelegationRowsDomainsAndReceiptBinding(t *testing.T) {
	ctx := t.Context()
	s := nroTestSource()
	impl, ok := selectAdapter(s)
	if !ok || impl != nroRegistration || !publicationSupported(s) {
		t.Fatal("registration adapter")
	}
	addresses := map[string]string{}
	proof, e := parseNRO(ctx, strings.NewReader(nroTestReport), s, 100, false, func(r intelligence.NormalizedRecord) error {
		if r.Geo.PhysicalCountry != "" || r.Geo.Coordinates != nil || r.Geo.City != "" || r.Geo.Region != "" {
			t.Fatal("address registration mapped to physical fact")
		}
		addresses[r.Geo.Prefix.String()] = r.Geo.RegistrationCountry
		return r.Validate()
	})
	if e != nil || proof.Records != 7 || proof.Prefixes != 3 || addresses["1.0.0.1/32"] != "AU" || addresses["1.0.0.2/31"] != "AU" || addresses["2001:200::/35"] != "JP" {
		t.Fatal("range projection", proof, e)
	}
	for name, txt := range map[string]string{
		"removed row":               strings.Replace(nroTestReport, "apnic|AU|ipv4|11.0.0.0|256|20110811|available|holder|e-stats\n", "", 1),
		"conflicting overlap":       strings.Replace(nroTestReport, "8.0.0.0|256", "1.0.0.2|4", 1),
		"report clock disagreement": strings.Replace(nroTestReport, "|20261108|+0000", "|20261109|+0000", 1),
		"wrong domain":              strings.Replace(nroTestReport, "1.0.0.1|3", "1.0.0.1|4294967296", 1),
		"unmasked IPv6":             strings.Replace(nroTestReport, "2001:200::|35", "2001:200::1|35", 1),
		"false origin":              strings.Replace(nroTestReport, "|e-stats", "|iana", 1),
		"unexpected suffix":         nroTestReport + "\ninvalid",
	} {
		if _, e := parseNRO(ctx, strings.NewReader(txt), s, 100, false, nil); e == nil {
			t.Error(name)
		}
	}
	if subscription.PublicPrefix(netip.MustParsePrefix("8.0.0.0/5")) || subscription.PublicPrefix(netip.MustParsePrefix("2000::/3")) || !subscription.PublicPrefix(netip.MustParsePrefix("8.8.8.0/24")) {
		t.Fatal("reserved interior range")
	}
}
func TestNROCompleteReportChecksumReconciliationAndIndependentRevalidation(t *testing.T) {
	ctx := t.Context()
	data := []byte(nroTestReport)
	eng, orig, fetch, now, binding := prepared(t, data, "text")
	s := nroTestSource()
	s.Fixture, s.Rights, s.Admission = orig.Fixture, orig.Rights, "active"
	s.Fixture.Parser, s.Fixture.Schema, s.Fixture.PayloadFormat = s.Parser.ID, s.Parser.Schema, "nro-delegated-excerpt"
	s.Fixture.TestedAt = now.Format(time.RFC3339)
	certifyGeoTestSource(t, eng, s)
	h := sha256.Sum256(data)
	sum := []byte(hashString(h) + "  nro-delegated-stats\n")
	fetch.assets = map[string][]byte{nroURL: data, nroURL + ".sha256": sum}
	res, e := eng.Ingest(ctx, s, now, binding)
	if e != nil || res.Snapshot == nil {
		t.Fatalf("live source %v %#v", e, res.Decision)
	}
	snap := *res.Snapshot
	if snap.NROProof == nil || snap.NROProof.Prefixes != 3 || len(snap.Records) != 3 || !snap.PublishedAt.Equal(now) {
		t.Fatal("unbound NRO normalization")
	}
	pol := []intelligence.SourcePolicy{res.Policy}
	plan, e := intelligence.ReconcilePartitioned(ctx, eng.workspace, intelligence.BuildState{}, pol, []intelligence.SourceSnapshot{snap}, now, binding)
	if e != nil || len(plan.State.Sources) != 1 {
		t.Fatal("reconcile", e)
	}
	_, stats, e := RevalidateStoredSources(ctx, eng.workspace, []Source{s}, plan.State, now, binding)
	if e != nil || len(stats) != 1 || stats[0].nroProjection != snap.NROProof.Projection {
		t.Fatal("live revalidation", e)
	}
	missing := snap
	missing.NROProof = nil
	rejected, e := intelligence.Reconcile(intelligence.BuildState{}, pol, []intelligence.SourceSnapshot{missing}, now, binding)
	if e != nil || len(rejected.State.Sources) != 0 {
		t.Fatal("missing proof", e)
	}
	tampered := snap
	tampered.Records = append([]intelligence.NormalizedRecord(nil), snap.Records...)
	g := *tampered.Records[0].Geo
	g.RegistrationCountry = "US"
	tampered.Records[0].Geo = &g
	if _, e := intelligence.Reconcile(intelligence.BuildState{}, pol, []intelligence.SourceSnapshot{tampered}, now, binding); e == nil {
		t.Fatal("tampered registration accepted")
	}
	fetch.assets[nroURL+".sha256"] = bytes.Replace(sum, []byte("nro-delegated-stats"), []byte("other-stats"), 1)
	denied, e := eng.Ingest(ctx, s, now, binding)
	if e != nil || denied.Snapshot != nil {
		t.Fatal("misbound sidecar accepted", e)
	}
	if _, e := parseNRO(ctx, strings.NewReader(nroTestReport), s, 1, false, nil); !errors.Is(e, errNRO) {
		t.Fatal("unbounded output", e)
	}
}
