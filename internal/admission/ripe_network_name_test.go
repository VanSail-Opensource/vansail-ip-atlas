package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func ripeNamesTestSource() Source {
	return Source{ID: intelligence.RIPENetworkNameSourceID, Family: "ripe-registry", Category: "network_identity", URL: ripeNamesURL,
		Format: "text-gz", Scope: "prefix", Coverage: "positive_only", MaxCompressedBytes: ripeNamesCompressed, MaxAge: 720 * time.Hour, Weight: 100,
		Parser: Parser{intelligence.RIPENetworkNameSourceID, "ripe-db-inet6num-v2", 2}, Publication: Publication{"embedded", ripeNamesURL, "last-modified"},
		Fields: []string{"inet6num", "netname", "source", "last-modified", "country", "descr", "mnt-by", "status"}, PublicFields: []string{"network_name", "isp"}, FieldMappings: map[string][]string{"netname": {"network_name"}, "descr": {"isp"}}}
}

const ripeTestInventory = `# RIPE test export

Inet6Num: 2a00:1700::/32
NetName: V6-EXAMPLE-NETWORK
remarks: contact@example.invalid
+ example continuing opaque text
SOURCE: ripe # Filtered
last-modified: 2026-10-01T00:00:00Z

inet6num: 2a00:1700::/40
netname: contact@example.invalid
source: RIPE
last-modified: 2026-11-07T00:00:00Z

inet6num: 2a00:1700:ff00::/40
netname: NotTheAuthority
source: OTHER

inet6num: 2a00:1700:11::/48
netname: AB123-RIPE
source: RIPE
last-modified: 2026-11-07T00:00:00Z

inet6num: 2001:db8::/32
netname: NONPUBLIC
source: RIPE
last-modified: 2026-11-07T00:00:00Z

inet6num: 2a00:1900::/32
netname: OTHER-V6
country: BE
mnt-by: TELENET-DBM
status: AGGREGATED-BY-LIR
descr: Telenet N.V. Mobile Residential Broadband
source: RIPE
last-modified: 2026-11-08T00:00:00Z
`

func TestRIPENamesScopesAndIntrinsicDates(t *testing.T) {
	s := ripeNamesTestSource()
	if a, ok := selectAdapter(s); !ok || a != ripeNetworkNames || !publicationSupported(s) {
		t.Fatal("source contract")
	}
	now := time.Date(2026, 11, 8, 1, 0, 0, 0, time.UTC)
	rows := map[string]string{}
	inventory, n, err := readRIPENames(t.Context(), strings.NewReader(ripeTestInventory), now, 10, 1<<20, false, func(r intelligence.NormalizedRecord) error {
		rows[r.NetworkName.Prefix.String()] = r.NetworkName.Name
		return r.Validate()
	})
	if err != nil || inventory.rows != 6 || inventory.prefixes != 5 || inventory.named != 2 || !inventory.newest.Equal(now.Add(-time.Hour)) || n != int64(len(ripeTestInventory)) {
		t.Fatal("registry projection", inventory, n, err)
	}
	for k, v := range map[string]string{"2a00:1700::/32": "V6-EXAMPLE-NETWORK", "2a00:1700::/40": "", "2a00:1700:ff00::/40": "", "2a00:1700:11::/48": "", "2a00:1900::/32": "OTHER-V6"} {
		if actual, ok := rows[k]; !ok || actual != v {
			t.Fatal("scope not preserved", k)
		}
	}
	for _, bad := range []string{
		strings.Replace(ripeTestInventory, "::/32", "::1/32", 1),
		strings.Replace(ripeTestInventory, "::/40", "::/32", 1),
		strings.Replace(ripeTestInventory, "SOURCE: ripe # Filtered", "source: RIPE\nsource: RIPE", 1),
		strings.Replace(ripeTestInventory, "SOURCE: ripe # Filtered", "remarks: source missing", 1),
		strings.Replace(ripeTestInventory, "2a00:1700::/32", "8.8.8.0/24", 1),
		strings.Replace(ripeTestInventory, "2a00:1700::/32", "::ffff:8.8.8.0/120", 1),
		strings.Replace(ripeTestInventory, "2026-10-01T00:00:00Z", "2027-10-01T00:00:00Z", 1),
		strings.Replace(ripeTestInventory, "2026-10-01T00:00:00Z", "2026-11-07", 1),
		strings.Replace(ripeTestInventory, "last-modified: 2026-10-01T00:00:00Z", "", 1),
		strings.Replace(ripeTestInventory, "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z\n  ignored?", 1),
		strings.Replace(ripeTestInventory, "Inet6Num: 2a00:1700::/32", "route6: 2a00:1700::/32", 1),
		strings.Replace(ripeTestInventory, "remarks:", "bad=attribute:", 1),
	} {
		if _, _, e := readRIPENames(t.Context(), strings.NewReader(bad), now, 10, 1<<20, false, nil); e == nil {
			t.Fatal("invalid registry framing, date or scope accepted")
		}
	}
	if _, _, e := readRIPENames(t.Context(), strings.NewReader(ripeTestInventory), now, 3, 1<<20, true, nil); e == nil {
		t.Fatal("emission budget ignored")
	}
	if _, _, e := readRIPENames(t.Context(), strings.NewReader(ripeTestInventory), now, 10, 30, true, nil); e == nil {
		t.Fatal("decoded byte budget ignored")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, e := readRIPENames(ctx, strings.NewReader(ripeTestInventory), now, 10, 1<<20, false, nil); e == nil {
		t.Fatal("cancelled inventory accepted")
	}
}

func TestRIPENamesGzipMembersAndEncoding(t *testing.T) {
	s := ripeNamesTestSource()
	clock := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	data := gzipMRTFixture(t, []byte(ripeTestInventory))
	badCRC := bytes.Clone(data)
	badCRC[len(data)-8] ^= 1
	for _, body := range [][]byte{badCRC, data[:len(data)-1], append(bytes.Clone(data), 0), append(bytes.Clone(data), data...)} {
		if _, _, _, e := readRIPENamesArchive(t.Context(), bytes.NewReader(body), s, clock, 10, 1<<20, false, nil); e == nil {
			t.Fatal("corrupt gzip member or extra bytes accepted")
		}
	}
	text := bytes.Replace([]byte(ripeTestInventory), []byte("contact@example.invalid\n+"), []byte{'c', 0xe9, '\n', '+'}, 1)
	z := gzipMRTFixture(t, text)
	if _, _, _, e := readRIPENamesArchive(t.Context(), bytes.NewReader(z), s, clock, 10, 1<<20, true, nil); e == nil {
		t.Fatal("bad UTF-8 archive accepted")
	}
	if _, _, _, e := readRIPENamesArchive(t.Context(), bytes.NewReader(z), s, clock, 10, 1<<20, false, nil); e != nil {
		t.Fatal("opaque Latin-1 attribute rejected", e)
	}
}

func TestRIPENamesPairedIntakeReceiptAndRetraction(t *testing.T) {
	ctx := t.Context()
	text := []byte(ripeTestInventory)
	eng, orig, fetch, now, binding := prepared(t, text, "text")
	s := ripeNamesTestSource()
	s.Fixture, s.Rights, s.Admission = orig.Fixture, orig.Rights, "active"
	s.Fixture.Parser, s.Fixture.Schema, s.Fixture.PayloadFormat = s.Parser.ID, s.Parser.Schema, "ripe-inet6num-excerpt"
	s.Fixture.TestedAt = now.Format(time.RFC3339)
	certifyGeoTestSource(t, eng, s)
	primary := gzipMRTFixture(t, text)
	utf := gzipMRTFixture(t, bytes.Replace(text, []byte("contact@example.invalid\n+"), []byte("different opaque description\n+"), 1))
	fetch.assets = map[string][]byte{ripeNamesURL: primary, ripeNamesUTF8URL: utf}
	r, e := eng.IngestPartitioned(ctx, s, now, binding)
	if e != nil || r.Snapshot == nil {
		t.Fatal("actual pair failed", r.Decision, e)
	}
	p := r.Snapshot.RIPENetworkProof
	if p == nil || p.Records != 6 || p.NamedPrefixes != 2 || p.PayloadHash != sha256.Sum256(primary) || p.UTF8Hash != sha256.Sum256(utf) || !p.PublishedAt.Equal(now) {
		t.Fatal("unbound source pair")
	}
	plan, e := intelligence.ReconcilePartitioned(ctx, eng.workspace, intelligence.BuildState{}, []intelligence.SourcePolicy{r.Policy}, []intelligence.SourceSnapshot{*r.Snapshot}, now, binding)
	if e != nil || len(plan.State.Sources) != 1 {
		t.Fatal("reconcile", e)
	}
	_, stats, e := RevalidateStoredSources(ctx, eng.workspace, []Source{s}, plan.State, now, binding)
	if e != nil || len(stats) != 1 || stats[0].Records != 5 || !stats[0].ripeNameDigest.Matches(p) {
		t.Fatal("independent receipt verification", e)
	}
	stale, e := eng.Ingest(ctx, s, now.Add(s.MaxAge), binding)
	if e != nil || stale.Snapshot != nil || stale.Decision.State != "stale" {
		t.Fatal("retrieval renewed an expired edition", e, stale.Decision)
	}
	for _, change := range [][2]string{{"TELENET-DBM", "OTHER-MNT"}, {"OTHER-V6", "OTHER-V7"}, {"2001:db8::/32", "2001:db8:1::/48"}, {"source: OTHER", "source: ANOTHER"}, {"2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"}} {
		fetch.assets[ripeNamesUTF8URL] = gzipMRTFixture(t, bytes.Replace(text, []byte(change[0]), []byte(change[1]), 1))
		denied, e := eng.IngestPartitioned(ctx, s, now, binding)
		if e != nil || denied.Snapshot != nil {
			t.Fatal("unpaired projection accepted", e)
		}
	}
}
