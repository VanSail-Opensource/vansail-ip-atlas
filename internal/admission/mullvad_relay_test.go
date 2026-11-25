package admission

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func mullvadTestSource() Source {
	return Source{ID: intelligence.MullvadRelaySourceID, Family: "mullvad-relay-locations", Category: "geolocation", Scope: "exact_ip", Coverage: "mapping", Format: "json", MaxAge: 720 * time.Hour, MaxCompressedBytes: mullvadLimit, Weight: 70, URL: mullvadList, Parser: Parser{intelligence.MullvadRelaySourceID, "mullvad-transparent-relay-json-v1", 1}, Publication: Publication{"snapshot_metadata", mullvadTimestamp, "sigsum.timestamp.digest"}, Fields: []string{"location", "city", "latitude", "longitude", "active", "include_in_country", "ipv4_addr_in", "ipv6_addr_in"}, PublicFields: []string{"physical_country", "region", "city", "latitude", "longitude"}, FieldMappings: map[string][]string{"location": {"physical_country"}, "city": {"region", "city"}, "latitude": {"latitude"}, "longitude": {"longitude"}}}
}

const mullvadLocFixture = `{"locations":{"us-chi":{"city":"Chicago, IL","latitude":41.881832,"longitude":-87.623177},"ch-zrh":{"city":"Zurich","latitude":47.366667,"longitude":8.55}},"wireguard":{"relays":[`
const mullvadChicago = `{"location":"us-chi","active":true,"include_in_country":true,"ipv4_addr_in":"8.8.8.1","ipv6_addr_in":"2001:4860::1"}`
const mullvadZurich = `{"location":"ch-zrh","active":true,"include_in_country":true,"ipv4_addr_in":"1.1.1.1"}`

func TestMullvadExactCityProjection(t *testing.T) {
	inactive := strings.Replace(mullvadChicago, `"active":true`, `"active":false`, 1)
	excluded := strings.Replace(mullvadChicago, `"include_in_country":true`, `"include_in_country":false`, 1)
	input := mullvadLocFixture + strings.Join([]string{inactive, mullvadChicago, excluded, mullvadZurich}, ",") + `]}}`
	source := mullvadTestSource()
	if impl, ok := selectAdapter(source); !ok || impl != mullvadRelaysJSON || !publicationSupported(source) {
		t.Fatal("missing source contract")
	}
	var out []intelligence.NormalizedRecord
	digest, err := parseMullvadRelays(t.Context(), strings.NewReader(input), source, 3, func(r intelligence.NormalizedRecord) error { out = append(out, r); return r.Validate() })
	if err != nil || len(out) != 3 {
		t.Fatalf("expected three exact addresses: %v", err)
	}
	for _, r := range out {
		g := r.Geo
		if g.Prefix.Bits() != g.Prefix.Addr().BitLen() || g.Coordinates.Precision != 3 {
			t.Fatal("incorrect host or geographic precision")
		}
		switch g.PhysicalCountry {
		case "CH":
			if g.Region != "" || g.City != "Zurich" || g.Coordinates.Longitude != 8.55 {
				t.Fatal("added a region or changed the published coordinate")
			}
		case "US":
			if g.Region != "Illinois" || g.City != "Chicago" || g.Coordinates.Latitude != 41.881832 {
				t.Fatal("explicit state or centroid lost")
			}
		default:
			t.Fatal("unexpected country")
		}
	}
	changed := mullvadLocFixture + mullvadZurich + "," + strings.Replace(mullvadChicago, `"location":`, `"hostname":"ignored.example","public_key":"ignored","location":`, 1) + `]}}`
	d2, e := parseMullvadRelays(t.Context(), strings.NewReader(changed), source, 3, nil)
	n, h := digest.Sum()
	n2, h2 := d2.Sum()
	if e != nil || n != 3 || n != n2 || h != h2 || h == ([32]byte{}) {
		t.Fatal("metadata or row order changed the content clock")
	}
	for _, bad := range []string{
		strings.Replace(input, `"city":"Chicago, IL"`, `"city":"Chicago, IL","city":"X"`, 1),
		strings.Replace(input, `"latitude":41.881832`, `"latitude":null`, 1),
		strings.Replace(input, `"city":"Chicago, IL"`, `"city":"Chicago, XX"`, 1),
		strings.Replace(input, `"longitude":8.55`, `"longitude":181`, 1),
		mullvadLocFixture + mullvadChicago + "," + mullvadChicago + `]}}`,
		mullvadLocFixture + strings.Replace(mullvadChicago, "8.8.8.1", "127.0.0.1", 1) + `]}}`,
		mullvadLocFixture + strings.Replace(mullvadChicago, "2001:4860::1", "::ffff:8.8.8.1", 1) + `]}}`,
		mullvadLocFixture + strings.Replace(mullvadChicago, "8.8.8.1", "8.8.8.0/24", 1) + `]}}`,
		mullvadLocFixture + strings.Replace(mullvadChicago, "us-chi", "us-qxx", 1) + `]}}`,
		mullvadLocFixture + inactive + `]}}`, input + ` {}`,
	} {
		if _, err := parseMullvadRelays(t.Context(), strings.NewReader(bad), source, 12, nil); err == nil {
			t.Fatal("invalid data accepted")
		}
	}
	if _, err := parseMullvadRelays(t.Context(), strings.NewReader(input), source, 2, nil); err == nil {
		t.Fatal("host budget ignored")
	}
}

func TestMullvadAuthenticSignedDigestAndClock(t *testing.T) {
	// Public publisher test vector; no relay identities or API credentials.
	data, err := os.ReadFile("testdata/mullvad-timestamp-20261124.sigsum")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGSUM_POLICY_DIR", t.TempDir()) // production trusts the pinned builtin exclusively
	want := "8f8718b6b72f0686cace4a0030b0107f6b86d800bc4789495e73d6c712d3b426"
	signed := time.Date(2026, 11, 24, 16, 7, 32, 0, time.UTC)
	h, stamp, err := intelligence.VerifyMullvadEnvelope(string(data))
	if err != nil || !stamp.Equal(signed) || hashString(h) != want {
		t.Fatal("actual signed envelope rejected", err)
	}
	for _, bad := range []string{string(bytes.Replace(data, []byte(want[:4]), []byte("1234"), 1)), string(bytes.Replace(data, []byte("16:07:32"), []byte("16:07:33"), 1)), string(bytes.Replace(data, []byte("signature=4a"), []byte("signature=4b"), 1)), string(data) + "trailing=1\n", strings.Repeat("x", intelligence.MullvadMaxEnvelope+1)} {
		if _, _, err := intelligence.VerifyMullvadEnvelope(bad); err == nil {
			t.Fatal("invalid signed envelope accepted")
		}
	}
	packet := intelligence.MullvadRelayProof{Envelope: string(data), AcquiredAt: signed.Add(time.Hour), Hosts: 1, Projection: sha256.Sum256([]byte("test projection"))}
	if err := packet.Validate(signed.Add(5*24*time.Hour), signed.Add(-time.Hour), h); err != nil {
		t.Fatal("lost authenticated snapshot after acquisition", err)
	}
	for _, tm := range []time.Time{signed.Add(-time.Second), signed.Add(24 * time.Hour)} {
		packet.AcquiredAt = tm
		if err := packet.Validate(signed.Add(25*time.Hour), signed, h); err == nil {
			t.Fatal("acquisition outside signed window accepted")
		}
	}
	packet.AcquiredAt = signed
	if packet.Validate(signed, signed, sha256.Sum256([]byte("different file"))) == nil || packet.Validate(signed, signed.Add(time.Second), h) == nil {
		t.Fatal("unbound payload or renewed content age")
	}
	fetch := &fixtureFetch{assets: map[string][]byte{mullvadTimestamp: data, mullvadData + want: []byte(mullvadLocFixture + mullvadChicago + `]}}`)}}
	engine := &Engine{fetch: fetch}
	if _, _, err := engine.fetchMullvad(t.Context(), filepath.Join(t.TempDir(), "data"), mullvadTestSource(), signed.Add(24*time.Hour)); err == nil || fetch.calls != 1 {
		t.Fatal("stale envelope selected a download")
	}
	if _, _, err := engine.fetchMullvad(t.Context(), filepath.Join(t.TempDir(), "data"), mullvadTestSource(), signed); err == nil || fetch.calls != 3 {
		t.Fatal("fixture substituted for signed full body")
	}
}
