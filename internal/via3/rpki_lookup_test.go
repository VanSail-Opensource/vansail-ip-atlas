package via3

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

type rpkiLookupFixture struct {
	Base64 string `json:"base64"`
	Cases  []struct {
		IP           string `json:"ip"`
		Origin       uint32 `json:"origin"`
		Announcement string `json:"announcement"`
		Status       int    `json:"status"`
	} `json:"cases"`
}

func TestRPKISelectedAnnouncementIgnoresUnrelatedMoreSpecificRows(t *testing.T) {
	data, err := os.ReadFile("../../fixtures/bin/rpki-prefix-lookup.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture rpkiLookupFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	encoded, err := base64.StdEncoding.DecodeString(fixture.Base64)
	if err != nil {
		t.Fatal(err)
	}
	shard, err := Read(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range fixture.Cases {
		announcement, _ := netip.ParsePrefix(item.Announcement)
		row, ok := shard.FindRPKI(netip.MustParseAddr(item.IP), item.Origin, announcement)
		status := -1
		if ok {
			status = int(row[8])
		}
		if status != item.Status {
			t.Errorf("%s AS%d announcement %s: got %d want %d", item.IP, item.Origin, item.Announcement, status, item.Status)
		}
	}
}

// This opt-in deterministic synthetic export is consumed unchanged by Go and
// TypeScript; it is never a source-admission or production-data fixture.
func TestExportRPKIPrefixLookupFixture(t *testing.T) {
	if os.Getenv("ATLAS_EXPORT_RPKI_CORPUS") != "1" {
		t.Skip("opt-in shared fixture export")
	}
	row := func(asn uint32, status, maximum byte) []byte {
		r := make([]byte, 16)
		p32(r, 0, bits(20))
		p32(r, 4, asn)
		r[8], r[9] = status, maximum
		return r
	}
	s := newShard(9, row(3356, 2, 16), row(13335, 1, 24), row(174, 3, 0), row(3356, 1, 48), row(13335, 2, 32), row(174, 3, 0))
	s.set(1, prefixRows(key("203.0.113.0/24", false, 2), key("2001:db8:1::/48", false, 5)))
	s.set(8, prefixRows(key("203.0.0.0/16", false, 0), key("203.0.0.0/16", false, 1), key("2001:db8::/32", false, 3), key("2001:db8::/32", false, 4)))
	encoded, err := Write(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	fixture := rpkiLookupFixture{Base64: base64.StdEncoding.EncodeToString(encoded)}
	for _, item := range []struct {
		ip     string
		origin uint32
		prefix string
		status int
	}{
		{"203.0.113.1", 3356, "203.0.0.0/16", 2},
		{"203.0.113.1", 13335, "203.0.0.0/16", 1},
		{"203.0.113.1", 174, "203.0.113.0/24", 3},
		{"203.0.113.1", 13335, "203.0.113.0/24", -1},
		{"203.0.113.1", 13335, "203.0.113.0/25", -1},
		{"203.0.114.1", 174, "203.0.113.0/24", -1},
		{"203.0.113.1", 13335, "", -1},
		{"2001:db8:1::1", 3356, "2001:db8::/32", 1},
		{"2001:db8:1::1", 13335, "2001:db8::/32", 2},
		{"2001:db8:1::1", 174, "2001:db8:1::/48", 3},
		{"2001:db8:1::1", 3356, "2001:db8:1::/48", -1},
		{"2001:db8:1::1", 3356, "2001:db8:1::/64", -1},
	} {
		fixture.Cases = append(fixture.Cases, struct {
			IP           string `json:"ip"`
			Origin       uint32 `json:"origin"`
			Announcement string `json:"announcement"`
			Status       int    `json:"status"`
		}{item.ip, item.origin, item.prefix, item.status})
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../../fixtures/bin/rpki-prefix-lookup.json", append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
