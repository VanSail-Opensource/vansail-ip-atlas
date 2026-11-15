package admission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// Full upstream captures are private and optional. This observes complete-body
// parser behavior without manufacturing an authenticated intake receipt.
func TestObservedPrivatePublicSources(t *testing.T) {
	base := filepath.Join("..", "..", "build-private", "source-expansion-20261115")
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for _, item := range []struct{ name, digest string }{
		{"tor-exit-addresses.txt", "2dd1e8c0b10444af0980601a85afad8940f64e93867450701d1acab5eabaade4"},
		{"ipverse-as.json", "4bab4bbb5fb04991f172a0f87503b2cc734e28f79b78de999709da00d2ae8f62"},
	} {
		t.Run(item.name, func(t *testing.T) {
			file, err := os.Open(filepath.Join(base, item.name))
			if os.IsNotExist(err) {
				t.Skip("private captured full payload absent")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			h := sha256.New()
			if _, err = io.Copy(h, file); err != nil || hex.EncodeToString(h.Sum(nil)) != item.digest {
				t.Fatal("private capture hash mismatch", err)
			}
			if _, err = file.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			var records, current int
			var oldest time.Time
			emit := func(r intelligence.NormalizedRecord) error {
				records++
				if err := r.Validate(); err != nil {
					return err
				}
				item := now
				if r.Usage != nil {
					item = r.Usage.ObservedAt
				}
				if r.Evidence != nil {
					item = r.Evidence.ItemPublishedAt
				}
				if now.Before(item.Add(720 * time.Hour)) {
					current++
					if oldest.IsZero() || item.Before(oldest) {
						oldest = item
					}
				}
				return nil
			}
			if item.name == "tor-exit-addresses.txt" {
				_, err = parseTorExitAddresses(context.Background(), file, now, 720*time.Hour, 1_000_000, emit)
			} else {
				err = parseIPverseUsageJSON(context.Background(), file, "ipverse-as", 1_000_000, emit)
			}
			if err != nil || records == 0 || current == 0 {
				t.Fatal("full source parse failed", records, current, err)
			}
			t.Logf("normalized=%d current=%d earliest_item=%s", records, current, oldest.Format(time.RFC3339))
		})
	}
}

func TestTorExitObservationsKeepItemClockAndDiscardRelayMetadata(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	body := "ExitNode 0123456789ABCDEF0123456789ABCDEF01234567\nPublished 2026-11-14 01:00:00\nLastStatus 2026-11-15 10:00:00\nExitAddress 8.8.8.8 2026-11-15 10:10:00\nExitAddress 8.8.4.4 2026-09-01 10:10:00\nExitAddress 10.0.0.1 2026-11-15 10:10:00\n"
	var got []intelligence.NormalizedRecord
	clock, err := parseTorExitAddresses(context.Background(), strings.NewReader(body), now, 720*time.Hour, 100, func(r intelligence.NormalizedRecord) error { got = append(got, r); return nil })
	if err != nil || len(got) != 1 || !clock.Equal(time.Date(2026, 11, 15, 10, 10, 0, 0, time.UTC)) {
		t.Fatal(clock, got, err)
	}
	e := got[0].Evidence
	if e.Signal != "tor" || e.Address.String() != "8.8.8.8" || e.ItemPublishedAt != clock {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(body, "LastStatus", "Hostname", 1), strings.Replace(body, "8.8.8.8", "example.com", 1), strings.Replace(body, "2026-11-15 10:10:00", "2026-11-18 10:10:00", 1), strings.Replace(body, "LastStatus 2026-11-15 10:00:00\n", "", 1), body + "ExitNode 0123456789ABCDEF0123456789ABCDEF01234567\n"} {
		if _, err := parseTorExitAddresses(context.Background(), strings.NewReader(bad), now, 720*time.Hour, 100, nil); err == nil {
			t.Fatal("malformed descriptor accepted")
		}
	}
}

func TestIPverseUsageJSONKeepsOnlyUnambiguousObservedCategories(t *testing.T) {
	body := `[{"asn":13335,"metadata":{"category":"hosting","lastModified":"2026-11-14","networkRole":"tier1_transit"},"stats":null,"lastAnnounced":"2026-11-15"},{"asn":15169,"metadata":{"category":"isp","lastModified":"2026-11-14"},"stats":null,"lastAnnounced":"2026-11-15"}]`
	var got []intelligence.NormalizedRecord
	err := parseIPverseUsageJSON(context.Background(), strings.NewReader(body), "ipverse-as", 100, func(r intelligence.NormalizedRecord) error { got = append(got, r); return nil })
	if err != nil || len(got) != 1 || got[0].Usage.ASN != 13335 || got[0].Usage.Evidence.Type != "hosting" || got[0].Usage.Prefix.IsValid() || got[0].Usage.ObservedAt.IsZero() {
		t.Fatal(got, err)
	}
	for _, bad := range []string{`[{}]`, `[{"asn":13335,"metadata":null}]`, `[{"asn":13335,"metadata":{"category":"hosting"}}]`, strings.Replace(body, `"hosting"`, `"new-category"`, 1), strings.Replace(body, `"asn":13335`, `"asn":13335,"asn":15169`, 1), body + `{}`, strings.Replace(body, `"2026-11-14"`, `"bad"`, 1), `[{"asn":13335,"metadata":{"category":"hosting","lastModified":"2026-11-14","x":"` + strings.Repeat("x", 1<<20) + `"}}]`} {
		if err := parseIPverseUsageJSON(context.Background(), strings.NewReader(bad), "ipverse-as", 100, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
			t.Fatal("malformed JSON admitted")
		}
	}
}
