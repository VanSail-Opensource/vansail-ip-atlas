package admission

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

func TestActualSignedPublisherTransport(t *testing.T) {
	if os.Getenv("ATLAS_ENGINEERING_ORIGINAL") != "1" {
		t.Skip("direct publisher diagnostic")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	directory := t.TempDir()
	transport := acquire.New()
	envelope := filepath.Join(directory, "publication")
	result, err := transport.Fetch(ctx, mullvadTimestamp, envelope, intelligence.MullvadMaxEnvelope)
	if err != nil {
		t.Fatal("timestamp download failed")
	}
	t.Logf("timestamp bytes %d", result.Bytes)
	signed, err := os.ReadFile(envelope)
	if err != nil {
		t.Fatal("timestamp file failed")
	}
	digest, clock, err := intelligence.VerifyMullvadEnvelope(string(signed))
	if err != nil {
		t.Fatal("witness verification failed")
	}
	now := time.Now().UTC()
	if now.Before(clock) || !now.Before(clock.Add(24*time.Hour)) {
		t.Fatal("authenticated timestamp is outside 24 hours")
	}
	t.Logf("authenticated timestamp age %s", now.Sub(clock).Round(time.Second))
	body := filepath.Join(directory, "payload")
	result, err = transport.Fetch(ctx, mullvadData+hex.EncodeToString(digest[:]), body, mullvadLimit)
	if err != nil {
		t.Fatal("immutable body download failed")
	}
	if result.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("immutable body digest mismatch")
	}
	t.Logf("authenticated immutable payload bytes %d", result.Bytes)
	f, err := os.Open(body)
	if err != nil {
		t.Fatal("payload file failed")
	}
	defer f.Close()
	rows, err := parseMullvadRelays(ctx, f, mullvadTestSource(), intelligence.MullvadMaxHosts, nil)
	if err != nil {
		t.Fatal("whole-original row validation failed")
	}
	count, _ := rows.Sum()
	t.Logf("eligible original observations %d", count)
}
