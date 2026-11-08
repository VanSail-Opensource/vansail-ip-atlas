package main

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/ulikunitz/xz"
)

func TestPreviousCaptureIntegrityAndTime(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "samples"), 0o755)
	data := []byte("1.1.1.1\n")
	path := filepath.Join(root, "samples", "test.txt.fragment")
	os.WriteFile(path, data, 0o644)
	m := manifest{SchemaVersion: 1, GeneratedAt: "2026-10-30T10:51:08Z", Sources: []sourceRecord{{
		ID: "test", Status: "captured", SamplePath: "samples/test.txt.fragment", SampleBytes: len(data), SampleSHA256: hashBytes(data),
	}}}
	encoded, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(root, "manifest.json"), encoded, 0o644)
	got, err := loadPrevious(root, true)
	if err != nil || got["test"].CapturedAt != m.GeneratedAt {
		t.Fatalf("previous capture: %+v, %v", got, err)
	}
	os.WriteFile(path, []byte("8.8.8.8\n"), 0o644)
	if _, err := loadPrevious(root, true); err == nil {
		t.Fatal("accepted changed bytes")
	}
	m.Sources[0].SamplePath = "../escape"
	encoded, _ = json.Marshal(m)
	os.WriteFile(filepath.Join(root, "manifest.json"), encoded, 0o644)
	if _, err := loadPrevious(root, true); err == nil {
		t.Fatal("accepted escaping artifact path")
	}
}

func TestFailedRecaptureRetainsLastGoodFragment(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "samples"), 0o755)
	os.Mkdir(filepath.Join(root, "format-only"), 0o755)
	data := []byte("1.1.1.1\n")
	os.WriteFile(filepath.Join(root, "samples/test.txt.fragment"), data, 0o644)
	os.WriteFile(filepath.Join(root, "format-only/test.md"), []byte("failed attempt"), 0o644)
	old := sourceRecord{ID: "test", Status: "captured", CapturedAt: "2026-10-30T00:00:00Z", SamplePath: "samples/test.txt.fragment", SampleBytes: len(data), SampleSHA256: hashBytes(data)}
	failed := sourceRecord{ID: "test", Status: "fetch_failed", Blocker: "HTTP 504", FormatOnlyRecord: "format-only/test.md"}
	got, err := retainFailedCapture(root, old, failed)
	if err != nil || got.SampleSHA256 != old.SampleSHA256 || got.CapturedAt != old.CapturedAt || got.LastCaptureError != failed.Blocker || !isCaptured(got) {
		t.Fatalf("last good capture was not retained: %+v, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, failed.FormatOnlyRecord)); !os.IsNotExist(err) {
		t.Fatal("failed-attempt document became an orphan")
	}
}

func TestDiscoveriesRejectSecretsAndUnknownIDs(t *testing.T) {
	for _, entry := range []discoveryEntry{
		{ID: "missing", URL: "https://example.com/file", Format: "csv"},
		{ID: "test", URL: "https://example.com/file?token=secret", Format: "csv"},
		{ID: "test", URL: "https://user:secret@example.com/file", Format: "csv"},
		{ID: "test", URL: "https://example.com/file", Format: "csv", Blocker: "blocked"},
	} {
		entry.EvidenceURL, entry.Note = "https://example.com/", "format inspection"
		data, _ := json.Marshal(discoveries{SchemaVersion: 1, Entries: []discoveryEntry{entry}})
		path := filepath.Join(t.TempDir(), "discovery.json")
		os.WriteFile(path, data, 0o644)
		if _, err := loadDiscoveries(path, []source{{ID: "test"}}); err == nil {
			t.Fatal("accepted invalid discovery")
		}
	}
}

func TestXZTarBoundedMember(t *testing.T) {
	var raw, compressed bytes.Buffer
	w := tar.NewWriter(&raw)
	content := "ExitNode redacted\nExitAddress 1.1.1.1 2026-11-01 00:00:00\n"
	w.WriteHeader(&tar.Header{Name: "exit-lists/2026-11-01", Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg})
	w.Write([]byte(content))
	w.Close()
	xw, err := xz.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	xw.Write(raw.Bytes())
	xw.Close()
	got, err := decodeSample("tar-xz", compressed.Bytes())
	if err != nil || string(got.data) != content || got.archiveEntry != "exit-lists/2026-11-01" {
		t.Fatalf("XZ member: %+v, %v", got, err)
	}
	// A large advertised dictionary must not cause a matching allocation when
	// the decoder only emits a bounded prefix from the first block.
	data := append([]byte(nil), compressed.Bytes()...)
	if data[14] != 0x21 || data[15] != 1 {
		t.Fatal("unexpected synthetic XZ filter layout")
	}
	data[16] = 40
	size := (int(data[12]) + 1) * 4
	binary.LittleEndian.PutUint32(data[12+size-4:12+size], crc32.ChecksumIEEE(data[12:12+size-4]))
	if got, err := decodeSample("tar-xz", data); err != nil || string(got.data) != content {
		t.Fatalf("large advertised dictionary prefix: %v", err)
	}
	data[16] = 41 // Invalid dictionary property, rather than a valid large one.
	binary.LittleEndian.PutUint32(data[12+size-4:12+size], crc32.ChecksumIEEE(data[12:12+size-4]))
	if _, err := decodeSample("tar-xz", data); err == nil {
		t.Fatal("accepted invalid XZ dictionary property")
	}
}

func TestVMessMalformedBase64IsRedacted(t *testing.T) {
	data := "vmess://" + string(bytes.Repeat([]byte("A"), 65536)) + "!secret"
	if got := sanitizeSubscriptionLine(data); got != "vmess://<redacted-base64-json>" {
		t.Fatal("malformed VMess payload was retained")
	}
}

func TestDNSRejectsSpecialDestinations(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "198.18.1.130", "192.168.1.1", "192.0.2.1", "::ffff:127.0.0.1"} {
		data := []byte(`{"Status":0,"Answer":[{"type":1,"data":"` + address + `"}]}`)
		if _, err := decodeDNSAnswers(data); err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	got, err := decodeDNSAnswers([]byte(`{"Status":0,"Answer":[{"type":5,"data":"cdn.example"},{"type":1,"data":"1.1.1.1"}]}`))
	if err != nil || len(got) != 1 || got[0].String() != "1.1.1.1" {
		t.Fatalf("DNS answer: %v, %v", got, err)
	}
}

func FuzzDecodeSample(f *testing.F) {
	for _, seed := range [][]byte{[]byte("ip\n1.1.1.1\n"), []byte("PK\x03\x04"), []byte("<!DOCTYPE html>")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		for _, format := range []string{"csv", "csv-zip", "uri-list"} {
			result, err := decodeSample(format, data)
			if err == nil && len(result.data) > maxSampleBytes {
				t.Fatal("sample exceeds budget")
			}
		}
	})
}
