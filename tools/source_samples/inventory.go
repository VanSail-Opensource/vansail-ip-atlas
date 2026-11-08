package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Discoveries are private reconnaissance inputs, never production configuration.
type discoveries struct {
	SchemaVersion int              `json:"schema_version"`
	Entries       []discoveryEntry `json:"entries"`
}

type discoveryEntry struct {
	ID          string `json:"id"`
	URL         string `json:"url,omitempty"`
	Format      string `json:"format,omitempty"`
	EvidenceURL string `json:"evidence_url"`
	Note        string `json:"note"`
	Blocker     string `json:"blocker,omitempty"`
}

func loadDiscoveries(path string, sources []source) (map[string]discoveryEntry, error) {
	out := make(map[string]discoveryEntry)
	if path == "" {
		return out, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d discoveries
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&d); err != nil {
		return nil, err
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF || d.SchemaVersion != 1 {
		return nil, errors.New("invalid discovery version or trailing JSON")
	}
	known := make(map[string]bool, len(sources))
	for _, src := range sources {
		if src.ID == "" || src.ID == "." || src.ID == ".." || strings.ContainsAny(src.ID, "/\\:") {
			return nil, errors.New("unsafe source ID")
		}
		known[src.ID] = true
	}
	for _, entry := range d.Entries {
		if !known[entry.ID] || out[entry.ID].ID != "" || entry.EvidenceURL == "" || entry.Note == "" {
			return nil, fmt.Errorf("invalid or duplicate discovery entry %q", entry.ID)
		}
		if (entry.URL == "") == (entry.Blocker == "") {
			return nil, fmt.Errorf("discovery %q needs exactly one URL or blocker", entry.ID)
		}
		if entry.URL != "" {
			u, err := url.Parse(entry.URL)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || entry.Format == "" || entry.Format == "unknown" {
				return nil, fmt.Errorf("invalid discovery URL/format for %q", entry.ID)
			}
			// No credential-bearing templates or query strings belong in artifacts.
			for key := range u.Query() {
				if key != "inline" {
					return nil, fmt.Errorf("unapproved URL query for %q", entry.ID)
				}
			}
		}
		out[entry.ID] = entry
	}
	return out, nil
}

func isCaptured(rec sourceRecord) bool {
	return rec.Status == "captured" || rec.Status == "captured_sanitized"
}

func retainFailedCapture(root string, previous, failed sourceRecord) (sourceRecord, error) {
	if failed.FormatOnlyRecord != "" {
		if err := os.Remove(filepath.Join(root, failed.FormatOnlyRecord)); err != nil {
			return sourceRecord{}, err
		}
	}
	previous.LastCaptureError = failed.Blocker
	return previous, nil
}

func containsString(values []string, wanted string) bool {
	for _, v := range values {
		if v == wanted {
			return true
		}
	}
	return false
}

func loadPrevious(root string, enabled bool) (map[string]sourceRecord, error) {
	out := make(map[string]sourceRecord)
	if !enabled {
		return out, nil
	}
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.SchemaVersion < 1 || m.SchemaVersion > 2 || m.PublicOutputAllowed {
		return nil, errors.New("invalid previous private manifest")
	}
	for _, rec := range m.Sources {
		if out[rec.ID].ID != "" {
			return nil, errors.New("duplicate previous source")
		}
		for _, path := range []string{rec.SamplePath, rec.FormatOnlyRecord} {
			if path != "" && (!filepath.IsLocal(path) || strings.Contains(path, "\\") || strings.Contains(path, ":")) {
				return nil, errors.New("non-local previous artifact path")
			}
		}
		if rec.FormatOnlyRecord != "" && !strings.HasPrefix(rec.FormatOnlyRecord, "format-only/") {
			return nil, errors.New("invalid format-only artifact directory")
		}
		if isCaptured(rec) {
			if !strings.HasPrefix(rec.SamplePath, "samples/") {
				return nil, fmt.Errorf("missing sample path for %q", rec.ID)
			}
			fragment, err := os.ReadFile(filepath.Join(root, rec.SamplePath))
			if err != nil || len(fragment) != rec.SampleBytes || hashBytes(fragment) != rec.SampleSHA256 {
				return nil, fmt.Errorf("previous sample integrity failure for %q", rec.ID)
			}
			if rec.CapturedAt == "" {
				rec.CapturedAt = m.GeneratedAt
				rec.CaptureTimeBasis = "legacy_manifest_generated_at"
			}
			if rec.CaptureTimeBasis == "" {
				rec.CaptureTimeBasis = "capture_completed_at"
				if rec.SampleURL == "" {
					rec.CaptureTimeBasis = "legacy_manifest_generated_at"
				}
			}
		}
		out[rec.ID] = rec
	}
	return out, nil
}

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".capture-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
