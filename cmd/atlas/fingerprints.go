package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"vansail-ip-atlas/internal/admission"
	"vansail-ip-atlas/internal/intelligence"
)

type fingerprintCount struct {
	Records  uint64 `json:"records"`
	SourceID string `json:"source_id"`
}
type fingerprintMetadata struct {
	FingerprintFileSHA256 string             `json:"fingerprint_file_sha256"`
	NormalizedStateSHA256 string             `json:"normalized_state_sha256"`
	SchemaVersion         uint16             `json:"schema_version"`
	SourceRecordCounts    []fingerprintCount `json:"source_record_counts"`
	TotalRecords          uint64             `json:"total_records"`
}

func stateFingerprints(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("state-fingerprints", flag.ContinueOnError)
	workspace := fs.String("workspace", ".", "reviewed private intake workspace")
	out := fs.String("out", "build-private/record-fingerprints.ndjson", "private semantic fingerprint file")
	clock := fs.Int64("clock", time.Now().UTC().Unix(), "current UTC validation clock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *clock < 0 {
		return errors.New("invalid fingerprint arguments")
	}
	root, err := resolveProductionRoot(*workspace)
	if err != nil {
		return err
	}
	destination := rooted(root, *out)
	parent, err := filepath.Abs(filepath.Dir(destination))
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(filepath.Join(root, "build-private"), parent)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || len(relative) > 3 && relative[:3] == ".."+string(filepath.Separator) {
		return errors.New("fingerprints must remain build-private")
	}
	if err = os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return errors.New("fingerprint directory cannot traverse links")
	}
	configHash, sourceBytes, err := intakeConfigHash(root)
	if err != nil {
		return err
	}
	catalog, err := admission.DecodeCatalog(bytes.NewReader(sourceBytes))
	if err != nil {
		return err
	}
	cert, err := admission.CertificationFingerprint(ctx, root, catalog)
	if err != nil {
		return err
	}
	binding := sha256.Sum256(append(append([]byte("intake-policy-v1\x00"), configHash[:]...), cert[:]...))
	state, err := intelligence.VerifyPrivateStateSeal(ctx, root, binding)
	if err != nil {
		return err
	}
	if _, _, err = admission.RevalidateStoredSources(ctx, root, catalog, state, time.Unix(*clock, 0).UTC(), binding); err != nil {
		return err
	}
	stateHash, err := authenticatedStateFileHash(ctx, root, state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(parent, "fingerprints-*.partial")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	hash := sha256.New()
	writer := bufio.NewWriterSize(io.MultiWriter(file, hash), 64<<10)
	metadata := fingerprintMetadata{NormalizedStateSHA256: digestString(stateHash), SchemaVersion: 1, SourceRecordCounts: []fingerprintCount{}}
	var written uint64
	for _, source := range state.Sources {
		count := fingerprintCount{SourceID: source.ID}
		err = intelligence.WalkStoredSource(ctx, root, source, func(record intelligence.NormalizedRecord) error {
			// Container publication affects evaluation age, not identity of the
			// underlying observed fact. Retain item clocks, family, weight and all
			// actual fields so factual or dependence changes remain measurable.
			if record.Evidence != nil {
				value := *record.Evidence
				value.SourcePublishedAt = time.Time{}
				record.Evidence = &value
			}
			if record.Coverage != nil {
				value := *record.Coverage
				value.PublishedAt = time.Time{}
				record.Coverage = &value
			}
			// RIB first-heard time is retained privately for audit, not used as
			// publication age or an exposed route fact.
			record.MRTOriginatedAt = nil
			record.MRT = nil
			data, err := json.Marshal(record)
			if err != nil {
				return err
			}
			semantic := sha256.Sum256(data)
			row := struct {
				SemanticSHA256 string `json:"semantic_sha256"`
				SourceID       string `json:"source_id"`
			}{digestString(semantic), source.ID}
			data, err = json.Marshal(row)
			if err != nil {
				return err
			}
			written += uint64(len(data) + 1)
			if written > 10<<30 {
				return errors.New("fingerprint scratch budget exceeded")
			}
			if _, err = writer.Write(data); err != nil {
				return err
			}
			if err = writer.WriteByte('\n'); err != nil {
				return err
			}
			count.Records++
			metadata.TotalRecords++
			return nil
		})
		if err != nil {
			return err
		}
		metadata.SourceRecordCounts = append(metadata.SourceRecordCounts, count)
	}
	if err = writer.Flush(); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	metadata.FingerprintFileSHA256 = fmt.Sprintf("%x", hash.Sum(nil))
	current, err := privateStateHash(ctx, root)
	if err != nil || current != stateHash {
		return errors.New("private state changed during fingerprinting")
	}
	config, _, err := intakeConfigHash(root)
	if err != nil || config != configHash {
		return errors.New("source policy changed during fingerprinting")
	}
	currentCert, err := admission.CertificationFingerprint(ctx, root, catalog)
	if err != nil || currentCert != cert {
		return errors.New("source certification changed during fingerprinting")
	}
	if err = os.Rename(file.Name(), destination); err != nil {
		return err
	}
	return writeJSON(destination+".meta.json", metadata)
}

func authenticatedStateFileHash(ctx context.Context, root string, state intelligence.BuildState) ([32]byte, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return [32]byte{}, err
	}
	expected := sha256.Sum256(data)
	current, err := privateStateHash(ctx, root)
	if err != nil || current != expected {
		return [32]byte{}, errors.New("authenticated private state changed before fingerprinting")
	}
	return expected, nil
}
