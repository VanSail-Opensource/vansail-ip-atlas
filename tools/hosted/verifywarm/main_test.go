package main

import (
	"errors"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func TestPartitionedMetadataComparesOnlyRealSourceMetadata(t *testing.T) {
	original := intelligence.StoredSource{
		ID: "fixture", Fingerprint: [32]byte{1}, Records: []intelligence.NormalizedRecord{},
		RecordPartitions: []intelligence.RecordPartition{{SHA256: [32]byte{2}, Records: 100}},
	}
	changed := original
	changed.Records = nil
	changed.RecordPartitions = []intelligence.RecordPartition{{SHA256: [32]byte{3}, Records: 100}}
	if err := verifyPartitionedSourceMetadata(original, changed); err != nil {
		t.Fatal(err)
	}
	changed.Fingerprint = [32]byte{4}
	if err := verifyPartitionedSourceMetadata(original, changed); !errors.Is(err, sourceIdentity) {
		t.Fatalf("changed fingerprint accepted: %v", err)
	}
	changed = original
	changed.Records = []intelligence.NormalizedRecord{{Version: 3}}
	if err := verifyPartitionedSourceMetadata(original, changed); !errors.Is(err, rowPopulation) {
		t.Fatalf("inline row accepted: %v", err)
	}
}
