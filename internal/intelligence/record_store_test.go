package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordStorePartitionsIntegrityAndCancellation(t *testing.T) {
	root := t.TempDir()
	limits := DefaultRecordStoreLimits()
	limits.PartitionRecords = 2
	store, err := NewRecordStore(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(context.Background())
	for _, asn := range []uint32{13335, 15169, 174, 3356, 1299} {
		r := NormalizedRecord{Version: 3, Kind: RecordASNIdentity, ASNIdentity: &ASNIdentityEvidence{ASN: asn, Name: "Network"}}
		if err := writer.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	parts, err := writer.Finish()
	if err != nil || len(parts) != 3 {
		t.Fatalf("partitions=%d err=%v", len(parts), err)
	}
	source := StoredSource{RecordPartitions: parts}
	seen := 0
	if err := WalkStoredSource(context.Background(), root, source, func(r NormalizedRecord) error { seen++; return r.Validate() }); err != nil || seen != 5 {
		t.Fatalf("walk=%d %v", seen, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WalkStoredSource(canceled, root, source, func(NormalizedRecord) error { return nil }); err != context.Canceled {
		t.Fatalf("cancellation=%v", err)
	}
	name := filepath.Join(root, ".atlas-private", "records-v2", partitionName(parts[0]))
	f, err := os.OpenFile(name, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte{0}, 0); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	seen = 0
	if err := WalkStoredSource(context.Background(), root, source, func(NormalizedRecord) error { seen++; return nil }); err == nil || seen != 0 {
		t.Fatalf("corrupt partition emitted records=%d err=%v", seen, err)
	}
}

func TestRecordStoreExactBoundaryAndBudgetFailure(t *testing.T) {
	record := NormalizedRecord{Version: 3, Kind: RecordASNIdentity, ASNIdentity: &ASNIdentityEvidence{ASN: 13335}}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultRecordStoreLimits()
	limits.PartitionBytes = int64(len(recordHeader) + 2*(4+len(encoded)))
	limits.DiskBytes = 1 << 20
	root := t.TempDir()
	store, err := NewRecordStore(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(context.Background())
	defer writer.Abort()
	for i := 0; i < 2; i++ {
		if err = writer.Append(record); err != nil {
			t.Fatal(err)
		}
	}
	if err = writer.Append(record); err != nil {
		t.Fatal(err)
	}
	parts, err := writer.Finish()
	if err != nil || len(parts) != 2 || parts[0].DecodedBytes != limits.PartitionBytes || parts[0].Records != 2 {
		t.Fatal("decoded partition boundary changed", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".atlas-private", "records-v2"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".partial" {
			t.Fatal("failed writer retained partial")
		}
	}
	fullRoot := t.TempDir()
	full, err := NewRecordStore(fullRoot, RecordStoreLimits{PartitionBytes: 1 << 20, PartitionRecords: 100000, RecordBytes: 1 << 20, DiskBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	padding := make([]byte, 1<<20)
	digest := sha256.Sum256(padding)
	name := filepath.Join(full.root, partitionName(RecordPartition{SHA256: digest}))
	if err = os.WriteFile(name, padding, 0600); err != nil {
		t.Fatal(err)
	}
	full, err = NewRecordStore(fullRoot, full.limits)
	if err != nil {
		t.Fatal(err)
	}
	blocked := full.Writer(context.Background())
	defer blocked.Abort()
	if err = blocked.Append(record); err == nil {
		t.Fatal("actual encoded disk cap bypassed")
	}
	if err = blocked.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestRecordStoreAbortsOwnedPartialAndKeepsUnrelatedFile(t *testing.T) {
	root := t.TempDir()
	store, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(root, "keep")
	if err = os.WriteFile(unrelated, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(context.Background())
	if err = writer.Append(NormalizedRecord{Version: 3, Kind: RecordASNIdentity, ASNIdentity: &ASNIdentityEvidence{ASN: 13335}}); err != nil {
		t.Fatal(err)
	}
	if err = writer.Abort(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(filepath.Join(root, ".atlas-private", "records-v2"))
	if err != nil || len(files) != 0 {
		t.Fatalf("partial files %v %v", files, err)
	}
	if _, err = os.Stat(unrelated); err != nil {
		t.Fatal(err)
	}
}
