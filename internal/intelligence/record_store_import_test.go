package intelligence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func importFixture(t *testing.T) (string, RecordPartition) {
	t.Helper()
	source, err := NewRecordStore(t.TempDir(), DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	writer := source.Writer(context.Background())
	defer writer.Abort()
	record := NormalizedRecord{Version: 3, Kind: RecordASNIdentity, ASNIdentity: &ASNIdentityEvidence{ASN: 13335, Name: "Fixture"}}
	if err = writer.Append(record); err != nil {
		t.Fatal(err)
	}
	parts, err := writer.Finish()
	if err != nil || len(parts) != 1 {
		t.Fatal(err)
	}
	return filepath.Join(source.root, partitionName(parts[0])), parts[0]
}
func TestImportPartitionVerifiesAndChargesUniqueDestination(t *testing.T) {
	from, part := importFixture(t)
	root := t.TempDir()
	store, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err = store.ImportPartition(ctx, from, part); err != nil {
			t.Fatal(err)
		}
		if store.objects != 1 || store.DiskBytes() != uint64(part.Bytes) {
			t.Fatal("duplicate import accounting differs")
		}
	}
	// Replace only the destination, including on filesystems supporting links.
	to := filepath.Join(store.root, partitionName(part))
	if err = os.Remove(to); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(to, make([]byte, part.Bytes), 0600); err != nil {
		t.Fatal(err)
	}
	if err = store.ImportPartition(ctx, from, part); err == nil {
		t.Fatal("corrupt duplicate accepted")
	}
	if store.objects != 1 || store.DiskBytes() != uint64(part.Bytes) {
		t.Fatal("existing destination reservation lost")
	}
}
func TestImportPartitionChecksLimitsAndRollsBackOwnedFailure(t *testing.T) {
	from, part := importFixture(t)
	ctx := context.Background()
	for _, scenario := range []string{"file count", "disk", "partition", "record", "canceled", "corrupt"} {
		t.Run(scenario, func(t *testing.T) {
			limits := DefaultRecordStoreLimits()
			if scenario == "disk" {
				limits.PartitionBytes = part.Bytes
				limits.DiskBytes = part.Bytes
			}
			if scenario == "partition" {
				limits.PartitionBytes = 16
			}
			if scenario == "record" {
				limits.RecordBytes = 1
			}
			store, err := NewRecordStore(t.TempDir(), limits)
			if err != nil {
				t.Fatal(err)
			}
			input := from
			clock := ctx
			if scenario == "file count" {
				store.objects = maxRecordPartitions
			}
			if scenario == "canceled" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				clock = c
			}
			if scenario == "corrupt" {
				input = filepath.Join(t.TempDir(), "bad")
				if err = os.WriteFile(input, make([]byte, part.Bytes), 0600); err != nil {
					t.Fatal(err)
				}
			}
			count := store.objects
			if err = store.ImportPartition(clock, input, part); err == nil {
				t.Fatal("invalid import accepted")
			}
			if store.DiskBytes() != 0 || store.objects != count {
				t.Fatal("cleaned failure retained reservation")
			}
			if _, err = os.Lstat(filepath.Join(store.root, partitionName(part))); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid destination present", err)
			}
		})
	}
}

func TestImportPartitionConcurrentWriterAccountsIdenticalObjectOnce(t *testing.T) {
	from, part := importFixture(t)
	root := t.TempDir()
	store, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	start := make(chan struct{})
	const participants = 8
	done := make(chan error, participants)
	for i := 0; i < participants; i++ {
		if i%2 == 0 {
			go func() { <-start; done <- store.ImportPartition(ctx, from, part) }()
		} else {
			writer := store.Writer(ctx)
			if err := writer.Append(NormalizedRecord{Version: 3, Kind: RecordASNIdentity, ASNIdentity: &ASNIdentityEvidence{ASN: 13335, Name: "Fixture"}}); err != nil {
				t.Fatal(err)
			}
			go func() { defer writer.Abort(); <-start; _, e := writer.Finish(); done <- e }()
		}
	}
	close(start)
	for i := 0; i < participants; i++ {
		if err = <-done; err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	if store.objects != 1 || reopened.objects != 1 || store.DiskBytes() != uint64(part.Bytes) || store.DiskBytes() != reopened.DiskBytes() {
		t.Fatal("concurrent import/writer reservation differs from physical inventory")
	}
}
