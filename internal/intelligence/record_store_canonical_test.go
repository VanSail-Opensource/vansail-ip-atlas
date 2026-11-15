package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func canonicalTestRecord() NormalizedRecord {
	return NormalizedRecord{Version: 3, Kind: RecordOrigins, Origins: &OriginMapping{Prefix: netip.MustParsePrefix("8.8.8.0/24"), Origins: []uint32{13335, 15169}}}
}

func canonicalTestPartition(t *testing.T, record NormalizedRecord) (string, CanonicalPartition) {
	t.Helper()
	root := t.TempDir()
	store, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(context.Background())
	defer writer.Abort()
	if err = writer.Append(record); err != nil {
		t.Fatal(err)
	}
	parts, err := writer.FinishCanonical()
	if err != nil || len(parts) != 1 {
		t.Fatalf("finish canonical: %d %v", len(parts), err)
	}
	return root, parts[0]
}

func TestCanonicalRecordFramePreservesBytesAfterDecodedMutation(t *testing.T) {
	record := canonicalTestRecord()
	_, part := canonicalTestPartition(t, record)
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(context.Background())
	defer writer.Abort()
	seen := 0
	if err = part.Walk(context.Background(), func(frame CanonicalRecordFrame) error {
		seen++
		value, err := frame.Record()
		if err != nil || !reflect.DeepEqual(value, record) {
			t.Fatalf("record changed: %#v %v", value, err)
		}
		if frame.EncodedBytes() != len(encoded) || frame.Digest() != sha256.Sum256(encoded) {
			t.Fatal("canonical logical identity changed")
		}
		value.Origins.Prefix = netip.MustParsePrefix("1.1.1.0/24")
		value.Origins.Origins[0] = 0
		if frame.Digest() != sha256.Sum256(encoded) {
			t.Fatal("decoded payload aliases canonical bytes")
		}
		return frame.AppendTo(writer)
	}); err != nil || seen != 1 {
		t.Fatalf("walk: %d %v", seen, err)
	}
	copied, err := writer.FinishCanonical()
	if err != nil || len(copied) != 1 || copied[0].Descriptor() != part.Descriptor() {
		t.Fatalf("copy changed stored bytes: %#v %v", copied, err)
	}
	descriptor := copied[0].Descriptor()
	descriptor.Bytes = 0
	if err = copied[0].Walk(context.Background(), func(frame CanonicalRecordFrame) error {
		value, err := frame.Record()
		if err != nil || !reflect.DeepEqual(value, record) {
			t.Fatalf("copied mutable value: %#v %v", value, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalRecordCapabilitiesRejectZeroClosedAndCancellation(t *testing.T) {
	var frame CanonicalRecordFrame
	if _, err := frame.Record(); err == nil || frame.EncodedBytes() != 0 || frame.Digest() != ([32]byte{}) {
		t.Fatal("zero frame accepted")
	}
	if frame.AppendTo(nil) == nil || (CanonicalPartition{}).Walk(context.Background(), func(CanonicalRecordFrame) error { return nil }) == nil {
		t.Fatal("zero capability accepted")
	}
	if _, err := (*RecordWriter)(nil).FinishCanonical(); err == nil {
		t.Fatal("nil writer accepted")
	}
	_, part := canonicalTestPartition(t, canonicalTestRecord())
	if part.Walk(context.Background(), nil) == nil {
		t.Fatal("nil sink accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := part.Walk(ctx, func(CanonicalRecordFrame) error { t.Fatal("canceled walk emitted"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	root := t.TempDir()
	store, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	closed := store.Writer(context.Background())
	if err = closed.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err = closed.FinishCanonical(); err == nil {
		t.Fatal("closed writer minted capability")
	}
	canceled := store.Writer(ctx)
	defer canceled.Abort()
	if err = part.Walk(context.Background(), func(frame CanonicalRecordFrame) error {
		if frame.AppendTo(closed) == nil || frame.AppendTo(nil) == nil {
			t.Fatal("invalid destination accepted")
		}
		if err := frame.AppendTo(canceled); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled append: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if err = part.Walk(ctx, func(CanonicalRecordFrame) error { cancel(); return nil }); err == nil {
		t.Fatalf("callback cancellation: %v", err)
	}
}

func TestCanonicalRecordFrameKeepsDestinationLimits(t *testing.T) {
	record := canonicalTestRecord()
	_, part := canonicalTestPartition(t, record)
	encoded, _ := json.Marshal(record)
	for _, test := range []struct {
		name   string
		change func(*RecordStoreLimits)
	}{
		{"record", func(l *RecordStoreLimits) { l.RecordBytes = len(encoded) - 1 }},
		{"partition", func(l *RecordStoreLimits) { l.PartitionBytes = int64(len(recordHeader) + 4 + len(encoded) - 1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultRecordStoreLimits()
			test.change(&limits)
			store, err := NewRecordStore(t.TempDir(), limits)
			if err != nil {
				t.Fatal(err)
			}
			writer := store.Writer(context.Background())
			defer writer.Abort()
			if err = part.Walk(context.Background(), func(frame CanonicalRecordFrame) error {
				if frame.AppendTo(writer) == nil {
					t.Fatal("destination byte limit bypassed")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if store.DiskBytes() != 0 {
				t.Fatal("failed append reserved disk")
			}
		})
	}
	limits := DefaultRecordStoreLimits()
	limits.PartitionRecords = 1
	store, err := NewRecordStore(t.TempDir(), limits)
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(context.Background())
	defer writer.Abort()
	if err = part.Walk(context.Background(), func(frame CanonicalRecordFrame) error {
		if err := frame.AppendTo(writer); err != nil {
			return err
		}
		return frame.AppendTo(writer)
	}); err != nil {
		t.Fatal(err)
	}
	parts, err := writer.FinishCanonical()
	if err != nil || len(parts) != 2 || parts[0].Descriptor().Records != 1 || parts[1].Descriptor().Records != 1 {
		t.Fatalf("destination count limit bypassed: %#v %v", parts, err)
	}
}

func TestCanonicalPartitionRejectsReplacementAndLinkedRoot(t *testing.T) {
	for _, mode := range []string{"corrupt", "truncate", "linked-object", "linked-directory"} {
		t.Run(mode, func(t *testing.T) {
			root, part := canonicalTestPartition(t, canonicalTestRecord())
			directory := filepath.Join(root, ".atlas-private", "records-v2")
			path := filepath.Join(directory, partitionName(part.Descriptor()))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "corrupt":
				data[len(data)-1] ^= 1
				err = os.WriteFile(path, data, 0600)
			case "truncate":
				err = os.WriteFile(path, data[:len(data)-1], 0600)
			case "linked-object":
				target := filepath.Join(t.TempDir(), "replacement")
				if err = os.WriteFile(target, data, 0600); err == nil {
					err = os.Remove(path)
				}
				if err == nil {
					err = os.Symlink(target, path)
				}
			case "linked-directory":
				target := filepath.Join(root, ".atlas-private", "moved-records")
				if err = os.Rename(directory, target); err == nil {
					err = os.Symlink(target, directory)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			seen := 0
			if err = part.Walk(context.Background(), func(CanonicalRecordFrame) error { seen++; return nil }); err == nil || seen != 0 {
				t.Fatalf("replacement emitted %d records: %v", seen, err)
			}
		})
	}
}

func TestCanonicalPartitionCannotAdoptExistingNoncanonicalObjects(t *testing.T) {
	root := t.TempDir()
	store, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	record := canonicalTestRecord()
	encoded, _ := json.Marshal(record)
	encoded = append([]byte(" \n"), encoded...)
	data := append([]byte(nil), []byte(recordHeader)...)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(encoded)))
	data = append(data, encoded...)
	part := RecordPartition{SHA256: sha256.Sum256(data), Bytes: int64(len(data)), Records: 1}
	if err = os.WriteFile(filepath.Join(store.root, partitionName(part)), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = WalkStoredSource(context.Background(), root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(got NormalizedRecord) error {
		if !reflect.DeepEqual(got, record) {
			t.Fatal("legacy noncanonical decode changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store, err = NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(context.Background())
	caps, err := writer.FinishCanonical()
	if err != nil || len(caps) != 0 {
		t.Fatalf("existing object adopted as canonical: %#v %v", caps, err)
	}
	writer = store.Writer(context.Background())
	if err = writer.Append(record); err != nil {
		t.Fatal(err)
	}
	caps, err = writer.FinishCanonical()
	if err != nil || len(caps) != 1 || caps[0].Descriptor() == part {
		t.Fatalf("writer failed to produce separate canonical identity: %#v %v", caps, err)
	}
}
