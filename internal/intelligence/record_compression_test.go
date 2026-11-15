package intelligence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func putRecordFixture(t *testing.T, root string, data []byte, part RecordPartition) RecordPartition {
	t.Helper()
	part.SHA256 = sha256.Sum256(data)
	part.Bytes = int64(len(data))
	directory, err := recordDirectory(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, partitionName(part)), data, 0600); err != nil {
		t.Fatal(err)
	}
	return part
}
func TestLegacyRawPrivatePartitionMigrationAndCompressedDeterminism(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	policy, snapshot, binding := stateFixture()
	data, err := json.Marshal(snapshot.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), []byte(recordHeader)...)
	raw = binary.LittleEndian.AppendUint32(raw, uint32(len(data)))
	raw = append(raw, data...)
	legacy := putRecordFixture(t, root, raw, RecordPartition{Records: 1})
	snapshot.Records = nil
	snapshot.RecordPartitions = []RecordPartition{legacy}
	first, err := ReconcilePartitioned(ctx, root, BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil {
		t.Fatal(err)
	}
	parts := first.State.Sources[0].RecordPartitions
	if len(parts) != 1 || parts[0].Codec != "zstd-v1" || parts[0].DecodedBytes <= 0 {
		t.Fatal("legacy raw partition did not migrate")
	}
	second, err := ReconcilePartitioned(ctx, root, first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil || second.FullRebuild || second.State.Sources[0].RecordPartitions[0] != parts[0] {
		t.Fatal("compressed content identity changed", err)
	}
}
func TestPrivateCompressedPartitionRejectsEnvelopeAndBounds(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(ctx)
	defer writer.Abort()
	record := NormalizedRecord{Version: 3, Kind: RecordASNIdentity, ASNIdentity: &ASNIdentityEvidence{ASN: 13335, Name: "Example"}}
	if err = writer.Append(record); err != nil {
		t.Fatal(err)
	}
	parts, err := writer.Finish()
	if err != nil {
		t.Fatal(err)
	}
	valid := parts[0]
	encoded, err := os.ReadFile(filepath.Join(store.root, partitionName(valid)))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"trailing", "concatenated", "checksum", "decoded-long", "decoded-short", "count", "window", "codec"} {
		t.Run(kind, func(t *testing.T) {
			data := append([]byte(nil), encoded...)
			part := valid
			switch kind {
			case "trailing":
				data = append(data, 0)
			case "concatenated":
				data = append(data, encoded[len(compressedRecordHeader):]...)
			case "checksum":
				data[len(data)-1] ^= 1
			case "decoded-long":
				part.DecodedBytes++
			case "decoded-short":
				part.DecodedBytes--
			case "count":
				part.Records++
			case "codec":
				part.Codec = "unknown"
			case "window":
				data = append([]byte(compressedRecordHeader), 0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x01, 0, 0, 0, 0, 0, 0)
			}
			part = putRecordFixture(t, root, data, part)
			if err := WalkStoredSource(ctx, root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(NormalizedRecord) error { return nil }); err == nil {
				t.Fatal("invalid compressed private partition accepted")
			}
		})
	}
}

func TestPrivateRawPartitionRejectsInvalidUTF8BeforeJSONReplacement(t *testing.T) {
	root := t.TempDir()
	record := NormalizedRecord{Version: 3, Kind: RecordASNIdentity, ASNIdentity: &ASNIdentityEvidence{ASN: 13335, Name: "Example"}}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	position := bytes.Index(data, []byte("Example"))
	if position < 0 {
		t.Fatal("fixture label missing")
	}
	data[position] = 0xff
	raw := append([]byte(recordHeader), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(raw[len(recordHeader):], uint32(len(data)))
	raw = append(raw, data...)
	part := putRecordFixture(t, root, raw, RecordPartition{Records: 1})
	seen := 0
	if err := WalkStoredSource(context.Background(), root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(NormalizedRecord) error { seen++; return nil }); err == nil || seen != 0 {
		t.Fatal("invalid UTF-8 was replaced instead of rejected", err)
	}
}
