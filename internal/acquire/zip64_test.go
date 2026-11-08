package acquire

import (
	"archive/tar"
	"context"
	"encoding/binary"
	"testing"
)

// Promote the small synthetic ZIP's end records to ZIP64. No large allocation,
// downloaded bytes or external fixture is needed to exercise 64-bit framing.
func zip64Fixture(t *testing.T) []byte {
	t.Helper()
	data := archiveFixture(t, "zip", []*tar.Header{{Name: "facts.csv", Mode: 0600, Size: 3, Typeflag: tar.TypeReg}})
	end := append([]byte{}, data[len(data)-22:]...)
	output := append([]byte{}, data[:len(data)-22]...)
	offset := len(output)
	record := make([]byte, 56)
	binary.LittleEndian.PutUint32(record, 0x06064b50)
	binary.LittleEndian.PutUint64(record[4:], 44)
	binary.LittleEndian.PutUint16(record[12:], 45)
	binary.LittleEndian.PutUint16(record[14:], 45)
	binary.LittleEndian.PutUint64(record[24:], uint64(binary.LittleEndian.Uint16(end[8:])))
	binary.LittleEndian.PutUint64(record[32:], uint64(binary.LittleEndian.Uint16(end[10:])))
	binary.LittleEndian.PutUint64(record[40:], uint64(binary.LittleEndian.Uint32(end[12:])))
	binary.LittleEndian.PutUint64(record[48:], uint64(binary.LittleEndian.Uint32(end[16:])))
	output = append(output, record...)
	locator := make([]byte, 20)
	binary.LittleEndian.PutUint32(locator, 0x07064b50)
	binary.LittleEndian.PutUint64(locator[8:], uint64(offset))
	binary.LittleEndian.PutUint32(locator[16:], 1)
	output = append(output, locator...)
	binary.LittleEndian.PutUint16(end[8:], 0xffff)
	binary.LittleEndian.PutUint16(end[10:], 0xffff)
	binary.LittleEndian.PutUint32(end[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(end[16:], 0xffffffff)
	return append(output, end...)
}

func TestZIP64BoundedHappyPath(t *testing.T) {
	data := zip64Fixture(t)
	output := map[string]string{}
	if err := WalkArchive(context.Background(), inputArchive(data), "zip", DefaultArchiveLimits(), testConsume(output)); err != nil || output["facts.csv"] != "xxx" {
		t.Fatalf("ZIP64: %v", err)
	}
}

func TestZIP64CountSizeAndMultidiskBombs(t *testing.T) {
	valid := zip64Fixture(t)
	for _, mutation := range []func([]byte){
		func(b []byte) {
			binary.LittleEndian.PutUint64(b[len(b)-98+24:], 10001)
			binary.LittleEndian.PutUint64(b[len(b)-98+32:], 10001)
		},
		func(b []byte) { binary.LittleEndian.PutUint64(b[len(b)-98+4:], 1<<63) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[len(b)-98+48:], 1<<63) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[len(b)-98+40:], 1<<63) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[len(b)-42+16:], 2) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[len(b)-42+8:], 1<<63) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[len(b)-98+16:], 1) },
	} {
		data := append([]byte{}, valid...)
		mutation(data)
		if err := WalkArchive(context.Background(), inputArchive(data), "zip", DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
			t.Fatal("ZIP64 bomb accepted")
		}
	}
}

func TestZIPPreflightCountsActualDirectoryBeforeLibraryAllocation(t *testing.T) {
	data := archiveFixture(t, "zip", []*tar.Header{{Name: "first", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}, {Name: "second", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}})
	end := len(data) - 22
	binary.LittleEndian.PutUint16(data[end+8:], 1)
	binary.LittleEndian.PutUint16(data[end+10:], 1)
	// Must fail in preflight, before archive/zip processes the second record.
	if err := zipEntryCount(inputArchive(data), 1); err != ErrArchive {
		t.Fatal("forged directory count passed preflight")
	}
	data64 := zip64Fixture(t)
	binary.LittleEndian.PutUint64(data64[len(data64)-98+24:], 0)
	binary.LittleEndian.PutUint64(data64[len(data64)-98+32:], 0)
	if err := zipEntryCount(inputArchive(data64), 1); err != ErrArchive {
		t.Fatal("forged ZIP64 count passed preflight")
	}
}

func TestZIPRejectsAmbiguousEndRecordInComment(t *testing.T) {
	data := archiveFixture(t, "zip", []*tar.Header{{Name: "facts", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}})
	end := len(data) - 22
	comment := make([]byte, 23)
	binary.LittleEndian.PutUint32(comment, 0x06054b50)
	binary.LittleEndian.PutUint16(data[end+20:], uint16(len(comment)))
	data = append(data, comment...)
	if err := zipEntryCount(inputArchive(data), 10000); err != ErrArchive {
		t.Fatal("preflight and archive/zip could select different end records")
	}
}
