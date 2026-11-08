package acquire

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

func archiveFixture(t *testing.T, format string, headers []*tar.Header) []byte {
	t.Helper()
	var data bytes.Buffer
	if format == "zip" {
		writer := zip.NewWriter(&data)
		for _, header := range headers {
			info := &zip.FileHeader{Name: header.Name, Method: zip.Deflate}
			if header.Typeflag == tar.TypeSymlink {
				info.SetMode(fs.ModeSymlink | 0600)
			}
			entry, err := writer.CreateHeader(info)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(entry, strings.Repeat("x", int(header.Size))); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		writer := tar.NewWriter(&data)
		for _, header := range headers {
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if header.Typeflag != tar.TypeSymlink && header.Typeflag != tar.TypeLink {
				if _, err := io.WriteString(writer, strings.Repeat("x", int(header.Size))); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return data.Bytes()
}

func inputArchive(data []byte) ArchiveInput {
	reader := bytes.NewReader(data)
	return ArchiveInput{Reader: reader, ReaderAt: reader, Size: int64(len(data))}
}

func testConsume(output map[string]string) func(string, io.Reader) error {
	return func(name string, reader io.Reader) error {
		data, err := io.ReadAll(reader)
		if err == nil {
			output[name] = string(data)
		}
		return err
	}
}

func TestArchiveStreamingHappyPaths(t *testing.T) {
	limits := DefaultArchiveLimits()
	for _, format := range []string{"tar", "zip"} {
		t.Run(format, func(t *testing.T) {
			data := archiveFixture(t, format, []*tar.Header{{Name: "records/part.csv", Mode: 0600, Size: 3, Typeflag: tar.TypeReg}})
			output := map[string]string{}
			if err := WalkArchive(context.Background(), inputArchive(data), format, limits, testConsume(output)); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(output, map[string]string{"records/part.csv": "xxx"}) {
				t.Fatal("wrong streamed entries")
			}
		})
	}
	var gz bytes.Buffer
	writer := gzip.NewWriter(&gz)
	writer.Write([]byte("synthetic bulk data\n"))
	writer.Close()
	bz, err := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWQ3ECTAAAAdRgAAQQAA+bQ4gIAAimjJo2k9BTAATTS++/ISFwDQBJqxdyRThQkA3ECTA")
	if err != nil {
		t.Fatal(err)
	}
	for _, example := range []struct {
		format string
		data   []byte
	}{{"gzip", gz.Bytes()}, {"bzip2", bz}, {"plain", []byte("synthetic bulk data\n")}} {
		output := map[string]string{}
		if err := WalkArchive(context.Background(), inputArchive(example.data), example.format, limits, testConsume(output)); err != nil || output["payload"] != "synthetic bulk data\n" {
			t.Fatalf("%s failed: %v", example.format, err)
		}
	}
}

func TestArchiveRejectsTraversalLinksAndDuplicatePaths(t *testing.T) {
	for _, format := range []string{"tar", "zip"} {
		for _, name := range []string{"../escape", "/absolute", "C:/drive", "a\\escape", "a/../escape", "a//b", "a/./b", "a:stream", "a/space. "} {
			t.Run(format+name, func(t *testing.T) {
				data := archiveFixture(t, format, []*tar.Header{{Name: name, Mode: 0600, Size: 1, Typeflag: tar.TypeReg}})
				if err := WalkArchive(context.Background(), inputArchive(data), format, DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
					t.Fatal("unsafe entry accepted")
				}
			})
		}
		for _, headers := range [][]*tar.Header{
			{{Name: "same", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}, {Name: "same", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}},
			{{Name: "same", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}, {Name: "SAME", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}},
			{{Name: "parent", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}, {Name: "parent/child", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}},
			{{Name: "parent/child", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}, {Name: "parent", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}},
			{{Name: "link", Mode: 0600, Typeflag: tar.TypeSymlink, Linkname: "../private"}},
		} {
			data := archiveFixture(t, format, headers)
			if err := WalkArchive(context.Background(), inputArchive(data), format, DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
				t.Fatalf("%s accepted duplicate/link", format)
			}
		}
	}
}

func TestArchiveResourceLimitsAndCancellation(t *testing.T) {
	for _, format := range []string{"tar", "zip"} {
		data := archiveFixture(t, format, []*tar.Header{{Name: "one", Mode: 0600, Size: 10, Typeflag: tar.TypeReg}, {Name: "two", Mode: 0600, Size: 10, Typeflag: tar.TypeReg}})
		for _, limits := range []ArchiveLimits{
			{CompressedBytes: int64(len(data) - 1), DecodedBytes: 1 << 20, EntryBytes: 100, Entries: 10, NameBytes: 100},
			{CompressedBytes: 1 << 20, DecodedBytes: 1 << 20, EntryBytes: 9, Entries: 10, NameBytes: 100},
			{CompressedBytes: 1 << 20, DecodedBytes: 1 << 20, EntryBytes: 100, Entries: 1, NameBytes: 100},
		} {
			if err := WalkArchive(context.Background(), inputArchive(data), format, limits, testConsume(map[string]string{})); err != ErrArchive {
				t.Fatal("resource bound ignored")
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		consume := func(_ string, reader io.Reader) error {
			cancel()
			_, err := io.ReadAll(reader)
			return err
		}
		if err := WalkArchive(ctx, inputArchive(data), format, DefaultArchiveLimits(), consume); err != ErrArchive {
			t.Fatal("mid-entry cancellation ignored")
		}
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Write(bytes.Repeat([]byte("x"), 1<<20))
	writer.Close()
	limits := DefaultArchiveLimits()
	limits.DecodedBytes, limits.EntryBytes = 1024, 1024
	if err := WalkArchive(context.Background(), inputArchive(compressed.Bytes()), "gzip", limits, func(string, io.Reader) error { return nil }); err != ErrArchive {
		t.Fatal("early-return parser bypassed decompression bomb bound")
	}
}

func TestArchiveCorruptionTrailingDataAndUnsupportedFormats(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Write([]byte("synthetic"))
	writer.Close()
	valid := compressed.Bytes()
	for _, data := range [][]byte{valid[:len(valid)-1], append(append([]byte{}, valid...), valid...), append(append([]byte{}, valid...), 1)} {
		if err := WalkArchive(context.Background(), inputArchive(data), "gzip", DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
			t.Fatal("gzip corruption/trailing frame accepted")
		}
	}
	for _, format := range []string{"xz", "tar.xz", "unknown"} {
		if err := WalkArchive(context.Background(), inputArchive(valid), format, DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
			t.Fatal("uncertified codec accepted")
		}
	}
	tarData := archiveFixture(t, "tar", []*tar.Header{{Name: "record", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}})
	if err := WalkArchive(context.Background(), inputArchive(append(tarData, 1)), "tar", DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
		t.Fatal("hidden tar trailer accepted")
	}
	zipData := archiveFixture(t, "zip", []*tar.Header{{Name: "record", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}})
	for _, corrupt := range [][]byte{zipData[:len(zipData)-1], append(append([]byte{}, zipData...), 1)} {
		if err := WalkArchive(context.Background(), inputArchive(corrupt), "zip", DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
			t.Fatal("corrupt zip accepted")
		}
	}
	// Reject central-directory count bombs before archive/zip allocates entries.
	mutated := append([]byte{}, zipData...)
	binary.LittleEndian.PutUint16(mutated[len(mutated)-22+8:], 10001)
	binary.LittleEndian.PutUint16(mutated[len(mutated)-22+10:], 10001)
	if err := WalkArchive(context.Background(), inputArchive(mutated), "zip", DefaultArchiveLimits(), testConsume(map[string]string{})); err != ErrArchive {
		t.Fatal("central directory count bomb accepted")
	}
}
