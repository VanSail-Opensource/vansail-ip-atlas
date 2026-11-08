package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestScannerInputRequiresBoundedRegularFile(t *testing.T) {
	directory := t.TempDir()
	if _, err := openRegularInput(directory, via3.MaxFile-1); err == nil {
		t.Fatal("directory accepted as a scanner input")
	}
	path := filepath.Join(directory, "oversized.via3")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	err = file.Truncate(via3.MaxFile)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readInspectFile(context.Background(), path); err == nil {
		t.Fatal("24 MiB boundary accepted")
	}
	valid := []byte("bounded inspection bytes")
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readInspectFile(context.Background(), path)
	if err != nil || !bytes.Equal(data, valid) {
		t.Fatal("bounded regular file changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readInspectFile(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatal("scanner input cancellation lost")
	}
}

func TestScannerInputRejectsSymlinks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.via3")
	link := filepath.Join(directory, "link.via3")
	if err := os.WriteFile(target, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink creation unavailable")
	}
	if _, err := openRegularInput(link, via3.MaxFile-1); err == nil {
		t.Fatal("symlink accepted as an immutable input")
	}
}

type countingZeros struct{ read int64 }

func (reader *countingZeros) Read(buffer []byte) (int, error) {
	clear(buffer)
	reader.read += int64(len(buffer))
	return len(buffer), nil
}

func TestScannerReadBoundsGrowingInput(t *testing.T) {
	reader := &countingZeros{}
	if _, err := readInspectBytes(context.Background(), reader, via3.MaxFile-1); err == nil {
		t.Fatal("growing input exceeded expected file length")
	}
	if reader.read != via3.MaxFile {
		t.Fatalf("read escaped strict file cap: %d", reader.read)
	}
	if _, err := readInspectBytes(context.Background(), bytes.NewReader([]byte("changed")), 1); err == nil {
		t.Fatal("changed file length accepted")
	}
	if _, err := readInspectBytes(context.Background(), io.NopCloser(bytes.NewReader(nil)), via3.MaxFile); err == nil {
		t.Fatal("invalid expected size accepted")
	}
}
