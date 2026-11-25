package via3

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func fileGolden(t *testing.T, g goldenCorpus) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{filepath.Join(root, "objects"), filepath.Join(root, "releases", g.Pointer.ReleaseID)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, path), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("current.json", canonical(g.Pointer))
	write(filepath.Join("releases", g.Pointer.ReleaseID, "manifest.json"), canonical(g.Manifest))
	for _, obj := range g.Objects {
		data, err := base64.StdEncoding.DecodeString(obj.Base64)
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join("objects", obj.Info.SHA256+".via3"), data)
	}
	return root
}

func TestFileIndexKeepsVerifiedFactsAndCallerOwnershipThroughEviction(t *testing.T) {
	g := golden(t)
	root := fileGolden(t, g)
	clock := g.Clock
	ctx := context.Background()
	reader, err := OpenRelease(root, func() int64 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if reader.NativeIndexBytes() != 0 || reader.Reads != 1 {
		t.Fatal("single-query OpenRelease read unrelated data")
	}
	if err := reader.PrepareNativeIndex(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	memory := memoryRelease(t, g, func() int64 { return clock })
	if reader.NativeIndexBytes() == 0 || reader.Reads != len(g.Objects) {
		t.Fatal("incomplete native index")
	}
	reader.native.pages.routerBytes = PublicCacheDecoded - rowPageSize
	reader.native.pages.setMetadata(0)
	for _, vector := range g.Vectors {
		got, err := reader.Lookup(ctx, vector.Q)
		if err != nil {
			t.Fatal(err)
		}
		want, err := memory.Lookup(ctx, vector.Q)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("different complete answer", vector.Q, err)
		}
		c, err := reader.ClassC(ctx, vector.Q)
		if err != nil {
			t.Fatal(err)
		}
		w, err := memory.ClassC(ctx, vector.Q)
		if err != nil || !reflect.DeepEqual(c, w) {
			t.Fatal("different class-C answer", vector.Q, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("eviction mutated a returned answer")
		}
		if reader.native.pages.pages > 1 {
			t.Fatal("evicted pages remain pinned")
		}
	}
	a, err := reader.Prefixes(ctx, "AS13335", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := memory.Prefixes(ctx, "AS13335", 0)
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("prefix page differs")
	}
	reader.Close()
	if _, err := reader.Lookup(ctx, g.Vectors[0].Q); ErrorCode(err) != "closed" {
		t.Fatal("closed reader accepted lookup", err)
	}
}

func TestFileIndexRejectsTamperingAndReturnsReadFailure(t *testing.T) {
	g := golden(t)
	clock := func() int64 { return g.Clock }
	root := fileGolden(t, g)
	r, err := OpenRelease(root, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.PrepareNativeIndex(context.Background(), t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// An I/O failure of the private file is propagated by the real operation.
	if err := r.native.resource.file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lookup(context.Background(), "203.0.113.1"); err == nil {
		t.Fatal("failed native read accepted")
	}
	r.Close()
	for _, obj := range g.Objects {
		if obj.Info.Kind == 1 {
			continue
		}
		path := filepath.Join(root, "objects", obj.Info.SHA256+".via3")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] ^= 1
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		break
	}
	r, err = OpenRelease(root, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.PrepareNativeIndex(context.Background(), t.TempDir()); ErrorCode(err) != "integrity" {
		t.Fatal("changed immutable data accepted", err)
	}
}

func TestNativePreparationCancellationAndPrivatePageIntegrity(t *testing.T) {
	g := golden(t)
	r := memoryRelease(t, g, func() int64 { return g.Clock })
	dir := t.TempDir()
	var cancel context.CancelFunc
	ctx, cancel := context.WithCancel(context.Background())
	original := r.load
	remaining := 3
	r.load = func(hash string) ([]byte, error) {
		remaining--
		if remaining == 0 {
			cancel()
		}
		return original(hash)
	}
	if err := r.PrepareNativeIndex(ctx, dir); err != context.Canceled {
		t.Fatal(err)
	}
	if r.native != nil {
		t.Fatal("partial index became visible")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed preparation leaked private data", err)
	}
	for _, ref := range r.references {
		if ref.onsite != nil {
			t.Fatal("partial object index became visible")
		}
	}
	r.load = original
	if _, err := r.Lookup(context.Background(), "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	if err := r.PrepareNativeIndex(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	before := r.Reads
	if err := r.PrepareNativeIndex(context.Background(), dir); err != nil || r.Reads != before {
		t.Fatal("idempotent preparation re-read the release", err)
	}
	path := r.native.resource.path
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in every private page while preserving file size and all
	// public input files. Only a digest bound to the verified source detects it.
	for n := range r.native.pages.dir {
		off := int64(n * rowPageSize)
		var b [1]byte
		if _, err = r.native.resource.file.ReadAt(b[:], off); err != nil {
			t.Fatal(err)
		}
		b[0] ^= 0xff
		if _, err = f.WriteAt(b[:], off); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Lookup(context.Background(), "203.0.113.1"); ErrorCode(err) != "integrity" {
		t.Fatal("modified private index accepted", err)
	}
	r.Close()
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("closed private index remained on disk", err)
	}
}
