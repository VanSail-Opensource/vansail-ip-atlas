package via3

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestPublicProfileRejectsDeclaredDecodeBeforeAllocation(t *testing.T) {
	g := golden(t)
	data, _ := base64.StdEncoding.DecodeString(g.Objects[0].Base64)
	p64(data, 36, PublicObjectDecoded+1)
	hash := Hash(data)
	r := &Release{Manifest: Manifest{ValidFrom: g.Clock, ValidUntil: g.Clock + 3600}, objects: map[string]ObjectInfo{hash: {Bytes: len(data), Kind: u16(data, 10), SHA256: hash, Partition: "all"}}, load: func(string) ([]byte, error) { return data, nil }, cache: make(map[string]*Shard), Clock: func() int64 { return g.Clock }}
	r.beginQuery()
	if _, err := r.object(context.Background(), hash); ErrorCode(err) != "resource_limit" {
		t.Fatalf("declared oversized decode reached parser: %v", err)
	}
	if r.cacheBytes != 0 || len(r.activeObjects) != 0 {
		t.Fatal("failed object retained decoded allocations")
	}
}
func TestPublicProfileOriginAndAnswerLimits(t *testing.T) {
	row := make([]byte, 16)
	p32(row, 0, bits(19))
	p32(row, 8, PublicOrigins+1)
	values := make([]uint32, PublicOrigins+1)
	for i := range values {
		values[i] = uint32(i + 1)
	}
	s := newShard(10, row)
	s.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
	s.set(4, intVector(values...))
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	if ErrorCode(ValidatePublicProfile(s)) != "resource_limit" {
		t.Fatal("oversized origin vector accepted by deploy profile")
	}
	b := newAnswerBudget()
	if err := b.path(PublicPathASNs); err != nil {
		t.Fatal(err)
	}
	if ErrorCode(b.path(1)) != "resource_limit" {
		t.Fatal("path output array unbounded")
	}
	b = newAnswerBudget()
	if err := b.cellOrigins(PublicOrigins); err != nil {
		t.Fatal(err)
	}
	if ErrorCode(b.cellOrigins(1)) != "resource_limit" {
		t.Fatal("class C aggregate origin arrays unbounded")
	}
	b = newAnswerBudget()
	if ErrorCode(b.charge(PublicAnswerBytes)) != "resource_limit" {
		t.Fatal("answer byte cap not reserved before allocation")
	}
}
func TestPublicLiveArenaIncludesPinnedAndCache(t *testing.T) {
	r := &Release{cache: make(map[string]*Shard)}
	r.beginQuery()
	if err := r.admit("router", PublicObjectDecoded); err != nil {
		t.Fatal(err)
	}
	r.residents["router"].router = true
	r.residents["router"].cache = true
	r.endQuery()
	r.beginQuery()
	if err := r.admit("a", PublicObjectDecoded); err != nil {
		t.Fatal(err)
	}
	if err := r.admit("b", PublicObjectDecoded); err != nil {
		t.Fatal(err)
	}
	if err := r.admit("b", PublicObjectDecoded); err != nil {
		t.Fatal("shared router/cache backing charged more than once", err)
	}
	if ErrorCode(r.admit("c", 1)) != "resource_limit" {
		t.Fatal("pinned router excluded from live query cap")
	}
	if err := r.admit("b", PublicObjectDecoded); err != nil {
		t.Fatal("same active object charged twice", err)
	}
	r.endQuery()
	if r.residentBytes != PublicObjectDecoded || len(r.activeObjects) != 0 {
		t.Fatal("query-only resident buffers retained after completion")
	}
}
func TestPublicQueriesReleasePinsOnEveryExit(t *testing.T) {
	g := golden(t)
	now := g.Clock
	r := memoryRelease(t, g, func() int64 { return now })
	assertReleased := func() {
		t.Helper()
		if len(r.active) != 0 || len(r.activeObjects) != 0 || r.activeBytes != 0 {
			t.Fatal("query retained decoded pins")
		}
		for _, entry := range r.residents {
			if entry.query {
				t.Fatal("resident query flag survived")
			}
		}
	}
	if _, err := r.Lookup(context.Background(), "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	assertReleased()
	if _, err := r.ClassC(context.Background(), "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	assertReleased()
	if _, err := r.Prefixes(context.Background(), "AS13335", 99); ErrorCode(err) != "invalid_cursor" {
		t.Fatal(err)
	}
	assertReleased()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = r.Lookup(ctx, "203.0.113.1")
	assertReleased()
	now = g.Manifest.ValidUntil
	_, _ = r.Lookup(context.Background(), "203.0.113.1")
	assertReleased()
}
func TestSelfConsistentManifestCannotExtendValidity(t *testing.T) {
	g := golden(t)
	m := g.Manifest
	m.ValidUntil = m.ValidFrom + 721*3600
	descriptor := Descriptor{Codec: m.Codec, FormatVersion: m.FormatVersion, Mode: m.Mode, Objects: m.Objects, SchemaVersion: m.SchemaVersion, ValidFrom: m.ValidFrom, ValidUntil: m.ValidUntil}
	m.ReleaseID = Hash(canonical(descriptor))
	p := Pointer{FormatVersion: 3, ManifestPath: "/_atlas/releases/" + m.ReleaseID + "/manifest.json", ManifestSHA256: Hash(canonical(m)), ReleaseID: m.ReleaseID}
	if _, err := NewRelease(canonical(p), canonical(m), func(string) ([]byte, error) { t.Fatal("unqualified manifest fetched object"); return nil, nil }, func() int64 { return g.Clock }); ErrorCode(err) != "manifest" {
		t.Fatalf("self-consistent manifest extended maximum interval: %v", err)
	}
}

func FuzzRead(f *testing.F) {
	g := golden(f)
	for _, object := range g.Objects {
		data, _ := base64.StdEncoding.DecodeString(object.Base64)
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxFile {
			return
		}
		_, _ = Read(context.Background(), data)
	})
}
