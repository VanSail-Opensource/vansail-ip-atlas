package via3

import (
	"context"
	"slices"
	"testing"
)

func TestOperationsReadOnlyRequiredDestinationKinds(t *testing.T) {
	g := golden(t)
	ctx := context.Background()
	newReader := func(t *testing.T, allowed []uint16) *Release {
		r := memoryRelease(t, g, func() int64 { return g.Clock })
		load := r.load
		r.load = func(hash string) ([]byte, error) {
			kind := r.references[hash].info.Kind
			if !slices.Contains(allowed, kind) {
				t.Fatalf("unexpected kind %d", kind)
			}
			return load(hash)
		}
		return r
	}
	t.Run("prefix page", func(t *testing.T) {
		r := newReader(t, []uint16{8})
		if _, err := r.Prefixes(ctx, "AS13335", 0); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Class C", func(t *testing.T) {
		r := newReader(t, []uint16{7, 4})
		if a, err := r.ClassC(ctx, "203.0.113.1"); err != nil || a == nil {
			t.Fatal(err)
		}
	})
	t.Run("corrupt requested profile", func(t *testing.T) {
		r := memoryRelease(t, g, func() int64 { return g.Clock })
		load := r.load
		r.load = func(hash string) ([]byte, error) {
			b, err := load(hash)
			if r.references[hash].info.Kind == 7 && err == nil {
				b = slices.Clone(b)
				b[len(b)-1] ^= 1
			}
			return b, err
		}
		if _, err := r.Lookup(ctx, "203.0.113.1"); ErrorCode(err) != "integrity" {
			t.Fatal("general lookup accepted corrupt profile", err)
		}
		if _, err := r.ClassC(ctx, "203.0.113.1"); ErrorCode(err) != "integrity" {
			t.Fatalf("corrupt requested profile: %v", err)
		}
	})
}
