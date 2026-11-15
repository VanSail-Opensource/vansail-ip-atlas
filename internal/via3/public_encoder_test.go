package via3

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

func TestPublicEncoderPreservesFrozenFramesAfterUnlikeHistory(t *testing.T) {
	ctx := context.Background()
	var encoder PublicEncoder
	defer encoder.Close()
	// Exercise both the retained single-segment workspace and the temporary
	// bounded-window encoder, then return to small frozen shards after each.
	for _, count := range []int{1, (MaxWindow - 8) / 32, MaxWindow/32 + 1} {
		index, err := profilePrefixIndex(ctx, count, 1)
		if err != nil {
			t.Fatal(err)
		}
		large := newShard(5, make([]byte, 8))
		large.set(1, index)
		want, err := Write(ctx, large)
		if err != nil {
			t.Fatal(err)
		}
		got, err := encoder.Write(ctx, large)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("independent frame changed for %d keys: %v", count, err)
		}
		if _, err := Read(ctx, got); err != nil {
			t.Fatal("reused frame requires previous history", err)
		}
		g := golden(t)
		for i := len(g.Objects) - 1; i >= 0; i-- {
			object := g.Objects[i]
			expected, err := base64.StdEncoding.DecodeString(object.Base64)
			if err != nil {
				t.Fatal(err)
			}
			shard, err := Read(ctx, expected)
			if err != nil {
				t.Fatal(err)
			}
			got, err := encoder.Write(ctx, shard)
			if err != nil || !bytes.Equal(got, expected) || Hash(got) != object.Info.SHA256 {
				t.Fatalf("frozen kind %d changed after %d keys: %v", shard.Kind, count, err)
			}
		}
	}
}

func TestPublicEncoderKeepsValidationCancellationAndLifetime(t *testing.T) {
	ctx := context.Background()
	valid := newShard(5, make([]byte, 8))
	valid.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
	var encoder PublicEncoder
	if _, err := encoder.Write(ctx, valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Kind = 99
	for _, tc := range []struct {
		ctx   context.Context
		shard Shard
	}{
		{ctx, invalid},
		{func() context.Context { canceled, cancel := context.WithCancel(ctx); cancel(); return canceled }(), valid},
	} {
		_, freshErr := Write(tc.ctx, tc.shard)
		data, reusedErr := encoder.Write(tc.ctx, tc.shard)
		if freshErr == nil || reusedErr == nil || freshErr.Error() != reusedErr.Error() || data != nil {
			t.Fatalf("error behavior changed: fresh=%v reused=%v", freshErr, reusedErr)
		}
		if errors.Is(freshErr, context.Canceled) != errors.Is(reusedErr, context.Canceled) {
			t.Fatal("cancellation identity changed")
		}
		want, err := Write(ctx, valid)
		if err != nil {
			t.Fatal(err)
		}
		got, err := encoder.Write(ctx, valid)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("failed write contaminated subsequent frame", err)
		}
	}
	if err := encoder.Close(); err != nil || encoder.encoder != nil {
		t.Fatal("close retained its compression workspace", err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal("close is not idempotent", err)
	}
	if data, err := encoder.Write(ctx, valid); err == nil || data != nil || encoder.encoder != nil {
		t.Fatal("closed encoder resurrected its workspace")
	}
	if _, err := encoder.CompilePartition(ctx, PartitionInput{Partition: "all"}); err == nil {
		t.Fatal("closed encoder accepted compilation")
	}
	var unused PublicEncoder
	if err := unused.Close(); err != nil || unused.encoder != nil {
		t.Fatal("closing an unused encoder allocated a workspace", err)
	}
}
