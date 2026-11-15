package main

import (
	"context"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func TestFingerprintIdentityRejectsConcurrentStateReplacement(t *testing.T) {
	root, authenticated := stateCommandFixture(t)
	if _, err := authenticatedStateFileHash(context.Background(), root, authenticated); err != nil {
		t.Fatal(err)
	}
	replacement := authenticated
	replacement.EvaluatedAt = replacement.EvaluatedAt.Add(time.Second)
	if err := intelligence.SavePrivateState(root, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticatedStateFileHash(context.Background(), root, authenticated); err == nil {
		t.Fatal("rows from authenticated A were allowed to bind replacement B")
	}
}
