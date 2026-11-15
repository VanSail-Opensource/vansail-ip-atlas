package admission

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestExactAssetPublicationDoesNotInheritLongLivedReleaseAge(t *testing.T) {
	now := time.Date(2026, 11, 9, 1, 0, 0, 0, time.UTC)
	asset := "https://github.com/unit/publisher/releases/download/latest/data.csv"
	payload := []byte("observed current replacement asset")
	created := now.Add(-time.Hour)
	metadata := metadataFor(t, asset, payload, now.Add(-150*24*time.Hour), created)
	got, err := verifyRelease(metadata, asset, sha256.Sum256(payload), int64(len(payload)), now)
	if err != nil || !got.Equal(created) {
		t.Fatalf("exact replacement inherited unrelated release age: %v %v", got, err)
	}
	old := now.Add(-721 * time.Hour)
	metadata = metadataFor(t, asset, payload, now, old)
	got, err = verifyRelease(metadata, asset, sha256.Sum256(payload), int64(len(payload)), now)
	if err != nil || !got.Equal(old) {
		t.Fatalf("new release renewed old asset: %v %v", got, err)
	}
}
