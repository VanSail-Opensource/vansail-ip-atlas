package admission

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

// This dedicated workflow never acquires state or writes a production receipt.
type editionProbe struct {
	direct                  *acquire.Fetcher
	historical              string
	alternate, immutableCSV int
}

func (p *editionProbe) Fetch(ctx context.Context, url, dst string, bound int64) (acquire.Result, error) {
	if url == rootZoneAlternateGzipURL {
		p.alternate++
	}
	if strings.HasPrefix(url, tweetImmutableBase) && strings.HasSuffix(url, "/week.csv") && url != tweetFeedOrigin {
		p.immutableCSV++
	}
	// The two recorded branch heads select real immutable publisher trees.
	// Only the historical control redirects the head and live-manifest names.
	// All returned status, metadata and payload bytes come from the real origin.
	if p.historical != "" {
		if url == tweetFeedManifest {
			url = tweetImmutableBase + p.historical + "/manifest.json"
		}
		if url == tweetCommitAPI+"?path=week.csv&sha=master&per_page=1" {
			url = tweetCommitAPI + "?path=week.csv&sha=" + p.historical + "&per_page=1"
		}
	}
	return p.direct.Fetch(ctx, url, dst, bound)
}

func editionTransport(t *testing.T) *editionProbe {
	t.Helper()
	if os.Getenv("ATLAS_ENGINEERING_EDITION_CHECK") != "true" {
		t.Skip("requires direct publisher transport")
	}
	f, err := acquire.NewWithGitHubMetadataToken(os.Getenv("ATLAS_GITHUB_METADATA_TOKEN"))
	if err != nil {
		t.Fatal("standard transport initialization failed")
	}
	return &editionProbe{direct: f}
}

func weeklyComplete(t *testing.T, f *editionProbe, clock time.Time, expectedDigest string, expectedRows int) {
	t.Helper()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "actual")
	e := Engine{fetch: f}
	published, err := e.fetchTweetFeed(ctx, path, tweetTestSource(), clock)
	if err != nil || published.After(clock) {
		t.Fatal("complete edition verification failed")
	}
	hash, size, err := hashFile(ctx, path, tweetFeedByteLimit)
	if err != nil || expectedDigest != "" && hashString(hash) != expectedDigest {
		t.Fatal("complete edition digest failed")
	}
	fd, err := os.Open(path)
	if err != nil {
		t.Fatal("complete edition unavailable")
	}
	accepted := 0
	rows, err := scanTweetFeed(ctx, fd, published, tweetFeedRowLimit, func(row intelligence.NormalizedRecord) error { accepted++; return row.Validate() })
	closeErr := fd.Close()
	if err != nil || closeErr != nil || rows <= 0 || accepted <= 0 || expectedRows != 0 && rows != expectedRows || f.historical != "" && f.immutableCSV != 1 {
		t.Fatal("complete edition row verification failed")
	}
	t.Logf("weekly original bytes=%d sha256=%x rows=%d accepted=%d publication=%s age_seconds=%d selected_immutable=%t", size, hash, rows, accepted, published.UTC().Format(time.RFC3339), int64(clock.Sub(published)/time.Second), f.immutableCSV == 1)
}

func TestPublisherEditionsDirect(t *testing.T) {
	t.Run("current-archive", func(t *testing.T) {
		p := editionTransport(t)
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Second)
		path := filepath.Join(t.TempDir(), "original")
		orig, err := p.Fetch(ctx, rootZoneURL, path, rootZoneLimit)
		if err != nil || orig.LastModified.After(now) {
			t.Fatal("original acquisition failed")
		}
		h, n, err := hashFile(ctx, path, rootZoneLimit)
		if err != nil || h == ([32]byte{}) || n != orig.Bytes || hashString(h) != orig.SHA256 {
			t.Fatal("original hash unavailable")
		}
		e := Engine{fetch: p}
		z, err := e.verifyRootZone(ctx, path, h, n, now)
		if err != nil || !now.Before(z.until) {
			t.Fatal("complete independent copy verification failed")
		}
		fd, err := os.Open(path)
		if err != nil {
			t.Fatal("validated original unavailable")
		}
		count := 0
		_, err = parseRootZone(ctx, fd, 2*rootServerCount, func(row intelligence.NormalizedRecord) error { count++; return row.Validate() })
		closeErr := fd.Close()
		if err != nil || closeErr != nil || count != 26 || p.alternate > 1 {
			t.Fatal("exact observation population failed")
		}
		t.Logf("archive original bytes=%d sha256=%x rows=%d alternate_needed=%t valid_until=%s", n, h, count, p.alternate == 1, z.until.UTC().Format(time.RFC3339))
	})
	t.Run("current-weekly", func(t *testing.T) {
		weeklyComplete(t, editionTransport(t), time.Now().UTC().Truncate(time.Second), "", 0)
	})
	for _, v := range []struct {
		tag, ref, clock, digest string
		rows                    int
	}{
		{"first-change", "1c0971d1a5a038e882e76582344b431179841dc9", "2026-11-25T07:28:35Z", "fa49b22b5db2e43a4aaf77a7c74f41134392fc4e3c06ecc0147f6eef056c0ae4", 1816},
		{"second-change", "5b42528e8b8491c21d6c01162945c1b01c32e8fc", "2026-11-25T07:55:45Z", "834d39fdb8e2e159a20e0d988db2594fe106bd247b8e4eb86c1eaa4a45ea4dfc", 1822},
	} {
		t.Run(v.tag, func(t *testing.T) {
			p := editionTransport(t)
			p.historical = v.ref
			c, err := time.Parse(time.RFC3339, v.clock)
			if err != nil {
				t.Fatal("invalid control clock")
			}
			weeklyComplete(t, p, c, v.digest, v.rows)
		})
	}
}
