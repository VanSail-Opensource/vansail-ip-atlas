package admission

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"
)

const tweetCommitAPI = "https://api.github.com/repos/0xDanielLopez/TweetFeed/commits"
const tweetImmutableBase = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/"

type tweetCommit struct {
	commitMetadata
	Parents []struct{ SHA, URL string }
}

func (e *Engine) tweetRevision(ctx context.Context, dir, ref string, now time.Time) (tweetCommit, time.Time, error) {
	var zero tweetCommit
	if ref != "master" && !commitSHA(ref) {
		return zero, time.Time{}, errTweetFeedEdition
	}
	file := filepath.Join(dir, "tweet-commit")
	url := tweetCommitAPI + "?path=week.csv&sha=" + ref + "&per_page=1"
	if _, err := e.fetch.Fetch(ctx, url, file, 128<<10); err != nil {
		return zero, time.Time{}, err
	}
	data, err := boundedFile(ctx, file, 128<<10)
	var entries []tweetCommit
	if err != nil || uniqueJSON(data) != nil || json.Unmarshal(data, &entries) != nil || len(entries) != 1 {
		return zero, time.Time{}, errTweetFeedEdition
	}
	r := entries[0]
	if !commitSHA(r.SHA) || r.URL != tweetCommitAPI+"/"+r.SHA || len(r.Parents) != 1 {
		return zero, time.Time{}, errTweetFeedEdition
	}
	parent := r.Parents[0]
	if !commitSHA(parent.SHA) || parent.SHA == r.SHA || parent.URL != tweetCommitAPI+"/"+parent.SHA {
		return zero, time.Time{}, errTweetFeedEdition
	}
	committed, err := timestamp(r.Commit.Committer.Date)
	if err != nil || committed.After(now.Add(24*time.Hour)) {
		return zero, time.Time{}, errTweetFeedEdition
	}
	return r, committed, nil
}

func (a tweetFeedArtifact) sameContent(b tweetFeedArtifact) bool {
	return a.digest == b.digest && a.size == b.size && a.rows == b.rows
}

// The week.csv path query returns the last change reachable from ref, which
// can predate a manifest-only refresh. Read its manifest from that same commit.
func (e *Engine) tweetManifestAt(ctx context.Context, dir, sha string, now time.Time) (tweetFeedArtifact, error) {
	file := filepath.Join(dir, "tweet-manifest")
	if _, err := e.fetch.Fetch(ctx, tweetImmutableBase+sha+"/manifest.json", file, 1<<20); err != nil {
		return tweetFeedArtifact{}, err
	}
	return readTweetFeedManifest(ctx, file, now)
}

// Resolve only the latest changed CSV and the edition present in its immediate
// parent. A post-clock live manifest must match the immutable child before its
// predecessor can be considered. Exactly one selected immutable CSV is read.
func (e *Engine) fetchImmutableTweetFeed(ctx context.Context, payload string, s Source, live tweetFeedArtifact, now time.Time) (time.Time, error) {
	dir := filepath.Dir(payload)
	ref := "master"
	var childTime time.Time
	future := live.published.After(now)
	for generation := 0; generation < 2; generation++ {
		revision, committed, err := e.tweetRevision(ctx, dir, ref, now)
		if err != nil {
			return time.Time{}, err
		}
		if generation == 1 && (committed.After(childTime) || committed.After(now)) {
			return time.Time{}, errTweetFeedEdition
		}
		proof, err := e.tweetManifestAt(ctx, dir, revision.SHA, now)
		if err != nil || proof.published.After(committed) {
			return time.Time{}, errTweetFeedEdition
		}
		if generation == 1 && ref != revision.SHA {
			// Other files may have changed since this CSV. Bind the actual
			// parent tree to the older CSV before using its publication time.
			parentProof, err := e.tweetManifestAt(ctx, dir, ref, now)
			if err != nil || !parentProof.sameContent(proof) || parentProof.published.Before(proof.published) || parentProof.published.After(childTime) {
				return time.Time{}, errTweetFeedEdition
			}
		}
		matches := proof.sameContent(live)
		if generation == 0 && future && (!matches || proof.published.After(live.published)) {
			return time.Time{}, errTweetFeedEdition
		}
		if !committed.After(now) && (matches || future && generation == 1) {
			if matches && live.published.Before(proof.published) {
				proof.published = live.published
			}
			if !now.Before(proof.published.Add(s.MaxAge)) {
				return time.Time{}, errTweetFeedEdition
			}
			if _, err := e.fetch.Fetch(ctx, tweetImmutableBase+revision.SHA+"/week.csv", payload, min(s.MaxCompressedBytes, proof.size)); err != nil {
				return time.Time{}, err
			}
			return proof.published, proof.verify(ctx, payload)
		}
		ref, childTime = revision.Parents[0].SHA, committed
	}
	return time.Time{}, errTweetFeedEdition
}
