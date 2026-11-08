package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"vansail-ip-atlas/internal/acquire"
)

func commitSource(locator, assetURL string) (acquire.GitHubCommitQuery, bool) {
	query, ok := acquire.ParseGitHubCommitURL(locator)
	if !ok || !safeHTTPS(assetURL) {
		return acquire.GitHubCommitQuery{}, false
	}
	u, err := url.Parse(assetURL)
	if err != nil || u.Host != "raw.githubusercontent.com" || u.RawPath != "" || u.Path != "/"+query.Owner+"/"+query.Repository+"/"+query.Ref+"/"+query.Path {
		return acquire.GitHubCommitQuery{}, false
	}
	return query, true
}

func publicationSupported(source Source) bool {
	switch source.Publication.Kind {
	case "github_release":
		return source.Publication.Field == "published_at" && validReleaseLocator(source.Publication.Locator, source.URL)
	case "github_commit":
		_, ok := commitSource(source.Publication.Locator, source.URL)
		return ok && source.Publication.Field == "commit.committer.date"
	default:
		return false
	}
}

type commitMetadata struct {
	SHA, URL string
	Commit   struct {
		Author, Committer struct{ Date string }
	}
}

// Commit metadata alone is insufficient. The path-filtered query must describe
// the same repository/ref/file as the source, and an independently downloaded
// immutable commit URL must have exactly the original payload's SHA-256/size.
// This uses GitHub's HTTPS publisher assertions, never Git's SHA-1 blob digest
// as a collision-resistant content hash. Mutable refs racing an update fail.
func (e *Engine) verifyCommit(ctx context.Context, metadataPath, quarantine string, source Source, digest [32]byte, size int64, now time.Time) (time.Time, error) {
	deny := errors.New("publication proof rejected")
	query, ok := commitSource(source.Publication.Locator, source.URL)
	if !ok || now.IsZero() || size <= 0 || digest == ([32]byte{}) {
		return time.Time{}, deny
	}
	data, err := boundedFile(ctx, metadataPath, 4<<20)
	if err != nil || uniqueJSON(data) != nil {
		return time.Time{}, deny
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('[') || !decoder.More() {
		return time.Time{}, deny
	}
	var metadata commitMetadata
	if decoder.Decode(&metadata) != nil || decoder.More() {
		return time.Time{}, deny
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim(']') || !commitSHA(metadata.SHA) || metadata.URL != "https://api.github.com/repos/"+query.Owner+"/"+query.Repository+"/commits/"+metadata.SHA {
		return time.Time{}, deny
	}
	author, err := timestamp(metadata.Commit.Author.Date)
	if err != nil || author.After(now.Add(24*time.Hour)) {
		return time.Time{}, deny
	}
	published, err := timestamp(metadata.Commit.Committer.Date)
	if err != nil || published.After(now.Add(24*time.Hour)) {
		return time.Time{}, deny
	}
	if author.Before(published) {
		published = author
	}
	immutable := "https://raw.githubusercontent.com/" + query.Owner + "/" + query.Repository + "/" + metadata.SHA + "/" + query.Path
	bound := filepath.Join(quarantine, "immutable")
	if _, err := e.fetch.Fetch(ctx, immutable, bound, source.MaxCompressedBytes); err != nil {
		return time.Time{}, deny
	}
	actual, actualSize, err := hashFile(ctx, bound, source.MaxCompressedBytes)
	if err != nil || actual != digest || actualSize != size {
		return time.Time{}, deny
	}
	return published, nil
}

func commitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
