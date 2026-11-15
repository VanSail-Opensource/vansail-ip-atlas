package acquire

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const fixtureMetadata = "https://api.github.com/repos/unit/publisher/releases/tags/latest"
const fixtureCommitMetadata = "https://api.github.com/repos/unit/publisher/commits?path=data.csv&sha=main&per_page=1"

func TestGitHubMetadataTokenScope(t *testing.T) {
	for _, test := range []struct {
		url  string
		auth bool
	}{
		{fixtureMetadata, true},
		{fixtureCommitMetadata, true},
		{"https://api.github.com/repos/unit/publisher/releases/latest", true},
		{"https://api.github.com/repos/unit/publisher/releases/1234", true},
		{"https://api.github.com/user", false},
		{"https://api.github.com/repos/unit/publisher/actions/secrets", false},
		{"https://api.github.com/repos/unit/publisher/releases", false},
		{"https://api.github.com/repos/unit/publisher/releases/assets/1234", false},
		{"https://api.github.com/repos/unit/publisher/releases/tags/../latest", false},
		{"https://api.github.com/repos/unit/publisher/releases/tags/%6catest", false},
		{"https://api.github.com/repos/unit/publisher/releases/tags/latest/extra", false},
		{"https://api.github.com:443/repos/unit/publisher/releases/tags/latest", false},
		{"https://api.github.com.example.com/repos/unit/publisher/releases/tags/latest", false},
		{"https://sub.api.github.com/repos/unit/publisher/releases/tags/latest", false},
		{"https://raw.githubusercontent.com/unit/publisher/main/data.csv", false},
		{fixtureRelease, false},
	} {
		t.Run(test.url, func(t *testing.T) {
			f, err := NewWithGitHubMetadataToken("synthetic_test_token")
			if err != nil {
				t.Fatal(err)
			}
			f.client.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
				if got := request.Header.Get("Authorization"); (got == "Bearer synthetic_test_token") != test.auth || !test.auth && got != "" {
					t.Error("credential scope mismatch")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), ContentLength: 2}, nil
			})
			if _, err := f.Fetch(context.Background(), test.url, filepath.Join(t.TempDir(), "metadata"), 100); err != nil {
				t.Fatal("synthetic request rejected")
			}
		})
	}
	for _, token := range []string{"with space", "with\nnewline", "with\rreturn", "with\ttab", "with\x00nul", "nonasciié", strings.Repeat("x", 4097)} {
		if f, err := NewWithGitHubMetadataToken(token); err != ErrFetch || f != nil {
			t.Fatal("invalid token accepted or nonopaque error returned")
		}
	}
	f, err := NewWithGitHubMetadataToken("")
	if err != nil || f == nil {
		t.Fatal("anonymous acquisition is no longer supported")
	}
	for _, raw := range []string{
		"http://api.github.com/repos/unit/publisher/releases/latest",
		"https://user:synthetic@api.github.com/repos/unit/publisher/releases/latest",
		fixtureMetadata + "?",
		fixtureMetadata + "#fragment",
		fixtureCommitMetadata + "&extra=value",
	} {
		if githubMetadataURL(raw) {
			t.Fatal("noncanonical metadata endpoint accepted")
		}
	}
}

func TestGitHubMetadataRedirectNeverForwardsToken(t *testing.T) {
	for _, target := range []string{fixtureCommitMetadata, "https://api.github.com/user", "https://sub.api.github.com/data", "https://raw.githubusercontent.com/unit/publisher/main/data.csv", "https://example.com/data"} {
		t.Run(target, func(t *testing.T) {
			f, err := NewWithGitHubMetadataToken("synthetic_test_token")
			if err != nil {
				t.Fatal(err)
			}
			requests := 0
			f.client.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
				requests++
				if requests == 1 {
					if request.Header.Get("Authorization") == "" {
						t.Error("metadata request was not authenticated")
					}
					return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{target}}, Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}, nil
				}
				if request.Header.Get("Authorization") != "" || request.Header.Get("Referer") != "" {
					t.Error("redirect retained a credential or referrer")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), ContentLength: 2}, nil
			})
			if _, err := f.Fetch(context.Background(), fixtureMetadata, filepath.Join(t.TempDir(), "metadata"), 100); err != nil || requests != 2 {
				t.Fatal("synthetic metadata redirect failed")
			}
		})
	}
}

func TestGitHubMetadataRedirectChainCannotRestoreToken(t *testing.T) {
	f, err := NewWithGitHubMetadataToken("synthetic_test_token")
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{"https://api.github.com/user", "https://sub.api.github.com/data", fixtureCommitMetadata}
	requests := 0
	f.client.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
		if requests > 0 && request.Header.Get("Authorization") != "" {
			t.Error("redirect chain restored initial credentials")
		}
		requests++
		if requests <= len(targets) {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {targets[requests-1]}}, Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}, nil
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), ContentLength: 2}, nil
	})
	if _, err := f.Fetch(context.Background(), fixtureMetadata, filepath.Join(t.TempDir(), "metadata"), 100); err != nil || requests != 4 {
		t.Fatal("synthetic metadata redirect chain failed")
	}
}

func TestGitHubMetadataRateLimitRetryPolicy(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		status int
		header http.Header
		wait   time.Duration
		retry  bool
	}{
		{"secondary", 403, http.Header{"Retry-After": {"60"}}, time.Minute, true},
		{"primary", 403, http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {strconv.FormatInt(now.Add(40*time.Second).Unix(), 10)}}, 40 * time.Second, true},
		{"later-reset", 403, http.Header{"Retry-After": {"1"}, "X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {strconv.FormatInt(now.Add(40*time.Second).Unix(), 10)}}, 40 * time.Second, true},
		{"http-date", 429, http.Header{"Retry-After": {now.Add(10 * time.Second).Format(http.TimeFormat)}}, 10 * time.Second, true},
		{"server", 503, nil, time.Second, true},
		{"forbidden", 403, nil, 0, false},
		{"unauthorized", 401, http.Header{"Retry-After": {"1"}}, 0, false},
		{"long-delay", 403, http.Header{"Retry-After": {"61"}}, 0, false},
		{"long-reset", 403, http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {strconv.FormatInt(now.Add(time.Hour).Unix(), 10)}}, 0, false},
		{"invalid-delay", 429, http.Header{"Retry-After": {"invalid"}}, 0, false},
		{"invalid-reset", 403, http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {"invalid"}}, 0, false},
		{"overflow-delay", 429, http.Header{"Retry-After": {"18446744073709551615"}}, 0, false},
		{"extreme-reset", 403, http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {"9223372036854775807"}}, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			wait, retry := githubMetadataRetry(test.status, test.header, now)
			if wait != test.wait || retry != test.retry {
				t.Fatalf("retry policy = %s, %t; want %s, %t", wait, retry, test.wait, test.retry)
			}
		})
	}
}

func TestGitHubMetadataRetryIntegrationAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name, target string
		cancel       bool
		requests     int
	}{
		{"metadata", fixtureMetadata, false, 2},
		{"bulk", "https://example.com/data", false, 1},
		{"other-api", "https://api.github.com/user", false, 1},
		{"cancel", fixtureMetadata, true, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, err := NewWithGitHubMetadataToken("synthetic_test_token")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			requests, delays := 0, 0
			f.delay = func(ctx context.Context, delay time.Duration) error {
				delays++
				if delay != time.Minute {
					t.Error("declared metadata delay was not honored")
				}
				if test.cancel {
					cancel()
					return ErrFetch
				}
				return nil
			}
			f.client.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
				requests++
				status := 403
				if requests == 2 {
					status = 200
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": {"60"}}, Body: io.NopCloser(strings.NewReader("{}")), ContentLength: 2}, nil
			})
			result, err := f.Fetch(ctx, test.target, filepath.Join(t.TempDir(), "metadata"), 100)
			if requests != test.requests || (err == nil) != (test.requests == 2) || err != nil && err != ErrFetch {
				t.Fatal("metadata retry escaped bounds or returned nonopaque error")
			}
			if test.requests == 2 && (delays != 1 || result.Bytes != 2 || f.budget.Load() != 2560<<20-2) {
				t.Fatal("successful retry changed payload accounting")
			}
		})
	}
}
