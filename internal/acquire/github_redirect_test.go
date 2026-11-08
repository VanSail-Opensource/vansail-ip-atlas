package acquire

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These are synthetic redirect shapes, never real authorization material.
const fixtureRelease = "https://github.com/unit/publisher/releases/download/v1/asset.csv"
const fixtureSignedAsset = "https://release-assets.githubusercontent.com/github-production-release-asset/unit/fixture?sig=synthetic-only&se=1"

func TestGitHubReleaseAssetSignedRedirectContext(t *testing.T) {
	client := New().client
	original, _ := http.NewRequest(http.MethodGet, fixtureRelease, nil)
	target, _ := http.NewRequest(http.MethodGet, fixtureSignedAsset, nil)
	target.Header.Set("Referer", fixtureRelease)
	if err := client.CheckRedirect(target, []*http.Request{original}); err != nil {
		t.Fatal("bounded release-asset redirect rejected")
	}
	if target.Header.Get("Referer") != "" {
		t.Fatal("redirect retained a referrer")
	}
	for _, test := range []struct {
		name, origin, target, method string
		chain                        []string
	}{
		{"untrusted-origin", "https://example.com/asset", fixtureSignedAsset, "GET", nil},
		{"github-raw-path", "https://github.com/unit/publisher/raw/main/asset", fixtureSignedAsset, "GET", nil},
		{"github-latest-alias", "https://github.com/unit/publisher/releases/latest/download/asset", fixtureSignedAsset, "GET", nil},
		{"github-initial-query", fixtureRelease + "?sig=synthetic-only", fixtureSignedAsset, "GET", nil},
		{"github-credentials", "https://user:synthetic-only@github.com/unit/publisher/releases/download/v1/asset.csv", fixtureSignedAsset, "GET", nil},
		{"github-encoded-path", "https://github.com/unit/publisher/releases/download/v1/%61sset.csv", fixtureSignedAsset, "GET", nil},
		{"github-path-traversal", "https://github.com/unit/publisher/releases/download/v1/../asset.csv", fixtureSignedAsset, "GET", nil},
		{"github-non-get", fixtureRelease, fixtureSignedAsset, "HEAD", nil},
		{"other-target", fixtureRelease, "https://example.com/asset?sig=synthetic-only", "GET", nil},
		{"lookalike-target", fixtureRelease, "https://release-assets.githubusercontent.com.example.com/asset?sig=synthetic-only", "GET", nil},
		{"private-target", fixtureRelease, "https://127.0.0.1/asset?sig=synthetic-only", "GET", nil},
		{"http-target", fixtureRelease, "http://release-assets.githubusercontent.com/asset?sig=synthetic-only", "GET", nil},
		{"credential-target", fixtureRelease, "https://user:synthetic-only@release-assets.githubusercontent.com/asset?sig=synthetic-only", "GET", nil},
		{"explicit-target-port", fixtureRelease, "https://release-assets.githubusercontent.com:443/asset?sig=synthetic-only", "GET", nil},
		{"fragment-target", fixtureRelease, fixtureSignedAsset + "#hidden", "GET", nil},
		{"empty-query", fixtureRelease, "https://release-assets.githubusercontent.com/asset?", "GET", nil},
		{"malformed-query", fixtureRelease, "https://release-assets.githubusercontent.com/asset?sig=%zz", "GET", nil},
		{"query-control", fixtureRelease, "https://release-assets.githubusercontent.com/asset?sig=%0d%0a", "GET", nil},
		{"query-invalid-utf8", fixtureRelease, "https://release-assets.githubusercontent.com/asset?sig=%ff", "GET", nil},
		{"query-field-count", fixtureRelease, "https://release-assets.githubusercontent.com/asset?" + queryFields(65), "GET", nil},
		{"oversized-query", fixtureRelease, "https://release-assets.githubusercontent.com/asset?sig=" + strings.Repeat("x", 3073), "GET", nil},
		{"oversized-url", fixtureRelease, "https://release-assets.githubusercontent.com/" + strings.Repeat("a", 4096) + "?sig=x", "GET", nil},
		{"intermediate-origin", fixtureRelease, fixtureSignedAsset, "GET", []string{"https://example.com/relay"}},
		{"redirect-after-signed-query", fixtureRelease, "https://example.com/next", "GET", []string{fixtureSignedAsset}},
		{"another-signed-query", fixtureRelease, fixtureSignedAsset, "GET", []string{fixtureSignedAsset}},
	} {
		t.Run(test.name, func(t *testing.T) {
			original, _ := http.NewRequest(test.method, test.origin, nil)
			target, err := http.NewRequest(http.MethodGet, test.target, nil)
			if err != nil {
				return
			}
			via := []*http.Request{original}
			for _, url := range test.chain {
				r, _ := http.NewRequest(http.MethodGet, url, nil)
				via = append(via, r)
			}
			if client.CheckRedirect(target, via) == nil {
				t.Fatal("untrusted signed-redirect context accepted")
			}
		})
	}
}

func queryFields(count int) string {
	var fields []string
	for i := 0; i < count; i++ {
		fields = append(fields, "k"+strings.Repeat("x", i)+"=x")
	}
	return strings.Join(fields, "&")
}

func TestSignedGitHubRedirectStreamsOnlyPayloadAndOpaqueErrors(t *testing.T) {
	f := New()
	f.attempts = 1
	f.delay = func(context.Context, time.Duration) error { return nil }
	requests := 0
	f.client.Transport = roundTrip(func(req *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{fixtureSignedAsset}}, Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}, nil
		}
		if req.URL.Host != "release-assets.githubusercontent.com" || req.URL.RawQuery == "" || req.Header.Get("Referer") != "" {
			t.Error("redirect context or referrer policy changed")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("payload")), ContentLength: 7}, nil
	})
	directory := t.TempDir()
	destination := filepath.Join(directory, "asset")
	result, err := f.Fetch(context.Background(), fixtureRelease, destination, 100)
	if err != nil || result.Bytes != 7 || requests != 2 {
		t.Fatal("signed download failed")
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != "payload" {
		t.Fatal("download did not retain exactly payload bytes")
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 1 {
		t.Fatal("redirect URI or partial file was retained")
	}
	requests = 0
	if _, err := f.Fetch(context.Background(), fixtureSignedAsset, filepath.Join(directory, "direct"), 100); err != ErrFetch || requests != 0 {
		t.Fatal("signed initial URL accepted")
	}
	f.client.Transport = roundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://example.com/asset?sig=synthetic-only"}}, Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}, nil
	})
	if _, err := f.Fetch(context.Background(), fixtureRelease, filepath.Join(directory, "rejected"), 100); err != ErrFetch {
		t.Fatal("rejected redirect exposed URL or inner error")
	}
	requests = 0
	f.client.Transport = roundTrip(func(req *http.Request) (*http.Response, error) {
		requests++
		location := fixtureSignedAsset
		if requests == 2 {
			location = "https://example.com/next"
		}
		if requests > 2 {
			t.Error("request escaped the signed terminal asset hop")
		}
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{location}}, Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}, nil
	})
	if _, err := f.Fetch(context.Background(), fixtureRelease, filepath.Join(directory, "post-signed"), 100); err != ErrFetch || requests != 2 {
		t.Fatal("post-signature redirect was followed")
	}
}
