package acquire

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type countedGroupBody struct {
	io.Reader
	bytes *atomic.Int64
}

func (b countedGroupBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.bytes.Add(int64(n))
	return n, err
}
func (countedGroupBody) Close() error { return nil }

func TestScopedDownloadBudgetIncludesOversizeFailuresAndOriginalRun(t *testing.T) {
	parent, err := NewBounded(100, 1)
	if err != nil {
		t.Fatal(err)
	}
	var received atomic.Int64
	parent.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: countedGroupBody{strings.NewReader("payload"), &received}, Header: make(http.Header), ContentLength: -1}, nil
	})
	group, err := parent.WithByteBudget(10)
	if err != nil || group.client != parent.client || group.slots != parent.slots || group.budget != parent.budget {
		t.Fatal("group replaced transport, concurrency or original run ceiling", err)
	}
	root := t.TempDir()
	if _, err = group.Fetch(context.Background(), "https://example.com/first", filepath.Join(root, "first"), 6); err != ErrFetch {
		t.Fatal("oversize body succeeded", err)
	}
	if received.Load() != 7 || group.secondaryBudget.Load() != 3 {
		t.Fatal("oversize probe was omitted from shared byte accounting")
	}
	if _, err = group.Fetch(context.Background(), "https://example.com/second", filepath.Join(root, "second"), 100); err != ErrFetch || received.Load() != 10 || parent.budget.Load() != 90 {
		t.Fatal("failed transfer reset or overran group/global byte ceiling", err, received.Load())
	}
	if _, err = group.WithByteBudget(10); err != ErrFetch {
		t.Fatal("re-scoping reset an exhausted acquisition budget")
	}
}

func TestScopedKnownBodiesMayExactlyConsumeTheirGroupCeiling(t *testing.T) {
	parent, err := NewBounded(100, 1)
	if err != nil {
		t.Fatal(err)
	}
	parent.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("data")), Header: make(http.Header), ContentLength: 4}, nil
	})
	group, err := parent.WithByteBudget(8)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, name := range []string{"first", "second"} {
		if _, err = group.Fetch(context.Background(), "https://example.com/"+name, filepath.Join(root, name), 100); err != nil {
			t.Fatal("exactly framed body could not consume the last allowed bytes", err)
		}
	}
	if group.secondaryBudget.Load() != 0 || parent.budget.Load() != 92 {
		t.Fatal("known body byte accounting differs")
	}
}

func TestScopedHeaderOnlyFailureKeepsColdFallbackBodyBudget(t *testing.T) {
	parent, err := NewBounded(100, 1)
	if err != nil {
		t.Fatal(err)
	}
	parent.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("missing")), Header: make(http.Header), ContentLength: 7}, nil
	})
	group, err := parent.WithByteBudget(20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = group.Fetch(context.Background(), "https://example.com/missing", filepath.Join(t.TempDir(), "payload"), 20); !errors.Is(err, ErrFetch) || !errors.Is(err, ErrNotFound) {
		t.Fatal("missing archive accepted", err)
	}
	if remaining, valid := group.GroupBytesRemaining(); !valid || remaining != 20 || parent.budget.Load() != 100 {
		t.Fatal("header-only failure consumed a body budget", remaining)
	}
}

func TestOnlyHTTP404IsAnArchiveNotFoundSignal(t *testing.T) {
	for _, status := range []int{401, 403, 404, 410, 429, 500, 503} {
		f := New()
		f.attempts = 1
		f.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("private upstream detail")), Header: make(http.Header), ContentLength: 23}, nil
		})
		_, err := f.Fetch(context.Background(), "https://example.com/archive", filepath.Join(t.TempDir(), "asset"), 100)
		if !errors.Is(err, ErrFetch) || errors.Is(err, ErrNotFound) != (status == 404) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "https://") {
			t.Fatal("archive status was misclassified or exposed upstream detail", status, err)
		}
	}
}
