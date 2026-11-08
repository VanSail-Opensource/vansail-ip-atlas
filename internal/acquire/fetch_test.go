package acquire

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type heldBody struct {
	release <-chan struct{}
	reader  *strings.Reader
	active  *atomic.Int32
}

func (b *heldBody) Read(p []byte) (int, error) { <-b.release; return b.reader.Read(p) }
func (b *heldBody) Close() error               { b.active.Add(-1); return nil }

func TestGlobalDownloadConcurrencyBound(t *testing.T) {
	f := New()
	release := make(chan struct{})
	entered := make(chan struct{}, 12)
	var active, peak atomic.Int32
	f.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		n := active.Add(1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		return &http.Response{StatusCode: 200, Body: &heldBody{release, strings.NewReader("payload"), &active}, Header: make(http.Header), ContentLength: 7}, nil
	})
	var group sync.WaitGroup
	destination := t.TempDir()
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			if _, err := f.Fetch(context.Background(), "https://example.com/data", filepath.Join(destination, strconv.Itoa(i)), 10); err != nil {
				t.Error(err)
			}
		}(i)
	}
	for i := 0; i < 3; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatal("bounded workers did not start")
		}
	}
	close(release)
	group.Wait()
	if peak.Load() != 3 {
		t.Fatalf("concurrent downloads %d, expected 3", peak.Load())
	}
}

func TestTotalRunBudgetIsNotResetForAnotherAsset(t *testing.T) {
	f, err := NewBounded(10, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("payload")), Header: make(http.Header), ContentLength: 7}, nil
	})
	directory := t.TempDir()
	if _, err = f.Fetch(context.Background(), "https://example.com/first", filepath.Join(directory, "first"), 100); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Fetch(context.Background(), "https://example.com/second", filepath.Join(directory, "second"), 100); err != ErrFetch {
		t.Fatal("run budget reset")
	}
	if _, err = os.Stat(filepath.Join(directory, "second")); !os.IsNotExist(err) {
		t.Fatal("budget failure left published partial")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fake(body string, status int, requests *int) *Fetcher {
	return &Fetcher{client: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		*requests++
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), ContentLength: -1}, nil
	})}, attempts: 2, delay: func(context.Context, time.Duration) error { return nil }}
}

func TestRejectUnsafeInitialAndRedirectTargets(t *testing.T) {
	for _, raw := range []string{"http://example.com/a", "https://127.0.0.1/a", "https://[::1]/a", "https://169.254.169.254/a", "https://10.0.0.1/a", "https://example.com/a?secret=x", "https://user:pass@example.com/a", "https://example.com/\na", "https://2130706433/a", "https://example.com:80/a"} {
		if validURL(raw) {
			t.Fatalf("unsafe URL accepted")
		}
	}
	client := New().client
	req, _ := http.NewRequest("GET", "https://127.0.0.1/a", nil)
	if client.CheckRedirect(req, []*http.Request{{}}) == nil {
		t.Fatal("private redirect accepted")
	}
	req, _ = http.NewRequest("GET", "https://example.com/a", nil)
	if client.CheckRedirect(req, make([]*http.Request, 4)) == nil {
		t.Fatal("unbounded redirects")
	}
}

func TestStreamingLimitAtomicityAndNo304Freshness(t *testing.T) {
	temp := t.TempDir()
	dest := filepath.Join(temp, "asset")
	os.WriteFile(dest, []byte("last-good"), 0600)
	count := 0
	f := fake(strings.Repeat("x", 20), 200, &count)
	if _, err := f.Fetch(context.Background(), "https://example.com/data", dest, 10); err != ErrFetch {
		t.Fatal("size limit")
	}
	bytes, _ := os.ReadFile(dest)
	if string(bytes) != "last-good" {
		t.Fatal("failed download replaced cache")
	}
	entries, _ := os.ReadDir(temp)
	if len(entries) != 1 {
		t.Fatal("partial file remained")
	}
	f = fake("", 304, &count)
	if _, err := f.Fetch(context.Background(), "https://example.com/data", dest, 10); err != ErrFetch {
		t.Fatal("304 treated as new payload")
	}
	fresh := filepath.Join(temp, "fresh")
	f = fake("payload", 200, &count)
	result, err := f.Fetch(context.Background(), "https://example.com/data", fresh, 10)
	if err != nil || result.Bytes != 7 || len(result.SHA256) != 64 {
		t.Fatalf("stream result %+v %v", result, err)
	}
}

func TestBoundedRetriesAndCancellation(t *testing.T) {
	count := 0
	f := fake("", 429, &count)
	if _, err := f.Fetch(context.Background(), "https://example.com/data", filepath.Join(t.TempDir(), "asset"), 10); err != ErrFetch || count != 2 {
		t.Fatal("retry bound")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	count = 0
	if _, err := f.Fetch(ctx, "https://example.com/data", filepath.Join(t.TempDir(), "asset"), 10); err != ErrFetch || count != 0 {
		t.Fatal("cancellation ignored")
	}
	f.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("private opaque failure") })
	if _, err := f.Fetch(context.Background(), "https://example.com/data", filepath.Join(t.TempDir(), "asset"), 10); err != ErrFetch {
		t.Fatal("unsafe error output")
	}
}
