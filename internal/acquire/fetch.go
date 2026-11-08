// Package acquire downloads approved bulk assets into a private build directory.
// It never accepts subscription hosts or embedded links as fetch targets.
package acquire

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"vansail-ip-atlas/internal/subscription"
)

var ErrFetch = errors.New("bulk asset acquisition failed")

type Result struct {
	SHA256 string
	Bytes  int64
}
type Fetcher struct {
	client   *http.Client
	attempts int
	delay    func(context.Context, time.Duration) error
	slots    chan struct{}
	budget   *atomic.Int64
}

type budgetReader struct {
	reader    io.Reader
	remaining *atomic.Int64
}

func (r budgetReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		left := r.remaining.Load()
		if left <= 0 {
			return 0, ErrFetch
		}
		reserved := int64(len(p))
		if reserved > left {
			reserved = left
		}
		if !r.remaining.CompareAndSwap(left, left-reserved) {
			continue
		}
		n, err := r.reader.Read(p[:int(reserved)])
		if n < 0 || int64(n) > reserved {
			return 0, ErrFetch
		}
		r.remaining.Add(reserved - int64(n))
		return n, err
	}
}

func validURL(raw string) bool {
	if len(raw) > 4096 || strings.ContainsAny(raw, "\x00\t\n\r \\?#") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || strings.Contains(u.Hostname(), "%") || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		return subscription.Public(ip)
	}
	// Hostnames must be ordinary DNS names; legacy numeric host forms cannot bypass address checks.
	labels := strings.Split(u.Hostname(), ".")
	if len(labels) < 2 {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".invalid", ".test", ".example", ".onion"} {
		if strings.HasSuffix(strings.ToLower(u.Hostname()), suffix) {
			return false
		}
	}
	legacyNumeric := true
	for _, label := range labels {
		atom := strings.ToLower(label)
		if strings.HasPrefix(atom, "0x") {
			if _, err := strconv.ParseUint(atom[2:], 16, 32); err != nil {
				legacyNumeric = false
			}
		} else if _, err := strconv.ParseUint(atom, 10, 32); err != nil {
			legacyNumeric = false
		}
	}
	if legacyNumeric {
		return false
	}
	numeric := true
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if c < '0' || c > '9' {
				numeric = false
			}
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return !numeric && len(u.Hostname()) <= 253
}

func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, ErrFetch
	}
	answers, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(answers) == 0 {
		return nil, ErrFetch
	}
	// Reject the entire answer set when any address is private; never check one answer then dial a different DNS result.
	for _, ip := range answers {
		if !subscription.Public(ip) {
			return nil, ErrFetch
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	for _, ip := range answers {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ErrFetch
		}
	}
	return nil, ErrFetch
}

// githubReleaseSource recognizes only an exact, query-free canonical asset URL.
// It does not discover assets, follow embedded payload links or establish rights.
func githubReleaseSource(request *http.Request) bool {
	if request == nil || request.URL == nil || request.Method != http.MethodGet {
		return false
	}
	u := request.URL
	if !validURL(u.String()) || u.Host != "github.com" || u.RawPath != "" || path.Clean(u.Path) != u.Path || strings.Contains(u.Path, "%") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 6 || parts[2] != "releases" || parts[3] != "download" {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 255 {
			return false
		}
		for _, r := range part {
			if r <= 32 || r >= 127 || r == '\\' {
				return false
			}
		}
	}
	return true
}

func githubSignedAsset(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.Host != "release-assets.githubusercontent.com" || u.User != nil || u.Fragment != "" || u.RawPath != "" || len(u.String()) > 4096 || u.RawQuery == "" || len(u.RawQuery) > 3072 {
		return false
	}
	// Validate the ordinary URL without rewriting the signed query. Its exact
	// bytes remain transient request state and never become cache/log metadata.
	base := *u
	base.RawQuery = ""
	base.ForceQuery = false
	if !validURL(base.String()) || base.Path == "" || path.Clean(base.Path) != base.Path {
		return false
	}
	for _, r := range u.RawQuery {
		if r <= 32 || r >= 127 || r == '#' || r == '\\' {
			return false
		}
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(values) == 0 || len(values) > 64 {
		return false
	}
	textSafe := func(value string) bool {
		if !utf8.ValidString(value) {
			return false
		}
		for _, r := range value {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return false
			}
		}
		return true
	}
	for key, entries := range values {
		if key == "" || len(key) > 128 || !textSafe(key) {
			return false
		}
		for _, value := range entries {
			if !textSafe(value) {
				return false
			}
		}
	}
	return true
}

func checkRedirect(request *http.Request, via []*http.Request) error {
	if request == nil || request.URL == nil || len(via) == 0 || len(via) > 3 {
		return ErrFetch
	}
	// Do not forward the source path or an ephemeral asset signature as referrer.
	request.Header.Del("Referer")
	for _, previous := range via {
		if previous == nil || previous.URL == nil || !validURL(previous.URL.String()) {
			return ErrFetch
		}
	}
	if validURL(request.URL.String()) {
		return nil
	}
	// The exception is one terminal hop directly from GitHub's release endpoint.
	// Any further redirect after a query-bearing hop is rejected by the loop
	// above, including a query-free target that could otherwise receive secrets.
	if len(via) == 1 && request.Method == http.MethodGet && githubReleaseSource(via[0]) && githubSignedAsset(request.URL) {
		return nil
	}
	return ErrFetch
}

func New() *Fetcher {
	transport := &http.Transport{Proxy: nil, DialContext: publicDial, DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConns: 3, MaxIdleConnsPerHost: 1, ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: checkRedirect}
	budget := &atomic.Int64{}
	budget.Store(2560 << 20)
	return &Fetcher{client: client, attempts: 2, slots: make(chan struct{}, 3), budget: budget, delay: func(ctx context.Context, d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ErrFetch
		case <-timer.C:
			return nil
		}
	}}
}

// NewBounded creates one run-scoped downloader. Use a 1024 MiB total and one
// worker for the two sequential MRT families; retries consume the same budget.
func NewBounded(totalCompressedBytes int64, workers int) (*Fetcher, error) {
	if totalCompressedBytes <= 0 || totalCompressedBytes > 2560<<20 || workers < 1 || workers > 3 {
		return nil, ErrFetch
	}
	f := New()
	f.budget.Store(totalCompressedBytes)
	f.slots = make(chan struct{}, workers)
	return f, nil
}

// Fetch uses bounded retries, a streaming size limit, private partial files and atomic publication.
// The caller must separately verify the exact payload's publication proof before admitting it.
func (f *Fetcher) Fetch(ctx context.Context, raw, destination string, maxBytes int64) (Result, error) {
	if !validURL(raw) || maxBytes <= 0 || maxBytes > 1024<<20 || f.attempts < 1 || f.attempts > 3 {
		return Result{}, ErrFetch
	}
	if f.slots != nil {
		select {
		case f.slots <- struct{}{}:
			defer func() { <-f.slots }()
		case <-ctx.Done():
			return Result{}, ErrFetch
		}
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return Result{}, ErrFetch
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
		return Result{}, ErrFetch
	}
	for attempt := 0; attempt < f.attempts; attempt++ {
		if ctx.Err() != nil {
			return Result{}, ErrFetch
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return Result{}, ErrFetch
		}
		request.Header.Set("User-Agent", "VanSail-Atlas-BulkBuilder/3")
		response, err := f.client.Do(request)
		if err != nil {
			if attempt+1 < f.attempts && f.delay(ctx, time.Second) == nil {
				continue
			}
			return Result{}, ErrFetch
		}
		if response.StatusCode != http.StatusOK {
			status := response.StatusCode
			retry := time.Second
			if seconds, e := strconv.Atoi(response.Header.Get("Retry-After")); e == nil && seconds > 0 && seconds <= 5 {
				retry = time.Duration(seconds) * time.Second
			}
			response.Body.Close()
			if (status == 429 || status >= 500) && attempt+1 < f.attempts && f.delay(ctx, retry) == nil {
				continue
			}
			return Result{}, ErrFetch
		}
		if response.ContentLength > maxBytes {
			response.Body.Close()
			return Result{}, ErrFetch
		}
		temp, err := os.CreateTemp(filepath.Dir(absolute), ".asset-*.partial")
		if err != nil {
			response.Body.Close()
			return Result{}, ErrFetch
		}
		hash := sha256.New()
		var body io.Reader = response.Body
		if f.budget != nil {
			body = budgetReader{body, f.budget}
		}
		n, copyErr := io.Copy(io.MultiWriter(temp, hash), io.LimitReader(body, maxBytes+1))
		response.Body.Close()
		syncErr := temp.Sync()
		closeErr := temp.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || n > maxBytes || response.ContentLength >= 0 && n != response.ContentLength || ctx.Err() != nil {
			os.Remove(temp.Name())
			return Result{}, ErrFetch
		}
		if err = os.Rename(temp.Name(), absolute); err != nil {
			os.Remove(temp.Name())
			return Result{}, ErrFetch
		}
		return Result{hex.EncodeToString(hash.Sum(nil)), n}, nil
	}
	return Result{}, ErrFetch
}
