package acquire

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AppleRelayURL is the operator's public first-party representation. Redirected
// files cannot supply either the original data or its modification preconditions.
const AppleRelayURL = "https://mask-api.icloud.com/egress-ip-ranges.csv"

// An entity tag is opaque in HTTP. Apple's observed encoding supplies only a
// candidate second to challenge, never a publication clock by itself.
func appleRelayTagCandidate(tag string, size int64) (time.Time, bool) {
	if size <= 0 || size > 32<<20 || len(tag) < 5 || len(tag) > 20 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return time.Time{}, false
	}
	stamp, length, ok := strings.Cut(tag[1:len(tag)-1], "-")
	seconds, err := strconv.ParseUint(stamp, 16, 32)
	if !ok || err != nil || seconds == 0 || strconv.FormatUint(seconds, 16) != stamp || strconv.FormatInt(size, 16) != length {
		return time.Time{}, false
	}
	return time.Unix(int64(seconds), 0).UTC(), true
}

func appleRelayRepresentation(response *http.Response, tag string) bool {
	tags := response.Header.Values("ETag")
	encoding := response.Header.Values("Content-Encoding")
	return len(tags) == 1 && tags[0] == tag && !response.Uncompressed && len(response.Header.Values("Content-Range")) == 0 &&
		(len(encoding) == 0 || len(encoding) == 1 && strings.EqualFold(encoding[0], "identity"))
}

// VerifyAppleRelayClock brackets the representation's modification time to one
// second. Independent date conditions avoid ETag precondition precedence in
// RFC 9110. Each successful response must identify the original strong tag.
// Admission separately verifies the witnessed substantive prefix transition.
func (f *Fetcher) VerifyAppleRelayClock(ctx context.Context, tag string, size int64) (time.Time, error) {
	candidate, ok := appleRelayTagCandidate(tag, size)
	if !ok || f == nil || f.client == nil || ctx == nil || ctx.Err() != nil {
		return time.Time{}, ErrFetch
	}
	if f.slots != nil {
		select {
		case f.slots <- struct{}{}:
			defer func() { <-f.slots }()
		case <-ctx.Done():
			return time.Time{}, ErrFetch
		}
	}
	// The publisher's edge can briefly fail a single condition. Only a complete
	// fresh bracket against the same strong value can establish the clock.
	for attempt := 0; attempt < max(1, min(f.attempts, 2)); attempt++ {
		if attempt > 0 {
			if f.delay == nil || f.delay(ctx, time.Second) != nil {
				return time.Time{}, ErrFetch
			}
		}
		if f.appleRelayBracket(ctx, tag, size, candidate) == nil {
			return candidate, nil
		}
		if ctx.Err() != nil {
			return time.Time{}, ErrFetch
		}
	}
	return time.Time{}, ErrFetch
}

func (f *Fetcher) appleRelayBracket(ctx context.Context, tag string, size int64, candidate time.Time) error {
	conditions := [...]struct {
		header string
		date   time.Time
		status int
	}{
		{"If-Modified-Since", candidate, http.StatusNotModified},
		{"If-Unmodified-Since", candidate.Add(-time.Second), http.StatusPreconditionFailed},
		{"If-Unmodified-Since", candidate, http.StatusOK},
	}
	for _, condition := range conditions {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, AppleRelayURL, nil)
		if err != nil {
			return ErrFetch
		}
		req.Header.Set(condition.header, condition.date.Format(http.TimeFormat))
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("User-Agent", fetchUserAgent)
		response, err := f.client.Do(req)
		if err != nil {
			return ErrFetch
		}
		closeErr := response.Body.Close()
		if closeErr != nil || response.StatusCode != condition.status || ctx.Err() != nil {
			return ErrFetch
		}
		// Apple omits the ETag on 412 and may describe its error response
		// with an unrelated length. A supplied validator must still agree.
		if condition.status == http.StatusPreconditionFailed && len(response.Header.Values("ETag")) == 0 {
			continue
		}
		if !appleRelayRepresentation(response, tag) || condition.status == http.StatusOK && response.ContentLength != size {
			return ErrFetch
		}
	}
	return nil
}
