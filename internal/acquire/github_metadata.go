package acquire

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// NewWithGitHubMetadataToken explicitly opts one acquisition run into GitHub
// metadata authentication. The token is transient and applies only to canonical
// commit/release metadata requests, never bulk assets or redirected requests.
// An empty token preserves anonymous operation outside authenticated workflows.
func NewWithGitHubMetadataToken(token string) (*Fetcher, error) {
	if len(token) > 4096 {
		return nil, ErrFetch
	}
	for _, c := range token {
		if c <= 32 || c >= 127 {
			return nil, ErrFetch
		}
	}
	f := New()
	f.githubMetadataToken = token
	return f, nil
}

func githubMetadataURL(raw string) bool {
	if _, ok := ParseGitHubCommitURL(raw); ok {
		return true
	}
	if !validURL(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host != "api.github.com" || u.RawPath != "" || u.RawQuery != "" {
		return false
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 6 && len(parts) != 7 || parts[0] != "" || parts[1] != "repos" || !commitAtom(parts[2]) || !commitAtom(parts[3]) || parts[4] != "releases" {
		return false
	}
	if len(parts) == 7 {
		return parts[5] == "tags" && commitAtom(parts[6])
	}
	if parts[5] == "latest" {
		return true
	}
	if parts[5] == "" || len(parts[5]) > 20 {
		return false
	}
	for _, c := range parts[5] {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, err = strconv.ParseUint(parts[5], 10, 64)
	return err == nil
}

// githubMetadataRetry recognizes rate limits without reading/logging response
// bodies. A declared deadline above the one-minute retry budget fails closed;
// shortening that deadline would retry before GitHub permits another request.
func githubMetadataRetry(status int, header http.Header, now time.Time) (time.Duration, bool) {
	if status != http.StatusForbidden && status != http.StatusTooManyRequests && (status < 500 || status > 599) {
		return 0, false
	}
	wait := time.Second
	rateLimited := false
	if raw := header.Get("Retry-After"); raw != "" {
		rateLimited = true
		var requested time.Duration
		if seconds, err := strconv.ParseUint(raw, 10, 64); err == nil {
			if seconds > 60 {
				return 0, false
			}
			requested = time.Duration(seconds) * time.Second
		} else {
			deadline, err := http.ParseTime(raw)
			if err != nil {
				return 0, false
			}
			requested = deadline.Sub(now)
		}
		if requested > time.Minute {
			return 0, false
		}
		if requested > wait {
			wait = requested
		}
	}
	if header.Get("X-RateLimit-Remaining") == "0" {
		rateLimited = true
		seconds, err := strconv.ParseInt(header.Get("X-RateLimit-Reset"), 10, 64)
		if err != nil || seconds < 0 {
			return 0, false
		}
		// Bound the Unix integer before constructing a Time, including values
		// outside Time's representable internal epoch range.
		if seconds > now.Add(time.Minute).Unix() {
			return 0, false
		}
		deadline := time.Unix(seconds, 0)
		if requested := deadline.Sub(now); requested > wait {
			wait = requested
		}
	}
	if status == http.StatusForbidden && !rateLimited {
		return 0, false
	}
	return wait, true
}
