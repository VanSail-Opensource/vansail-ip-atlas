package admission

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"vansail-ip-atlas/internal/subscription"
)

func safeHTTPS(raw string) bool {
	if len(raw) == 0 || len(raw) > 4096 || strings.ContainsAny(raw, "\\?#") {
		return false
	}
	for _, r := range raw {
		if r <= 32 || r >= 127 {
			return false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Port() != "" && u.Port() != "443" || strings.Contains(u.Hostname(), "%") || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		return subscription.Public(ip)
	}
	host := strings.ToLower(u.Hostname())
	labels := strings.Split(host, ".")
	if len(labels) < 2 || len(host) > 253 || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	alphaTLD := false
	for _, r := range labels[len(labels)-1] {
		alphaTLD = alphaTLD || r >= 'a' && r <= 'z'
	}
	if !alphaTLD {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validReleaseLocator(locator, assetURL string) bool {
	if !safeHTTPS(locator) || !safeHTTPS(assetURL) {
		return false
	}
	metadata, _ := url.Parse(locator)
	asset, _ := url.Parse(assetURL)
	if metadata.Host != "api.github.com" || asset.Host != "github.com" || metadata.RawPath != "" || asset.RawPath != "" || path.Clean(metadata.Path) != metadata.Path || path.Clean(asset.Path) != asset.Path {
		return false
	}
	mp, ap := strings.Split(strings.TrimPrefix(metadata.Path, "/"), "/"), strings.Split(strings.TrimPrefix(asset.Path, "/"), "/")
	if len(mp) < 5 || mp[0] != "repos" || mp[3] != "releases" || len(ap) != 6 || ap[2] != "releases" || ap[3] != "download" || mp[1] != ap[0] || mp[2] != ap[1] || ap[4] == "" || ap[5] == "" {
		return false
	}
	// Exactly one GitHub release selector. No API query/recursive URL discovery.
	if len(mp) == 5 {
		if mp[4] == "latest" {
			return true
		}
		for _, r := range mp[4] {
			if r < '0' || r > '9' {
				return false
			}
		}
		return mp[4] != ""
	}
	return len(mp) == 6 && mp[4] == "tags" && mp[5] != ""
}

type releaseMetadata struct {
	PublishedAt string         `json:"published_at"`
	Draft       bool           `json:"draft"`
	Assets      []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	URL       string `json:"browser_download_url"`
	Digest    string `json:"digest"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
	Size      int64  `json:"size"`
}

func verifyReleaseFile(ctx context.Context, metadataPath, assetURL string, digest [32]byte, size int64, now time.Time) (time.Time, error) {
	data, err := boundedFile(ctx, metadataPath, 4<<20)
	if err != nil {
		return time.Time{}, err
	}
	return verifyRelease(data, assetURL, digest, size, now)
}

func verifyRelease(data []byte, assetURL string, digest [32]byte, size int64, now time.Time) (time.Time, error) {
	deny := errors.New("publication proof rejected")
	if len(data) > 4<<20 || now.IsZero() || size <= 0 || digest == ([32]byte{}) || uniqueJSON(data) != nil {
		return time.Time{}, deny
	}
	var metadata releaseMetadata
	// Additional fields are normal GitHub metadata, but structural duplicate keys
	// were rejected above. Only this explicit typed projection establishes proof.
	if json.Unmarshal(data, &metadata) != nil || metadata.Draft || len(metadata.Assets) == 0 || len(metadata.Assets) > 10000 {
		return time.Time{}, deny
	}
	published, err := timestamp(metadata.PublishedAt)
	if err != nil || published.After(now.Add(24*time.Hour)) {
		return time.Time{}, deny
	}
	matched := false
	for _, asset := range metadata.Assets {
		if asset.URL != assetURL {
			continue
		}
		if matched || asset.State != "uploaded" || asset.Size != size || !strings.HasPrefix(asset.Digest, "sha256:") {
			return time.Time{}, deny
		}
		expected, err := decodeHash(strings.TrimPrefix(asset.Digest, "sha256:"))
		if err != nil || subtle.ConstantTimeCompare(expected[:], digest[:]) != 1 {
			return time.Time{}, deny
		}
		created, err := timestamp(asset.CreatedAt)
		if err != nil || created.After(now.Add(24*time.Hour)) {
			return time.Time{}, deny
		}
		// Republishing a release cannot freshen an older uploaded asset. This
		// conservative clock is bounded by both release and exact-asset creation.
		if created.Before(published) {
			published = created
		}
		matched = true
	}
	if !matched {
		return time.Time{}, deny
	}
	return published, nil
}

func timestamp(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("explicit UTC publication required")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.Year() < 1970 {
		return time.Time{}, errors.New("publication timestamp invalid")
	}
	return parsed.UTC(), nil
}

// Keep SHA formatting explicit rather than relying on runtime struct layouts.
func hashString(digest [32]byte) string { return hex.EncodeToString(digest[:]) }
