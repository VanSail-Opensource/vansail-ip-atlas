package admission

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

const (
	tweetFeedCSV       = "https://tweetfeed.live/feeds/week.csv"
	tweetFeedManifest  = "https://api.tweetfeed.live/v1/manifest"
	tweetFeedOrigin    = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv"
	tweetFeedByteLimit = 8 << 20
	tweetFeedRowLimit  = 100_000
)

func tweetFeedSource(s Source) bool {
	return s.ID == "tweetfeed-week" && s.Parser.ID == "tweetfeed-week-csv" &&
		s.Parser.Schema == "tweetfeed-six-column-ioc-v1" && s.Parser.Version == 1 &&
		s.Family == "ffraud-original" && s.Format == "csv" && s.URL == tweetFeedCSV &&
		s.Publication == (Publication{"snapshot_metadata", tweetFeedManifest, "artifacts.week.csv.updated_at"}) &&
		fieldsEqual(s.Fields, "date", "user", "type", "value", "tags", "tweet_url") &&
		fieldsEqual(s.Signals, "fraud") && mappedFields(s, map[string]string{"value": "reason_flags", "tags": "reason_flags"})
}

// Each row reports one indicator. Discard all other indicator types without
// interpreting their values, including URLs that happen to have an IP host.
// Reporters, free-form tags and post references never enter normalized data.
func scanTweetFeed(ctx context.Context, input io.Reader, published time.Time, maximum int, emit func(intelligence.NormalizedRecord) error) (int, error) {
	limited := &io.LimitedReader{R: contextReader{ctx, input}, N: tweetFeedByteLimit + 1}
	reader := bufio.NewReaderSize(limited, 32<<10)
	rows, accepted := 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return rows, err
		}
		line, err := reader.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil || limited.N <= 0 || len(line) <= 1 || !utf8.Valid(line) {
			return rows, errors.New("weekly IOC feed framing invalid")
		}
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte{'\n'}), []byte{'\r'})
		if bytes.ContainsAny(line, "\x00\r\t") {
			return rows, errors.New("weekly IOC feed encoding invalid")
		}
		c := csv.NewReader(bytes.NewReader(line))
		c.FieldsPerRecord = 6
		fields, err := c.Read()
		if err != nil || fields[1] == "" || fields[3] == "" || fields[5] == "" {
			return rows, errors.New("weekly IOC feed row invalid")
		}
		rows++
		if rows > min(maximum, tweetFeedRowLimit) {
			return rows, errors.New("weekly IOC feed input row limit exceeded")
		}
		observed, err := time.Parse(time.DateTime, fields[0])
		if err != nil || len(fields[0]) != len(time.DateTime) || observed.Year() < 1970 || observed.After(published) {
			return rows, errors.New("weekly IOC observation timestamp invalid")
		}
		switch fields[2] {
		case "url", "domain", "sha256", "md5":
			continue
		case "ip":
		default:
			return rows, errors.New("weekly IOC indicator type changed")
		}
		ip, err := netip.ParseAddr(fields[3])
		if err != nil || ip.Zone() != "" {
			return rows, errors.New("weekly IOC IP literal invalid")
		}
		ip = ip.Unmap()
		if !subscription.Public(ip) {
			continue
		}
		reported := false
		for tag := range strings.FieldsSeq(fields[4]) {
			if strings.EqualFold(tag, "#phishing") {
				reported = true
				break
			}
		}
		if !reported {
			continue
		}
		accepted++
		if emit != nil {
			value := intelligence.Evidence{Address: ip, Signal: "fraud", Family: "ffraud-original", Scope: intelligence.Exact, SourcePublishedAt: published, ItemPublishedAt: observed, Current: true}
			if err = emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &value}); err != nil {
				return rows, err
			}
		}
	}
	if rows == 0 || accepted == 0 {
		return rows, errors.New("weekly IOC feed contains no qualifying reports")
	}
	return rows, nil
}

type tweetFeedArtifact struct {
	published time.Time
	digest    [32]byte
	size      int64
	rows      int
}

func readTweetFeedManifest(ctx context.Context, manifestPath string, now time.Time) (tweetFeedArtifact, error) {
	deny := errors.New("weekly IOC feed manifest rejected")
	var proof tweetFeedArtifact
	data, err := boundedFile(ctx, manifestPath, 1<<20)
	if err != nil || uniqueJSON(data) != nil || now.IsZero() {
		return proof, deny
	}
	var manifest struct {
		Version   int    `json:"schema_version"`
		Generated string `json:"generated_at"`
		Artifacts []struct {
			Name, Path, Format, Window, SHA256, URL string
			Bytes                                   int64
			Rows                                    int
			Updated                                 string `json:"updated_at"`
		} `json:"artifacts"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.Version != 1 {
		return proof, deny
	}
	generated, err := timestamp(manifest.Generated)
	if err != nil || generated.After(now.Add(24*time.Hour)) {
		return proof, deny
	}
	for _, a := range manifest.Artifacts {
		if a.Path != "week.csv" && a.Name != "week.csv" {
			continue
		}
		if proof.rows != 0 || a.Path != "week.csv" || a.Name != "week.csv" || a.Format != "csv" || a.Window != "week" || a.Rows <= 0 || a.Rows > tweetFeedRowLimit || a.Bytes <= 0 || a.Bytes > tweetFeedByteLimit || a.URL != tweetFeedOrigin {
			return tweetFeedArtifact{}, deny
		}
		checksum, err := decodeHash(a.SHA256)
		if err != nil || a.SHA256 != hashString(checksum) || checksum == ([32]byte{}) {
			return tweetFeedArtifact{}, deny
		}
		updated, err := timestamp(a.Updated)
		if err != nil || updated.After(generated) {
			return tweetFeedArtifact{}, deny
		}
		proof = tweetFeedArtifact{published: updated, digest: checksum, size: a.Bytes, rows: a.Rows}
	}
	if proof.rows == 0 {
		return proof, deny
	}
	return proof, nil
}

var errTweetFeedEdition = errors.New("weekly IOC feed bytes differ from publisher edition")

func (proof tweetFeedArtifact) verify(ctx context.Context, payloadPath string) error {
	checksum, size, err := hashFile(ctx, payloadPath, tweetFeedByteLimit)
	if err != nil {
		return err
	}
	if proof.size != size || proof.digest != checksum {
		return errTweetFeedEdition
	}
	file, err := os.Open(payloadPath)
	if err != nil {
		return err
	}
	rows, err := scanTweetFeed(ctx, file, proof.published, tweetFeedRowLimit, nil)
	if closeErr := file.Close(); closeErr != nil || err != nil || rows != proof.rows {
		return errors.New("weekly IOC feed records differ from publisher manifest")
	}
	return nil
}

// The publisher's static CDN may still serve the previous edition. Determine
// freshness only from the official manifest, then allow one retrieval of the
// exact week.csv origin it explicitly names. No repository discovery or links
// inside a CSV record control a request.
func (e *Engine) fetchTweetFeed(ctx context.Context, payload string, s Source, now time.Time) (time.Time, error) {
	metadata := filepath.Join(filepath.Dir(payload), "publication")
	if _, err := e.fetch.Fetch(ctx, tweetFeedManifest, metadata, 1<<20); err != nil {
		return time.Time{}, err
	}
	proof, err := readTweetFeedManifest(ctx, metadata, now)
	if err != nil {
		return time.Time{}, err
	}
	if !now.Before(proof.published.Add(s.MaxAge)) {
		return time.Time{}, errors.New("weekly IOC publisher edition expired")
	}
	_, err = e.fetch.Fetch(ctx, tweetFeedCSV, payload, min(s.MaxCompressedBytes, int64(tweetFeedByteLimit)))
	if err == nil {
		err = proof.verify(ctx, payload)
		if !errors.Is(err, errTweetFeedEdition) {
			return proof.published, err
		}
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	alternate := filepath.Join(filepath.Dir(payload), "current-week")
	if _, err = e.fetch.Fetch(ctx, tweetFeedOrigin, alternate, min(s.MaxCompressedBytes, proof.size)); err != nil {
		return time.Time{}, err
	}
	if err = proof.verify(ctx, alternate); err != nil {
		return time.Time{}, err
	}
	if err = os.Rename(alternate, payload); err != nil {
		return time.Time{}, err
	}
	return proof.published, nil
}
