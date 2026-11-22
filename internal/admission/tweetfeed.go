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
	"strings"
	"time"
	"unicode/utf8"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

const (
	tweetFeedCSV       = "https://tweetfeed.live/feeds/week.csv"
	tweetFeedManifest  = "https://api.tweetfeed.live/v1/manifest"
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

func verifyTweetFeedFile(ctx context.Context, manifestPath, payloadPath string, digest [32]byte, size int64, now time.Time) (time.Time, error) {
	deny := errors.New("weekly IOC feed publication proof rejected")
	data, err := boundedFile(ctx, manifestPath, 1<<20)
	if err != nil || uniqueJSON(data) != nil || size <= 0 || size > tweetFeedByteLimit {
		return time.Time{}, deny
	}
	var manifest struct {
		Version   int    `json:"schema_version"`
		Generated string `json:"generated_at"`
		Artifacts []struct {
			Name, Path, Format, Window, SHA256 string
			Bytes                              int64
			Rows                               int
			Updated                            string `json:"updated_at"`
		} `json:"artifacts"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.Version != 1 {
		return time.Time{}, deny
	}
	generated, err := timestamp(manifest.Generated)
	if err != nil || generated.After(now.Add(24*time.Hour)) {
		return time.Time{}, deny
	}
	var published time.Time
	expectedRows := 0
	for _, a := range manifest.Artifacts {
		if a.Path != "week.csv" && a.Name != "week.csv" {
			continue
		}
		if expectedRows != 0 || a.Path != "week.csv" || a.Name != "week.csv" || a.Format != "csv" || a.Window != "week" || a.Rows <= 0 || a.Rows > tweetFeedRowLimit || a.Bytes != size || a.SHA256 != hashString(digest) {
			return time.Time{}, deny
		}
		published, err = timestamp(a.Updated)
		if err != nil || published.After(generated) {
			return time.Time{}, deny
		}
		expectedRows = a.Rows
	}
	if expectedRows == 0 {
		return time.Time{}, deny
	}
	file, err := os.Open(payloadPath)
	if err != nil {
		return time.Time{}, deny
	}
	rows, err := scanTweetFeed(ctx, file, published, tweetFeedRowLimit, nil)
	if closeErr := file.Close(); closeErr != nil || err != nil || rows != expectedRows {
		return time.Time{}, deny
	}
	return published, nil
}
