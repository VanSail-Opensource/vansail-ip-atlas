package admission

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"html"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

type dbipMonthlyPlan struct {
	AssetURL   string
	Published  time.Time
	SHA1       [20]byte
	MD5        [16]byte
	Rows       uint64
	PageSHA256 [32]byte
}

func validDBIPAsset(raw string, month time.Time) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "download.db-ip.com" && u.RawPath == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil && month.Day() == 1 && month.Hour() == 0 && month.Minute() == 0 && month.Second() == 0 && month.Nanosecond() == 0 && raw == "https://download.db-ip.com/free/dbip-city-lite-"+month.UTC().Format("2006-01")+".csv.gz"
}
func resolveDBIPMonthlyPage(data []byte, now time.Time) (dbipMonthlyPlan, error) {
	var result dbipMonthlyPlan
	deny := errors.New("DB-IP monthly CSV publication metadata ambiguous or invalid")
	if len(data) == 0 || len(data) > 4<<20 || !utf8.Valid(data) || now.IsZero() {
		return result, deny
	}
	page := string(data)
	cards := regexp.MustCompile(`(?is)<dl\b[^>]*>(.*?)</dl>`).FindAllStringSubmatchIndex(page, -1)
	pair := regexp.MustCompile(`(?is)<dt\b[^>]*>\s*([^<]+?)\s*</dt>\s*<dd\b[^>]*>(.*?)</dd>`)
	tags := regexp.MustCompile(`(?s)<[^>]*>`)
	link := regexp.MustCompile(`(?is)<a\b[^>]*\bhref\s*=\s*["'](https://download\.db-ip\.com/free/dbip-city-lite-[0-9]{4}-[0-9]{2}\.csv\.gz)["'][^>]*>`)
	matches := 0
	for _, span := range cards {
		values := map[string]string{}
		bad := false
		for _, entry := range pair.FindAllStringSubmatch(page[span[2]:span[3]], -1) {
			key := strings.TrimSpace(html.UnescapeString(entry[1]))
			value := strings.TrimSpace(html.UnescapeString(tags.ReplaceAllString(entry[2], "")))
			if _, exists := values[key]; exists {
				bad = true
			}
			values[key] = value
		}
		if values["Format"] != "CSV" {
			continue
		}
		if bad {
			return result, deny
		}
		links := link.FindAllStringSubmatch(page[span[1]:min(span[1]+2048, len(page))], -1)
		if len(links) != 1 {
			return result, deny
		}
		month, err := time.Parse("January 2006", values["Release"])
		if err != nil || month.After(now.Add(24*time.Hour)) || !validDBIPAsset(links[0][1], month) {
			return result, deny
		}
		sha, err := hex.DecodeString(values["SHA1SUM"])
		if err != nil || len(sha) != 20 || hex.EncodeToString(sha) != values["SHA1SUM"] {
			return result, deny
		}
		md, err := hex.DecodeString(values["MD5SUM"])
		if err != nil || len(md) != 16 || hex.EncodeToString(md) != values["MD5SUM"] {
			return result, deny
		}
		count := values["Number of records"]
		if !regexp.MustCompile(`^[0-9]{1,3}(,[0-9]{3})*$|^[0-9]+$`).MatchString(count) {
			return result, deny
		}
		rows, err := strconv.ParseUint(strings.ReplaceAll(count, ",", ""), 10, 64)
		if err != nil || rows == 0 || rows > 100_000_000 {
			return result, deny
		}
		matches++
		result = dbipMonthlyPlan{AssetURL: links[0][1], Published: month, Rows: rows, PageSHA256: sha256.Sum256(data)}
		copy(result.SHA1[:], sha)
		copy(result.MD5[:], md)
	}
	if matches != 1 {
		return dbipMonthlyPlan{}, deny
	}
	return result, nil
}

type geoDecodedCounter struct {
	bytes, lines int64
	last         byte
}

func (c *geoDecodedCounter) Write(p []byte) (int, error) {
	c.bytes += int64(len(p))
	c.lines += int64(bytes.Count(p, []byte{'\n'}))
	if len(p) > 0 {
		c.last = p[len(p)-1]
	}
	return len(p), nil
}
func verifyDBIPGzip(ctx context.Context, file *os.File, size int64, source Source, plan dbipMonthlyPlan) (*intelligence.GeoSourceProof, error) {
	sha256Hash, sha1Hash, md5Hash := sha256.New(), sha1.New(), md5.New()
	counter := &geoDecodedCounter{}
	err := acquire.WalkArchive(ctx, acquire.ArchiveInput{Reader: file, ReaderAt: file, Size: size}, "gzip", acquire.ArchiveLimits{CompressedBytes: source.MaxCompressedBytes, DecodedBytes: 3 << 30, EntryBytes: 3 << 30, Entries: 1, NameBytes: 4096}, func(_ string, input io.Reader) error {
		_, err := io.Copy(io.MultiWriter(sha256Hash, sha1Hash, md5Hash, counter), input)
		return err
	})
	if err != nil {
		return nil, err
	}
	lines := counter.lines
	if counter.bytes > 0 && counter.last != '\n' {
		lines++
	}
	if counter.bytes == 0 || uint64(lines) != plan.Rows || !bytes.Equal(sha1Hash.Sum(nil), plan.SHA1[:]) || !bytes.Equal(md5Hash.Sum(nil), plan.MD5[:]) {
		return nil, errors.New("DB-IP decoded payload does not match publisher checksums/count")
	}
	proof := &intelligence.GeoSourceProof{Version: 1, AssetURL: plan.AssetURL, DecodedBytes: counter.bytes, UpstreamClock: plan.Published, PageSHA256: plan.PageSHA256}
	copy(proof.DecodedSHA256[:], sha256Hash.Sum(nil))
	return proof, nil
}
