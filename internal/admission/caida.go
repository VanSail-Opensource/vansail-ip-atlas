package admission

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

// Discovery is an executable projection of the existing closed catalog object.
// Only the exact serial-2 contract below is supported, not arbitrary HTML URLs.
type Discovery struct {
	Mode              string `yaml:"mode"`
	IndexURL          string `yaml:"index_url"`
	FilenamePattern   string `yaml:"filename_pattern"`
	Ordering          string `yaml:"ordering"`
	RequiresExactFile bool   `yaml:"requires_exact_file"`
	NoGuessing        bool   `yaml:"no_guessing"`
}

const caidaFilenamePattern = `^[0-9]{8}\.as-rel2\.txt\.bz2$`

func caidaSource(s Source) bool {
	d := s.Discovery
	return s.Parser.ID == "caida-relationships" && selectBulkAdapter(s) && s.Format == "text-bz2" && s.URL == "" && d != nil && d.Mode == "latest-timestamped-asset" && d.IndexURL == intelligence.CAIDASerial2Index && d.FilenamePattern == caidaFilenamePattern && d.Ordering == "filename-date-desc-then-url-bytes" && d.RequiresExactFile && d.NoGuessing && s.Publication.Kind == "embedded" && s.Publication.Locator == d.IndexURL && s.Publication.Field == "topology_observation_date"
}

// Apache's observed directory index uses quoted relative hrefs. Selection is
// limited to canonical monthly names; neither its display date nor the filename
// provides the eventual freshness clock. A bad newest body never falls back.
func resolveCAIDASerial2Index(page []byte, now time.Time) (string, error) {
	if len(page) == 0 || len(page) > 1<<20 || !utf8.Valid(page) || now.IsZero() || !bytes.Contains(page, []byte("<html>")) || !bytes.HasSuffix(bytes.TrimSpace(page), []byte("</html>")) {
		return "", errors.New("bounded CAIDA index required")
	}
	links := regexp.MustCompile(`(?i)<a\b[^>]*>`).FindAll(page, 10_001)
	href := regexp.MustCompile(`^<a[\t\r\n ]+href="([^"]*)"[\t\r\n ]*>$`)
	if len(links) > 10_000 || len(regexp.MustCompile(`(?i)<a\b`).FindAllIndex(page, 10_001)) != len(links) {
		return "", errors.New("CAIDA index link budget exceeded")
	}
	var newest time.Time
	var selected string
	seen := map[string]bool{}
	for _, link := range links {
		match := href.FindSubmatch(link)
		if len(match) != 2 {
			return "", errors.New("CAIDA index href outside observed schema")
		}
		name := string(match[1])
		switch name {
		case "?C=N;O=D", "?C=M;O=A", "?C=S;O=A", "?C=D;O=A", "/datasets/as-relationships/", "README.txt", "md5.md5":
			continue
		}
		asset := intelligence.CAIDASerial2Index + name
		month, err := intelligence.CAIDASerial2AssetMonth(asset)
		if err != nil || seen[name] {
			return "", errors.New("CAIDA index asset ambiguous or noncanonical")
		}
		seen[name] = true
		if month.After(newest) {
			newest, selected = month, asset
		}
	}
	if selected == "" || newest.After(now.Add(24*time.Hour)) {
		return "", errors.New("CAIDA current asset unavailable")
	}
	return selected, nil
}

// Every explicit topology date participates in the minimum; a newer BGP header
// cannot renew an older input. Clique/IXP annotations do not create Tier-1 facts.
func parseCAIDASerial2(ctx context.Context, input io.Reader, maximum int, emit func(intelligence.NormalizedRecord) error) (intelligence.CAIDASourceProof, error) {
	var proof intelligence.CAIDASourceProof
	if ctx == nil || input == nil || maximum <= 0 || maximum > 100_000_000 || emit == nil {
		return proof, errors.New("bounded CAIDA reader and sink required")
	}
	r := &io.LimitedReader{R: contextReader{ctx, input}, N: (3 << 30) + 1}
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 4096), 1<<20)
	scan.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if atEOF && len(data) > 0 && bytes.IndexByte(data, '\n') < 0 {
			return 0, nil, errors.New("CAIDA final line incomplete")
		}
		return bufio.ScanLines(data, atEOF)
	})
	seen := map[string]bool{}
	body := false
	for scan.Scan() {
		line := scan.Text()
		if !utf8.ValidString(line) || line == "" || strings.TrimSpace(line) != line {
			return proof, errors.New("CAIDA physical line invalid")
		}
		if strings.HasPrefix(line, "#") {
			if body || len(seen) >= 10_000 || seen[line] {
				return proof, errors.New("CAIDA header duplicate, late or oversized")
			}
			seen[line] = true
			switch {
			case strings.HasPrefix(line, "# source:topology|"):
				parts := strings.Split(line, "|")
				if len(parts) != 5 || parts[1] != "BGP" && parts[1] != "looking-glass" || !identity(parts[3]) || !identity(parts[4]) {
					return proof, errors.New("CAIDA topology header invalid")
				}
				date, err := time.Parse("20060102", parts[2])
				if err != nil || len(parts[2]) != 8 || date.Year() < 1970 {
					return proof, errors.New("CAIDA topology date invalid")
				}
				proof.Headers++
				if parts[1] == "BGP" {
					proof.BGPHeaders++
				}
				if proof.FirstObservedAt.IsZero() || date.Before(proof.FirstObservedAt) {
					proof.FirstObservedAt = date
				}
				if date.After(proof.LastObservedAt) {
					proof.LastObservedAt = date
				}
			case strings.HasPrefix(line, "# input clique: "), strings.HasPrefix(line, "# IXP ASes: "):
				// Publisher inference annotations are retained only in private input.
			default:
				return proof, errors.New("unreviewed CAIDA header")
			}
			continue
		}
		body = true
		proof.Rows++
		values := strings.Split(line, "|")
		if proof.BGPHeaders == 0 || proof.Rows > uint64(maximum) || len(values) != 4 || values[3] != "bgp" && values[3] != "mlp" && values[3] != "bgp,mlp" {
			return proof, errors.New("CAIDA serial-2 row invalid")
		}
		if err := emitRelationship(values, emit); err != nil {
			return proof, err
		}
	}
	if err := scan.Err(); err != nil {
		return proof, err
	}
	if r.N <= 0 || proof.Rows == 0 || ctx.Err() != nil {
		return proof, errors.New("CAIDA input incomplete or oversized")
	}
	return proof, nil
}

func verifyCAIDAFile(ctx context.Context, path string, size int64, s Source, asset string, indexHash, payloadHash [32]byte, now time.Time) (*intelligence.CAIDASourceProof, error) {
	if !caidaSource(s) || size <= 0 || size > s.MaxCompressedBytes {
		return nil, errors.New("CAIDA proof controls invalid")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var proof intelligence.CAIDASourceProof
	limits := acquire.ArchiveLimits{CompressedBytes: s.MaxCompressedBytes, DecodedBytes: 3 << 30, EntryBytes: 3 << 30, Entries: 1, NameBytes: 4096}
	err = acquire.WalkArchive(ctx, acquire.ArchiveInput{Reader: f, ReaderAt: f, Size: size}, "bzip2", limits, func(_ string, reader io.Reader) error {
		var parseErr error
		proof, parseErr = parseCAIDASerial2(ctx, reader, 100_000_000, func(intelligence.NormalizedRecord) error { return nil })
		return parseErr
	})
	if err != nil {
		return nil, err
	}
	proof.Version, proof.AssetURL, proof.IndexSHA256, proof.PayloadSHA256 = 1, asset, indexHash, payloadHash
	if err = proof.Validate(now, proof.FirstObservedAt, payloadHash); err != nil {
		return nil, err
	}
	return &proof, nil
}
