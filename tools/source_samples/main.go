package main

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigPath = "configs/sources.yaml"
	defaultOutputRoot = "fixtures/source-samples"
	maxTransferBytes  = 4 << 20
	maxSampleBytes    = 8 << 10
	maxBinaryBytes    = 4 << 10
	requestTimeout    = 45 * time.Second
)

type catalog struct {
	Build struct {
		Download struct {
			UserAgent string `yaml:"user_agent"`
		} `yaml:"download"`
	} `yaml:"build"`
	Sources []source `yaml:"sources"`
}

type source struct {
	ID               string           `yaml:"id"`
	EvidenceFamily   string           `yaml:"evidence_family"`
	SourceGroup      string           `yaml:"source_group"`
	Category         string           `yaml:"category"`
	Admission        string           `yaml:"admission"`
	Repository       string           `yaml:"repository"`
	Download         download         `yaml:"download"`
	Discovery        discovery        `yaml:"discovery"`
	Fields           []string         `yaml:"fields"`
	Scope            string           `yaml:"scope"`
	Notes            string           `yaml:"notes"`
	PublicationProof publicationProof `yaml:"publication_proof"`
	Coverage         coverage         `yaml:"coverage"`
	Fixture          fixture          `yaml:"fixture"`
}

type download struct {
	URL              string `yaml:"url"`
	Format           string `yaml:"format"`
	MaxCompressedMiB int    `yaml:"max_compressed_mib"`
}

type discovery struct {
	Mode              string `yaml:"mode"`
	RequiresExactFile bool   `yaml:"requires_exact_file"`
	Hint              string `yaml:"-"`
}

func (d *discovery) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		d.Hint = node.Value
		return nil
	}
	type plain discovery
	return node.Decode((*plain)(d))
}

type publicationProof struct {
	Kind string `yaml:"kind"`
}

type coverage struct {
	Kind  string `yaml:"kind"`
	Scope string `yaml:"scope"`
}

type fixture struct {
	Status         string `yaml:"status"`
	SchemaObserved bool   `yaml:"schema_observed"`
}

type manifest struct {
	SchemaVersion       int            `json:"schema_version"`
	Purpose             string         `json:"purpose"`
	PublicOutputAllowed bool           `json:"public_output_allowed"`
	GeneratedAt         string         `json:"generated_at"`
	SourceCatalogSHA256 string         `json:"source_catalog_sha256"`
	Summary             manifestStats  `json:"summary"`
	Sources             []sourceRecord `json:"sources"`
}

type manifestStats struct {
	Total              int            `json:"total"`
	Captured           int            `json:"captured"`
	CapturedSanitized  int            `json:"captured_sanitized"`
	FormatOnlyNoURL    int            `json:"format_only_no_url"`
	RetiredNotCaptured int            `json:"retired_not_captured"`
	FetchFailed        int            `json:"fetch_failed"`
	Blocked            int            `json:"blocked"`
	ByDeclaredFormat   map[string]int `json:"by_declared_format"`
}

type sourceRecord struct {
	ID                       string   `json:"id"`
	Category                 string   `json:"category"`
	Admission                string   `json:"admission"`
	EvidenceFamily           string   `json:"evidence_family"`
	SourceGroup              string   `json:"source_group"`
	DeclaredFormat           string   `json:"declared_format"`
	FormatFamily             string   `json:"format_family"`
	DeclaredFields           []string `json:"declared_fields"`
	Scope                    string   `json:"scope"`
	Coverage                 string   `json:"coverage"`
	PublicationProof         string   `json:"publication_proof"`
	ExistingFixtureStatus    string   `json:"existing_fixture_status"`
	Status                   string   `json:"status"`
	CapturedAt               string   `json:"captured_at,omitempty"`
	CaptureTimeBasis         string   `json:"capture_time_basis,omitempty"`
	LastCaptureError         string   `json:"last_capture_error,omitempty"`
	SampleURL                string   `json:"sample_url,omitempty"`
	SampleFormat             string   `json:"sample_format,omitempty"`
	DiscoveryEvidence        string   `json:"discovery_evidence,omitempty"`
	DiscoveryNote            string   `json:"discovery_note,omitempty"`
	SamplePath               string   `json:"sample_path,omitempty"`
	SampleBytes              int      `json:"sample_bytes,omitempty"`
	SampleSHA256             string   `json:"sample_sha256,omitempty"`
	ObservedKind             string   `json:"observed_kind,omitempty"`
	ArchiveEntry             string   `json:"archive_entry,omitempty"`
	HTTPStatus               int      `json:"http_status,omitempty"`
	ContentType              string   `json:"content_type,omitempty"`
	ContentEncoding          string   `json:"content_encoding,omitempty"`
	RemoteContentLength      int64    `json:"remote_content_length,omitempty"`
	TransferBytes            int      `json:"transfer_bytes,omitempty"`
	Truncated                bool     `json:"truncated,omitempty"`
	Redactions               []string `json:"redactions,omitempty"`
	FormatNotes              []string `json:"format_notes,omitempty"`
	Blocker                  string   `json:"blocker,omitempty"`
	FormatOnlyRecord         string   `json:"format_only_record,omitempty"`
	ExplicitlyNotFixtureTest bool     `json:"explicitly_not_fixture_tested"`
}

type capturer struct {
	client    *http.Client
	userAgent string
}

type rawResponse struct {
	body          []byte
	status        int
	contentType   string
	contentLength int64
	truncated     bool
}

type sampleResult struct {
	data         []byte
	observedKind string
	archiveEntry string
	redactions   []string
	formatNotes  []string
	wasSanitized bool
	binary       bool
}

func main() {
	configPath := flag.String("config", defaultConfigPath, "source catalog path")
	outputRoot := flag.String("out", defaultOutputRoot, "sample output directory")
	discoveryPath := flag.String("discovery", "fixtures/source-samples/discovery.json", "build-private sample discovery inventory (empty disables)")
	missingOnly := flag.Bool("missing-only", false, "retain hash-verified existing captures and fill missing records")
	only := flag.String("only", "", "comma-separated source IDs; requires -missing-only")
	publicDNS := flag.Bool("public-dns", false, "resolve download hosts through HTTPS to 1.1.1.1 (never subscription hosts)")
	flag.Parse()

	catalogBytes, err := os.ReadFile(*configPath)
	must(err)
	var cfg catalog
	must(yaml.Unmarshal(catalogBytes, &cfg))
	must(os.MkdirAll(filepath.Join(*outputRoot, "samples"), 0o755))
	must(os.MkdirAll(filepath.Join(*outputRoot, "format-only"), 0o755))
	overrides, err := loadDiscoveries(*discoveryPath, cfg.Sources)
	must(err)
	previous, err := loadPrevious(*outputRoot, *missingOnly)
	must(err)
	if *missingOnly {
		data, err := os.ReadFile(filepath.Join(*outputRoot, "manifest.json"))
		must(err)
		var prior manifest
		must(json.Unmarshal(data, &prior))
		if prior.SourceCatalogSHA256 != hashBytes(catalogBytes) {
			must(errors.New("catalog changed; regenerate rather than retaining previous source metadata"))
		}
	}
	if *only != "" && !*missingOnly {
		must(errors.New("-only requires -missing-only"))
	}
	selected := strings.Split(*only, ",")
	if *only != "" {
		for _, id := range selected {
			found := false
			for _, src := range cfg.Sources {
				if src.ID == id {
					found = true
					break
				}
			}
			if !found {
				must(fmt.Errorf("unknown selected source %q", id))
			}
		}
	}

	c := &capturer{
		client:    newHTTPClientWithDNS(*publicDNS),
		userAgent: cfg.Build.Download.UserAgent,
	}
	if c.userAgent == "" {
		c.userAgent = "IPDB-BulkBuilder/0.1 format-sample-capture"
	}

	records := make([]sourceRecord, 0, len(cfg.Sources))
	for i, src := range cfg.Sources {
		rec := baseRecord(src)
		old, exists := previous[src.ID]
		if exists && (*only != "" && !containsString(selected, src.ID) || *only == "" && isCaptured(old)) {
			records = append(records, old)
			continue
		}
		entry := overrides[src.ID]
		rec.DiscoveryEvidence = entry.EvidenceURL
		rec.DiscoveryNote = entry.Note
		if entry.URL != "" {
			src.Download.URL = entry.URL
			src.Download.Format = entry.Format
		}
		rec.SampleURL = src.Download.URL
		rec.SampleFormat = src.Download.Format
		fmt.Printf("[%02d/%02d] %s (%s)\n", i+1, len(cfg.Sources), src.ID, src.Download.Format)
		if entry.Blocker != "" && src.Admission != "retired" {
			rec.Status = "blocked"
			rec.Blocker = entry.Blocker
			writeFormatOnly(*outputRoot, src, &rec)
		} else {
			processSource(c, *outputRoot, src, &rec)
		}
		captured := isCaptured(rec)
		if exists && isCaptured(old) && rec.Status == "fetch_failed" {
			rec, err = retainFailedCapture(*outputRoot, old, rec)
			must(err)
			fmt.Printf("retained previous capture for %s; retry failed: %s\n", src.ID, rec.LastCaptureError)
		}
		if captured {
			rec.CapturedAt = time.Now().UTC().Format(time.RFC3339)
			rec.CaptureTimeBasis = "capture_completed_at"
			// Only remove an obsolete record after its replacement is safely stored.
			if exists && old.FormatOnlyRecord != "" {
				must(os.Remove(filepath.Join(*outputRoot, old.FormatOnlyRecord)))
			}
			if exists && old.SamplePath != "" && old.SamplePath != rec.SamplePath {
				must(os.Remove(filepath.Join(*outputRoot, old.SamplePath)))
			}
		}
		records = append(records, rec)
	}

	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	sum := summarize(records)
	m := manifest{
		SchemaVersion:       2,
		Purpose:             "Build-private source format reconnaissance. Not a parser fixture, schema verification, rights approval, or publication artifact.",
		PublicOutputAllowed: false,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		SourceCatalogSHA256: hashBytes(catalogBytes),
		Summary:             sum,
		Sources:             records,
	}
	writeJSON(filepath.Join(*outputRoot, "manifest.json"), m)
	must(atomicWrite(filepath.Join(*outputRoot, "README.md"), []byte(renderREADME(sum, records))))
	fmt.Printf("captured=%d sanitized=%d format-only=%d blocked=%d failed=%d total=%d\n", sum.Captured, sum.CapturedSanitized, sum.FormatOnlyNoURL, sum.Blocked, sum.FetchFailed, sum.Total)
}

func processSource(c *capturer, outputRoot string, src source, rec *sourceRecord) {
	if src.Admission == "retired" {
		rec.Status = "retired_not_captured"
		rec.Blocker = "catalog admission is retired; no sample is needed for implementation"
		writeFormatOnly(outputRoot, src, rec)
		return
	}
	if src.Download.URL == "" {
		rec.Status = "format_only_no_url"
		rec.Blocker = "no exact downloadable artifact is declared in the catalog"
		if src.Discovery.RequiresExactFile {
			rec.Blocker += "; exact file path must be selected and verified"
		}
		if src.Download.Format == "unknown" || src.Download.Format == "" {
			rec.Blocker += "; format is not declared"
		}
		writeFormatOnly(outputRoot, src, rec)
		return
	}

	resp, err := c.fetch(src.Download.URL)
	if err != nil {
		rec.Status = "fetch_failed"
		rec.Blocker = err.Error()
		writeFormatOnly(outputRoot, src, rec)
		return
	}
	rec.HTTPStatus = resp.status
	rec.ContentType = resp.contentType
	rec.RemoteContentLength = resp.contentLength
	rec.TransferBytes = len(resp.body)
	rec.Truncated = resp.truncated

	result, err := decodeSample(src.Download.Format, resp.body)
	if err != nil {
		rec.Status = "fetch_failed"
		rec.Blocker = err.Error()
		writeFormatOnly(outputRoot, src, rec)
		return
	}
	rec.ObservedKind = result.observedKind
	// A fragment is not a full snapshot even when the HTTP transfer completed.
	rec.Truncated = rec.Truncated || result.binary || len(resp.body) > len(result.data) && !result.wasSanitized
	rec.ArchiveEntry = result.archiveEntry
	rec.Redactions = result.redactions
	rec.FormatNotes = result.formatNotes
	rec.Status = "captured"
	if result.wasSanitized {
		rec.Status = "captured_sanitized"
	}
	rec.SampleBytes = len(result.data)
	rec.SampleSHA256 = hashBytes(result.data)
	ext := sampleExtension(src.Download.Format, result)
	name := src.ID + ext + ".fragment"
	rec.SamplePath = filepath.ToSlash(filepath.Join("samples", name))
	must(atomicWrite(filepath.Join(outputRoot, rec.SamplePath), result.data))
}

func baseRecord(src source) sourceRecord {
	format := src.Download.Format
	return sourceRecord{
		ID:                       src.ID,
		Category:                 src.Category,
		Admission:                src.Admission,
		EvidenceFamily:           src.EvidenceFamily,
		SourceGroup:              src.SourceGroup,
		DeclaredFormat:           format,
		FormatFamily:             formatFamily(format),
		DeclaredFields:           append([]string(nil), src.Fields...),
		Scope:                    src.Scope,
		Coverage:                 src.Coverage.Kind,
		PublicationProof:         src.PublicationProof.Kind,
		ExistingFixtureStatus:    src.Fixture.Status,
		FormatNotes:              declaredFormatNotes(format),
		ExplicitlyNotFixtureTest: true,
	}
}

func (c *capturer) fetch(target string) (rawResponse, error) {
	if !strings.HasPrefix(target, "https://") {
		return rawResponse{}, errors.New("source URL is not HTTPS")
	}
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if err != nil {
			return rawResponse{}, err
		}
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept-Encoding", "identity")
		if strings.HasPrefix(target, "https://api.github.com/repos/") && strings.Contains(target, "/releases/assets/") {
			req.Header.Set("Accept", "application/octet-stream")
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", maxTransferBytes-1))
		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxTransferBytes))
		closeErr := resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
			continue
		}
		if closeErr != nil {
			lastErr = closeErr
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			lastErr = fmt.Errorf("HTTP %d from source", resp.StatusCode)
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
			continue
		}
		if len(body) == 0 {
			return rawResponse{}, errors.New("source returned an empty body")
		}
		truncated := len(body) >= maxTransferBytes || resp.ContentLength > int64(len(body))
		return rawResponse{
			body:          body,
			status:        resp.StatusCode,
			contentType:   resp.Header.Get("Content-Type"),
			contentLength: resp.ContentLength,
			truncated:     truncated,
		}, nil
	}
	return rawResponse{}, lastErr
}

func newHTTPClient() *http.Client {
	return newHTTPClientWithDNS(false)
}

func newHTTPClientWithDNS(publicDNS bool) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	resolve := net.DefaultResolver.LookupNetIP
	if publicDNS {
		resolve = publicDownloadResolver()
	}
	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := resolve(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			sort.SliceStable(ips, func(i, j int) bool {
				return ips[i].Is4() && !ips[j].Is4()
			})
			var lastErr error
			for _, ip := range ips {
				if !isPublicAddress(ip) {
					continue
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("refusing private or special source host %q", host)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirected to non-HTTPS URL")
			}
			return nil
		},
	}
}

func isPublicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "100::/64", "2001:2::/48", "3fff::/20"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return ip.IsGlobalUnicast() && ip.Zone() == ""
}

func decodeSample(format string, body []byte) (sampleResult, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	result := sampleResult{formatNotes: declaredFormatNotes(format)}
	payload := body
	if bytes.HasPrefix(body, []byte{0x1f, 0x8b}) {
		plain, err := gunzipPrefix(body, maxTransferBytes)
		if err != nil && len(plain) == 0 {
			return result, fmt.Errorf("gzip decode: %w", err)
		}
		result.formatNotes = append(result.formatNotes, "container: gzip (fragment may end mid-stream)")
		if format == "tar-gz" {
			data, entry, notes, err := tarEntrySample(plain)
			if err != nil {
				return result, err
			}
			result.data = data
			result.archiveEntry = entry
			result.observedKind = "tar-entry-" + strings.TrimPrefix(filepath.Ext(entry), ".")
			result.formatNotes = append(result.formatNotes, "archive: tar; stored first regular entry fragment")
			result.formatNotes = append(result.formatNotes, notes...)
			return result, nil
		}
		payload = plain
	} else if bytes.HasPrefix(body, []byte("BZh")) {
		plain, err := bzip2Prefix(body, maxTransferBytes)
		if err != nil && len(plain) == 0 {
			return result, fmt.Errorf("bzip2 decode: %w", err)
		}
		result.formatNotes = append(result.formatNotes, "container: bzip2 (fragment may end mid-stream)")
		payload = plain
	} else if bytes.HasPrefix(body, []byte("PK\x03\x04")) {
		data, name, err := zipPrefix(body)
		if err != nil {
			return result, err
		}
		result.archiveEntry = name
		result.formatNotes = append(result.formatNotes, "container: ZIP; bounded local-member prefix only; central directory and CRC are not verified")
		payload = data
	} else if bytes.HasPrefix(body, []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}) {
		plain, err := xzBlockPrefix(body)
		if err != nil {
			return result, err
		}
		data, name, notes, err := tarEntrySample(plain)
		if err != nil {
			return result, err
		}
		result.data, result.archiveEntry = data, name
		result.observedKind = "tar-entry-text"
		result.formatNotes = append(result.formatNotes, "container: XZ tar; bounded member prefix only", "archive integrity not verified")
		result.formatNotes = append(result.formatNotes, notes...)
		return result, nil
	} else if bytes.HasPrefix(body, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		return result, errors.New("declared archive/codec is not supported by this reconnaissance capture tool")
	}
	if err := rejectNonData(payload); err != nil {
		return result, err
	}

	switch format {
	case "mmdb", "xdb", "mrt-gz", "mrt-bz2":
		result.data = limitBytes(payload, maxBinaryBytes)
		result.observedKind = "binary-" + format
		result.binary = true
		result.formatNotes = append(result.formatNotes, "binary fragment only; inspect with the eventual bounded parser")
	case "uri-list", "auto-subscription", "base64-subscription":
		data, notes, redactions, err := subscriptionSample(format, payload)
		if err != nil {
			return result, err
		}
		result.data = limitBytes(data, maxSampleBytes)
		result.observedKind = "sanitized-subscription-lines"
		result.wasSanitized = true
		result.redactions = redactions
		result.formatNotes = append(result.formatNotes, notes...)
	default:
		result.data = textPrefix(bytes.NewReader(payload), maxSampleBytes)
		if !utf8.Valid(result.data) {
			return result, errors.New("invalid UTF-8 text sample")
		}
		result.observedKind = sniffTextKind(result.data, format)
	}
	if len(result.data) == 0 {
		return result, errors.New("no sample bytes could be decoded")
	}
	if format != "mmdb" && format != "xdb" && format != "mrt-gz" && format != "mrt-bz2" && !utf8MostlyPrintable(result.data) {
		result.observedKind = "binary-unexpected"
		result.formatNotes = append(result.formatNotes, "warning: text/CSV/JSON source contains non-printable bytes")
	}
	return result, nil
}

func gunzipPrefix(data []byte, max int) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, int64(max)))
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return out, err
}

func bzip2Prefix(data []byte, max int) ([]byte, error) {
	zr := bzip2.NewReader(bytes.NewReader(data))
	out, err := io.ReadAll(io.LimitReader(zr, int64(max)))
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return out, err
}

func tarEntrySample(data []byte) ([]byte, string, []string, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	for i := 0; i < 64; i++ {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", nil, fmt.Errorf("tar header: %w", err)
		}
		if !safeArchiveName(header.Name) {
			return nil, "", nil, errors.New("unsafe tar member name")
		}
		if header.Typeflag != tar.TypeReg || header.Size == 0 {
			continue
		}
		if strings.HasSuffix(header.Name, ".json") {
			continue
		}
		entry := textPrefix(io.Reader(io.LimitReader(tr, maxSampleBytes)), maxSampleBytes)
		if len(entry) == 0 {
			continue
		}
		if !containsNetworkData(entry) {
			continue
		}
		return entry, header.Name, []string{fmt.Sprintf("first regular entry: %s", header.Name)}, nil
	}
	return nil, "", nil, errors.New("no regular file entry found in tar prefix")
}

func containsNetworkData(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, token := range strings.Fields(line) {
			if _, err := netip.ParseAddr(token); err == nil {
				return true
			}
			if _, err := netip.ParsePrefix(token); err == nil {
				return true
			}
		}
		if _, err := netip.ParseAddr(strings.Trim(line, "[]")); err == nil {
			return true
		}
	}
	return false
}

func subscriptionSample(format string, payload []byte) ([]byte, []string, []string, error) {
	decoded := payload
	notes := []string{}
	redactions := []string{"credentials", "ports", "URI query/fragment", "non-IP hosts"}
	switch format {
	case "base64-subscription":
		out, ok := decodeBase64Prefix(payload)
		if ok {
			decoded = out
			notes = append(notes, "decoded one base64 layer before sanitizing")
		} else if looksLikeSubscriptionText(payload) {
			notes = append(notes, "declared base64, but observed plain subscription text; sanitized without decoding")
		} else {
			return nil, nil, nil, errors.New("base64 subscription prefix could not be decoded safely")
		}
	case "auto-subscription":
		if out, ok := decodeBase64Prefix(payload); ok && looksLikeSubscriptionText(out) {
			decoded = out
			notes = append(notes, "detected and decoded one base64 layer")
		} else {
			notes = append(notes, "treated as plain subscription text")
		}
	case "uri-list":
		if out, ok := decodeBase64Prefix(payload); ok && looksLikeSubscriptionText(out) {
			decoded = out
			notes = append(notes, "declared URI list, but detected and decoded one base64 layer")
		} else {
			notes = append(notes, "treated as plain URI text")
		}
	}
	if !looksLikeSubscriptionText(decoded) && format != "uri-list" {
		return nil, nil, nil, errors.New("decoded subscription is not recognizable text/JSON/YAML")
	}
	text := sanitizeSubscriptionText(decoded)
	return limitBytes([]byte(text), maxSampleBytes), notes, redactions, nil
}

func decodeBase64Prefix(data []byte) ([]byte, bool) {
	compact := make([]byte, 0, min(len(data), 1<<20))
	for _, b := range data {
		if len(compact) >= 1<<20 {
			break
		}
		if b == ' ' || b == '\n' || b == '\r' || b == '\t' {
			continue
		}
		compact = append(compact, b)
	}
	if len(compact) < 16 {
		return nil, false
	}
	if i := bytes.IndexByte(compact, '='); i >= 0 {
		compact = compact[:i]
	}
	for len(compact)%4 != 0 {
		compact = compact[:len(compact)-1]
	}
	if len(compact) < 16 {
		return nil, false
	}
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(string(compact))
		if err == nil && len(decoded) >= 16 && looksLikeSubscriptionText(decoded) {
			return decoded, true
		}
	}
	for _, enc := range encodings {
		decoded, _ := io.ReadAll(io.LimitReader(base64.NewDecoder(enc, bytes.NewReader(compact)), 1<<20))
		if len(decoded) >= 16 && looksLikeSubscriptionText(decoded) {
			return decoded, true
		}
	}
	return nil, false
}

func looksLikeSubscriptionText(data []byte) bool {
	if !utf8MostlyPrintable(limitBytes(data, 1<<20)) {
		return false
	}
	s := string(limitBytes(data, 1<<20))
	lower := strings.ToLower(s)
	return strings.Contains(s, "://") || strings.Contains(lower, "proxies:") || strings.Contains(lower, "outbounds") || strings.HasPrefix(strings.TrimSpace(s), "{") || strings.HasPrefix(strings.TrimSpace(s), "[")
}

var uriLineRE = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)$`)

func sanitizeSubscriptionText(data []byte) string {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	out := make([]string, 0, 20)
	comments := 0
	dataLines := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			if comments >= 4 {
				continue
			}
			comments++
			out = append(out, "# <redacted>")
			continue
		}
		out = append(out, sanitizeSubscriptionLine(line))
		dataLines++
		if dataLines >= 16 {
			break
		}
	}
	if dataLines == 0 {
		return "<redacted>\n"
	}
	return strings.Join(out, "\n") + "\n"
}

func sanitizeSubscriptionLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "vmess://") {
		return sanitizeVMess(trimmed)
	}
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return "# <redacted>"
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return sanitizeJSONText(trimmed)
	}
	if strings.Contains(trimmed, "server:") || strings.Contains(trimmed, "password:") || strings.Contains(trimmed, "proxies:") || strings.Contains(trimmed, "outbounds:") {
		return sanitizeYAMLLine(trimmed)
	}
	m := uriLineRE.FindStringSubmatch(trimmed)
	if m == nil {
		if _, err := netip.ParseAddr(strings.Trim(trimmed, "[]")); err == nil {
			return safeHost(trimmed)
		}
		return "<redacted>"
	}
	return sanitizeProxyURI(m[1], m[2])
}

func sanitizeProxyURI(scheme, rest string) string {
	authority := rest
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority = authority[:i]
	}
	userinfo := ""
	hostport := authority
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		userinfo = authority[:i]
		hostport = authority[i+1:]
	}
	host, port := splitHostPortLoose(hostport)
	hostOut := safeHost(host)
	p := "<port>"
	if port == "" {
		p = ""
	}
	auth := hostOut
	if userinfo != "" {
		auth = "<redacted>@" + auth
	}
	if p != "" {
		auth += ":" + p
	}
	return scheme + "://" + auth + "<redacted-suffix>"
}

func sanitizeVMess(line string) string {
	payload := strings.TrimPrefix(line, "vmess://")
	decoded, ok := decodeBase64Text(payload)
	if !ok {
		return "vmess://<redacted-base64-json>"
	}
	var value any
	if err := json.Unmarshal(decoded, &value); err != nil {
		return "vmess://<redacted-base64-json>"
	}
	sanitized := sanitizeJSONValue("", value)
	pretty, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return "vmess://<redacted-base64-json>"
	}
	return "vmess://<base64-json>\n# decoded shape after redaction:\n" + truncateString(string(pretty), 1500)
}

func decodeBase64Text(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 1<<20 {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(s); err == nil && len(decoded) > 0 {
			return decoded, true
		}
	}
	return nil, false
}

func sanitizeJSONText(s string) string {
	var value any
	if err := json.Unmarshal([]byte(s), &value); err != nil {
		return "<redacted-json>"
	}
	out, err := json.MarshalIndent(sanitizeJSONValue("", value), "", "  ")
	if err != nil {
		return "<redacted-json>"
	}
	return truncateString(string(out), 3000)
}

func sanitizeJSONValue(key string, value any) any {
	lower := strings.ToLower(key)
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out[k] = sanitizeJSONValue(k, v[k])
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = sanitizeJSONValue(key, v[i])
		}
		return out
	case string:
		if lower == "add" || lower == "server" || lower == "address" {
			return safeHost(v)
		}
		if isSensitiveKey(lower) {
			return "<redacted>"
		}
		return v
	default:
		if lower == "port" {
			return "<port>"
		}
		return value
	}
}

func sanitizeYAMLLine(line string) string {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return "<redacted>"
	}
	prefix := line[:colon]
	key := strings.TrimSpace(strings.TrimLeft(prefix, "- "))
	lower := strings.ToLower(key)
	if lower == "server" || lower == "address" {
		return prefix + ": " + safeHost(strings.TrimSpace(line[colon+1:]))
	}
	if lower == "port" {
		return prefix + ": <port>"
	}
	if isSensitiveKey(lower) {
		return prefix + ": <redacted>"
	}
	return line
}

func isSensitiveKey(k string) bool {
	switch k {
	case "password", "passwd", "pwd", "uuid", "id", "psk", "key", "auth", "username", "user", "secret", "token", "sni", "server_name", "servername", "host", "path", "tag", "name", "ps", "remarks", "alpn", "fingerprint", "public-key", "short-id", "alterid":
		return true
	default:
		return false
	}
}

func splitHostPortLoose(s string) (string, string) {
	if strings.HasPrefix(s, "[") {
		if end := strings.IndexByte(s, ']'); end >= 0 {
			host := s[1:end]
			port := strings.TrimPrefix(s[end+1:], ":")
			return host, port
		}
	}
	if strings.Count(s, ":") == 1 {
		parts := strings.SplitN(s, ":", 2)
		return parts[0], parts[1]
	}
	if strings.Count(s, ":") > 1 {
		return s, ""
	}
	return s, ""
}

func safeHost(host string) string {
	host = strings.TrimSpace(strings.Trim(host, "[]<>"))
	if host == "" {
		return "<host>"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "<non-ip-host>"
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !isPublicAddress(addr) {
		return "<special-ip>"
	}
	return addr.String()
}

func sniffTextKind(data []byte, format string) string {
	s := strings.TrimSpace(string(data))
	if s == "" {
		return "empty"
	}
	if format == "text" {
		return "text-lines"
	}
	if format == "range-csv" || format == "csv" || format == "csv-zip" {
		return "csv-fragment"
	}
	if format == "tsv" {
		return "tsv-fragment"
	}
	if format == "csv-gz" {
		return "csv-fragment"
	}
	if format == "tsv-gz" {
		return "tsv-fragment"
	}
	if format == "json" {
		if json.Valid(data) {
			return "json"
		}
		return "json-fragment"
	}
	if format == "jsonl" || format == "json-lines" {
		return "jsonl-fragment"
	}
	if format == "rir-extended" {
		return "rir-extended-fragment"
	}
	if format == "cidr-text" || format == "proxyip-full-text" {
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
				continue
			}
			if strings.HasPrefix(line, "||") {
				return "adblock-ip-rules"
			}
			break
		}
		return "ip-or-cidr-lines"
	}
	first := strings.SplitN(s, "\n", 2)[0]
	if strings.Contains(first, "\t") {
		return "tsv-fragment"
	}
	if strings.Contains(first, ",") {
		return "csv-fragment"
	}
	return "text-lines"
}

func formatFamily(format string) string {
	switch format {
	case "range-csv", "csv", "csv-gz":
		return "delimited-csv"
	case "tsv", "tsv-gz":
		return "delimited-tsv"
	case "json", "jsonl", "json-lines":
		return "json"
	case "mmdb":
		return "maxmind-mmdb"
	case "xdb":
		return "ip2region-xdb"
	case "tar-gz", "tar-xz", "csv-zip":
		return "archive"
	case "mrt-gz", "mrt-bz2":
		return "mrt"
	case "uri-list", "base64-subscription", "auto-subscription":
		return "proxy-subscription"
	case "cidr-text", "proxyip-full-text", "text", "text-gz", "text-bz2":
		return "line-text"
	case "rir-extended":
		return "rir-delegated"
	case "":
		return "undiscovered"
	case "unknown":
		return "unknown"
	default:
		return "other"
	}
}

func declaredFormatNotes(format string) []string {
	switch format {
	case "range-csv":
		return []string{"expected: CSV range rows (start,end,country); observe exact header and column count from the sample"}
	case "csv", "csv-gz":
		return []string{"expected: CSV with a header or fixed columns; confirm quoting and null conventions"}
	case "tsv", "tsv-gz":
		return []string{"expected: tab-delimited rows; confirm presence of a header"}
	case "json", "jsonl", "json-lines":
		return []string{"expected: JSON document or one JSON value per line; inspect for arrays/maps and nullable fields"}
	case "mmdb":
		return []string{"expected: MaxMind DB binary; decoder must inspect metadata before lookups"}
	case "xdb":
		return []string{"expected: IP2Region binary xdb; decoder must validate its own header and bounds"}
	case "mrt-gz", "mrt-bz2":
		return []string{"expected: MRT binary stream; MRT ingestion remains disabled pending approval and parser work"}
	case "tar-gz":
		return []string{"expected: tar archive; sample stores the first regular file content fragment"}
	case "cidr-text":
		return []string{"expected: line-oriented IP/CIDR entries; comments and blank lines need explicit handling"}
	case "proxyip-full-text":
		return []string{"expected: full literal-IP list; no secondary quality/region feeds may be combined"}
	case "uri-list":
		return []string{"expected: proxy URI lines; retain literal public IPs only and strip all URI material"}
	case "base64-subscription":
		return []string{"expected: one base64 wrapper around subscription lines; nested depth must stay bounded"}
	case "auto-subscription":
		return []string{"expected: auto-detect base64 or text/YAML/JSON subscription; never fetch embedded links"}
	case "text", "text-gz", "text-bz2":
		return []string{"expected: line-oriented text; confirm comments, header lines and record delimiters"}
	case "csv-zip":
		return []string{"expected: ZIP archive containing CSV member(s); extract one bounded member before parsing"}
	case "tar-xz":
		return []string{"expected: xz-compressed tar archive; a bounded xz decoder is required before extraction"}
	case "rir-extended":
		return []string{"expected: RIR delegated-stats extended lines; parse by record type and summary lines"}
	case "":
		return []string{"format is not declared; exact artifact discovery is required"}
	case "unknown":
		return []string{"format is unknown; exact artifact discovery and schema observation are required"}
	default:
		return []string{"format requires dedicated inspection before parser implementation"}
	}
}

func sampleExtension(format string, result sampleResult) string {
	if result.binary {
		switch format {
		case "mmdb":
			return ".mmdb"
		case "xdb":
			return ".xdb"
		case "mrt-gz":
			return ".mrt"
		case "mrt-bz2":
			return ".mrt"
		}
	}
	switch format {
	case "range-csv", "csv", "csv-gz", "csv-zip":
		return ".csv"
	case "tsv", "tsv-gz":
		return ".tsv"
	case "json":
		return ".json"
	case "jsonl", "json-lines":
		return ".jsonl"
	case "rir-extended":
		return ".delegated"
	default:
		return ".txt"
	}
}

func writeFormatOnly(root string, src source, rec *sourceRecord) {
	name := src.ID + ".md"
	rec.FormatOnlyRecord = filepath.ToSlash(filepath.Join("format-only", name))
	content := renderFormatOnly(src, rec)
	must(atomicWrite(filepath.Join(root, rec.FormatOnlyRecord), []byte(content)))
}

func renderFormatOnly(src source, rec *sourceRecord) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Source format record: `%s`\n\n", src.ID)
	fmt.Fprintf(&b, "- Status: `%s`\n", rec.Status)
	fmt.Fprintf(&b, "- Admission: `%s`\n", src.Admission)
	fmt.Fprintf(&b, "- Category: `%s`\n", src.Category)
	fmt.Fprintf(&b, "- Declared format: `%s`\n", blankAsUnknown(src.Download.Format))
	fmt.Fprintf(&b, "- Format family: `%s`\n", rec.FormatFamily)
	fmt.Fprintf(&b, "- Evidence scope: `%s` / coverage `%s`\n", src.Scope, src.Coverage.Kind)
	fmt.Fprintf(&b, "- Declared fields: `%s`\n", strings.Join(src.Fields, "`, `"))
	fmt.Fprintf(&b, "- Publication proof: `%s`\n", src.PublicationProof.Kind)
	fmt.Fprintf(&b, "- Existing fixture status: `%s`\n\n", src.Fixture.Status)
	fmt.Fprintf(&b, "## Capture blocker\n\n%s\n\n", rec.Blocker)
	if rec.DiscoveryEvidence != "" {
		fmt.Fprintf(&b, "## Discovery evidence\n\n%s\n\n%s\n\n", rec.DiscoveryEvidence, rec.DiscoveryNote)
	}
	fmt.Fprintf(&b, "## Format notes\n\n")
	for _, note := range declaredFormatNotes(src.Download.Format) {
		fmt.Fprintf(&b, "- %s\n", note)
	}
	fmt.Fprintf(&b, "\n## Next implementation step\n\n")
	fmt.Fprintf(&b, "Resolve and validate an exact downloadable artifact, observe its schema, then add a bounded parser fixture. Do not infer the schema from repository prose or promote this record to `fixture_tested` without parser evidence.\n")
	return b.String()
}

func renderREADME(sum manifestStats, records []sourceRecord) string {
	var b strings.Builder
	b.WriteString("# Source Format Samples\n\n")
	b.WriteString("Build-private reconnaissance for future source adapters. These files are **not** parser fixtures, schema verification, rights approval, publication data, or evidence that a source is current. Never copy this directory into `web/.output/public` or a VIA3/release artifact.\n\n")
	fmt.Fprintf(&b, "- Total catalog entries: %d\n", sum.Total)
	fmt.Fprintf(&b, "- Captured raw fragments: %d\n", sum.Captured)
	fmt.Fprintf(&b, "- Captured sanitized fragments: %d\n", sum.CapturedSanitized)
	fmt.Fprintf(&b, "- Format-only records with no exact URL: %d\n", sum.FormatOnlyNoURL)
	fmt.Fprintf(&b, "- Retired entries not captured: %d\n", sum.RetiredNotCaptured)
	fmt.Fprintf(&b, "- Fetch/decode failures: %d\n\n", sum.FetchFailed)
	fmt.Fprintf(&b, "- Reviewed capture blockers: %d\n\n", sum.Blocked)
	b.WriteString("`manifest.json` is the machine-readable index. Each captured fragment is in `samples/`; each uncaptured entry has a format record in `format-only/`. Subscription samples are sanitized: credentials, ports, URI suffixes, and non-IP hosts are replaced, and no embedded host is resolved or fetched.\n\n")
	b.WriteString("## Catalog status\n\n| Source ID | Category | Declared format | Observed kind | Record |\n|---|---|---|---|---|\n")
	for _, rec := range records {
		record := rec.SamplePath
		if record == "" {
			record = rec.FormatOnlyRecord
		}
		observed := rec.ObservedKind
		if observed == "" {
			observed = "-"
		}
		fmt.Fprintf(&b, "| `%s` | %s | `%s` | `%s` | `%s` |\n", rec.ID, rec.Category, blankAsUnknown(rec.DeclaredFormat), observed, record)
	}
	b.WriteString("\n## Fill missing samples\n\n```powershell\ngo run ./tools/source_samples -config configs/sources.yaml -out fixtures/source-samples -missing-only\n```\n")
	b.WriteString("\n`discovery.json` records observed download locations and explicit blockers for reconnaissance only; it never changes production source admission, rights or freshness. Declared catalog formats remain in the manifest alongside the selected sample format. Capture times are not publication proofs. Existing captures retain their original bytes after hash verification; v1 capture times use the original index generation time, explicitly marked `legacy_manifest_generated_at`. Omit `-missing-only` to refresh all sources, or add `-only id1,id2` to retry selected records.\n")
	b.WriteString("\nIf system DNS uses synthetic special-use addresses, add `-public-dns` to resolve selected download hosts via HTTPS to `1.1.1.1`; every resulting destination still passes public-address checks. This option never resolves hosts found inside subscriptions. Captures are capped at 4 MiB transferred, 4 MiB decoded, 8 KiB text or 4 KiB binary stored and 64 archive entries. XZ decodes only the first LZMA2 block with at most 4 MiB of history, regardless of the advertised dictionary size. ZIP/XZ fragments do not establish whole-archive integrity.\n")
	b.WriteString("\nThe command performs bounded HTTPS reads only. It rejects private, loopback, link-local and multicast download hosts, uses one request at a time, does not use HTTP `304` or fetch time as freshness proof, and never executes downloaded content.\n")
	return b.String()
}

func summarize(records []sourceRecord) manifestStats {
	s := manifestStats{Total: len(records), ByDeclaredFormat: map[string]int{}}
	for _, rec := range records {
		switch rec.Status {
		case "captured":
			s.Captured++
		case "captured_sanitized":
			s.CapturedSanitized++
		case "format_only_no_url":
			s.FormatOnlyNoURL++
		case "retired_not_captured":
			s.RetiredNotCaptured++
		case "fetch_failed":
			s.FetchFailed++
		case "blocked":
			s.Blocked++
		}
		format := rec.DeclaredFormat
		if format == "" {
			format = "(undeclared)"
		}
		s.ByDeclaredFormat[format]++
	}
	return s
}

func textPrefix(r io.Reader, max int) []byte {
	data, _ := io.ReadAll(io.LimitReader(r, int64(max)))
	if len(data) == 0 {
		return data
	}
	if len(data) == max {
		if i := bytes.LastIndexByte(data, '\n'); i > 0 {
			data = data[:i+1]
		}
	}
	return data
}

func limitBytes(data []byte, max int) []byte {
	if len(data) > max {
		return data[:max]
	}
	return data
}

func truncateString(s string, max int) string {
	if len(s) > max {
		return s[:max] + "\n# <truncated>"
	}
	return s
}

func utf8MostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	bad := 0
	for _, b := range sample {
		if b == 0 {
			return false
		}
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			bad++
		}
	}
	return bad*20 < len(sample)
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func blankAsUnknown(s string) string {
	if s == "" {
		return "(undeclared)"
	}
	return s
}

func writeJSON(path string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	must(err)
	data = append(data, '\n')
	must(atomicWrite(path, data))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
