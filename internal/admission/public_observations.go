package admission

import (
	"bufio"
	"context"
	"encoding/hex"
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

const torExitURL = "https://check.torproject.org/exit-addresses"

func torExitSource(s Source) bool {
	return s.Parser.ID == "tor-exit-addresses" && s.Parser.Schema == "tordnsel-exit-addresses-v1" && s.URL == torExitURL && s.Publication.Kind == "embedded" && s.Publication.Locator == s.URL && s.Publication.Field == "exit_address_observed_at" && s.Format == "text" && s.Scope == "exact_ip" && s.Category == "proxy" && s.Coverage == "positive_only" && fieldsEqual(s.PublicFields, "reason_flags") && fieldsEqual(s.Signals, "tor") && mappedFields(s, map[string]string{"tor_exit": "reason_flags"})
}

// The complete payload supplies dated observations, not an assessed negative set.
// Relay fingerprints and status metadata never leave this parser. The maximum
// accepted observation is a conservative content clock; every item retains its
// own earlier clock, which reconciliation uses to clamp release validity.
func parseTorExitAddresses(ctx context.Context, input io.Reader, now time.Time, maxAge time.Duration, maximum int, emit func(intelligence.NormalizedRecord) error) (time.Time, error) {
	var newest time.Time
	if ctx == nil || input == nil || now.IsZero() || maxAge <= 0 || maxAge > 720*time.Hour || maximum <= 0 || maximum > 100_000_000 {
		return newest, errors.New("bounded Tor observations required")
	}
	r := &io.LimitedReader{R: contextReader{ctx, input}, N: (64 << 20) + 1}
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 4096), 4096)
	stage, rows, exits := 0, 0, 0
	parseTime := func(s string) (time.Time, error) {
		v, e := time.Parse("2006-01-02 15:04:05", s)
		if e != nil || v.Year() < 1970 || v.After(now.Add(24*time.Hour)) {
			return time.Time{}, errors.New("Tor observation clock invalid")
		}
		return v.UTC(), nil
	}
	for scan.Scan() {
		line := scan.Text()
		if !utf8.ValidString(line) {
			return newest, errors.New("Tor UTF-8 invalid")
		}
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "ExitNode "):
			if stage != 0 && (stage != 3 || exits == 0) {
				return newest, errors.New("incomplete Tor descriptor")
			}
			h := strings.TrimPrefix(line, "ExitNode ")
			if len(h) != 40 {
				return newest, errors.New("Tor fingerprint invalid")
			}
			if _, err := hex.DecodeString(h); err != nil {
				return newest, errors.New("Tor fingerprint invalid")
			}
			stage, exits = 1, 0
		case strings.HasPrefix(line, "Published "):
			if stage != 1 {
				return newest, errors.New("Tor publication order invalid")
			}
			if _, err := parseTime(strings.TrimPrefix(line, "Published ")); err != nil {
				return newest, err
			}
			stage = 2
		case strings.HasPrefix(line, "LastStatus "):
			if stage != 2 {
				return newest, errors.New("Tor status order invalid")
			}
			if _, err := parseTime(strings.TrimPrefix(line, "LastStatus ")); err != nil {
				return newest, err
			}
			stage = 3
		case strings.HasPrefix(line, "ExitAddress "):
			if stage != 3 {
				return newest, errors.New("Tor exit outside descriptor")
			}
			parts := strings.Split(strings.TrimPrefix(line, "ExitAddress "), " ")
			if len(parts) != 3 {
				return newest, errors.New("Tor exit shape invalid")
			}
			ip, err := netip.ParseAddr(parts[0])
			if err != nil || ip.Zone() != "" {
				return newest, errors.New("Tor exit literal invalid")
			}
			ip = ip.Unmap()
			observed, err := parseTime(parts[1] + " " + parts[2])
			if err != nil {
				return newest, err
			}
			rows++
			exits++
			if rows > maximum {
				return newest, errors.New("Tor observation count exceeded")
			}
			if !subscription.Public(ip) || !now.Before(observed.Add(maxAge)) {
				continue
			}
			if observed.After(newest) {
				newest = observed
			}
			if emit != nil {
				if err := emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Family: "tor-official", Signal: "tor", Scope: intelligence.Exact, Address: ip, SourcePublishedAt: now, ItemPublishedAt: observed, Current: true}}); err != nil {
					return newest, err
				}
			}
		default:
			return newest, errors.New("uncertified Tor descriptor field")
		}
	}
	if err := scan.Err(); err != nil {
		return newest, err
	}
	if r.N <= 0 || stage != 3 || exits == 0 || rows == 0 {
		return newest, errors.New("truncated or oversized Tor payload")
	}
	if newest.IsZero() {
		return newest, errors.New("Tor payload has no current public observations")
	}
	return newest, nil
}

func verifyTorExitFile(ctx context.Context, path string, s Source, now time.Time) (time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()
	return parseTorExitAddresses(ctx, f, now, s.MaxAge, 100_000_000, nil)
}

// Ipverse's category is an ASN's primary function, never direct address usage.
// The explicit item clock is retained. ISP, null and unknown classifications do
// not invent residential/mobile facts; networkRole is deliberately discarded.
func parseIPverseUsageJSON(ctx context.Context, input io.Reader, family string, maximum int, emit func(intelligence.NormalizedRecord) error) error {
	if ctx == nil || input == nil || !identity(family) || maximum <= 0 || maximum > 1_000_000 || emit == nil {
		return errors.New("bounded ASN usage JSON required")
	}
	stream := &rpkiJSONStream{ctx: ctx, reader: bufio.NewReaderSize(&io.LimitedReader{R: input, N: (128 << 20) + 1}, 64<<10), limit: 128 << 20}
	first, err := stream.nonspace()
	if err != nil || first != '[' {
		return errors.New("ASN usage array required")
	}
	count := 0
	seen := map[uint32]bool{}
	for {
		first, err = stream.nonspace()
		if err != nil {
			return errors.New("truncated ASN usage array")
		}
		if first == ']' {
			break
		}
		if first != '{' {
			return errors.New("ASN usage object required")
		}
		raw, err := stream.value(first, 64<<10)
		if err != nil {
			return err
		}
		if err = uniqueJSON(raw); err != nil {
			return err
		}
		var v struct {
			ASN      *uint32 `json:"asn"`
			Metadata *struct {
				Category     json.RawMessage `json:"category"`
				LastModified json.RawMessage `json:"lastModified"`
			} `json:"metadata"`
		}
		if err = json.Unmarshal(raw, &v); err != nil || v.ASN == nil || v.Metadata == nil || len(v.Metadata.Category) == 0 || len(v.Metadata.LastModified) == 0 {
			return errors.New("ASN usage schema invalid")
		}
		var category, modified *string
		if json.Unmarshal(v.Metadata.Category, &category) != nil || json.Unmarshal(v.Metadata.LastModified, &modified) != nil {
			return errors.New("ASN usage metadata invalid")
		}
		count++
		if count > maximum || seen[*v.ASN] {
			return errors.New("ASN usage count or duplicate identity invalid")
		}
		seen[*v.ASN] = true
		kind := ""
		if category != nil {
			switch *category {
			case "hosting", "business":
				kind = *category
			case "education_research":
				kind = "education"
			case "government_admin":
				kind = "government"
			case "isp":
			default:
				return errors.New("uncertified ASN category")
			}
		}
		if modified != nil {
			observed, e := time.Parse("2006-01-02", *modified)
			if e != nil || observed.Year() < 1970 {
				return errors.New("ASN usage item clock invalid")
			}
			if kind != "" && intelligence.IsPublicASN(*v.ASN) {
				if err = emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{ASN: *v.ASN, ObservedAt: observed.UTC(), Evidence: intelligence.UsageEvidence{Family: family, Type: kind, Current: true}}}); err != nil {
					return err
				}
			}
		}
		first, err = stream.nonspace()
		if err != nil {
			return errors.New("truncated ASN usage array")
		}
		if first == ']' {
			break
		}
		if first != ',' {
			return errors.New("ASN usage separator invalid")
		}
		if next, e := stream.peekNonspace(); e != nil || next == ']' {
			return errors.New("ASN usage trailing comma")
		}
	}
	if _, err = stream.nonspace(); err != io.EOF {
		return errors.New("ASN usage trailing content")
	}
	if count == 0 {
		return errors.New("empty ASN usage payload")
	}
	return nil
}
