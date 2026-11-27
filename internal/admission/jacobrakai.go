package admission

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

const (
	jacobrakaiID         = "jacobrakai-honeypot"
	jacobrakaiParserID   = "jacobrakai-honeypot-json"
	jacobrakaiSchema     = "jacobrakai-honeypot-tiered-json-v1"
	jacobrakaiURL        = "https://jacobrakai.org/feed/blocklist.json"
	jacobrakaiFixture    = "jacobrakai-honeypot-excerpt"
	jacobrakaiByteLimit  = 1 << 20
	jacobrakaiRowLimit   = 5000
	jacobrakaiWindow     = 720 * time.Hour
	jacobrakaiServeSlack = 48 * time.Hour
)

var errJacobrakai = errors.New("honeypot export lacks a complete dated tier observation")

func jacobrakaiSource(s Source) bool {
	return s.ID == jacobrakaiID && s.Family == jacobrakaiID && s.SourceGroup == jacobrakaiID &&
		s.Category == "abuse" && s.Coverage == "positive_only" && s.Scope == "exact_ip" &&
		s.URL == jacobrakaiURL && s.Format == "json" && s.MaxCompressedBytes == jacobrakaiByteLimit &&
		s.MaxAge == jacobrakaiWindow && s.Weight == 25 && s.Parser == (Parser{jacobrakaiParserID, jacobrakaiSchema, 1}) &&
		s.Publication == (Publication{"embedded", jacobrakaiURL, "meta.updated"}) &&
		fieldsEqual(s.Signals, "abuse", "scanner") && fieldsEqual(s.PublicFields, "reason_flags") &&
		fieldsEqual(s.Fields, "meta.updated", "ip", "tier", "attempts", "bans", "first_seen", "last_seen", "first_banned", "asn") &&
		mappedFields(s, map[string]string{"ip": "reason_flags", "tier": "reason_flags"})
}

type jacobrakaiMeta struct {
	Updated           string            `json:"updated"`
	License           string            `json:"license"`
	Count             int               `json:"count"`
	CountByTier       map[string]int    `json:"count_by_tier"`
	WindowDays        int               `json:"window_days"`
	ScannerMinEvents  uint32            `json:"scanner_min_events"`
	Name              string            `json:"name"`
	Maintainer        string            `json:"maintainer"`
	Homepage          string            `json:"homepage"`
	Contact           string            `json:"contact"`
	Description       string            `json:"description"`
	UpdateFrequency   string            `json:"update_frequency"`
	Disclaimer        string            `json:"disclaimer"`
	FieldNotes        string            `json:"field_notes"`
	InclusionCriteria string            `json:"inclusion_criteria"`
	CSVColumns        []string          `json:"csv_columns"`
	Formats           map[string]string `json:"formats"`
}

type jacobrakaiRow struct {
	Address     string          `json:"ip"`
	Tier        string          `json:"tier"`
	Attempts    *uint32         `json:"attempts"`
	Bans        *uint32         `json:"bans"`
	FirstSeen   string          `json:"first_seen"`
	LastSeen    string          `json:"last_seen"`
	FirstBanned json.RawMessage `json:"first_banned"`
	ASN         *string         `json:"asn"`
}

// readJacobrakai checks completeness and validates every row before returning
// any evidence. Excerpt mode is restricted to offline fixture certification.
// This is an IPv4-only, single-observer export. No endpoint is contacted.
func readJacobrakai(ctx context.Context, input io.Reader, s Source, maximum int, excerpt bool) (time.Time, []intelligence.Evidence, error) {
	if ctx == nil || input == nil || !jacobrakaiSource(s) || maximum <= 0 {
		return time.Time{}, nil, errJacobrakai
	}
	body, err := io.ReadAll(io.LimitReader(contextReader{ctx, input}, jacobrakaiByteLimit+1))
	if err != nil || len(body) > jacobrakaiByteLimit {
		return time.Time{}, nil, errJacobrakai
	}
	var doc struct {
		Meta jacobrakaiMeta  `json:"meta"`
		IPs  []jacobrakaiRow `json:"ips"`
	}
	if strictJSON(body, &doc) != nil {
		return time.Time{}, nil, errJacobrakai
	}
	m := doc.Meta
	published, err := timestamp(m.Updated)
	if err != nil || m.License != "CC0-1.0" || m.WindowDays != 30 || m.ScannerMinEvents != 1000 || m.Count <= 0 || m.Count > jacobrakaiRowLimit || len(doc.IPs) == 0 || len(doc.IPs) > min(maximum, jacobrakaiRowLimit) || (!excerpt && len(doc.IPs) != m.Count) || (excerpt && len(doc.IPs) >= m.Count) {
		return time.Time{}, nil, errJacobrakai
	}
	count := 0
	for tier, n := range m.CountByTier {
		if (tier != "credential" && tier != "scanner" && tier != "loader") || n < 0 || n > m.Count {
			return time.Time{}, nil, errJacobrakai
		}
		count += n
	}
	if count != m.Count {
		return time.Time{}, nil, errJacobrakai
	}

	oldest := published.Add(-jacobrakaiWindow)
	seen := make(map[netip.Addr]bool, len(doc.IPs))
	seenTiers := make(map[string]int, 3)
	values := make([]intelligence.Evidence, 0, len(doc.IPs))
	for _, row := range doc.IPs {
		if err := ctx.Err(); err != nil {
			return time.Time{}, nil, err
		}
		ip, ipErr := netip.ParseAddr(row.Address)
		first, firstErr := timestamp(row.FirstSeen)
		last, lastErr := timestamp(row.LastSeen)
		seenTiers[row.Tier]++
		if ipErr != nil || !ip.Is4() || !subscription.Public(ip) || seen[ip] || firstErr != nil || lastErr != nil || first.Before(oldest) || last.Before(first) || last.After(published) || seenTiers[row.Tier] > m.CountByTier[row.Tier] || row.Attempts == nil || row.Bans == nil || row.ASN == nil {
			return time.Time{}, nil, errJacobrakai
		}
		seen[ip] = true
		var firstBan *string
		if json.Unmarshal(row.FirstBanned, &firstBan) != nil {
			return time.Time{}, nil, errJacobrakai
		}
		var signal intelligence.Signal
		switch row.Tier {
		case "credential":
			if *row.Attempts < 50 || *row.Bans == 0 || firstBan == nil {
				return time.Time{}, nil, errJacobrakai
			}
			if _, err = timestamp(*firstBan); err != nil {
				return time.Time{}, nil, errJacobrakai
			}
			signal = "abuse"
		case "scanner", "loader":
			if *row.Attempts == 0 || *row.Bans != 0 || firstBan != nil || row.Tier == "scanner" && *row.Attempts < m.ScannerMinEvents {
				return time.Time{}, nil, errJacobrakai
			}
			if row.Tier == "loader" {
				// Transfer to a decoy is not proof an address is malware or C2.
				continue
			}
			signal = "scanner"
		default:
			return time.Time{}, nil, errJacobrakai
		}
		values = append(values, intelligence.Evidence{Family: s.Family, Signal: signal, Scope: intelligence.Exact, Address: ip, SourcePublishedAt: published, ItemPublishedAt: last, Current: true})
	}
	if len(values) == 0 {
		return time.Time{}, nil, errJacobrakai
	}
	return published, values, nil
}

func verifyJacobrakaiFile(ctx context.Context, input io.Reader, s Source, now time.Time) (time.Time, error) {
	published, _, err := readJacobrakai(ctx, input, s, jacobrakaiRowLimit, false)
	if err != nil || now.IsZero() || published.After(now) {
		return time.Time{}, errJacobrakai
	}
	return published, nil
}

func parseJacobrakai(ctx context.Context, input io.Reader, s Source, published time.Time, maximum int, emit func(intelligence.NormalizedRecord) error) error {
	clock, values, err := readJacobrakai(ctx, input, s, maximum, false)
	if err != nil || published.IsZero() || !clock.Equal(published) || emit == nil {
		return errJacobrakai
	}
	for i := range values {
		if err := emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &values[i]}); err != nil {
			return err
		}
	}
	return nil
}

// Leave enough time for protected build and preview gates to finish while
// preserving each eligible item's earlier original expiry. No fetch clock is
// used as an observation, and no expiry is ever rounded or extended.
func jacobrakaiEligible(observed, intake time.Time) bool {
	return !observed.IsZero() && observed.Add(jacobrakaiWindow).After(intake.Add(jacobrakaiServeSlack))
}

func validateJacobrakaiExcerpt(ctx context.Context, input io.Reader, s Source, selected adapter, tested time.Time) (uint64, error) {
	if selected != riskAdapter || s.Fixture.PayloadFormat != jacobrakaiFixture || s.Fixture.ContentEncoding != "" && s.Fixture.ContentEncoding != "identity" {
		return 0, errJacobrakai
	}
	clock, values, err := readJacobrakai(ctx, input, s, jacobrakaiRowLimit, true)
	if err != nil || tested.IsZero() || clock.After(tested) {
		return 0, errJacobrakai
	}
	for i := range values {
		record := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &values[i]}
		if err = record.Validate(); err != nil || !jacobrakaiEligible(record.Evidence.ItemPublishedAt, tested) {
			return 0, errJacobrakai
		}
	}
	return uint64(len(values)), nil
}
