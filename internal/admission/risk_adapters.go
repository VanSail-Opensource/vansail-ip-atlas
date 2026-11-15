package admission

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

// These adapters recognize observed publisher schemas. They do not certify
// redistribution rights, upstream independence, freshness or assessment coverage.
func selectRiskAdapter(s Source) bool {
	if s.Parser.Version != 1 || s.Category != "abuse" || s.Coverage != "positive_only" || s.Scope != "exact_ip" || !fieldsEqual(s.PublicFields, "reason_flags") {
		return false
	}
	switch s.Parser.ID {
	case "ip-count-tsv":
		return s.Parser.Schema == "ip-positive-count-tsv-v1" && s.Format == "tsv" && fieldsEqual(s.Signals, "abuse") && mappedFields(s, map[string]string{"ip": "reason_flags"})
	case "feodo-csv":
		if s.Parser.Schema != "feodo-six-column-csv-v1" || s.Format != "csv" && s.Format != "csv-gz" || len(s.Signals) == 0 || len(s.Signals) > 3 || !mappedFields(s, map[string]string{"dst_ip": "reason_flags"}) {
			return false
		}
		seen := map[string]bool{}
		for _, signal := range s.Signals {
			if seen[signal] || signal != "c2" && signal != "botnet" && signal != "malware" {
				return false
			}
			seen[signal] = true
		}
		return true
	}
	return false
}

// parseRiskPayload emits only literal public IP evidence. Counts are discarded,
// never weights or additional families; ports and labels never enter records.
// Feodo's last_online date is retained conservatively at UTC start of day. The
// caller must revalidate its age against the actual evaluation clock and abort
// the transactional sink on a later completeness/schema error.
func parseRiskPayload(ctx context.Context, input io.Reader, s Source, published time.Time, maximum int, emit func(intelligence.NormalizedRecord) error) error {
	if ctx == nil || input == nil || published.IsZero() || !selectRiskAdapter(s) || emit == nil || maximum <= 0 || maximum > 100_000_000 {
		return errors.New("bounded supported positive risk schema required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r := &io.LimitedReader{R: contextReader{ctx, input}, N: (3 << 30) + 1}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	rows, records := 0, 0
	header, complete := false, false
	emitIP := func(literal string, observed time.Time) error {
		address, err := netip.ParseAddr(literal)
		if err != nil || address.Zone() != "" || strings.TrimSpace(literal) != literal {
			return errors.New("risk feed IP literal invalid")
		}
		address = address.Unmap()
		if !subscription.Public(address) {
			return nil
		}
		for _, signal := range s.Signals {
			records++
			if records > maximum {
				return errors.New("risk normalized record budget exceeded")
			}
			value := intelligence.Evidence{Family: s.Family, Signal: intelligence.Signal(signal), Scope: intelligence.Exact, Address: address, SourcePublishedAt: published, ItemPublishedAt: observed, Current: true}
			if err := emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &value}); err != nil {
				return err
			}
		}
		return nil
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Text()
		if !utf8.ValidString(line) {
			return errors.New("risk feed UTF-8 invalid")
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if s.Parser.ID == "feodo-csv" && strings.HasPrefix(line, "# END ") {
				count := strings.TrimSuffix(strings.TrimPrefix(line, "# END "), " entries")
				n, err := strconv.ParseUint(count, 10, 32)
				if err != nil || !header || complete || uint64(rows) != n || line != "# END "+count+" entries" {
					return errors.New("Feodo completeness footer invalid")
				}
				complete = true
			}
			continue
		}
		if complete {
			return errors.New("risk rows follow completeness footer")
		}
		if s.Parser.ID == "ip-count-tsv" {
			rows++
			if rows > maximum {
				return errors.New("risk input row budget exceeded")
			}
			fields := strings.Split(line, "\t")
			if len(fields) != 2 || fields[1] == "" || strings.TrimSpace(fields[1]) != fields[1] {
				return errors.New("risk count TSV schema invalid")
			}
			count, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil || count == 0 {
				return errors.New("risk positive count invalid")
			}
			if err = emitIP(fields[0], time.Time{}); err != nil {
				return err
			}
			continue
		}
		reader := csv.NewReader(strings.NewReader(line))
		reader.FieldsPerRecord = 6
		fields, err := reader.Read()
		if err != nil {
			return errors.New("Feodo CSV six-column schema invalid")
		}
		if _, err = reader.Read(); err != io.EOF {
			return errors.New("Feodo CSV row framing invalid")
		}
		if !header {
			if strings.Join(fields, "\t") != "first_seen_utc\tdst_ip\tdst_port\tc2_status\tlast_online\tmalware" {
				return errors.New("Feodo CSV header changed")
			}
			header = true
			continue
		}
		rows++
		if rows > maximum {
			return errors.New("risk input row budget exceeded")
		}
		firstSeen, e1 := time.Parse("2006-01-02 15:04:05", fields[0])
		lastOnline, e2 := time.Parse("2006-01-02", fields[4])
		port, e3 := strconv.ParseUint(fields[2], 10, 16)
		if e1 != nil || e2 != nil || e3 != nil || firstSeen.Unix() <= 0 || lastOnline.Unix() <= 0 || !firstSeen.Before(lastOnline.Add(24*time.Hour)) || port == 0 || fields[3] != "online" && fields[3] != "offline" || fields[5] == "" || len(fields[5]) > 128 || !safePlace(fields[5]) {
			return errors.New("Feodo typed observation fields invalid")
		}
		if err = emitIP(fields[1], lastOnline); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanner.Err(); err != nil {
		return errors.New("risk feed exceeds bounded line framing")
	}
	if r.N <= 0 {
		return errors.New("risk decoded byte budget exceeded")
	}
	if records == 0 || s.Parser.ID == "feodo-csv" && (!header || !complete) {
		return errors.New("risk feed incomplete or contains no accepted observations")
	}
	return nil
}
