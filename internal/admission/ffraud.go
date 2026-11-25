package admission

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

const (
	ffraudByteLimit = 64 << 20
	ffraudRowLimit  = 5_000_000
	ffraudHeader    = "ip,ffraud_score,confirmations,category,type"
)

func selectFFraudAdapter(s Source) bool {
	return s.Parser.Version == 2 && s.Parser.Schema == "ffraud-five-column-risk-csv-v2" && s.Format == "csv" &&
		fieldsEqual(s.Fields, "ip", "ffraud_score", "confirmations", "category", "type") &&
		fieldsEqual(s.Signals, "abuse", "botnet", "c2", "datacenter", "fraud", "malware", "proxy", "scanner", "spam", "tor", "vpn") &&
		mappedFields(s, map[string]string{"ip": "reason_flags", "category": "reason_flags", "type": "reason_flags"})
}

func ffraudSignal(label string) (intelligence.Signal, bool) {
	switch label {
	case "c2", "malware", "botnet", "scanner", "spam":
		return intelligence.Signal(label), true
	case "phishing":
		return intelligence.Signal("fraud"), true
	case "brute_force", "web_attack", "abuse":
		return intelligence.Signal("abuse"), true
	default:
		return "", false
	}
}

// FFraud publishes an unquoted, five-column CSV. Additional columns (including
// future item dates), quoted/multiline values and unknown classifications require
// a reviewed schema version; they are never silently discarded. Scores and report
// counts are validated as publisher metadata, not calibrated weights or votes.
func scanFFraud(ctx context.Context, input io.Reader, maximum int, emit func(netip.Addr, intelligence.Signal) error) (int, error) {
	if ctx == nil || input == nil || maximum <= 0 || maximum > ffraudRowLimit {
		return 0, errors.New("bounded FFraud reader required")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	limited := &io.LimitedReader{R: contextReader{ctx, input}, N: ffraudByteLimit + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), 4096)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if atEOF && len(data) > 0 && bytes.IndexByte(data, '\n') < 0 {
			return 0, nil, errors.New("FFraud final row is incomplete")
		}
		return bufio.ScanLines(data, atEOF)
	})
	header := false
	rows := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return rows, err
		}
		line := scanner.Text()
		if !utf8.ValidString(line) || strings.ContainsAny(line, "\x00\r\t") {
			return rows, errors.New("FFraud row encoding invalid")
		}
		if !header {
			if strings.HasPrefix(line, "# ") {
				continue
			}
			if line != ffraudHeader {
				return rows, errors.New("FFraud CSV header changed")
			}
			header = true
			continue
		}
		rows++
		if rows > maximum {
			return rows, errors.New("FFraud input row budget exceeded")
		}
		var fields [5]string
		tail := line
		for i := 0; i < 4; i++ {
			var ok bool
			fields[i], tail, ok = strings.Cut(tail, ",")
			if !ok {
				return rows, errors.New("FFraud five-column framing invalid")
			}
		}
		fields[4] = tail
		if strings.ContainsAny(tail, ",\"") {
			return rows, errors.New("FFraud five-column framing invalid")
		}
		address, err := netip.ParseAddr(fields[0])
		if err != nil || address.Zone() != "" || strings.TrimSpace(fields[0]) != fields[0] {
			return rows, errors.New("FFraud IP literal invalid")
		}
		score, e1 := strconv.ParseUint(fields[1], 10, 8)
		confirmations, e2 := strconv.ParseUint(fields[2], 10, 32)
		signal, known := ffraudSignal(fields[3])
		if e1 != nil || e2 != nil || score < 50 || score > 100 || confirmations < 2 || strconv.FormatUint(score, 10) != fields[1] || strconv.FormatUint(confirmations, 10) != fields[2] || !known {
			return rows, errors.New("FFraud observation fields invalid")
		}
		switch fields[4] {
		case "", "proxy", "vpn", "tor", "datacenter", "mobile":
		default:
			return rows, errors.New("FFraud infrastructure label changed")
		}
		address = address.Unmap()
		if subscription.Public(address) && emit != nil {
			if err = emit(address, signal); err != nil {
				return rows, err
			}
			// This column is the publisher's explicit classification of this IP,
			// not an ASN/cloud-owner inference. It supplies another reason under
			// the same family and snapshot clock, never another independent vote.
			switch fields[4] {
			case "proxy", "vpn", "tor", "datacenter":
				if err = emit(address, intelligence.Signal(fields[4])); err != nil {
					return rows, err
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return rows, err
	}
	if err := scanner.Err(); err != nil {
		return rows, errors.New("FFraud bounded row framing invalid")
	}
	if limited.N <= 0 {
		return rows, errors.New("FFraud byte budget exceeded")
	}
	if !header || rows == 0 {
		return rows, errors.New("FFraud snapshot has no rows")
	}
	return rows, nil
}

func parseFFraudPayload(ctx context.Context, input io.Reader, s Source, published time.Time, maximum int, emit func(intelligence.NormalizedRecord) error) error {
	emitted := 0
	_, err := scanFFraud(ctx, input, min(maximum, ffraudRowLimit), func(address netip.Addr, signal intelligence.Signal) error {
		emitted++
		if emitted > maximum {
			return errors.New("FFraud normalized record budget exceeded")
		}
		value := intelligence.Evidence{Family: s.Family, Signal: signal, Scope: intelligence.Exact, Address: address, SourcePublishedAt: published, Current: true}
		return emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &value})
	})
	if err == nil && emitted == 0 {
		return errors.New("FFraud snapshot has no public observations")
	}
	return err
}

func ffraudCommitSource(s Source) bool {
	q, ok := commitSource(s.Publication.Locator, s.URL)
	return ok && q.Owner == "FFraud-com" && q.Repository == "ip-fraud-database" && q.Ref == "main" && q.Path == "threat-ips/confirmed-abusive.csv" && s.Publication.Kind == "github_commit" && s.Publication.Field == "commit.committer.date"
}

// Called only after the normal commit verifier independently downloaded the
// immutable CSV and matched its complete SHA-256 and byte count. Metadata from
// that same immutable commit binds its generated time and full input row count.
// A current commit, live_utc value or repeated download cannot renew an older
// generated_utc clock. No arbitrary metadata URL is accepted from the payload.
func (e *Engine) verifyFFraudGeneration(ctx context.Context, quarantine, sha, payload string, published time.Time) (time.Time, error) {
	deny := errors.New("FFraud publication proof rejected")
	if !commitSHA(sha) {
		return time.Time{}, deny
	}
	metadataPath := filepath.Join(quarantine, "ffraud-metadata")
	metadataURL := "https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/" + sha + "/metadata.json"
	if _, err := e.fetch.Fetch(ctx, metadataURL, metadataPath, 1<<20); err != nil {
		return time.Time{}, deny
	}
	data, err := boundedFile(ctx, metadataPath, 1<<20)
	if err != nil || uniqueJSON(data) != nil {
		return time.Time{}, deny
	}
	var metadata struct {
		Project      string `json:"project"`
		GeneratedUTC string `json:"generated_utc"`
		Counts       struct {
			ConfirmedAbusiveIPs uint64 `json:"confirmed_abusive_ips"`
		} `json:"counts"`
	}
	if json.Unmarshal(data, &metadata) != nil || metadata.Project != "ip-fraud-database" || metadata.Counts.ConfirmedAbusiveIPs == 0 || metadata.Counts.ConfirmedAbusiveIPs > ffraudRowLimit {
		return time.Time{}, deny
	}
	generated, err := timestamp(metadata.GeneratedUTC)
	if err != nil || generated.After(published) {
		return time.Time{}, deny
	}
	file, err := os.Open(payload)
	if err != nil {
		return time.Time{}, deny
	}
	defer file.Close()
	rows, err := scanFFraud(ctx, file, ffraudRowLimit, nil)
	if err != nil || uint64(rows) != metadata.Counts.ConfirmedAbusiveIPs {
		return time.Time{}, deny
	}
	return generated, nil
}
