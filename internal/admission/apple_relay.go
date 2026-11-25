package admission

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

const appleFileLimit = 32 << 20
const appleWitnessFile = "txt/apple-private-relay.txt"
const appleWitnessAPI = "https://api.github.com/repos/disposable/cloud-ip-ranges/commits"
const appleWitnessRaw = "https://raw.githubusercontent.com/disposable/cloud-ip-ranges/"

func appleRelaySource(s Source) bool {
	return s.ID == intelligence.AppleRelaySourceID && s.Family == intelligence.AppleRelaySourceID && s.Parser == (Parser{intelligence.AppleRelaySourceID, "apple-relay-egress-csv-v1", 1}) &&
		s.URL == acquire.AppleRelayURL && s.Format == "csv" && s.MaxCompressedBytes > 0 && s.MaxCompressedBytes <= appleFileLimit &&
		s.Category == "proxy" && s.Scope == "prefix" && s.Coverage == "positive_only" && fieldsEqual(s.Signals, "proxy") &&
		fieldsEqual(s.Fields, "ip") && fieldsEqual(s.PublicFields, "reason_flags") && mappedFields(s, map[string]string{"ip": "reason_flags"}) &&
		s.Publication == (Publication{"snapshot_metadata", acquire.AppleRelayURL, "egress.scope_change"})
}

func applePrefix(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.IsValid() || p.String() != raw {
		return netip.Prefix{}, intelligence.ErrAppleRelay
	}
	return p, nil
}

// Both publisher representations are parsed through EOF. City and postal columns
// are discarded at ingestion. Only the operator's explicit proxy scope survives.
func readApplePrefixes(ctx context.Context, input io.Reader, witness bool, maximum int, onPrefix func(netip.Prefix) error) (intelligence.ApplePrefixSet, time.Time, error) {
	if ctx == nil || input == nil || maximum <= 0 {
		return nil, time.Time{}, intelligence.ErrAppleRelay
	}
	limited := &io.LimitedReader{R: contextReader{ctx, input}, N: appleFileLimit + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 1024), 1024)
	var captured time.Time
	if witness {
		for _, line := range []string{"# provider: Apple Private Relay", "# category: cloud", "# source: " + acquire.AppleRelayURL} {
			if !scanner.Scan() || scanner.Text() != line {
				return nil, time.Time{}, intelligence.ErrAppleRelay
			}
		}
		if !scanner.Scan() {
			return nil, time.Time{}, intelligence.ErrAppleRelay
		}
		stamp, ok := strings.CutPrefix(scanner.Text(), "# last_update: ")
		var err error
		captured, err = time.Parse("2006-01-02T15:04:05.999999999", stamp)
		if !ok || err != nil || !scanner.Scan() || scanner.Text() != "" {
			return nil, time.Time{}, intelligence.ErrAppleRelay
		}
	}
	result := intelligence.ApplePrefixSet{}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, time.Time{}, err
		}
		line := scanner.Text()
		if witness && line == "" {
			continue
		}
		if !utf8.ValidString(line) || strings.IndexFunc(line, unicode.IsControl) >= 0 || strings.ContainsRune(line, '"') || len(result) >= maximum {
			return nil, time.Time{}, intelligence.ErrAppleRelay
		}
		raw := line
		if !witness {
			fields := strings.Split(line, ",")
			if len(fields) != 5 || len(fields[1]) != 2 || fields[1][0] < 'A' || fields[1][0] > 'Z' || fields[1][1] < 'A' || fields[1][1] > 'Z' {
				return nil, time.Time{}, intelligence.ErrAppleRelay
			}
			raw = fields[0]
		}
		p, err := applePrefix(raw)
		if err != nil || result.Insert(p) != nil {
			return nil, time.Time{}, intelligence.ErrAppleRelay
		}
		if onPrefix != nil {
			if err := onPrefix(p); err != nil {
				return nil, time.Time{}, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, time.Time{}, err
	}
	if len(result) == 0 || limited.N <= 0 {
		return nil, time.Time{}, intelligence.ErrAppleRelay
	}
	return result, captured, nil
}

func parseAppleRelay(ctx context.Context, input io.Reader, s Source, published time.Time, maximum int, emit func(intelligence.NormalizedRecord) error) error {
	if !appleRelaySource(s) || published.IsZero() || emit == nil {
		return intelligence.ErrAppleRelay
	}
	_, _, err := readApplePrefixes(ctx, input, false, maximum, func(prefix netip.Prefix) error {
		v := intelligence.Evidence{Family: s.Family, Signal: "proxy", Scope: intelligence.ExplicitPrefix, Prefix: prefix, SourcePublishedAt: published, Current: true, Weight: s.Weight}
		return emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &v})
	})
	return err
}

type appleCommit struct {
	commitMetadata
	Parents []struct{ SHA string }
}

func (e *Engine) appleWitness(ctx context.Context, dir, name, ref string) (intelligence.AppleRelayWitness, string, error) {
	var witness intelligence.AppleRelayWitness
	invalid := intelligence.ErrAppleRelay
	if ref != "master" && !commitSHA(ref) {
		return witness, "", invalid
	}
	// Using the first commit's parent as the second ref guarantees an ancestor
	// comparison even if the witness's default branch advances during intake.
	query := appleWitnessAPI + "?path=" + appleWitnessFile + "&sha=" + ref + "&per_page=1"
	meta := filepath.Join(dir, "apple-"+name+"-commit")
	if _, err := e.fetch.Fetch(ctx, query, meta, 1<<20); err != nil {
		return witness, "", err
	}
	data, err := boundedFile(ctx, meta, 1<<20)
	if err != nil {
		return witness, "", err
	}
	var rows []appleCommit
	if uniqueJSON(data) != nil || json.Unmarshal(data, &rows) != nil || len(rows) != 1 {
		return witness, "", invalid
	}
	m := rows[0]
	if !commitSHA(m.SHA) || len(m.Parents) != 1 || !commitSHA(m.Parents[0].SHA) || m.SHA == m.Parents[0].SHA || m.URL != appleWitnessAPI+"/"+m.SHA || m.Commit.Author.Date != m.Commit.Committer.Date {
		return witness, "", invalid
	}
	witness.Commit = m.SHA
	witness.CommittedAt, err = timestamp(m.Commit.Committer.Date)
	if err != nil {
		return witness, "", err
	}
	path := filepath.Join(dir, "apple-"+name+"-prefixes")
	if _, err = e.fetch.Fetch(ctx, appleWitnessRaw+m.SHA+"/"+appleWitnessFile, path, appleFileLimit); err != nil {
		return witness, "", err
	}
	input, err := os.Open(path)
	if err != nil {
		return witness, "", err
	}
	defer input.Close()
	h := sha256.New()
	prefixes, captured, err := readApplePrefixes(ctx, io.TeeReader(input, h), true, intelligence.AppleRelayMaxPrefixes, nil)
	if err != nil {
		return witness, "", err
	}
	copy(witness.FileHash[:], h.Sum(nil))
	witness.Prefixes = len(prefixes)
	witness.PrefixHash = prefixes.Hash()
	witness.CapturedAt = captured
	return witness, m.Parents[0].SHA, nil
}

func (e *Engine) fetchAppleRelay(ctx context.Context, path string, s Source, now time.Time) (*intelligence.AppleRelayProof, error) {
	clockVerifier, ok := e.fetch.(interface {
		VerifyAppleRelayClock(context.Context, string, int64) (time.Time, error)
	})
	if !ok || !appleRelaySource(s) {
		return nil, intelligence.ErrAppleRelay
	}
	original, err := e.fetch.Fetch(ctx, acquire.AppleRelayURL, path, s.MaxCompressedBytes)
	if err != nil {
		return nil, err
	}
	edition, err := clockVerifier.VerifyAppleRelayClock(ctx, original.ETag, original.Bytes)
	if err != nil {
		return nil, err
	}
	if edition.After(now) {
		return nil, intelligence.ErrAppleRelay
	}
	proof := &intelligence.AppleRelayProof{Edition: edition, ETag: original.ETag, Bytes: original.Bytes}
	input, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	h := sha256.New()
	prefixes, _, err := readApplePrefixes(ctx, io.TeeReader(input, h), false, intelligence.AppleRelayMaxPrefixes, nil)
	if err != nil {
		return nil, err
	}
	copy(proof.PayloadHash[:], h.Sum(nil))
	var parent string
	proof.After, parent, err = e.appleWitness(ctx, filepath.Dir(path), "after", "master")
	if err != nil {
		return nil, err
	}
	if len(prefixes) != proof.After.Prefixes || prefixes.Hash() != proof.After.PrefixHash {
		return nil, intelligence.ErrAppleRelay
	}
	proof.Before, _, err = e.appleWitness(ctx, filepath.Dir(path), "before", parent)
	if err != nil {
		return nil, err
	}
	return proof, proof.Validate(now, edition, proof.PayloadHash)
}
