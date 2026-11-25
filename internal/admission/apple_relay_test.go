package admission

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

func appleSampleSource() Source {
	return Source{ID: intelligence.AppleRelaySourceID, Family: intelligence.AppleRelaySourceID, Parser: Parser{intelligence.AppleRelaySourceID, "apple-relay-egress-csv-v1", 1}, URL: acquire.AppleRelayURL, Format: "csv", MaxCompressedBytes: appleFileLimit, Category: "proxy", Scope: "prefix", Coverage: "positive_only", Signals: []string{"proxy"}, Fields: []string{"ip"}, PublicFields: []string{"reason_flags"}, FieldMappings: map[string][]string{"ip": {"reason_flags"}}, Publication: Publication{"snapshot_metadata", acquire.AppleRelayURL, "egress.scope_change"}, Weight: 70, MaxAge: 720 * time.Hour}
}
func TestApplePositivePrefixesKeepScopeAndIgnoreGeography(t *testing.T) {
	s := appleSampleSource()
	clock := time.Date(2026, 11, 19, 15, 46, 45, 0, time.UTC)
	raw := "172.224.226.0/27,GB,GB-EN,London,\n2a02:26f7:b000:4000::/64,US,US-AK,Anchorage,\n"
	set := intelligence.ApplePrefixSet{}
	err := parseAppleRelay(context.Background(), strings.NewReader(raw), s, clock, 8, func(row intelligence.NormalizedRecord) error {
		if err := row.Validate(); err != nil {
			return err
		}
		if row.Geo != nil || row.Usage != nil || row.Evidence.Scope != intelligence.ExplicitPrefix || row.Evidence.Family != intelligence.AppleRelaySourceID {
			t.Fatal("unexpected non-proxy projection")
		}
		return set.Add(row, clock, s.Weight)
	})
	if err != nil || len(set) != 2 {
		t.Fatalf("scope parse: %v/%d", err, len(set))
	}
	witness := "# provider: Apple Private Relay\n# category: cloud\n# source: " + acquire.AppleRelayURL + "\n# last_update: 2026-11-20T05:43:31.557754\n\n2a02:26f7:b000:4000::/64\n172.224.226.0/27\n"
	other, observed, err := readApplePrefixes(context.Background(), strings.NewReader(witness), true, 8, nil)
	if err != nil || observed.Before(clock) || other.Hash() != set.Hash() {
		t.Fatal("differently ordered projections differ")
	}
	for _, tail := range []string{"172.224.226.0/27,GB,GB-EN,London,\n", "172.224.226.1/27,GB,,London,\n", "192.168.0.0/16,GB,,,\n", "172.224.225.0/29,G1,,,\n", "172.224.225.0/29,GB,,,extra,extra\n", "www.apple.com,GB,,,\n", "\x00,GB,,,\n", "172.224.225.0/29,GB,,\"x,y\",\n"} {
		if _, _, err := readApplePrefixes(context.Background(), strings.NewReader(raw+tail), false, 8, nil); err == nil {
			t.Fatalf("accepted invalid suffix %q", tail)
		}
	}
	for _, bad := range []string{strings.Replace(witness, "Apple Private Relay", "unrelated", 1), strings.Replace(witness, "icloud.com", "example.org", 1), strings.Replace(witness, "2026-11-20", "garbage", 1), witness + "10.0.0.0/8\n"} {
		if _, _, err := readApplePrefixes(context.Background(), strings.NewReader(bad), true, 8, nil); err == nil {
			t.Fatal("invalid witness accepted")
		}
	}
}

type appleTestOrigin struct {
	*fixtureFetch
	edition time.Time
}

func (origin appleTestOrigin) Fetch(ctx context.Context, url, path string, limit int64) (acquire.Result, error) {
	r, err := origin.fixtureFetch.Fetch(ctx, url, path, limit)
	if url == acquire.AppleRelayURL {
		r.ETag = fmt.Sprintf("\"%x-%x\"", origin.edition.Unix(), r.Bytes)
	}
	return r, err
}
func (origin appleTestOrigin) VerifyAppleRelayClock(_ context.Context, tag string, size int64) (time.Time, error) {
	if tag != fmt.Sprintf("\"%x-%x\"", origin.edition.Unix(), size) {
		return time.Time{}, acquire.ErrFetch
	}
	return origin.edition, nil
}

func TestAppleWitnessMustBracketAnActualEqualScope(t *testing.T) {
	clock := time.Date(2026, 11, 19, 15, 46, 45, 0, time.UTC)
	after, before, parent := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	query := func(ref string) string {
		return appleWitnessAPI + "?path=" + appleWitnessFile + "&sha=" + ref + "&per_page=1"
	}
	meta := func(sha, parent, clock string) string {
		return fmt.Sprintf(`[{"sha":"%s","url":"%s/%s","parents":[{"sha":"%s"}],"commit":{"author":{"date":"%s"},"committer":{"date":"%s"}}}]`, sha, appleWitnessAPI, sha, parent, clock, clock)
	}
	header := "# provider: Apple Private Relay\n# category: cloud\n# source: " + acquire.AppleRelayURL + "\n# last_update: "
	old := "172.224.226.0/27\n"
	newSet := old + "2a02:26f7:b000:4000::/64\n"
	for _, broken := range []string{"", "same-scope", "different-new-set", "mixed-origin", "witness-before-change", "missing-before", "missing-current"} {
		t.Run(broken, func(t *testing.T) {
			original := appleWitnessRaw + after + "/" + appleWitnessFile
			older := appleWitnessRaw + before + "/" + appleWitnessFile
			assets := map[string][]byte{
				acquire.AppleRelayURL: []byte("172.224.226.0/27,GB,GB-EN,London,\n2a02:26f7:b000:4000::/64,US,US-AK,Anchorage,\n"),
				query("master"):       []byte(meta(after, parent, "2026-11-20T06:00:00Z")),
				query(parent):         []byte(meta(before, strings.Repeat("d", 40), "2026-11-19T06:00:00Z")),
				original:              []byte(header + "2026-11-20T05:45:00\n\n" + newSet),
				older:                 []byte(header + "2026-11-19T05:45:00\n\n" + old),
			}
			switch broken {
			case "same-scope":
				assets[older] = []byte(header + "2026-11-19T05:45:00\n\n" + newSet)
			case "different-new-set":
				assets[original] = []byte(header + "2026-11-20T05:45:00\n\n" + old + "2a02:26f7:b001:4000::/64\n")
			case "mixed-origin":
				assets[original] = []byte(strings.ReplaceAll(string(assets[original]), acquire.AppleRelayURL, "https://example.org/elsewhere.csv"))
			case "witness-before-change":
				assets[original] = []byte(header + "2026-11-19T13:44:00\n\n" + newSet)
			case "missing-before":
				delete(assets, older)
			case "missing-current":
				delete(assets, original)
			}
			e := Engine{fetch: appleTestOrigin{&fixtureFetch{assets: assets}, clock}}
			p, err := e.fetchAppleRelay(context.Background(), filepath.Join(t.TempDir(), "original"), appleSampleSource(), clock.Add(7*24*time.Hour))
			if broken == "" {
				if err != nil || p.After.Prefixes != 2 || p.Before.Prefixes != 1 {
					t.Fatalf("valid edition rejected %v", err)
				}
			} else if err == nil {
				t.Error("unwitnessed or unchanged edition accepted")
			}
		})
	}
}
