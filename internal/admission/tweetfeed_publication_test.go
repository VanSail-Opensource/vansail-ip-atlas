package admission

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTweetFeedImmutableEditions(t *testing.T) {
	child := strings.Repeat("a", 40)
	parent := strings.Repeat("b", 40)
	grandparent := strings.Repeat("c", 40)
	first := []byte(tweetTestRow)
	second := []byte(strings.Replace(tweetTestRow, "1.1.1.1", "8.8.8.8", 1))
	other := []byte(strings.Replace(tweetTestRow, "1.1.1.1", "9.9.9.9", 1))
	before := "2026-11-03T07:15:00Z"
	after := "2026-11-03T07:30:00Z"
	manifest := func(data []byte, stamp string) []byte {
		return fmt.Appendf(nil, `{"schema_version":1,"generated_at":%q,"artifacts":[{"name":"week.csv","path":"week.csv","format":"csv","window":"week","url":%q,"rows":1,"bytes":%d,"sha256":"%x","updated_at":%q}]}`, stamp, tweetFeedOrigin, len(data), sha256.Sum256(data), stamp)
	}
	commit := func(sha, parent, date string) []byte {
		return fmt.Appendf(nil, `[{"sha":%q,"url":%q,"parents":[{"sha":%q,"url":%q}],"commit":{"committer":{"date":%q}}}]`, sha, tweetCommitAPI+"/"+sha, parent, tweetCommitAPI+"/"+parent, date)
	}
	masterAPI := tweetCommitAPI + "?path=week.csv&sha=master&per_page=1"
	parentAPI := tweetCommitAPI + "?path=week.csv&sha=" + parent + "&per_page=1"
	childFiles := tweetImmutableBase + child + "/"
	parentFiles := tweetImmutableBase + parent + "/"
	for _, tc := range []struct {
		name      string
		cutoff    string
		live      []byte
		modify    func(map[string][]byte)
		want      []byte
		wantDate  string
		wantCalls int
	}{
		{"matching CDN uses original publication clock without another CSV", "2026-11-03T07:36:00Z", manifest(second, "2026-11-03T07:35:00Z"), func(a map[string][]byte) {
			a[tweetFeedCSV] = second
			delete(a, childFiles+"week.csv")
		}, second, after, 4},
		{"matching origin uses the same immutable clock", "2026-11-03T07:36:00Z", manifest(second, "2026-11-03T07:35:00Z"), func(a map[string][]byte) {
			a[tweetFeedOrigin] = second
			delete(a, childFiles+"week.csv")
		}, second, after, 5},
		{"matching local bytes can bind the earlier weekly revision", "2026-11-03T07:36:00Z", manifest(first, "2026-11-03T07:20:00Z"), func(a map[string][]byte) {
			a[tweetFeedCSV] = first
			delete(a, parentFiles+"week.csv")
		}, first, before, 6},
		{"new digest during metadata outage cannot renew matching bytes", "2026-11-03T07:36:00Z", manifest(second, "2026-11-03T07:35:00Z"), func(a map[string][]byte) {
			a[tweetFeedCSV] = second
			delete(a, masterAPI)
		}, nil, "", 3},
		{"expired original cannot use a later matching heartbeat", "2026-12-03T07:30:00Z", manifest(second, "2026-12-03T07:29:00Z"), func(a map[string][]byte) {
			a[tweetFeedCSV] = second
		}, nil, "", 4},
		{"all rows must predate the earliest bound publication", "2026-11-03T07:36:00Z", manifest(second, "2026-11-03T07:35:00Z"), func(a map[string][]byte) {
			a[tweetFeedCSV] = second
			a[childFiles+"manifest.json"] = manifest(second, "2026-11-01T11:59:59Z")
		}, nil, "", 4},
		{"head matches live after both mutable copies differ", "2026-11-03T07:35:00Z", manifest(second, after), nil, second, after, 6},
		{"matching previous edition after live falls behind git", "2026-11-03T07:35:00Z", manifest(first, before), nil, first, before, 8},
		{"post-clock update anchored to child uses only its earlier original parent", "2026-11-03T07:28:00Z", manifest(second, after), nil, first, before, 6},
		{"select original CSV change behind a manifest-only parent", "2026-11-03T07:28:00Z", manifest(second, after), func(a map[string][]byte) {
			a[parentAPI] = commit(grandparent, strings.Repeat("d", 40), "2026-11-03T07:00:01Z")
			a[tweetImmutableBase+grandparent+"/manifest.json"] = manifest(first, "2026-11-03T07:00:00Z")
			a[tweetImmutableBase+grandparent+"/week.csv"] = first
		}, first, "2026-11-03T07:00:00Z", 7},
		{"refuse ancestor with unrelated parent tree", "2026-11-03T07:28:00Z", manifest(second, after), func(a map[string][]byte) {
			a[parentAPI] = commit(grandparent, strings.Repeat("d", 40), "2026-11-03T07:00:01Z")
			a[tweetImmutableBase+grandparent+"/manifest.json"] = manifest(other, "2026-11-03T07:00:00Z")
			a[tweetImmutableBase+grandparent+"/week.csv"] = other
		}, nil, "", -1},
		{"later manifest heartbeat can attest the immutable earlier original", "2026-11-03T07:33:00Z", manifest(second, "2026-11-03T07:35:00Z"), nil, second, after, 4},
		{"future CSV with unrelated immutable child refuses predecessor", "2026-11-03T07:28:00Z", manifest(other, after), nil, nil, "", -1},
		{"parent crossing cutoff cannot attest earlier payload", "2026-11-03T07:14:00Z", manifest(second, after), nil, nil, "", -1},
		{"parent exceeds freshness window", "2026-12-03T07:28:00Z", manifest(second, "2026-12-03T07:30:00Z"), func(a map[string][]byte) {
			a[childFiles+"manifest.json"] = manifest(second, "2026-12-03T07:30:00Z")
			a[masterAPI] = commit(child, parent, "2026-12-03T07:30:01Z")
		}, nil, "", -1},
		{"wrong canonical parent repository", "2026-11-03T07:28:00Z", manifest(second, after), func(a map[string][]byte) {
			a[masterAPI] = []byte(strings.Replace(string(a[masterAPI]), tweetCommitAPI+"/"+parent, "https://other.invalid/"+parent, 1))
		}, nil, "", -1},
		{"unrelated ancestor with no matching parent manifest fails", "2026-11-03T07:28:00Z", manifest(second, after), func(a map[string][]byte) { a[parentAPI] = commit(grandparent, parent, before) }, nil, "", -1},
		{"malformed anchor metadata", "2026-11-03T07:28:00Z", manifest(second, after), func(a map[string][]byte) { a[masterAPI] = []byte(`[{"sha":"bad","sha":"bad"}]`) }, nil, "", -1},
		{"different original payload", "2026-11-03T07:35:00Z", manifest(second, after), func(a map[string][]byte) { a[childFiles+"week.csv"] = other }, nil, "", -1},
		{"live manifest rejected before archive fetch", "2026-11-03T07:28:00Z", []byte(`{"schema_version":1}`), nil, nil, "", 1},
		{"do not consult history for missing assets without clock or edition mismatch", "2026-11-03T07:35:00Z", manifest(second, after), func(a map[string][]byte) { delete(a, tweetFeedCSV); delete(a, tweetFeedOrigin) }, nil, "", 3},
		{"earliest matching original publication controls item clock", "2026-11-03T07:35:00Z", manifest(first, "2026-11-03T07:19:00Z"), nil, first, before, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assets := map[string][]byte{tweetFeedManifest: tc.live, tweetFeedCSV: other, tweetFeedOrigin: other, masterAPI: commit(child, parent, "2026-11-03T07:30:01Z"), parentAPI: commit(parent, grandparent, "2026-11-03T07:15:01Z"), childFiles + "manifest.json": manifest(second, after), parentFiles + "manifest.json": manifest(first, before), childFiles + "week.csv": second, parentFiles + "week.csv": first}
			if tc.modify != nil {
				tc.modify(assets)
			}
			f := &fixtureFetch{assets: assets}
			engine := &Engine{fetch: f}
			now, err := time.Parse(time.RFC3339, tc.cutoff)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "payload")
			stamp, err := engine.fetchTweetFeed(context.Background(), path, tweetTestSource(), now)
			if tc.wantCalls >= 0 && f.calls != tc.wantCalls {
				t.Fatalf("%d calls want %d", f.calls, tc.wantCalls)
			}
			if tc.want == nil {
				if err == nil {
					t.Fatal("unattested edition accepted")
				}
				return
			}
			got, readErr := os.ReadFile(path)
			if err != nil || readErr != nil || stamp.After(now) || stamp.Format(time.RFC3339) != tc.wantDate || string(got) != string(tc.want) {
				t.Fatal(stamp, err, readErr)
			}
		})
	}
}
