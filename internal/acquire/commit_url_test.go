package acquire

import "testing"

func TestGitHubCommitMetadataURLIsNarrowlyBounded(t *testing.T) {
	good := "https://api.github.com/repos/unit/publisher/commits?path=data%2Fvrp.csv&sha=main&per_page=1"
	if _, ok := ParseGitHubCommitURL(good); !ok || !validURL(good) {
		t.Fatal("bounded path-filtered metadata URL rejected")
	}
	for _, raw := range []string{
		"https://api.github.com/repos/unit/publisher/commits?path=vrp.csv&sha=main&per_page=2",
		"https://api.github.com/repos/unit/publisher/commits?path=vrp.csv&sha=main&per_page=1&token=secret",
		"https://api.github.com/repos/unit/publisher/commits?path=vrp.csv&path=other.csv&sha=main&per_page=1",
		"https://api.github.com/repos/unit/publisher/commits?path=..%2Fvrp.csv&sha=main&per_page=1",
		"https://api.github.com/repos/unit/publisher/commits?path=%2Fvrp.csv&sha=main&per_page=1",
		"https://api.github.com/repos/unit/publisher/commits?path=vrp.csv&sha=refs%2Fheads%2Fmain&per_page=1",
		"https://api.github.com/repos/unit/publisher/commits?path=vrp.csv&sha=main&per_page=1#fragment",
		"https://api.github.com:443/repos/unit/publisher/commits?path=vrp.csv&sha=main&per_page=1",
		"https://elsewhere.example/repos/unit/publisher/commits?path=vrp.csv&sha=main&per_page=1",
		"https://api.github.com/repos/unit/publisher/commits?path=%ff&sha=main&per_page=1",
		"https://api.github.com/repos/unit/publisher/commits?path=vrp.csv&sha=main&per_page=1;extra=1",
	} {
		if _, ok := ParseGitHubCommitURL(raw); ok || validURL(raw) {
			t.Fatalf("unbounded query accepted: %s", raw)
		}
	}
}
