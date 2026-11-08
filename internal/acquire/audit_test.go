package acquire

import "testing"

func TestStrictURLDelimitersAndLegacyNumericHosts(t *testing.T) {
	for _, raw := range []string{
		"https://example.com:/data", "https://example.com/data?", "https://example.com/data#",
		"https://0x7f.0.0.1/data", "https://0x7f.1/data", "https://0177.0.0.1/data",
		"https://node.local/data", "https://node.internal/data", "https://node.localhost/data",
	} {
		if validURL(raw) {
			t.Fatal("ambiguous, local or noncanonical download URL accepted")
		}
	}
	for _, raw := range []string{"https://example.com/data.csv", "https://8.8.8.8/data.csv", "https://[2606:4700:4700::1111]:443/data.csv"} {
		if !validURL(raw) {
			t.Fatal("ordinary HTTPS bulk URL rejected")
		}
	}
}
