package intelligence

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
	"gopkg.in/yaml.v3"
	"vansail-ip-atlas/internal/subscription"
)

// DatasetAttribution is one reviewed global software-independent dataset credit.
// It belongs to a private source receipt and the separate global credits
// artifact. It must never be placed in normalized IP records or VIA3 objects.
type DatasetAttribution struct {
	Name       string `json:"name" yaml:"name"`
	Text       string `json:"text" yaml:"text"`
	URL        string `json:"url" yaml:"url"`
	LicenseURL string `json:"license_url,omitempty" yaml:"license_url,omitempty"`
}

func (a *DatasetAttribution) Validate() error {
	if a == nil || !creditText(a.Name, 128) || !creditText(a.Text, 2048) || !creditURL(a.URL) || a.LicenseURL != "" && !creditURL(a.LicenseURL) {
		return errors.New("reviewed dataset attribution fields invalid")
	}
	return nil
}
func creditText(value string, maximum int) bool {
	if !utf8.ValidString(value) || value == "" || len(value) > maximum*4 || utf8.RuneCountInString(value) > maximum || strings.TrimSpace(value) != value || !norm.NFC.IsNormalString(value) || creditSecret(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func creditSecret(value string) bool {
	lower := strings.ToLower(value)
	for _, literal := range []string{"vless://", "vmess://", "trojan://", "ss://", "ssr://", "hy://", "hy2://", "hysteria://", "hysteria2://", "tuic://", "anytls://", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"} {
		if strings.Contains(lower, literal) {
			return true
		}
	}
	if first := strings.Index(lower, "-----begin"); first >= 0 && strings.Contains(lower[first:], "private key-----") {
		return true
	}
	return false
}
func creditURL(value string) bool {
	if len(value) == 0 || len(value) > 2048 || !strings.HasPrefix(value, "https://") || strings.ContainsAny(value, "\\?#<>\"'") || creditSecret(value) {
		return false
	}
	for _, r := range value {
		if r <= 32 || r >= 127 {
			return false
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Port() != "" && u.Port() != "443" || strings.Contains(u.Hostname(), "%") || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if addr, err := netip.ParseAddr(u.Hostname()); err == nil {
		return subscription.Public(addr)
	}
	host := strings.ToLower(u.Hostname())
	labels := strings.Split(host, ".")
	if len(host) > 253 || len(labels) < 2 || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	legacyNumeric := true
	for _, label := range labels {
		base, atom := 10, label
		if strings.HasPrefix(atom, "0x") {
			base, atom = 16, atom[2:]
		}
		if _, err := strconv.ParseUint(atom, base, 32); err != nil {
			legacyNumeric = false
		}
	}
	if legacyNumeric {
		return false
	}
	alpha := false
	for _, r := range labels[len(labels)-1] {
		alpha = alpha || r >= 'a' && r <= 'z'
	}
	if !alpha {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func (a *DatasetAttribution) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("dataset attribution mapping required")
	}
	seen := map[string]bool{}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] || value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return errors.New("dataset attribution scalar invalid")
		}
		switch key.Value {
		case "name", "text", "url", "license_url":
		default:
			return errors.New("unknown dataset attribution field")
		}
		seen[key.Value] = true
		if value.Value == "" {
			return errors.New("empty dataset attribution field")
		}
	}
	type raw DatasetAttribution
	var value raw
	if err := node.Decode(&value); err != nil {
		return err
	}
	*a = DatasetAttribution(value)
	return a.Validate()
}
