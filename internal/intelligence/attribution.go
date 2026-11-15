package intelligence

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"image/png"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
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
	Name       string       `json:"name" yaml:"name"`
	Text       string       `json:"text" yaml:"text"`
	URL        string       `json:"url" yaml:"url"`
	LicenseURL string       `json:"license_url,omitempty" yaml:"license_url,omitempty"`
	Logo       *DatasetLogo `json:"logo,omitempty" yaml:"logo,omitempty"`
}

type DatasetLogo struct {
	Path   string `json:"path" yaml:"path"`
	SHA256 string `json:"sha256" yaml:"sha256"`
	Alt    string `json:"alt" yaml:"alt"`
}

func (l *DatasetLogo) Validate() error {
	if l == nil || len(l.SHA256) != 64 || strings.ToLower(l.SHA256) != l.SHA256 || l.Path != "/_atlas/legal/"+l.SHA256+".png" || !creditText(l.Alt, 128) {
		return errors.New("reviewed dataset logo invalid")
	}
	if _, err := hex.DecodeString(l.SHA256); err != nil {
		return errors.New("reviewed dataset logo digest invalid")
	}
	return nil
}

// A reviewed logo is a bounded local PNG. It is never fetched by a lookup from
// a publisher origin, and source receipts bind its exact content digest.
func ValidateDatasetLogoFile(workspace string, logo *DatasetLogo) error {
	if logo == nil {
		return nil
	}
	if err := logo.Validate(); err != nil {
		return err
	}
	path, err := filepath.Abs(filepath.Join(workspace, "fixtures", "source-certification", "logos", logo.SHA256+".png"))
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("reviewed dataset logo file unavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (256<<10)+1))
	if err != nil || len(data) > 256<<10 {
		return errors.New("dataset logo byte limit")
	}
	return ValidateDatasetLogoBytes(data, logo.SHA256)
}

// Legal artwork uses a closed PNG subset: non-interlaced 8-bit grayscale/RGB
// with optional alpha. One bounded symmetric physical-density chunk may precede
// consecutive IDAT chunks; text, profiles and other metadata remain forbidden.
func ValidateDatasetLogoBytes(data []byte, digest string) error {
	deny := errors.New("invalid dataset logo PNG")
	actual := sha256.Sum256(data)
	if len(data) > 256<<10 || len(data) < 45 || hex.EncodeToString(actual[:]) != digest || !bytes.Equal(data[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) {
		return deny
	}
	pos, stage := 8, 0
	physicalDensity := false
	for pos+12 <= len(data) {
		size := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		if size > 256<<10 || size > len(data)-pos-12 {
			return deny
		}
		kind := string(data[pos+4 : pos+8])
		body := data[pos+8 : pos+8+size]
		if crc32.ChecksumIEEE(data[pos+4:pos+8+size]) != binary.BigEndian.Uint32(data[pos+8+size:pos+12+size]) {
			return deny
		}
		switch kind {
		case "IHDR":
			if stage != 0 || size != 13 {
				return deny
			}
			width, height := binary.BigEndian.Uint32(body[:4]), binary.BigEndian.Uint32(body[4:8])
			color := body[9]
			if width < 1 || height < 1 || width > 512 || height > 512 || body[8] != 8 || (color != 0 && color != 2 && color != 4 && color != 6) || body[10] != 0 || body[11] != 0 || body[12] != 0 {
				return deny
			}
			stage = 1
		case "pHYs":
			if stage != 1 || physicalDensity || size != 9 {
				return deny
			}
			density := binary.BigEndian.Uint32(body[:4])
			if density < 1 || density > 40000 || density != binary.BigEndian.Uint32(body[4:8]) || body[8] != 1 {
				return deny
			}
			physicalDensity = true
		case "IDAT":
			if stage != 1 && stage != 2 {
				return deny
			}
			stage = 2
		case "IEND":
			if stage != 2 || size != 0 || pos+12 != len(data) {
				return deny
			}
			stage = 3
		default:
			return deny
		}
		pos += size + 12
	}
	if pos != len(data) || stage != 3 {
		return deny
	}
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		return deny
	}
	return nil
}

func (a *DatasetAttribution) Validate() error {
	if a == nil || !creditText(a.Name, 128) || !creditText(a.Text, 2048) || !creditURL(a.URL) || a.LicenseURL != "" && !creditURL(a.LicenseURL) {
		return errors.New("reviewed dataset attribution fields invalid")
	}
	if a.Logo != nil {
		return a.Logo.Validate()
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
		if key.Kind == yaml.ScalarNode && key.Tag == "!!str" && key.Value == "logo" && !seen[key.Value] {
			if value.Kind != yaml.MappingNode || len(value.Content) != 6 {
				return errors.New("dataset logo mapping invalid")
			}
			fields := map[string]bool{}
			for j := 0; j < len(value.Content); j += 2 {
				k, v := value.Content[j], value.Content[j+1]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || v.Kind != yaml.ScalarNode || v.Tag != "!!str" || fields[k.Value] || (k.Value != "path" && k.Value != "sha256" && k.Value != "alt") {
					return errors.New("dataset logo fields invalid")
				}
				fields[k.Value] = true
			}
			seen[key.Value] = true
			continue
		}
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
