// Package subscription extracts literal public IPs without retaining subscription metadata.
// Input bytes belong to the caller's controlled in-memory quarantine. No input is logged.
package subscription

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

var ErrInput = errors.New("subscription input rejected")

type Limits struct{ Bytes, LineBytes, JSONBytes, Nodes, UniqueIPs, Base64Depth int }

func DefaultLimits() Limits { return Limits{16 << 20, 131072, 1 << 20, 500000, 2000000, 2} }

type Record struct {
	IP          netip.Addr
	Proxy       bool
	PublishedAt time.Time
	Family      string
}
type Decoder struct{ Limits Limits }
type quarantineReader struct {
	context context.Context
	reader  io.Reader
}

func (r quarantineReader) Read(p []byte) (int, error) {
	if err := r.context.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func Public(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
		if netip.MustParsePrefix(p).Contains(ip) {
			return false
		}
	}
	return ip.Is4() || netip.MustParsePrefix("2000::/3").Contains(ip)
}

// Decode is all-or-nothing for malformed containers and resource violations.
// Invalid individual URI hosts are ignored. A caller must separately verify upstream item time.
func (d Decoder) Decode(ctx context.Context, r io.Reader, format string, published time.Time) ([]Record, error) {
	l := d.Limits
	if ctx.Err() != nil || published.IsZero() || l.Bytes <= 0 || l.Bytes > 16<<20 || l.LineBytes <= 0 || l.LineBytes > 131072 || l.JSONBytes <= 0 || l.JSONBytes > 1<<20 || l.Nodes <= 0 || l.Nodes > 500000 || l.UniqueIPs <= 0 || l.UniqueIPs > 2000000 || l.Base64Depth < 0 || l.Base64Depth > 2 {
		return nil, ErrInput
	}
	data, err := io.ReadAll(io.LimitReader(quarantineReader{ctx, r}, int64(l.Bytes)+1))
	if err != nil || len(data) > l.Bytes || !utf8.Valid(data) {
		return nil, ErrInput
	}
	set := make(map[netip.Addr]struct{})
	add := func(host string) error {
		if ctx.Err() != nil {
			return ErrInput
		}
		ip, e := netip.ParseAddr(host)
		if e != nil || !Public(ip) {
			return nil
		}
		ip = ip.Unmap()
		set[ip] = struct{}{}
		if len(set) > l.UniqueIPs {
			return ErrInput
		}
		return nil
	}
	if err := d.parse(ctx, bytes.TrimSpace(data), format, 0, add); err != nil {
		return nil, ErrInput
	}
	ips := make([]netip.Addr, 0, len(set))
	for ip := range set {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Compare(ips[j]) < 0 })
	result := make([]Record, len(ips))
	for i, ip := range ips {
		result[i] = Record{ip, true, published.UTC(), "public-subscription-aggregators"}
	}
	return result, nil
}

func (d Decoder) parse(ctx context.Context, data []byte, format string, depth int, add func(string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) > d.Limits.Bytes {
		return ErrInput
	}
	switch format {
	case "base64", "base64-subscription":
		if depth >= d.Limits.Base64Depth {
			return ErrInput
		}
		decoded, ok := decode64(string(data))
		if !ok {
			return ErrInput
		}
		return d.parse(ctx, decoded, "auto", depth+1, add)
	case "singbox-json", "json":
		return d.jsonContainer(ctx, data, add)
	case "mihomo-yaml", "yaml":
		return d.yamlContainer(ctx, data, add)
	case "auto", "auto-subscription":
		if len(data) == 0 {
			return nil
		}
		if data[0] == '{' || data[0] == '[' {
			return d.jsonContainer(ctx, data, add)
		}
		if bytes.HasPrefix(data, []byte("proxies:")) {
			return d.yamlContainer(ctx, data, add)
		}
		if !bytes.Contains(data, []byte("://")) {
			if decoded, ok := decode64(string(data)); ok {
				if depth >= d.Limits.Base64Depth {
					return ErrInput
				}
				return d.parse(ctx, decoded, "auto", depth+1, add)
			}
		}
	case "plaintext", "uri-list", "text":
	default:
		return ErrInput
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), d.Limits.LineBytes+1)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(scanner.Text())
		if len(line) > d.Limits.LineBytes {
			return ErrInput
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host, err := d.uri(ctx, line)
		if err != nil {
			continue
		}
		if err = add(host); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func decode64(text string) ([]byte, bool) {
	text = strings.TrimSpace(text)
	// Internal line wrapping is permitted only in a whole-subscription envelope.
	text = strings.NewReplacer("\r", "", "\n", "").Replace(text)
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding.Strict(), base64.StdEncoding.Strict(), base64.RawURLEncoding.Strict(), base64.URLEncoding.Strict()} {
		if data, err := encoding.DecodeString(text); err == nil && utf8.Valid(data) {
			return data, true
		}
	}
	return nil, false
}

func port(text string) bool {
	n, err := strconv.Atoi(text)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == text
}
func (d Decoder) uri(ctx context.Context, line string) (string, error) {
	scheme, payload, ok := strings.Cut(line, "://")
	if !ok {
		return "", ErrInput
	}
	scheme = strings.ToLower(scheme)
	if scheme == "vmess" {
		raw := []byte(payload)
		if !strings.HasPrefix(payload, "{") {
			var valid bool
			raw, valid = decode64(payload)
			if !valid {
				return "", ErrInput
			}
		}
		if len(raw) > d.Limits.JSONBytes || jsonShape(ctx, raw, 32, d.Limits.Nodes) != nil {
			return "", ErrInput
		}
		var vmess struct {
			Add  string          `json:"add"`
			Port json.RawMessage `json:"port"`
		}
		if json.Unmarshal(raw, &vmess) != nil {
			return "", ErrInput
		}
		rawPort := string(vmess.Port)
		if strings.HasPrefix(rawPort, "\"") {
			if json.Unmarshal(vmess.Port, &rawPort) != nil {
				return "", ErrInput
			}
		}
		if !port(rawPort) {
			return "", ErrInput
		}
		return vmess.Add, nil
	}
	if scheme == "ssr" {
		decoded, ok := decode64(payload)
		if !ok {
			return "", ErrInput
		}
		core := strings.SplitN(string(decoded), "/?", 2)[0]
		// SSR has five colon-delimited fields after the host. Split from the
		// right so literal IPv6 does not become a different server/port pair.
		pieces := make([]string, 6)
		for i := 5; i > 0; i-- {
			at := strings.LastIndexByte(core, ':')
			if at < 0 {
				return "", ErrInput
			}
			pieces[i], core = core[at+1:], core[:at]
		}
		pieces[0] = core
		if !port(pieces[1]) {
			return "", ErrInput
		}
		host := pieces[0]
		if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
			if !strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]") {
				return "", ErrInput
			}
			host = host[1 : len(host)-1]
		}
		return host, nil
	}
	switch scheme {
	case "vless", "trojan", "ss", "hy", "hy2", "hysteria", "hysteria2", "tuic", "anytls":
	default:
		return "", ErrInput
	}
	if scheme == "ss" && !strings.Contains(strings.SplitN(payload, "#", 2)[0], "@") {
		core := strings.SplitN(payload, "#", 2)[0]
		decoded, ok := decode64(core)
		if !ok {
			return "", ErrInput
		}
		line = "ss://" + string(decoded)
	}
	u, err := url.Parse(line)
	if err != nil || u.Opaque != "" || u.Host == "" || !port(u.Port()) {
		return "", ErrInput
	}
	host := u.Hostname()
	if strings.ContainsAny(host, "% \t\r\n") {
		return "", ErrInput
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return "", ErrInput
	}
	return host, nil
}

// jsonShape rejects ambiguous duplicate fields and excessive depth before typed decoding.
func jsonShape(ctx context.Context, data []byte, maxDepth, maxNodes int) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		if ctx.Err() != nil {
			return ErrInput
		}
		nodes++
		if depth > maxDepth || nodes > maxNodes {
			return ErrInput
		}
		token, err := decoder.Token()
		if err != nil {
			return ErrInput
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return ErrInput
				}
				name, ok := key.(string)
				if !ok {
					return ErrInput
				}
				// encoding/json matches struct fields case-insensitively, including
				// Unicode simple-fold aliases. Only exact source schema keys qualify.
				for _, canonical := range []string{"outbounds", "server", "server_port", "type", "add", "port"} {
					if name != canonical && strings.EqualFold(name, canonical) {
						return ErrInput
					}
				}
				if _, ok := seen[name]; ok {
					return ErrInput
				}
				seen[name] = struct{}{}
				if len(seen) > maxNodes {
					return ErrInput
				}
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInput
			}
		case '[':
			for decoder.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInput
			}
		default:
			return ErrInput
		}
		return nil
	}
	if value(0) != nil {
		return ErrInput
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInput
	}
	return nil
}

func (d Decoder) jsonContainer(ctx context.Context, data []byte, add func(string) error) error {
	if len(data) > d.Limits.JSONBytes || jsonShape(ctx, data, 32, d.Limits.Nodes) != nil {
		return ErrInput
	}
	var container struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Server     string `json:"server"`
			ServerPort uint16 `json:"server_port"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(data, &container) != nil {
		return ErrInput
	}
	for _, item := range container.Outbounds {
		if !proxyType(item.Type) || item.ServerPort == 0 {
			continue
		}
		if err := add(item.Server); err != nil {
			return err
		}
	}
	return nil
}

func (d Decoder) yamlContainer(ctx context.Context, data []byte, add func(string) error) error {
	if len(data) > d.Limits.JSONBytes {
		return ErrInput
	}
	var root yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&root) != nil {
		return ErrInput
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return ErrInput
	}
	nodes := 0
	var check func(*yaml.Node, int) error
	check = func(node *yaml.Node, depth int) error {
		if ctx.Err() != nil {
			return ErrInput
		}
		nodes++
		if nodes > d.Limits.Nodes || depth > 32 || node.Kind == yaml.AliasNode || node.Anchor != "" {
			return ErrInput
		}
		if node.Kind == yaml.MappingNode {
			seen := map[string]struct{}{}
			for i := 0; i < len(node.Content); i += 2 {
				key := node.Content[i]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
					return ErrInput
				}
				if _, ok := seen[key.Value]; ok {
					return ErrInput
				}
				seen[key.Value] = struct{}{}
			}
		}
		for _, child := range node.Content {
			if check(child, depth+1) != nil {
				return ErrInput
			}
		}
		return nil
	}
	if check(&root, 0) != nil {
		return ErrInput
	}
	var container struct {
		Proxies []struct {
			Type   string `yaml:"type"`
			Server string `yaml:"server"`
			Port   uint16 `yaml:"port"`
		} `yaml:"proxies"`
	}
	if root.Decode(&container) != nil {
		return ErrInput
	}
	for _, item := range container.Proxies {
		if !proxyType(item.Type) || item.Port == 0 {
			continue
		}
		if err := add(item.Server); err != nil {
			return err
		}
	}
	return nil
}

func proxyType(value string) bool {
	switch value {
	case "ss", "shadowsocks", "ssr", "shadowsocksr", "vmess", "vless", "trojan", "hy", "hy2", "hysteria", "hysteria2", "tuic", "anytls":
		return true
	}
	return false
}
