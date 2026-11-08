package subscription

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type cancellingContext struct{ calls int }

func (c *cancellingContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancellingContext) Done() <-chan struct{}       { return nil }
func (c *cancellingContext) Value(any) any               { return nil }
func (c *cancellingContext) Err() error {
	c.calls++
	if c.calls > 30 {
		return context.Canceled
	}
	return nil
}

func TestCancellationDuringTypedContainerTraversal(t *testing.T) {
	ctx := &cancellingContext{}
	input := `{"outbounds":[` + strings.Repeat(`{"type":"trojan","server":"8.8.8.8","server_port":443},`, 50) + `{}]}`
	if _, err := (Decoder{DefaultLimits()}).Decode(ctx, strings.NewReader(input), "json", time.Now()); err != ErrInput {
		t.Fatal("mid-parse cancellation ignored")
	}
}

func fixture64(s string) string { return base64.RawStdEncoding.EncodeToString([]byte(s)) }
func decode(t *testing.T, format, text string) ([]Record, error) {
	t.Helper()
	return (Decoder{DefaultLimits()}).Decode(context.Background(), strings.NewReader(text), format, time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC))
}

func TestSyntaxLiteralHostsAndImmediateRedaction(t *testing.T) {
	vmess := fixture64(`{"add":"8.8.8.8","port":"443","id":"synthetic-discard","sni":"discard.invalid"}`)
	cases := []struct {
		name, format, text string
		want               []string
	}{
		{"bracketed-v6", "uri-list", "vless://synthetic@[2606:4700:4700::1111]:443?security=discard#label", []string{"2606:4700:4700::1111"}},
		{"vmess-base64", "uri-list", "vmess://" + vmess, []string{"8.8.8.8"}},
		{"vmess-json", "uri-list", `vmess://{"add":"8.8.8.8","port":443}`, []string{"8.8.8.8"}},
		{"ss-userinfo", "uri-list", "ss://" + fixture64("synthetic:discard") + "@1.1.1.1:8388", []string{"1.1.1.1"}},
		{"ss-whole", "uri-list", "ss://" + fixture64("synthetic:discard@1.1.1.1:8388"), []string{"1.1.1.1"}},
		{"ssr", "uri-list", "ssr://" + fixture64("1.1.1.1:443:synthetic:synthetic:synthetic:discard/?label=discard"), []string{"1.1.1.1"}},
		{"ssr-v6", "uri-list", "ssr://" + fixture64("[2606:4700:4700::1111]:443:synthetic:synthetic:synthetic:discard"), []string{"2606:4700:4700::1111"}},
		{"base64-list", "base64", fixture64("trojan://discard@8.8.8.8:443\nvless://discard@1.1.1.1:443"), []string{"1.1.1.1", "8.8.8.8"}},
		{"yaml", "mihomo-yaml", "proxies:\n - type: trojan\n   server: 8.8.8.8\n   port: 443\n   password: synthetic-discard\n   name: discard.invalid\n", []string{"8.8.8.8"}},
		{"json", "singbox-json", `{"outbounds":[{"type":"trojan","server":"1.1.1.1","server_port":443,"password":"synthetic-discard"}]}`, []string{"1.1.1.1"}},
		{"json-non-proxy", "singbox-json", `{"outbounds":[{"type":"direct","server":"1.1.1.1","server_port":443}]}`, nil},
		{"json-missing-type", "singbox-json", `{"outbounds":[{"server":"1.1.1.1","server_port":443}]}`, nil},
		{"auto-wrapped-base64", "auto", fixture64("trojan://discard@8.8.8.8:443")[:12] + "\n" + fixture64("trojan://discard@8.8.8.8:443")[12:], []string{"8.8.8.8"}},
		{"domain", "uri-list", "trojan://discard@nonexistent.invalid:443", nil},
		{"private-special", "uri-list", "trojan://discard@127.0.0.1:443\nvless://discard@203.0.113.1:443\nvless://discard@[2001:db8::1]:443\nvless://discard@[::ffff:10.0.0.1]:443", nil},
		{"bad-ports", "uri-list", "trojan://discard@8.8.8.8:no\ntrojan://discard@8.8.8.8:65536\ntrojan://discard@8.8.8.8:0\ntrojan://discard@8.8.8.8:0443", nil},
		{"duplicates", "uri-list", strings.Repeat("vless://discard@8.8.8.8:443\n", 200), []string{"8.8.8.8"}},
	}
	for _, scheme := range []string{"trojan", "hy", "hy2", "hysteria", "hysteria2", "tuic", "anytls"} {
		cases = append(cases, struct {
			name, format, text string
			want               []string
		}{scheme, "uri-list", scheme + "://synthetic-discard@8.8.8.8:443", []string{"8.8.8.8"}})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			records, err := decode(t, test.format, test.text)
			if err != nil {
				t.Fatal(err)
			}
			var ips []string
			for _, record := range records {
				ips = append(ips, record.IP.String())
				if !record.Proxy || record.Family != "public-subscription-aggregators" || record.PublishedAt.IsZero() {
					t.Fatal("incomplete normalized record")
				}
			}
			if !reflect.DeepEqual(ips, test.want) {
				t.Fatalf("IPs %v want %v", ips, test.want)
			}
			encoded, _ := json.Marshal(records)
			for _, secret := range []string{"synthetic-discard", "discard.invalid", "password", "sni", "://"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatal("raw subscription metadata survived")
				}
			}
		})
	}
}

func TestMalformedContainersAndLimits(t *testing.T) {
	for _, test := range []struct{ format, text string }{
		{"json", `{"outbounds":[`}, {"json", `{"outbounds":[],"outbounds":[]}`},
		{"yaml", "proxies: ["}, {"yaml", "proxies: &p []\nother: *p"}, {"yaml", "proxies: []\n---\nproxies: []"},
		{"yaml", "proxies: []\nproxies: []"}, {"uri-list", strings.Repeat("X", 131073)},
		{"base64", fixture64(fixture64(fixture64("trojan://discard@8.8.8.8:443")))},
	} {
		if _, err := decode(t, test.format, test.text); err != ErrInput {
			t.Fatalf("accepted malformed %s", test.format)
		}
	}
	limits := DefaultLimits()
	limits.Bytes = 10
	if _, err := (Decoder{limits}).Decode(context.Background(), strings.NewReader(strings.Repeat("x", 11)), "text", time.Now()); err != ErrInput {
		t.Fatal("oversized body")
	}
	limits = DefaultLimits()
	limits.UniqueIPs = 1
	if _, err := (Decoder{limits}).Decode(context.Background(), strings.NewReader("vless://discard@8.8.8.8:443\nvless://discard@1.1.1.1:443"), "text", time.Now()); err != ErrInput {
		t.Fatal("excess unique IPs")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Decoder{DefaultLimits()}).Decode(ctx, strings.NewReader(""), "text", time.Now()); err != ErrInput {
		t.Fatal("cancel ignored")
	}
}

func FuzzLiteralDecoder(f *testing.F) {
	for _, seed := range []string{"vless://discard@8.8.8.8:443", "vmess://bad", "proxies: []", "{\"outbounds\":[]}"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 65536 {
			return
		}
		for _, format := range []string{"auto", "yaml", "json"} {
			records, err := (Decoder{DefaultLimits()}).Decode(context.Background(), strings.NewReader(input), format, time.Unix(1800000000, 0))
			if err == nil {
				for _, r := range records {
					if !Public(r.IP) || !r.Proxy || r.Family != "public-subscription-aggregators" {
						t.Fatal("invalid output")
					}
				}
			}
		}
	})
}
