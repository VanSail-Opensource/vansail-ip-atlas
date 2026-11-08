package subscription

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestTypedProxyContainersIgnoreNonProxyEntries(t *testing.T) {
	for _, example := range []struct{ format, text string }{
		{"json", `{"outbounds":[{"type":"direct","server":"8.8.8.8","server_port":443},{"server":"1.1.1.1","server_port":443},{"type":"trojan","server":"9.9.9.9","server_port":443}]}`},
		{"yaml", "proxies:\n - type: direct\n   server: 8.8.8.8\n   port: 443\n - server: 1.1.1.1\n   port: 443\n - type: trojan\n   server: 9.9.9.9\n   port: 443\n"},
	} {
		records, err := decode(t, example.format, example.text)
		if err != nil || len(records) != 1 || records[0].IP.String() != "9.9.9.9" {
			t.Fatalf("%s non-proxy entry became proxy evidence", example.format)
		}
	}
}

func TestMappedIPv6ZoneCannotDisappearBeforePublicHostValidation(t *testing.T) {
	if Public(netip.MustParseAddr("::ffff:8.8.8.8%synthetic-zone")) {
		t.Fatal("unmapping discarded an invalid server zone before validation")
	}
	for _, example := range []struct{ format, text string }{
		{"json", `{"outbounds":[{"type":"trojan","server":"::ffff:8.8.8.8%synthetic-zone","server_port":443}]}`},
		{"yaml", "proxies:\n - type: trojan\n   server: '::ffff:8.8.8.8%synthetic-zone'\n   port: 443\n"},
	} {
		if records, err := decode(t, example.format, example.text); err != nil || len(records) != 0 {
			t.Fatal("scoped mapped IPv6 server became public proxy evidence")
		}
	}
}

func TestMalformedRawProxyFieldTypesRejectContainer(t *testing.T) {
	for _, text := range []string{
		`{"outbounds":[{"type":42,"server":"8.8.8.8","server_port":443}]}`,
		`{"outbounds":[{"type":"trojan","server":["8.8.8.8"],"server_port":443}]}`,
		`{"outbounds":[{"type":"trojan","server":"8.8.8.8","server_port":true}]}`,
		`{"outbounds":[{"type":"trojan","server":"8.8.8.8","server_port":443.0}]}`,
		`{"outbounds":[{"type":"trojan","server":"8.8.8.8","server_port":{}}]}`,
	} {
		if records, err := decode(t, "json", text); err != ErrInput || len(records) != 0 {
			t.Fatal("malformed typed JSON container accepted")
		}
	}
	for _, text := range []string{
		"proxies:\n - type: [trojan]\n   server: 8.8.8.8\n   port: 443\n",
		"proxies:\n - type: trojan\n   server: {host: 8.8.8.8}\n   port: 443\n",
		"proxies:\n - type: trojan\n   server: 8.8.8.8\n   port: true\n",
	} {
		if records, err := decode(t, "yaml", text); err != ErrInput || len(records) != 0 {
			t.Fatal("malformed typed YAML container accepted")
		}
	}
}

func TestCaseFoldedJSONFieldsCannotOverrideCanonicalServer(t *testing.T) {
	for _, text := range []string{
		`{"outbounds":[{"type":"trojan","server":"8.8.8.8","SERVER":"1.1.1.1","server_port":443}]}`,
		`{"outbounds":[{"type":"trojan","SERVER":"8.8.8.8","server_port":443}]}`,
		`{"outbounds":[{"type":"trojan","server":"8.8.8.8","SERVER_PORT":443}]}`,
		`{"OUTBOUNDS":[{"type":"trojan","server":"8.8.8.8","server_port":443}]}`,
	} {
		if records, err := decode(t, "json", text); err != ErrInput || len(records) != 0 {
			t.Fatal("implicit case-folded JSON field alias accepted")
		}
	}
}

func TestAutoSubscriptionAcceptsLineWrappedBase64(t *testing.T) {
	encoded := fixture64("trojan://synthetic@8.8.8.8:443\nvless://synthetic@1.1.1.1:443\n")
	var wrapped strings.Builder
	for len(encoded) > 12 {
		wrapped.WriteString(encoded[:12] + "\r\n")
		encoded = encoded[12:]
	}
	wrapped.WriteString(encoded)
	records, err := decode(t, "auto", wrapped.String())
	if err != nil || len(records) != 2 {
		t.Fatal("line-wrapped Base64 envelope lost literal IP evidence")
	}
}

type cancelAfterRead struct {
	cancel context.CancelFunc
	data   *strings.Reader
	calls  int
}

func (r *cancelAfterRead) Read(p []byte) (int, error) {
	r.calls++
	if r.calls > 1 {
		return 0, io.EOF
	}
	n, err := r.data.Read(p)
	r.cancel()
	return n, err
}

func TestCancellationStopsBeforeAnotherQuarantineRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := &cancelAfterRead{cancel: cancel, data: strings.NewReader("trojan://synthetic@8.8.8.8:443")}
	records, err := (Decoder{DefaultLimits()}).Decode(ctx, input, "text", time.Unix(1794096000, 0))
	if err != ErrInput || len(records) != 0 || input.calls != 1 {
		t.Fatal("cancelled quarantine ingestion attempted another potentially blocking read")
	}
}
