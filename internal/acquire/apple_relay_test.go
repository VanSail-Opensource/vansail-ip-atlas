package acquire

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type appleTransport func(*http.Request) (*http.Response, error)

func (f appleTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestAppleModificationSecondRequiresThreeIndependentResponses(t *testing.T) {
	const tag = "\"6aff19e5-b7e66e\""
	const size = 12052078
	expected := time.Unix(0x6aff19e5, 0).UTC()
	for _, broken := range []string{"", "weak", "size", "range", "encoded", "previous-still-succeeds", "wrong-304-tag", "redirect"} {
		t.Run(broken, func(t *testing.T) {
			calls := 0
			transport := appleTransport(func(req *http.Request) (*http.Response, error) {
				if req.Method != "HEAD" || req.URL.String() != AppleRelayURL || req.Header.Get("Accept-Encoding") != "identity" {
					t.Fatal("changed original representation")
				}
				calls++
				h := make(http.Header)
				h.Set("ETag", tag)
				status := http.StatusOK
				switch calls {
				case 1:
					if req.Header.Get("If-Modified-Since") != expected.Format(http.TimeFormat) || req.Header.Get("If-Unmodified-Since") != "" {
						t.Fatal("invalid first date")
					}
					status = http.StatusNotModified
				case 2:
					if req.Header.Get("If-Unmodified-Since") != expected.Add(-time.Second).Format(http.TimeFormat) || req.Header.Get("If-Modified-Since") != "" {
						t.Fatal("invalid preceding date")
					}
					status = http.StatusPreconditionFailed
					h.Del("ETag")
				case 3:
					if req.Header.Get("If-Unmodified-Since") != expected.Format(http.TimeFormat) {
						t.Fatal("invalid exact second")
					}
				default:
					t.Fatal("extra fetch")
				}
				switch broken {
				case "encoded":
					h.Set("Content-Encoding", "gzip")
				case "range":
					h.Set("Content-Range", "bytes 0-1/2")
				case "previous-still-succeeds":
					if calls == 2 {
						status = http.StatusOK
					}
				case "wrong-304-tag":
					if calls == 1 {
						h.Set("ETag", "\"other\"")
					}
				case "redirect":
					if calls == 1 {
						status = http.StatusFound
						h.Set("Location", "https://example.com/relay.csv")
					}
				}
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("")), ContentLength: size, Request: req}, nil
			})
			f := New()
			f.client.Transport = transport
			input := tag
			length := int64(size)
			if broken == "weak" {
				input = "W/" + tag
			}
			if broken == "size" {
				length++
			}
			got, err := f.VerifyAppleRelayClock(context.Background(), input, length)
			if broken == "" {
				if err != nil || calls != 3 || !got.Equal(expected) {
					t.Fatalf("invalid complete proof: %v %s %d", err, got, calls)
				}
			} else if err == nil {
				t.Fatalf("accepted incomplete proof %s", broken)
			}
		})
	}
}
