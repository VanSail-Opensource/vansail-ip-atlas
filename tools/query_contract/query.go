// Package querycontract is the P0 executable IP/ASN URL contract. It performs
// syntax normalization only; it never resolves names or fetches data.
package querycontract

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Input struct {
	Kind      string `json:"kind"`
	Canonical string `json:"canonical"`
}

type Result struct {
	State  string `json:"state"`
	Route  string `json:"route,omitempty"`
	Q      string `json:"q,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Origin string `json:"origin,omitempty"`
	Query  string `json:"query,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Value includes the numeric representation of a canonical IP or ASN query.
// Only Address is set for an IP query, and only ASN is set for an ASN query.
type Value struct {
	Input
	Address netip.Addr
	ASN     uint32
}

func ParseInput(raw string) (Input, error) {
	v, err := ParseValue(raw)
	return v.Input, err
}

// ParseValue validates the query once and preserves its numeric lookup key.
func ParseValue(raw string) (Value, error) {
	if len(raw) > 128 || !utf8.ValidString(raw) {
		return Value{}, fmt.Errorf("invalid_input")
	}
	s := strings.Trim(raw, " \t\r\n\f\v")
	if s == "" {
		return Value{}, fmt.Errorf("invalid_input")
	}
	for _, r := range s {
		if r <= 32 || r == 127 {
			return Value{}, fmt.Errorf("invalid_input")
		}
	}
	if strings.Contains(s, "%") {
		return Value{}, fmt.Errorf("invalid_input")
	}
	if strings.ContainsAny(s, ".:") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return Value{}, fmt.Errorf("invalid_input")
		}
		canonical := s
		// ParseAddr requires canonical decimal octets for plain IPv4.
		// IPv6 may contain upper-case, expanded or IPv4-mapped forms.
		if !addr.Is4() {
			addr = addr.Unmap()
			var buf [64]byte
			encoded := addr.AppendTo(buf[:0])
			if s != string(encoded) {
				canonical = string(encoded)
			}
		}
		return Value{Input: Input{Kind: "ip", Canonical: canonical}, Address: addr}, nil
	}
	digits := s
	if len(digits) >= 2 && strings.EqualFold(digits[:2], "AS") {
		digits = digits[2:]
	}
	if digits == "" {
		return Value{}, fmt.Errorf("invalid_input")
	}
	for _, b := range []byte(digits) {
		if b < '0' || b > '9' {
			return Value{}, fmt.Errorf("invalid_input")
		}
	}
	// Leading zeroes are accepted without turning an arbitrarily long zero
	// prefix into an integer overflow. The total original input is bounded.
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return Value{}, fmt.Errorf("invalid_input")
	}
	asn, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || !publicASN(asn) {
		return Value{}, fmt.Errorf("invalid_input")
	}
	canonical := s
	if len(s) != 2+len(digits) || !strings.HasPrefix(s, "AS") {
		canonical = "AS" + digits
	}
	return Value{Input: Input{Kind: "asn", Canonical: canonical}, ASN: uint32(asn)}, nil
}

func publicASN(asn uint64) bool {
	return (asn >= 1 && asn <= 23455) || (asn >= 23457 && asn <= 64495) ||
		(asn >= 131072 && asn <= 4199999999)
}

// Resolve expects the raw query without its initial question mark. Membership
// of an origin in a prefix is intentionally a separate post-lookup operation.
func Resolve(route, raw string) Result {
	valid := route == "/ip" || route == "/ip/overview" || route == "/ip/quality" ||
		route == "/ip/class-c" || route == "/ip/bgp" || route == "/ip/asn"
	if !valid {
		return Result{State: "error", Error: "invalid_route"}
	}
	if len(raw) > 1024 || !utf8.ValidString(raw) {
		return Result{State: "error", Error: "invalid_query"}
	}
	values := make(map[string]string, 2)
	if raw != "" {
		for _, component := range strings.Split(raw, "&") {
			keyRaw, valueRaw, ok := strings.Cut(component, "=")
			key, keyErr := url.QueryUnescape(keyRaw)
			value, valueErr := url.QueryUnescape(valueRaw)
			_, duplicate := values[key]
			if !ok || keyErr != nil || valueErr != nil || !utf8.ValidString(key) ||
				!utf8.ValidString(value) || (key != "q" && key != "origin") ||
				value == "" || duplicate {
				return Result{State: "error", Error: "invalid_query"}
			}
			values[key] = value
		}
	}
	q, hasQ := values["q"]
	originRaw, hasOrigin := values["origin"]
	if !hasQ {
		if hasOrigin {
			return Result{State: "error", Error: "invalid_query"}
		}
		if route == "/ip" {
			return Result{State: "hero", Route: "/ip"}
		}
		return Result{State: "redirect", Route: "/ip"}
	}
	input, err := ParseInput(q)
	if err != nil {
		return Result{State: "error", Error: "invalid_input"}
	}
	origin := ""
	if hasOrigin {
		if route != "/ip/bgp" || input.Kind != "ip" {
			return Result{State: "error", Error: "invalid_origin"}
		}
		parsed, err := ParseInput(originRaw)
		if err != nil || parsed.Kind != "asn" {
			return Result{State: "error", Error: "invalid_origin"}
		}
		origin = parsed.Canonical
	}
	state, destination := "ok", route
	if route == "/ip" {
		state, destination = "redirect", "/ip/overview"
		if input.Kind == "asn" {
			destination = "/ip/asn"
		}
	} else if input.Kind == "asn" && (route == "/ip/overview" || route == "/ip/quality" || route == "/ip/class-c") {
		state, destination = "redirect", "/ip/asn"
	}
	query := "q=" + url.QueryEscape(input.Canonical)
	if origin != "" {
		query += "&origin=" + url.QueryEscape(origin)
	}
	return Result{State: state, Route: destination, Q: input.Canonical, Kind: input.Kind, Origin: origin, Query: query}
}

// ValidateOrigin checks only loaded facts. It never changes the requested origin.
func ValidateOrigin(requested uint32, origins []uint32) error {
	lo, hi := 0, len(origins)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if origins[mid] < requested {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == len(origins) || origins[lo] != requested {
		return fmt.Errorf("origin_not_member")
	}
	return nil
}
