package admission

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// RPKIClientMetadata is private proof derived from the complete original body.
// Operational host/TAL paths and per-source records never enter public facts.
type RPKIClientMetadata struct {
	BuiltAt, CoverageValidUntil             time.Time
	Rows, RetainedRows, ExpiredAtIntakeRows int
}

// parseRPKIClientPayload supports the publisher's full JSON, including operational
// arrays, without buffering the root or increasing ParseVRPJSON's 64MiB envelope.
// A custom framer bounds each value BEFORE json decoding: metadata<=64KiB,
// row<=1MiB, nesting<=32, total bytes/rows explicitly supplied by the caller.
// Callers must abort their private transactional sink on any eventual error;
// completeness and the payload-bound publication clock are known only at EOF.
func parseRPKIClientPayload(ctx context.Context, input io.Reader, limits intelligence.ParseLimits, now time.Time, emit func(intelligence.NormalizedRecord) error) (result RPKIClientMetadata, failure error) {
	defer func() {
		if ctx != nil && ctx.Err() != nil {
			failure = ctx.Err()
		}
	}()
	if ctx == nil || input == nil || now.IsZero() || limits.Bytes <= 0 || limits.Bytes > 3<<30 || limits.Records <= 0 || limits.Records > 100_000_000 || limits.LineBytes <= 0 || limits.LineBytes > 1<<20 {
		return result, errors.New("bounded RPKI-client parser inputs required")
	}
	stream := &rpkiJSONStream{ctx: ctx, reader: bufio.NewReaderSize(&io.LimitedReader{R: input, N: limits.Bytes + 1}, 64<<10), limit: limits.Bytes}
	first, err := stream.nonspace()
	if err != nil || first != '{' {
		return result, errors.New("RPKI-client JSON root required")
	}
	seen := make(map[string]bool, 5)
	var header rpkiClientHeader
	var minimumAll time.Time
	values := 0
	for {
		first, err = stream.nonspace()
		if err != nil {
			return result, errors.New("truncated RPKI-client root")
		}
		if first == '}' {
			if len(seen) == 0 {
				return result, errors.New("empty RPKI-client root")
			}
			break
		}
		if first != '"' {
			return result, errors.New("RPKI-client root key required")
		}
		raw, err := stream.value(first, 128)
		if err != nil {
			return result, err
		}
		var key string
		if json.Unmarshal(raw, &key) != nil || len(key) > 64 || seen[key] {
			return result, errors.New("RPKI-client duplicate or invalid root key")
		}
		seen[key] = true
		if first, err = stream.nonspace(); err != nil || first != ':' {
			return result, errors.New("RPKI-client root separator invalid")
		}
		switch key {
		case "metadata":
			first, err = stream.nonspace()
			if err != nil || first != '{' {
				return result, errors.New("RPKI-client metadata object required")
			}
			raw, err = stream.value(first, min(limits.LineBytes, 64<<10))
			if err != nil {
				return result, err
			}
			header, err = decodeRPKIClientHeader(raw, now, limits.Records)
			if err != nil {
				return result, err
			}
		case "roas", "bgpsec_keys", "nonfunc_cas", "aspas":
			if first, err = stream.nonspace(); err != nil || first != '[' {
				return result, errors.New("RPKI-client root array required")
			}
			for {
				first, err = stream.nonspace()
				if err != nil {
					return result, errors.New("truncated RPKI-client array")
				}
				if first == ']' {
					break
				}
				values++
				if values > limits.Records {
					return result, errors.New("RPKI-client value count exceeds budget")
				}
				raw, err = stream.value(first, limits.LineBytes)
				if err != nil {
					return result, err
				}
				if err = uniqueJSON(raw); err != nil {
					return result, errors.New("RPKI-client array value is not bounded unique JSON")
				}
				if key == "roas" {
					vrp, err := decodeRPKIClientVRP(raw)
					if err != nil {
						return result, err
					}
					result.Rows++
					if minimumAll.IsZero() || vrp.ValidUntil.Before(minimumAll) {
						minimumAll = vrp.ValidUntil
					}
					if !now.Before(vrp.ValidUntil) {
						result.ExpiredAtIntakeRows++
					}
					// This is the complete publisher snapshot at BuiltAt, not a
					// claim that every authorization remains current at intake.
					// The final proof below binds the original observation clock
					// before the earliest original authorization expiry.
					result.RetainedRows++
					if emit != nil {
						if err = emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordVRP, VRP: &vrp}); err != nil {
							return result, err
						}
					}
				}
				first, err = stream.nonspace()
				if err != nil {
					return result, errors.New("truncated RPKI-client array separator")
				}
				if first == ']' {
					break
				}
				if first != ',' {
					return result, errors.New("RPKI-client array separator invalid")
				}
				// A comma requires a subsequent value, never a trailing close.
				if next, err := stream.peekNonspace(); err != nil || next == ']' {
					return result, errors.New("RPKI-client trailing array comma")
				}
			}
		default:
			return result, errors.New("uncertified RPKI-client root field")
		}
		first, err = stream.nonspace()
		if err != nil {
			return result, errors.New("truncated RPKI-client root separator")
		}
		if first == '}' {
			break
		}
		if first != ',' {
			return result, errors.New("RPKI-client root separator invalid")
		}
		if next, err := stream.peekNonspace(); err != nil || next == '}' {
			return result, errors.New("RPKI-client trailing root comma")
		}
	}
	if _, err := stream.nonspace(); err != io.EOF {
		if err != nil {
			return result, err
		}
		return result, errors.New("RPKI-client trailing JSON content")
	}
	if !seen["metadata"] || !seen["roas"] || result.Rows != header.UniqueVRPs || result.RetainedRows != result.Rows || !header.BuiltAt.Before(minimumAll) {
		return result, errors.New("RPKI-client completeness or validity proof failed")
	}
	result.BuiltAt, result.CoverageValidUntil = header.BuiltAt, minimumAll
	return result, nil
}

type rpkiClientHeader struct {
	BuiltAt    time.Time
	UniqueVRPs int
}

func decodeRPKIClientHeader(raw []byte, now time.Time, maxRecords int) (rpkiClientHeader, error) {
	var result rpkiClientHeader
	if err := uniqueJSON(raw); err != nil {
		return result, errors.New("RPKI-client metadata JSON invalid")
	}
	// Only required typed facts survive parsing. Unknown operational counters and
	// arrays remain bounded by the small metadata object and are discarded here.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return result, errors.New("RPKI-client metadata object invalid")
	}
	var built string
	var total, unique, tals, invalid *uint64
	for _, field := range []struct {
		name   string
		target any
	}{
		{"buildtime", &built}, {"vrps", &total}, {"uniquevrps", &unique}, {"tals", &tals}, {"invalidtals", &invalid},
	} {
		value, ok := fields[field.name]
		if !ok || json.Unmarshal(value, field.target) != nil {
			return result, errors.New("RPKI-client required metadata field invalid")
		}
	}
	if total == nil || unique == nil || tals == nil || invalid == nil || *unique == 0 || *unique > uint64(maxRecords) || *total < *unique || *total > uint64(maxRecords) || *tals != 5 || *invalid != 0 {
		return result, errors.New("RPKI-client metadata completeness counts invalid")
	}
	stamp, err := timestamp(built)
	if err != nil || stamp.After(now.Add(24*time.Hour)) {
		return result, errors.New("RPKI-client embedded build clock invalid")
	}
	result.BuiltAt, result.UniqueVRPs = stamp, int(*unique)
	return result, nil
}

func decodeRPKIClientVRP(raw []byte) (intelligence.VRP, error) {
	// Go's struct decoder accepts folded names such as ASN. The certified wire
	// schema is case-sensitive, so check the exact five keys before decoding.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 5 {
		return intelligence.VRP{}, errors.New("RPKI-client VRP schema invalid")
	}
	for _, key := range []string{"asn", "expires", "maxLength", "prefix", "ta"} {
		if _, ok := fields[key]; !ok {
			return intelligence.VRP{}, errors.New("RPKI-client VRP schema invalid")
		}
	}
	var value struct {
		ASN       *uint32 `json:"asn"`
		Expires   *int64  `json:"expires"`
		MaxLength *uint16 `json:"maxLength"`
		Prefix    *string `json:"prefix"`
		TA        *string `json:"ta"`
	}
	if len(raw) == 0 || raw[0] != '{' || strictJSON(raw, &value) != nil || value.ASN == nil || value.Expires == nil || value.MaxLength == nil || value.Prefix == nil || value.TA == nil {
		return intelligence.VRP{}, errors.New("RPKI-client VRP fields invalid")
	}
	if *value.TA != "afrinic" && *value.TA != "apnic" && *value.TA != "arin" && *value.TA != "lacnic" && *value.TA != "ripe" {
		return intelligence.VRP{}, errors.New("RPKI-client trust anchor invalid")
	}
	prefix, err := netip.ParsePrefix(*value.Prefix)
	if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || len(*value.Prefix) > 64 || int(*value.MaxLength) < prefix.Bits() || int(*value.MaxLength) > prefix.Addr().BitLen() || *value.Expires <= 0 || *value.Expires > 253402300799 {
		return intelligence.VRP{}, errors.New("RPKI-client prefix or validity invalid")
	}
	// Authorization ASNs are all uint32, including AS0 and private/reserved ASNs.
	// They remain private. A private-ASN authorization still makes a mismatching
	// public announcement invalid; discarding it would manufacture not_found.
	return intelligence.VRP{Prefix: prefix, MaxLength: uint8(*value.MaxLength), ASN: *value.ASN,
		ValidUntil: time.Unix(*value.Expires, 0).UTC()}, nil
}

func verifyRPKIClientFile(ctx context.Context, path string, size int64, source Source, now time.Time) (RPKIClientMetadata, error) {
	var result RPKIClientMetadata
	if source.URL != "https://console.rpki-client.org/rpki.json" || source.Publication.Kind != "embedded" || source.Publication.Locator != source.URL || source.Publication.Field != "metadata.buildtime" || source.Format != "json" || source.Category != "rpki" || source.Parser.ID != "rpki-client-json" || source.Parser.Schema != "rpki-client-payloads-json-v1" || source.Parser.Version != 1 || size <= 0 || size > source.MaxCompressedBytes || source.MaxAge <= 0 || source.MaxAge > 720*time.Hour {
		return result, errors.New("reviewed RPKI-client embedded publication controls required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return result, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return result, errors.New("RPKI-client payload cannot traverse links")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return result, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return result, errors.New("RPKI-client payload framing changed")
	}
	result, err = parseRPKIClientPayload(ctx, file, intelligence.ParseLimits{Bytes: size, Records: 100_000_000, LineBytes: 1 << 20}, now, nil)
	if err != nil {
		return result, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return result, errors.New("RPKI-client payload changed during verification")
	}
	if !now.Before(result.BuiltAt.Add(source.MaxAge)) {
		return result, errors.New("RPKI-client embedded snapshot expired")
	}
	return result, nil
}

type rpkiJSONStream struct {
	ctx         context.Context
	reader      *bufio.Reader
	limit, read int64
}

func (s *rpkiJSONStream) byte() (byte, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	b, err := s.reader.ReadByte()
	if err != nil {
		return 0, err
	}
	s.read++
	if s.read > s.limit {
		return 0, errors.New("RPKI-client total byte budget exceeded")
	}
	return b, nil
}
func rpkiSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }
func (s *rpkiJSONStream) nonspace() (byte, error) {
	for {
		b, err := s.byte()
		if err != nil || !rpkiSpace(b) {
			return b, err
		}
	}
}
func (s *rpkiJSONStream) peekNonspace() (byte, error) {
	for {
		if err := s.ctx.Err(); err != nil {
			return 0, err
		}
		p, err := s.reader.Peek(1)
		if err != nil {
			return 0, err
		}
		if !rpkiSpace(p[0]) {
			return p[0], nil
		}
		if _, err = s.byte(); err != nil {
			return 0, err
		}
	}
}
func (s *rpkiJSONStream) value(first byte, maximum int) ([]byte, error) {
	if maximum <= 0 {
		return nil, errors.New("RPKI-client value bound invalid")
	}
	data := make([]byte, 0, min(maximum, 256))
	data = append(data, first)
	quoted := first == '"'
	escaped := false
	stack := make([]byte, 0, 32)
	if first == '{' || first == '[' {
		stack = append(stack, first)
	}
	for {
		if len(stack) == 0 && !quoted {
			if first == '"' {
				return data, nil
			}
			p, err := s.reader.Peek(1)
			if err == io.EOF {
				return data, nil
			}
			if err != nil {
				return nil, err
			}
			if rpkiSpace(p[0]) || p[0] == ',' || p[0] == ']' || p[0] == '}' {
				return data, nil
			}
		}
		if len(data) >= maximum {
			return nil, errors.New("RPKI-client value exceeds preallocation bound")
		}
		b, err := s.byte()
		if err != nil {
			return nil, errors.New("RPKI-client value truncated")
		}
		data = append(data, b)
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
			continue
		}
		if b == '"' {
			quoted = true
			continue
		}
		if b == '{' || b == '[' {
			if len(stack) >= 32 {
				return nil, errors.New("RPKI-client JSON nesting exceeds bound")
			}
			stack = append(stack, b)
			continue
		}
		if b == '}' || b == ']' {
			if len(stack) == 0 || b == '}' && stack[len(stack)-1] != '{' || b == ']' && stack[len(stack)-1] != '[' {
				return nil, errors.New("RPKI-client JSON delimiter mismatch")
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return data, nil
			}
		}
	}
}
