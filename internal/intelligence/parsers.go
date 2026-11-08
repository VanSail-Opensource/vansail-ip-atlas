package intelligence

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

type ParseLimits struct {
	Bytes     int64
	Records   int
	LineBytes int
}

func (l ParseLimits) validate() error {
	if l.Bytes <= 0 || l.Bytes > 3<<30 || l.Records <= 0 || l.Records > 100_000_000 || l.LineBytes <= 0 || l.LineBytes > 1<<20 {
		return errors.New("invalid parser limits")
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// ParseRelationships streams certified CAIDA-style rows. Optional publisher
// annotations and comments are discarded immediately and never enter the index.
func ParseRelationships(ctx context.Context, r io.Reader, current bool, limits ParseLimits) (*RelationshipIndex, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: contextReader{ctx, r}, N: limits.Bytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), limits.LineBytes)
	index := NewRelationships(current)
	count := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := scanner.Text()
		if !utf8.ValidString(line) {
			return nil, errors.New("relationship UTF-8 invalid")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
		if count > limits.Records {
			return nil, errors.New("relationship record budget exceeded")
		}
		fields := strings.Split(line, "|")
		if len(fields) < 3 || len(fields) > 4 {
			return nil, errors.New("relationship schema mismatch")
		}
		a, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return nil, errors.New("relationship ASN invalid")
		}
		b, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return nil, errors.New("relationship ASN invalid")
		}
		var relation Relation
		switch fields[2] {
		case "-1":
			relation = Customer
		case "0":
			relation = Peer
		default:
			return nil, errors.New("uncertified relationship code")
		}
		if err := index.Add(uint32(a), uint32(b), relation); err != nil {
			return nil, err
		}
	}
	if limited.N <= 0 {
		return nil, errors.New("relationship byte budget exceeded")
	}
	if err := scanner.Err(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("relationship read or line limit failed")
	}
	return index, nil
}

// ParseVRPCSV expects the explicitly certified header asn,prefix,maxLength.
// ASN accepts decimal or AS-prefixed decimal. Other schemas need their own adapter.
func ParseVRPCSV(ctx context.Context, r io.Reader, limits ParseLimits, sink func(VRP) error) error {
	if err := limits.validate(); err != nil {
		return err
	}
	limited := &io.LimitedReader{R: contextReader{ctx, r}, N: limits.Bytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), limits.LineBytes)
	header := false
	count := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Text()
		if !utf8.ValidString(line) {
			return errors.New("VRP UTF-8 invalid")
		}
		reader := csv.NewReader(strings.NewReader(line))
		reader.FieldsPerRecord = 3
		fields, err := reader.Read()
		if err != nil {
			return errors.New("VRP CSV schema invalid")
		}
		if !header {
			header = true
			if strings.Join(fields, ",") != "asn,prefix,maxLength" {
				return errors.New("VRP CSV header not certified")
			}
			continue
		}
		count++
		if count > limits.Records {
			return errors.New("VRP record budget exceeded")
		}
		record, err := vrpRecord(fields[0], fields[1], fields[2])
		if err != nil {
			return err
		}
		if err := sink(record); err != nil {
			return err
		}
	}
	if limited.N <= 0 {
		return errors.New("VRP byte budget exceeded")
	}
	if err := scanner.Err(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("VRP read or line limit failed")
	}
	if !header {
		return errors.New("VRP header missing")
	}
	return nil
}
func vrpRecord(asn, prefix, maximum string) (VRP, error) {
	asn = strings.TrimPrefix(asn, "AS")
	number, err := strconv.ParseUint(asn, 10, 32)
	if err != nil {
		return VRP{}, errors.New("VRP ASN invalid")
	}
	network, err := netip.ParsePrefix(prefix)
	if err != nil {
		return VRP{}, errors.New("VRP prefix invalid")
	}
	maxLength, err := strconv.ParseUint(maximum, 10, 8)
	if err != nil || int(maxLength) < network.Bits() || int(maxLength) > network.Addr().BitLen() {
		return VRP{}, errors.New("VRP maximum length invalid")
	}
	return VRP{network.Masked(), uint8(maxLength), uint32(number)}, nil
}

// ParseVRPJSON streams the explicit {"roas":[...]} schema. The input cap bounds
// decoder memory even for a single hostile scalar; each accepted object <=1 MiB.
func ParseVRPJSON(ctx context.Context, r io.Reader, limits ParseLimits, sink func(VRP) error) error {
	if err := limits.validate(); err != nil {
		return err
	}
	if limits.Bytes > 64<<20 {
		return errors.New("JSON parser total allocation envelope is 64 MiB")
	}
	limited := &io.LimitedReader{R: contextReader{ctx, r}, N: limits.Bytes + 1}
	decoder := json.NewDecoder(limited)
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("VRP JSON root invalid")
	}
	found := false
	count := 0
	keys := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return errors.New("VRP JSON key invalid")
		}
		name, ok := key.(string)
		if !ok || keys[name] {
			return errors.New("VRP JSON duplicate key")
		}
		keys[name] = true
		if name != "roas" {
			return errors.New("uncertified VRP JSON root field")
		}
		found = true
		token, err = decoder.Token()
		if err != nil || token != json.Delim('[') {
			return errors.New("VRP JSON records invalid")
		}
		for decoder.More() {
			if err := ctx.Err(); err != nil {
				return err
			}
			count++
			if count > limits.Records {
				return errors.New("VRP record budget exceeded")
			}
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				return errors.New("VRP JSON record invalid")
			}
			if len(raw) > 1<<20 {
				return errors.New("VRP JSON object budget exceeded")
			}
			record, err := decodeVRPJSONRecord(raw)
			if err != nil {
				return err
			}
			if err := sink(record); err != nil {
				return err
			}
		}
		if token, err = decoder.Token(); err != nil || token != json.Delim(']') {
			return errors.New("VRP JSON array invalid")
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || !found {
		return errors.New("VRP JSON root incomplete")
	}
	if token, err = decoder.Token(); err != io.EOF {
		return errors.New("VRP JSON trailing content")
	}
	if limited.N <= 0 {
		return errors.New("VRP JSON byte budget exceeded")
	}
	return nil
}

func decodeVRPJSONRecord(raw []byte) (VRP, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return VRP{}, errors.New("VRP JSON object required")
	}
	seen := map[string]bool{}
	asn, prefix, maximum := "", "", ""
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return VRP{}, errors.New("VRP duplicate or invalid field")
		}
		seen[key] = true
		value, err := decoder.Token()
		if err != nil {
			return VRP{}, errors.New("VRP JSON field invalid")
		}
		switch key {
		case "asn":
			switch v := value.(type) {
			case string:
				asn = v
			case json.Number:
				asn = string(v)
			default:
				return VRP{}, errors.New("VRP ASN invalid")
			}
		case "prefix":
			v, ok := value.(string)
			if !ok {
				return VRP{}, errors.New("VRP prefix invalid")
			}
			prefix = v
		case "maxLength":
			v, ok := value.(json.Number)
			if !ok {
				return VRP{}, errors.New("VRP maximum length invalid")
			}
			maximum = string(v)
		default:
			return VRP{}, errors.New("uncertified VRP JSON field")
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || len(seen) != 3 {
		return VRP{}, errors.New("VRP JSON object incomplete")
	}
	return vrpRecord(asn, prefix, maximum)
}
