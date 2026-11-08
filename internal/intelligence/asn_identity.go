package intelligence

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

// ASNIdentityEvidence contains direct network identity only. It cannot supply
// usage, IP location, business relationships or Tier-1 membership.
type ASNIdentityEvidence struct {
	ASN                         uint32
	Name, Organization, Country string
	Family                      string
	Weight                      float64
	Current                     bool
}
type ASNIdentityResult struct{ Name, Organization, Country string }
type ASNIdentityStats struct{ ReadRows, AcceptedRows, SkippedReservedASNs, SanitizedFields uint64 }

// ParseASNIdentityCSV streams the observed four-column publisher schema. The
// logical CSV record (including quoted physical newlines) is bounded before CSV
// decoding allocates fields. Reserved ASNs are counted and skipped; malformed
// decimal syntax aborts instead of guessing an identity.
func ParseASNIdentityCSV(ctx context.Context, reader io.Reader, limits ParseLimits, sink func(ASNIdentityEvidence) error) (ASNIdentityStats, error) {
	var stats ASNIdentityStats
	if err := limits.validate(); err != nil {
		return stats, err
	}
	if sink == nil {
		return stats, errors.New("ASN identity sink required")
	}
	limited := &io.LimitedReader{R: contextReader{ctx, reader}, N: limits.Bytes + 1}
	input := bufio.NewReaderSize(limited, 4096)
	var record []byte
	quoted := false
	header := false
	var logicalInput bytes.Reader
	csvInput := bufio.NewReaderSize(&logicalInput, 4096)
	csvReader := csv.NewReader(csvInput)
	csvReader.FieldsPerRecord = 4
	csvReader.ReuseRecord = true
	consume := func() error {
		if len(record) == 0 || bytes.Equal(record, []byte("\n")) || bytes.Equal(record, []byte("\r\n")) {
			return nil
		}
		if !utf8.Valid(record) {
			return errors.New("ASN identity UTF-8 invalid")
		}
		logicalInput.Reset(record)
		csvInput.Reset(&logicalInput)
		fields, err := csvReader.Read()
		if err != nil {
			return errors.New("ASN identity CSV schema invalid")
		}
		if _, err := csvReader.Read(); err != io.EOF {
			return errors.New("ASN identity CSV trailing record")
		}
		if !header {
			header = true
			if fields[0] != "asn" || fields[1] != "handle" || fields[2] != "description" || fields[3] != "country-code" {
				return errors.New("ASN identity CSV header not certified")
			}
			return nil
		}
		stats.ReadRows++
		if stats.ReadRows > uint64(limits.Records) {
			return errors.New("ASN identity record budget exceeded")
		}
		if fields[0] == "" {
			return errors.New("ASN identity decimal ASN invalid")
		}
		for _, digit := range fields[0] {
			if digit < '0' || digit > '9' {
				return errors.New("ASN identity decimal ASN invalid")
			}
		}
		asn, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return errors.New("ASN identity decimal ASN invalid")
		}
		if !IsPublicASN(uint32(asn)) {
			stats.SkippedReservedASNs++
			return nil
		}
		value := ASNIdentityEvidence{ASN: uint32(asn), Name: SafeLabel(fields[1]), Organization: SafeLabel(fields[2]), Country: country(fields[3])}
		if value.Name != fields[1] {
			stats.SanitizedFields++
		}
		if value.Organization != fields[2] {
			stats.SanitizedFields++
		}
		if value.Country != fields[3] {
			stats.SanitizedFields++
		}
		if err := sink(value); err != nil {
			return err
		}
		stats.AcceptedRows++
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		chunk, err := input.ReadSlice('\n')
		if limited.N <= 0 {
			return stats, errors.New("ASN identity byte budget exceeded")
		}
		if len(chunk) > limits.LineBytes-len(record) {
			return stats, errors.New("ASN identity logical CSV record budget exceeded")
		}
		record = append(record, chunk...)
		for _, value := range chunk {
			if value == '"' {
				quoted = !quoted
			}
		}
		if err == nil && !quoted {
			if err := consume(); err != nil {
				return stats, err
			}
			record = record[:0]
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			if len(record) > 0 {
				if err := consume(); err != nil {
					return stats, err
				}
			}
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			return stats, errors.New("ASN identity input read failed")
		}
	}
	if !header {
		return stats, errors.New("ASN identity header missing")
	}
	return stats, nil
}

// FuseASNIdentities treats each field independently. A family's highest-weight
// conflicting values abstain; across remaining families the highest weight wins
// only if its value is unique. Missing/zero-weight fields abstain. No source name
// or input ordering resolves ties.
func FuseASNIdentities(records []ASNIdentityEvidence) (ASNIdentityResult, error) {
	out := ASNIdentityResult{}
	if len(records) > 8192 {
		return out, errors.New("ASN identity boundary budget exceeded")
	}
	asn := uint32(0)
	for _, v := range records {
		if !v.Current {
			continue
		}
		if !IsPublicASN(v.ASN) || v.Family == "" || len(v.Family) > 256 || !finite(v.Weight) || v.Weight < 0 || v.Weight > 100 || len(v.Name) > 1024 || len(v.Organization) > 1024 || len(v.Country) > 2 {
			return out, errors.New("ASN identity evidence invalid")
		}
		if asn != 0 && asn != v.ASN {
			return out, errors.New("mixed ASN identity boundary")
		}
		asn = v.ASN
	}
	type vote struct {
		weight   float64
		value    string
		conflict bool
	}
	field := func(get func(ASNIdentityEvidence) string) string {
		families := map[string]vote{}
		for _, v := range records {
			if !v.Current {
				continue
			}
			value := get(v)
			if value == "" || v.Weight == 0 {
				continue
			}
			prior, exists := families[v.Family]
			if !exists || v.Weight > prior.weight {
				families[v.Family] = vote{weight: v.Weight, value: value}
			} else if v.Weight == prior.weight && value != prior.value {
				prior.conflict = true
				families[v.Family] = prior
			}
		}
		best := -1.0
		winner := ""
		conflict := false
		for _, v := range families {
			if v.conflict {
				continue
			}
			if v.weight > best {
				best = v.weight
				winner = v.value
				conflict = false
			} else if v.weight == best && v.value != winner {
				conflict = true
			}
		}
		if conflict {
			return ""
		}
		return winner
	}
	out.Name = field(func(v ASNIdentityEvidence) string { return SafeLabel(v.Name) })
	out.Organization = field(func(v ASNIdentityEvidence) string { return SafeLabel(v.Organization) })
	out.Country = field(func(v ASNIdentityEvidence) string { return country(v.Country) })
	return out, nil
}
