package admission

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

const nroURL = "https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats"
const nroLimit = 64 << 20

var errNRO = errors.New("invalid NRO global delegation report")

func nroSource(s Source) bool {
	return s.ID == intelligence.NRORegistrationID && s.URL == nroURL && s.Family == "nro-rir-delegation" && s.Category == "geolocation" && s.Format == "text" && s.Scope == "prefix" && s.Coverage == "positive_only" && s.MaxCompressedBytes > 0 && s.MaxCompressedBytes <= nroLimit && s.Parser == (Parser{"nro-delegated-registration", "nro-global-extended-v2", 1}) && s.Publication == (Publication{"embedded", nroURL, "header.serial"}) && len(s.Signals) == 0 && fieldsEqual(s.PublicFields, "registration_country") && fieldsEqual(s.Fields, "registry", "cc", "type", "start", "value", "status") && mappedFields(s, map[string]string{"cc": "registration_country"})
}
func nroUint(s string, bits int) (uint64, error) {
	n, e := strconv.ParseUint(s, 10, bits)
	if e != nil || strconv.FormatUint(n, 10) != s {
		return 0, errNRO
	}
	return n, nil
}
func nroDay(s string) (time.Time, error) {
	d, e := time.Parse("20060102", s)
	if e != nil || d.Year() < 1970 {
		return time.Time{}, errNRO
	}
	return d, nil
}

type nroRange struct{ first, last netip.Addr }

func nroResource(kind, start, count string) (nroRange, error) {
	var result nroRange
	n, e := nroUint(count, 64)
	if e != nil {
		return result, e
	}
	if kind == "ipv6" {
		ip, e := netip.ParseAddr(start)
		if e != nil || !ip.Is6() || ip.Is4In6() || ip.Zone() != "" || n > 128 {
			return result, errNRO
		}
		prefix := netip.PrefixFrom(ip, int(n))
		if prefix != prefix.Masked() {
			return result, errNRO
		}
		return nroRange{ip, lastAddress(prefix)}, nil
	}
	var at uint64
	if kind == "ipv4" {
		ip, e := netip.ParseAddr(start)
		if e != nil || !ip.Is4() {
			return result, errNRO
		}
		a := ip.As4()
		at = uint64(binary.BigEndian.Uint32(a[:]))
	} else if kind == "asn" {
		at, e = nroUint(start, 32)
		if e != nil {
			return result, e
		}
	} else {
		return result, errNRO
	}
	if n == 0 || n > (uint64(1)<<32)-at {
		return result, errNRO
	}
	var lo, hi [4]byte
	binary.BigEndian.PutUint32(lo[:], uint32(at))
	binary.BigEndian.PutUint32(hi[:], uint32(at+n-1))
	return nroRange{netip.AddrFrom4(lo), netip.AddrFrom4(hi)}, nil
}

// parseNRO validates all inventory categories, including excluded resource rows.
// RIR counts may represent non-CIDR IPv4 ranges. Only allocated/assigned IP space
// has a recipient country. An excerpt can exercise rows but never establishes a proof.
func parseNRO(ctx context.Context, r io.Reader, s Source, maxRecords int, excerpt bool, emit func(intelligence.NormalizedRecord) error) (intelligence.NRORegistrationProof, error) {
	var proof intelligence.NRORegistrationProof
	if maxRecords <= 0 {
		return proof, errNRO
	}
	bound := &io.LimitedReader{R: contextReader{ctx, r}, N: nroLimit + 1}
	scan := bufio.NewScanner(bound)
	scan.Buffer(make([]byte, 4096), 16<<10)
	counts := map[string]uint64{}
	seen := map[string]uint64{}
	spans := map[string][]nroRange{}
	var digest intelligence.NRORegistrationDigest
	dates := map[string]bool{"00000000": true}
	for scan.Scan() {
		if e := ctx.Err(); e != nil {
			return proof, e
		}
		line := scan.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		for i := range len(line) {
			if line[i] < 32 || line[i] > 126 {
				return proof, errNRO
			}
		}
		f := strings.Split(line, "|")
		if proof.Day.IsZero() {
			if len(f) != 7 || f[0] != "2" || f[1] != "nro" || f[2] != f[5] || f[6] != "+0000" {
				return proof, errNRO
			}
			day, e := nroDay(f[2])
			if e != nil {
				return proof, e
			}
			old, e := nroDay(f[4])
			if e != nil || old.After(day) {
				return proof, errNRO
			}
			proof.Day = day
			proof.Records, e = nroUint(f[3], 32)
			if e != nil || proof.Records == 0 || proof.Records > 2000000 {
				return proof, errNRO
			}
			continue
		}
		if len(counts) < 3 {
			if len(f) != 6 || f[0] != "nro" || f[1] != "*" || f[3] != "*" || f[5] != "summary" || (f[2] != "asn" && f[2] != "ipv4" && f[2] != "ipv6") {
				return proof, errNRO
			}
			n, e := nroUint(f[4], 32)
			if e != nil || n == 0 || n > proof.Records || counts[f[2]] != 0 {
				return proof, errNRO
			}
			counts[f[2]] = n
			continue
		}
		if len(f) != 9 || counts[f[2]] == 0 || seen[f[2]] >= counts[f[2]] || (f[6] != "reserved" && f[6] != "available" && f[6] != "allocated" && f[6] != "assigned") {
			return proof, errNRO
		}
		switch f[0] {
		case "apnic", "arin", "afrinic", "lacnic", "ripencc":
			if f[8] != "e-stats" {
				return proof, errNRO
			}
		case "iana":
			if f[8] != "iana" {
				return proof, errNRO
			}
		default:
			return proof, errNRO
		}
		if f[1] != "" && (len(f[1]) != 2 || f[1][0] < 'A' || f[1][0] > 'Z' || f[1][1] < 'A' || f[1][1] > 'Z') {
			return proof, errNRO
		}
		if !dates[f[5]] {
			d, e := nroDay(f[5])
			if e != nil || d.After(proof.Day) {
				return proof, errNRO
			}
			dates[f[5]] = true
		}
		span, e := nroResource(f[2], f[3], f[4])
		if e != nil {
			return proof, e
		}
		spans[f[2]] = append(spans[f[2]], span)
		seen[f[2]]++
		if f[0] == "iana" || f[2] == "asn" || f[6] != "assigned" && f[6] != "allocated" || !facts.CountryValid(f[1]) {
			continue
		}
		e = rangePrefixes(span.first, span.last, func(prefix netip.Prefix) error {
			if !subscription.PublicPrefix(prefix) {
				return nil
			}
			if proof.Prefixes >= uint64(maxRecords) || proof.Prefixes >= 5000000 {
				return errNRO
			}
			rec := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Family: s.Family, Weight: s.Weight, Current: true, Prefix: prefix, RegistrationCountry: f[1]}}
			if e := digest.Add(rec); e != nil {
				return e
			}
			proof.Prefixes++
			if emit != nil {
				return emit(rec)
			}
			return nil
		})
		if e != nil {
			return proof, e
		}
	}
	if err := scan.Err(); err != nil {
		return proof, err
	}
	if bound.N <= 0 || len(counts) != 3 || counts["asn"]+counts["ipv4"]+counts["ipv6"] != proof.Records || proof.Prefixes == 0 {
		return proof, errNRO
	}
	for kind, declared := range counts {
		if !excerpt && seen[kind] != declared {
			return proof, errNRO
		}
		ranges := spans[kind]
		slices.SortFunc(ranges, func(a, b nroRange) int { return a.first.Compare(b.first) })
		for i := 1; i < len(ranges); i++ {
			if !ranges[i-1].last.Less(ranges[i].first) {
				return proof, errNRO
			}
		}
	}
	_, proof.Projection = digest.Sum()
	return proof, nil
}
func validateNROExcerpt(ctx context.Context, input io.Reader, source Source, selected adapter, tested time.Time) (uint64, error) {
	if selected != nroRegistration || !nroSource(source) || source.Fixture.ContentEncoding != "" && source.Fixture.ContentEncoding != "identity" {
		return 0, errNRO
	}
	proof, err := parseNRO(ctx, input, source, 5000000, true, func(record intelligence.NormalizedRecord) error { return record.Validate() })
	if err != nil {
		return 0, err
	}
	if proof.Day.After(tested) {
		return 0, errNRO
	}
	return proof.Prefixes, nil
}

func (e *Engine) verifyNRO(ctx context.Context, path string, digest [32]byte, s Source, now time.Time) (*intelligence.NRORegistrationProof, error) {
	checksum := filepath.Join(filepath.Dir(path), "nro-checksum")
	if _, err := e.fetch.Fetch(ctx, nroURL+".sha256", checksum, 256); err != nil {
		return nil, err
	}
	data, err := boundedFile(ctx, checksum, 256)
	if err != nil || !bytes.Equal(data, []byte(hashString(digest)+"  nro-delegated-stats\n")) {
		return nil, errNRO
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	proof, err := parseNRO(ctx, file, s, 5000000, false, nil)
	if err != nil {
		return nil, err
	}
	proof.PayloadHash = digest
	proof.ChecksumHash = sha256.Sum256(data)
	if err = proof.Validate(now, proof.Day, digest); err != nil {
		return nil, err
	}
	return &proof, nil
}
