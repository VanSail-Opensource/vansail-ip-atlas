package admission

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

const (
	rootZoneURL              = "https://www.internic.net/domain/root.zone"
	rootZoneAlternateGzipURL = "https://www.internic.net/zones/root.zone.gz"
	rootZoneLimit            = 8 << 20
	rootServerCount          = 13
)

func rootZoneSource(s Source) bool {
	return s.ID == "iana-root-anycast" && s.Family == "dns-root-operators" && s.Category == "infrastructure" &&
		s.Parser == (Parser{"root-zone-anycast", "root-zone-in-soa-glue-v1", 1}) && len(s.Signals) == 0 &&
		s.MaxCompressedBytes > 0 && s.MaxCompressedBytes <= rootZoneLimit && s.Format == "text" && s.URL == rootZoneURL &&
		s.Scope == "exact_ip" && s.Coverage == "mapping" && s.Publication == (Publication{"embedded", rootZoneURL, "soa.serial"}) &&
		fieldsEqual(s.PublicFields, "anycast") && fieldsEqual(s.Fields, "ip", "type", "observed_at") && mappedFields(s, map[string]string{"ip": "anycast"})
}

type rootAddressSet map[netip.Addr]bool

func (seen rootAddressSet) add(u *intelligence.ScopedUsage, published time.Time) bool {
	x := u.Evidence
	ip := u.Prefix.Addr()
	if !x.Current || x.Anycast == nil || !*x.Anycast || x.DirectedBroadcast != nil ||
		x.Type != "" || x.Assignment != "" || x.Contextual || u.ASN != 0 ||
		!u.Prefix.IsSingleIP() || !subscription.Public(ip) || seen[ip] || !u.ObservedAt.Equal(published) {
		return false
	}
	seen[ip] = true
	return true
}

func (seen rootAddressSet) complete() bool {
	if len(seen) != 2*rootServerCount {
		return false
	}
	var v4 int
	for ip := range seen {
		if ip.Is4() {
			v4++
		}
	}
	return v4 == rootServerCount
}

type rootService struct {
	delegated bool
	v4, v6    netip.Addr
}

type rootZoneProjection struct {
	day, until, nsSignatureStart, nsSignatureEnd time.Time
	serial                                       string
	minimumTTL                                   uint32
	zonedigestSerial                             string
	services                                     [rootServerCount]rootService
}

func rootIdentity(name string) int {
	if len(name) != len("a.root-servers.net.") || !strings.EqualFold(name[1:], ".root-servers.net.") {
		return -1
	}
	letter := name[0]
	if letter >= 'A' && letter <= 'M' {
		letter += 'a' - 'A'
	}
	if letter < 'a' || letter > 'm' {
		return -1
	}
	return int(letter - 'a')
}

func (z *rootZoneProjection) includeTTL(ttl uint32) {
	if z.minimumTTL == 0 || ttl < z.minimumTTL {
		z.minimumTTL = ttl
	}
}

func (z *rootZoneProjection) record(f []string) error {
	invalid := errors.New("DNS root zone record invalid")
	if len(f) < 5 || f[2] != "IN" || !strings.HasSuffix(f[0], ".") {
		return invalid
	}
	n, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil || n == 0 {
		return invalid
	}
	ttl := uint32(n)
	switch f[3] {
	case "SOA":
		if len(f) != 11 || f[0] != "." || z.serial != "" || len(f[6]) != 10 {
			return invalid
		}
		if _, err = strconv.ParseUint(f[6], 10, 32); err != nil {
			return invalid
		}
		z.day, err = time.Parse("20060102", f[6][:8])
		if err != nil || z.day.Year() < 1970 {
			return invalid
		}
		z.serial = f[6]
	case "NS":
		if len(f) != 5 {
			return invalid
		}
		if f[0] != "." {
			return nil
		}
		id := rootIdentity(f[4])
		if id < 0 || z.services[id].delegated {
			return invalid
		}
		z.services[id].delegated = true
		z.includeTTL(ttl)
	case "A", "AAAA":
		if len(f) != 5 {
			return invalid
		}
		id := rootIdentity(f[0])
		if id < 0 {
			return nil
		}
		ip, err := netip.ParseAddr(f[4])
		if err != nil || ip.Zone() != "" || ip.Is4In6() || !subscription.Public(ip) || (f[3] == "A") != ip.Is4() {
			return invalid
		}
		dst := &z.services[id].v6
		if ip.Is4() {
			dst = &z.services[id].v4
		}
		if dst.IsValid() {
			return invalid
		}
		*dst = ip
		z.includeTTL(ttl)
	case "ZONEMD":
		if f[0] != "." || len(f) != 8 || f[5] != "1" || f[6] != "1" || z.zonedigestSerial != "" || len(f[7]) != 96 {
			return invalid
		}
		if _, err := hex.DecodeString(f[7]); err != nil {
			return invalid
		}
		z.zonedigestSerial = f[4]
	case "RRSIG":
		if len(f) != 13 {
			return invalid
		}
		if f[0] == "." && f[4] == "NS" {
			end, e1 := time.Parse("20060102150405", f[8])
			start, e2 := time.Parse("20060102150405", f[9])
			if e1 != nil || e2 != nil || !start.Before(end) || !strings.EqualFold(f[11], ".") {
				return invalid
			}
			if start.After(z.nsSignatureStart) {
				z.nsSignatureStart = start
			}
			if z.nsSignatureEnd.IsZero() || end.Before(z.nsSignatureEnd) {
				z.nsSignatureEnd = end
			}
		}
	case "DNSKEY", "DS":
		if len(f) != 8 {
			return invalid
		}
	case "NSEC":
		if len(f) < 6 {
			return invalid
		}
	default:
		return invalid
	}
	return nil
}

// Read only the published file. No host in a DNS record is ever resolved.
// Emit after complete framing and the exact delegated identity/glue checks.
func parseRootZone(ctx context.Context, input io.Reader, maximum int, emit func(intelligence.NormalizedRecord) error) (rootZoneProjection, error) {
	var z rootZoneProjection
	reader := bufio.NewReaderSize(&io.LimitedReader{R: contextReader{ctx, input}, N: rootZoneLimit + 1}, 32<<10)
	size := 0
	for {
		if err := ctx.Err(); err != nil {
			return z, err
		}
		line, err := reader.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		size += len(line)
		if err != nil || size > rootZoneLimit || bytes.IndexByte(line, 0) >= 0 {
			return z, errors.New("DNS root zone framing invalid")
		}
		if err = z.record(strings.Fields(string(line))); err != nil {
			return z, err
		}
	}
	if z.day.IsZero() || z.zonedigestSerial != z.serial || z.minimumTTL == 0 || !z.day.Before(z.nsSignatureEnd) || maximum < 2*rootServerCount {
		return z, errors.New("DNS root observation incomplete")
	}
	z.until = z.day.Add(time.Duration(z.minimumTTL) * time.Second)
	if z.nsSignatureEnd.Before(z.until) {
		z.until = z.nsSignatureEnd
	}
	seen := map[netip.Addr]bool{}
	for _, s := range z.services {
		if !s.delegated || !s.v4.IsValid() || !s.v6.IsValid() || seen[s.v4] || seen[s.v6] {
			return z, errors.New("DNS root service delegation and addresses differ")
		}
		seen[s.v4], seen[s.v6] = true, true
	}
	if emit != nil {
		for _, s := range z.services {
			for _, ip := range []netip.Addr{s.v4, s.v6} {
				yes := true
				value := intelligence.ScopedUsage{Prefix: netip.PrefixFrom(ip, ip.BitLen()), ObservedAt: z.day, Evidence: intelligence.UsageEvidence{Family: "dns-root-operators", Current: true, Anycast: &yes}}
				if err := emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordUsage, Usage: &value}); err != nil {
					return z, err
				}
			}
		}
	}
	return z, nil
}

// Both publisher directories contain complete gzip representations of the
// current zone. The text always chooses the edition. Never substitute facts or
// a date from a divergent compressed file.
var errRootZoneCopyUnavailable = errors.New("DNS root zone gzip unavailable")
var errRootZoneCopyOlder = errors.New("DNS root zone gzip has an earlier serial")

func (e *Engine) matchRootZoneGzip(ctx context.Context, url, path string, digest [32]byte, size int64, serial string, now time.Time) error {
	res, err := e.fetch.Fetch(ctx, url, path, rootZoneLimit)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errRootZoneCopyUnavailable
	}
	if res.LastModified.After(now) {
		return errors.New("DNS root gzip postdates evaluation")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	sha := sha256.New()
	var decoded int64
	var edition rootZoneProjection
	limits := acquire.ArchiveLimits{CompressedBytes: rootZoneLimit, DecodedBytes: rootZoneLimit, EntryBytes: rootZoneLimit, Entries: 1, NameBytes: 4096}
	err = acquire.WalkArchive(ctx, acquire.ArchiveInput{Reader: f, ReaderAt: f, Size: res.Bytes}, "gzip", limits, func(_ string, r io.Reader) error {
		limited := &io.LimitedReader{R: io.TeeReader(r, sha), N: rootZoneLimit + 1}
		var parseErr error
		edition, parseErr = parseRootZone(ctx, limited, 2*rootServerCount, nil)
		decoded = rootZoneLimit + 1 - limited.N
		return parseErr
	})
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	// Every successfully parsed serial is a ten-digit YYYYMMDDnn. A fully
	// formed prior edition can be a normal lagging publisher edge. Malformed
	// archives, newer editions, and different bytes under one serial fail.
	if edition.serial < serial {
		return errRootZoneCopyOlder
	}
	if edition.serial != serial || decoded != size || !bytes.Equal(sha.Sum(nil), digest[:]) {
		return errors.New("DNS root gzip differs from original text")
	}
	return nil
}

// Verify the original text, its independent publisher checksum and one
// identical complete gzip representation. A recovery tries only the second
// fixed publisher path, retaining the original SOA/TTL/signature bounds.
func (e *Engine) verifyRootZone(ctx context.Context, payload string, digest [32]byte, size int64, now time.Time) (rootZoneProjection, error) {
	var z rootZoneProjection
	deny := errors.New("DNS root zone publication rejected")
	if size <= 0 || size > rootZoneLimit {
		return z, deny
	}
	dir := filepath.Dir(payload)
	mdPath := filepath.Join(dir, "root-md5")
	metaInfo, err := e.fetch.Fetch(ctx, rootZoneURL+".md5", mdPath, 128)
	if err != nil || metaInfo.LastModified.After(now) {
		return z, deny
	}
	meta, err := boundedFile(ctx, mdPath, 128)
	if err != nil || len(meta) != md5.Size*2+1 || meta[len(meta)-1] != '\n' {
		return z, deny
	}
	input, err := os.Open(payload)
	if err != nil {
		return z, deny
	}
	md := md5.New()
	z, err = parseRootZone(ctx, io.TeeReader(input, md), 2*rootServerCount, nil)
	if closeErr := input.Close(); err != nil || closeErr != nil || z.day.After(now) || z.nsSignatureStart.After(now) || hex.EncodeToString(md.Sum(nil)) != string(meta[:md5.Size*2]) {
		return z, deny
	}
	err = e.matchRootZoneGzip(ctx, rootZoneURL+".gz", filepath.Join(dir, "root-gzip"), digest, size, z.serial, now)
	if errors.Is(err, errRootZoneCopyUnavailable) || errors.Is(err, errRootZoneCopyOlder) {
		err = e.matchRootZoneGzip(ctx, rootZoneAlternateGzipURL, filepath.Join(dir, "root-gzip-alternate"), digest, size, z.serial, now)
	}
	if err != nil {
		return z, deny
	}
	return z, nil
}
