package admission

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

const (
	ripeNamesURL        = "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz"
	ripeNamesUTF8URL    = "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.utf8.gz"
	ripeNamesCompressed = 512 << 20 // per export, at most 1 GiB for both
	ripeNamesDecoded    = 3 << 30   // combined decompressed size
)

var errRIPENames = errors.New("invalid IPv6 inet6num registry export")

func ripeNamesSource(s Source) bool {
	return s.ID == intelligence.RIPENetworkNameSourceID && s.Family == "ripe-registry" && s.URL == ripeNamesURL &&
		s.Category == "network_identity" && s.Format == "text-gz" && s.Scope == "prefix" && s.Coverage == "positive_only" &&
		s.MaxCompressedBytes > 0 && s.MaxCompressedBytes <= ripeNamesCompressed && len(s.Signals) == 0 &&
		s.Parser == (Parser{intelligence.RIPENetworkNameSourceID, "ripe-db-inet6num-v2", 2}) &&
		s.Publication == (Publication{"embedded", ripeNamesURL, "last-modified"}) &&
		fieldsEqual(s.Fields, "inet6num", "netname", "source", "last-modified", "country", "descr", "mnt-by", "status") && fieldsEqual(s.PublicFields, "network_name", "isp") &&
		mappedFields(s, map[string]string{"netname": "network_name", "descr": "isp"})
}

type ripeNamesInventory struct {
	rows, prefixes, named uint64
	newest                time.Time
	projection, scopes    [32]byte
}

type ripeNamesObject struct {
	resource, name, authority, modified                       string
	started, nameSet, suppressName, authoritySet, modifiedSet bool
	subscriber                                                ripeSubscriberEvidence
}

// RPSL continuation lines can contain free text. Consume them only for framing;
// continuation of a network name makes the complete name ineligible.
func readRIPENames(ctx context.Context, input io.Reader, now time.Time, maxRecords int, limit int64, checkUTF8 bool, emit func(intelligence.NormalizedRecord) error) (ripeNamesInventory, int64, error) {
	var out ripeNamesInventory
	if now.IsZero() || maxRecords <= 0 || limit <= 0 || limit > ripeNamesDecoded {
		return out, 0, errRIPENames
	}
	limited := &io.LimitedReader{R: contextReader{ctx, input}, N: limit + 1}
	scan := bufio.NewScanner(limited)
	scan.Buffer(make([]byte, 65536), 1<<20)
	seen := map[netip.Prefix]struct{}{}
	var digest intelligence.RIPENetworkNameDigest
	scopes := sha256.New()
	var row ripeNamesObject
	var lastAttr byte
	complete := func() error {
		if !row.started {
			return nil
		}
		if !row.authoritySet || row.resource == "" || out.rows >= intelligence.RIPENetworkNameMaxRecords {
			return errRIPENames
		}
		out.rows++
		p, e := netip.ParsePrefix(row.resource)
		if e != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Addr().Zone() != "" || p != p.Masked() {
			return errRIPENames
		}
		if _, dup := seen[p]; dup {
			return errRIPENames
		}
		seen[p] = struct{}{}
		au := len(row.authority) == 4 && strings.EqualFold(row.authority, "RIPE")
		var modified time.Time
		if row.modifiedSet {
			modified, e = time.Parse(time.RFC3339, row.modified)
			if e != nil || modified.UTC().Format(time.RFC3339) != row.modified || modified.Year() < 1970 || modified.After(now) {
				return errRIPENames
			}
		} else if au {
			return errRIPENames
		}
		eligible := subscription.PublicPrefix(p)
		// Compare the original scope and authority of every object, including
		// nonpublic space which never enters the public-name projection.
		addr := p.Addr().As16()
		var scope [27]byte
		copy(scope[:], addr[:])
		scope[16] = byte(p.Bits())
		if au {
			scope[17] = 1
		}
		if eligible {
			scope[18] = 1
		}
		binary.BigEndian.PutUint64(scope[19:], uint64(modified.Unix()))
		scopes.Write(scope[:])
		if !au {
			// Unknown authorities can only withhold a name. Still bind which
			// authority each independently generated export actually reported.
			if len(row.authority) > 32 {
				return errRIPENames
			}
			for i, b := range []byte(row.authority) {
				if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || i > 0 && (b >= '0' && b <= '9' || b == '-' || b == '_')) {
					return errRIPENames
				}
			}
			scopes.Write([]byte{byte(len(row.authority))})
			scopes.Write([]byte(strings.ToUpper(row.authority)))
		}
		if eligible {
			if out.prefixes >= uint64(maxRecords) {
				return errRIPENames
			}
			var name string
			if au && !row.suppressName && intelligence.ValidRIPENetworkName(row.name) {
				name = row.name
				out.named++
				if modified.After(out.newest) {
					out.newest = modified
				}
			}
			record := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordNetworkName, NetworkName: &intelligence.NetworkNameRecord{Prefix: p, Name: name, ModifiedAt: modified, SubscriberISP: row.subscriber.operator(name)}}
			if err := digest.Add(record); err != nil {
				return err
			}
			out.prefixes++
			if emit != nil {
				if err := emit(record); err != nil {
					return err
				}
			}
		}
		row = ripeNamesObject{}
		lastAttr = 0
		return nil
	}
	for scan.Scan() {
		line := scan.Bytes()
		if checkUTF8 && !utf8.Valid(line) {
			return out, 0, errRIPENames
		}
		if len(line) == 0 {
			if err := complete(); err != nil {
				return out, 0, err
			}
			continue
		}
		if line[0] == '#' || line[0] == '%' {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' || line[0] == '+' {
			if !row.started || lastAttr == 'p' || lastAttr == 's' || lastAttr == 't' {
				return out, 0, errRIPENames
			}
			if lastAttr == 'i' {
				row.subscriber.invalid = true
			}
			if lastAttr == 'n' {
				row.suppressName = true
			}
			continue
		}
		attr, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || len(attr) == 0 || len(attr) > 64 {
			return out, 0, errRIPENames
		}
		// Attribute names are ASCII case-insensitive (RFC 2622 section 2).
		// Ordinary lowercase exports need no per-line allocation for the key.
		uppercase := false
		for _, b := range attr {
			if b >= 'A' && b <= 'Z' {
				uppercase = true
				continue
			}
			if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-' {
				return out, 0, errRIPENames
			}
		}
		if uppercase {
			attr = bytes.ToLower(attr)
		}
		lastAttr = 0
		if !row.started && !bytes.Equal(attr, []byte("inet6num")) {
			return out, 0, errRIPENames
		}
		switch string(attr) {
		case "inet6num":
			if row.started {
				return out, 0, errRIPENames
			}
			row.started = true
			row.resource = string(bytes.TrimSpace(value))
			lastAttr = 'p'
		case "country", "mnt-by", "status", "descr":
			row.subscriber.observe(string(attr), bytes.TrimSpace(value))
			lastAttr = 'i'
		case "netname":
			if row.nameSet {
				row.suppressName = true
			}
			row.nameSet = true
			v := bytes.TrimSpace(value)
			if len(v) <= 128 {
				row.name = string(v)
			} else {
				row.suppressName = true
			}
			lastAttr = 'n'
		case "source":
			if row.authoritySet {
				return out, 0, errRIPENames
			}
			row.authoritySet = true
			v, _, _ := bytes.Cut(value, []byte("#"))
			row.authority = string(bytes.TrimSpace(v))
			if row.authority == "" {
				return out, 0, errRIPENames
			}
			lastAttr = 's'
		case "last-modified":
			if row.modifiedSet {
				return out, 0, errRIPENames
			}
			row.modifiedSet = true
			row.modified = string(bytes.TrimSpace(value))
			lastAttr = 't'
		}
	}
	if err := scan.Err(); err != nil {
		return out, 0, err
	}
	if limited.N <= 0 {
		return out, 0, errRIPENames
	}
	if err := complete(); err != nil {
		return out, 0, err
	}
	if out.named == 0 {
		return out, 0, errRIPENames
	}
	_, out.projection = digest.Sum()
	copy(out.scopes[:], scopes.Sum(nil))
	return out, limit + 1 - limited.N, nil
}

// Exactly one complete gzip member is accepted. Reading to EOF checks the gzip
// trailer and CRC; physical bytes after the member cannot start another export.
func readRIPENamesArchive(ctx context.Context, input io.Reader, s Source, now time.Time, maxRecords int, limit int64, utf bool, emit func(intelligence.NormalizedRecord) error) (ripeNamesInventory, int64, [32]byte, error) {
	var sum [32]byte
	var out ripeNamesInventory
	h := sha256.New()
	bound := &io.LimitedReader{R: contextReader{ctx, input}, N: s.MaxCompressedBytes + 1}
	physical := bufio.NewReader(io.TeeReader(bound, h))
	z, err := gzip.NewReader(physical)
	if err != nil {
		return out, 0, sum, err
	}
	defer z.Close()
	z.Multistream(false)
	out, n, err := readRIPENames(ctx, z, now, maxRecords, limit, utf, emit)
	if err != nil {
		return out, 0, sum, err
	}
	if _, err = physical.Peek(1); err != io.EOF || bound.N <= 0 {
		return out, 0, sum, errRIPENames
	}
	copy(sum[:], h.Sum(nil))
	return out, n, sum, nil
}

func (e *Engine) verifyRIPENames(ctx context.Context, path string, s Source, hash [32]byte, now time.Time) (*intelligence.RIPEIPv6NetworkProof, error) {
	secondary := filepath.Join(filepath.Dir(path), "inet6num-utf8.gz")
	if _, err := e.fetch.Fetch(ctx, ripeNamesUTF8URL, secondary, s.MaxCompressedBytes); err != nil {
		return nil, err
	}
	read := func(path string, limit int64, utf bool) (ripeNamesInventory, int64, [32]byte, error) {
		f, err := os.Open(path)
		if err != nil {
			return ripeNamesInventory{}, 0, [32]byte{}, err
		}
		defer f.Close()
		return readRIPENamesArchive(ctx, f, s, now, intelligence.RIPENetworkNameMaxRecords, limit, utf, nil)
	}
	primary, n1, h1, err := read(path, ripeNamesDecoded, false)
	if err != nil {
		return nil, err
	}
	if h1 != hash {
		return nil, errRIPENames
	}
	mirror, n2, h2, err := read(secondary, ripeNamesDecoded-n1, true)
	if err != nil {
		return nil, err
	}
	if primary != mirror {
		return nil, errRIPENames
	}
	p := &intelligence.RIPEIPv6NetworkProof{PublishedAt: primary.newest, PayloadHash: h1, UTF8Hash: h2, Projection: primary.projection, Records: primary.rows, Prefixes: primary.prefixes, NamedPrefixes: primary.named, PrimaryDecodedBytes: n1, UTF8DecodedBytes: n2}
	return p, p.Validate(now, p.PublishedAt, hash)
}

func validateRIPENamesExcerpt(ctx context.Context, r io.Reader, s Source, selected adapter, clock time.Time) (uint64, error) {
	if selected != ripeNetworkNames || !ripeNamesSource(s) || s.Fixture.ContentEncoding != "" && s.Fixture.ContentEncoding != "identity" {
		return 0, errRIPENames
	}
	v, _, err := readRIPENames(ctx, r, clock, 256, 1<<20, false, func(record intelligence.NormalizedRecord) error { return record.Validate() })
	return v.prefixes, err
}
