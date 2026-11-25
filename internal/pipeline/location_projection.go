package pipeline

import (
	"context"
	"errors"
	"io"
	"net/netip"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

// Only geographic and coordinate votes can survive a changed clock through
// this projection. Every emitted boundary and usage vote still comes from the
// current leaf. Contextual ASN labels never supply an anycast flag. All direct
// anycast votes and all geographic records are in the ordered bucket parts.
type locationValue struct {
	geo         via3.GeoData
	coordinates via3.CoordinateData
}

type locationProjection struct {
	spool            *bulkSpool
	scope            netip.Prefix
	entry            spatialCacheEntry
	hit              bool
	writer           *spatialStreamWriter
	input            *spatialStreamReader
	rows             *runReader
	pending          bool
	records, decoded uint64
}

// A full public-leaf hit does not visit its mapping inputs. Carry the exact
// authenticated projection so an intervening source update in a different
// scope does not discard it before the next clock advance.
func (s *bulkSpool) retainLocations(ctx context.Context, bucket *bulkBucket, policy [32]byte) error {
	key, err := s.leafKey("location", bucket, false, policy)
	if err != nil {
		return err
	}
	entry, hit, err := s.reuse.Lookup(ctx, "location", key)
	if err != nil || !hit {
		return err
	}
	_, err = s.reuse.Retain(ctx, entry, nil)
	return err
}

func (s *bulkSpool) openLocations(ctx context.Context, bucket *bulkBucket, policy [32]byte) (*locationProjection, error) {
	if s.reuse == nil {
		return nil, nil
	}
	key, err := s.leafKey("location", bucket, false, policy)
	if err != nil {
		return nil, err
	}
	entry, hit, err := s.reuse.Lookup(ctx, "location", key)
	if err != nil {
		return nil, err
	}
	p := &locationProjection{spool: s, scope: bucket.prefix, entry: entry, hit: hit}
	if !hit {
		p.entry = spatialCacheEntry{Key: key, Domain: "location", Leaf: &spatialCacheLeaf{}}
		p.writer, err = s.newSpatialStream(ctx)
		return p, err
	}
	if err = s.verifyParts(ctx, bucket.parts); err != nil {
		return nil, err
	}
	stream := entry.Leaf.Stream
	if stream == (spatialCacheStream{}) {
		return p, nil
	}
	p.input, err = s.openSpatialStream(ctx, stream)
	if err != nil {
		return nil, err
	}
	p.rows = &runReader{reader: p.input.reader, limit: DefaultLimits().RecordBytes}
	if err = p.advance(); err != nil {
		return nil, errors.Join(err, p.close())
	}
	return p, nil
}

func (p *locationProjection) advance() error {
	previous := p.rows.record
	err := p.rows.next()
	if err == io.EOF {
		p.pending = false
		return nil
	}
	if err != nil {
		return err
	}
	r := p.rows.record
	if !validSpatialPrefix(r.Prefix) || !(r.Prefix.Contains(p.scope.Addr()) || p.scope.Contains(r.Prefix.Addr())) || r.Kind != 2 && r.Kind != 3 || r.Exact || r.Inherited || r.ASN != 0 || r.Rank != 0 {
		return errors.New("cached geographic projection row invalid")
	}
	if previous.Prefix.IsValid() && (locationPrefixLess(r.Prefix, previous.Prefix) || r.Prefix == previous.Prefix && r.Kind <= previous.Kind) {
		return errors.New("cached geographic projection order invalid")
	}
	p.records++
	p.decoded += uint64(p.rows.row.frameBytes())
	if p.records > p.entry.Leaf.Stream.Records || p.decoded > p.entry.Leaf.Stream.DecodedBytes {
		return errors.New("cached geographic projection exceeds declared population")
	}
	p.pending = true
	return nil
}

func locationPrefixLess(a, b netip.Prefix) bool {
	if a.Addr() != b.Addr() {
		return a.Addr().Less(b.Addr())
	}
	return a.Bits() < b.Bits()
}

func (p *locationProjection) resolve(prefix netip.Prefix, policy intelligence.Policy, geo []intelligence.GeoEvidence, anycast, changed bool, parent locationValue) (locationValue, error) {
	if p != nil && p.hit {
		value := parent
		if p.pending && locationPrefixLess(p.rows.record.Prefix, prefix) {
			return value, errors.New("cached geographic boundary missing from current input")
		}
		for p.pending && p.rows.record.Prefix == prefix {
			r := p.rows.record
			if !changed {
				return value, errors.New("cached geographic value changed without geographic or anycast evidence")
			}
			if _, err := normalize(r); err != nil {
				return value, err
			}
			if r.Kind == 2 {
				if *r.Geo == value.geo {
					return value, errors.New("redundant cached geographic change")
				}
				value.geo = *r.Geo
			} else {
				if *r.Coordinates == value.coordinates {
					return value, errors.New("redundant cached coordinate change")
				}
				value.coordinates = *r.Coordinates
			}
			if err := p.advance(); err != nil {
				return value, err
			}
		}
		return value, nil
	}
	if !changed {
		return parent, nil
	}
	g, err := intelligence.FuseGeo(policy, geo, anycast)
	if err != nil {
		return locationValue{}, err
	}
	value := locationValue{coordinates: via3.CoordinateData{Unknown: true}}
	if g.PhysicalCountry != nil {
		value.geo.Country = *g.PhysicalCountry
	}
	if g.RegistrationCountry != nil {
		value.geo.RegistrationCountry = *g.RegistrationCountry
	}
	if g.Region != nil {
		value.geo.Region = *g.Region
	}
	if g.City != nil {
		value.geo.City = *g.City
	}
	if g.Coordinates != nil {
		value.coordinates = via3.CoordinateData{Latitude: g.Coordinates.Latitude, Longitude: g.Coordinates.Longitude, Precision: g.Coordinates.Precision}
	}
	if p == nil || p.writer.disabled {
		return value, nil
	}
	row := via3.PublicRecord{Version: 3, Kind: 2, Prefix: prefix, Geo: &value.geo}
	if value.geo != parent.geo {
		if err = p.write(row); err != nil {
			return value, err
		}
	}
	if value.coordinates != parent.coordinates {
		row.Kind, row.Geo, row.Coordinates = 3, nil, &value.coordinates
		err = p.write(row)
	}
	return value, err
}
func (p *locationProjection) write(row via3.PublicRecord) error {
	frame, err := encodeCompactRunRecord(row)
	if err != nil {
		return err
	}
	return p.writer.appendPublic(frame)
}

func (p *locationProjection) finish(ctx context.Context) error {
	if p == nil {
		return nil
	}
	files := map[[32]byte]string{}
	if p.hit {
		expected := p.entry.Leaf.Stream
		if p.pending || p.records != expected.Records || p.decoded != expected.DecodedBytes {
			return errors.New("incomplete cached geographic projection")
		}
		if p.input != nil {
			if err := p.input.verify(); err != nil {
				return err
			}
		}
	} else {
		stream, retained, err := p.writer.finish()
		if err != nil || !retained {
			return err
		}
		p.entry.Leaf.Stream = stream
		if stream != (spatialCacheStream{}) {
			files[stream.SHA256] = p.writer.path
		}
	}
	_, err := p.spool.reuse.Retain(ctx, p.entry, files)
	return err
}
func (p *locationProjection) close() error {
	if p == nil {
		return nil
	}
	if p.writer != nil {
		return p.writer.abort()
	}
	if p.input != nil {
		return p.input.Close()
	}
	return nil
}
