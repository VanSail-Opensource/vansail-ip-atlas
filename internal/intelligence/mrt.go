package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"time"
	"unicode/utf8"
)

type MRTLimits struct {
	Bytes          int64
	FrameBytes     uint32
	Records, Peers int
}
type MRTRecord struct {
	Prefix     netip.Prefix
	Origin     uint32
	Segments   []PathSegment
	ObservedAt time.Time
}
type mrtCursor struct {
	data   []byte
	offset int
}

func (c *mrtCursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.data)-c.offset {
		return nil, errors.New("MRT field bounds invalid")
	}
	out := c.data[c.offset : c.offset+n]
	c.offset += n
	return out, nil
}
func (c *mrtCursor) u8() (uint8, error) {
	b, e := c.take(1)
	if e != nil {
		return 0, e
	}
	return b[0], nil
}
func (c *mrtCursor) u16() (uint16, error) {
	b, e := c.take(2)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint16(b), nil
}
func (c *mrtCursor) u32() (uint32, error) {
	b, e := c.take(4)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint32(b), nil
}

// ParseMRT streams TABLE_DUMP_V2 unicast IPv4/IPv6 and their ADDPATH variants.
// Unsupported MRT types fail closed. It is not a BGP4MP update parser.
// Collector IDs, peer addresses, next hops, communities and path IDs are dropped.
func ParseMRT(ctx context.Context, r io.Reader, limits MRTLimits, sink func(MRTRecord) error) error {
	if limits.Bytes <= 0 || limits.Bytes > 3<<30 || limits.FrameBytes == 0 || limits.FrameBytes > 16<<20 || limits.Records <= 0 || limits.Peers <= 0 || limits.Peers > 65535 {
		return errors.New("invalid MRT parser limits")
	}
	reader := &io.LimitedReader{R: contextReader{ctx, r}, N: limits.Bytes + 1}
	peerCount := -1
	records := 0
	header := [12]byte{}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(reader, header[:])
		if err == io.EOF && n == 0 {
			if reader.N <= 0 {
				return errors.New("MRT byte budget exceeded")
			}
			if peerCount < 0 || records == 0 {
				return errors.New("MRT snapshot contains no RIB records")
			}
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("MRT header truncated")
		}
		kind, subtype := binary.BigEndian.Uint16(header[4:6]), binary.BigEndian.Uint16(header[6:8])
		length := binary.BigEndian.Uint32(header[8:12])
		if kind != 13 {
			return errors.New("unsupported MRT type")
		}
		if length > limits.FrameBytes || int64(length) > reader.N-1 {
			return errors.New("MRT frame budget exceeded")
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(reader, payload); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("MRT payload truncated")
		}
		cursor := mrtCursor{data: payload}
		if subtype == 1 {
			if _, err := cursor.take(4); err != nil {
				return err
			}
			viewLength, err := cursor.u16()
			if err != nil {
				return err
			}
			view, err := cursor.take(int(viewLength))
			if err != nil || !utf8.Valid(view) {
				return errors.New("MRT view encoding invalid")
			}
			count, err := cursor.u16()
			if err != nil || int(count) > limits.Peers {
				return errors.New("MRT peer budget exceeded")
			}
			for i := 0; i < int(count); i++ {
				flags, err := cursor.u8()
				if err != nil || flags&0xfc != 0 {
					return errors.New("MRT peer flags invalid")
				}
				ipBytes := 4
				if flags&1 != 0 {
					ipBytes = 16
				}
				asnBytes := 2
				if flags&2 != 0 {
					asnBytes = 4
				}
				if _, err := cursor.take(4 + ipBytes + asnBytes); err != nil {
					return err
				}
			}
			if cursor.offset != len(payload) {
				return errors.New("MRT peer table trailing bytes")
			}
			peerCount = int(count)
			continue
		}
		if peerCount < 0 {
			return errors.New("MRT RIB requires preceding peer table")
		}
		ipv6, addPath := false, false
		switch subtype {
		case 2:
		case 4:
			ipv6 = true
		case 8:
			addPath = true
		case 10:
			ipv6, addPath = true, true
		default:
			return errors.New("uncertified MRT subtype")
		}
		if _, err := cursor.take(4); err != nil {
			return err
		}
		bits, err := cursor.u8()
		maxBits := 32
		if ipv6 {
			maxBits = 128
		}
		if err != nil || int(bits) > maxBits {
			return errors.New("MRT prefix length invalid")
		}
		prefixBytes, err := cursor.take((int(bits) + 7) / 8)
		if err != nil {
			return err
		}
		var addr netip.Addr
		if ipv6 {
			var raw [16]byte
			copy(raw[:], prefixBytes)
			addr = netip.AddrFrom16(raw)
		} else {
			var raw [4]byte
			copy(raw[:], prefixBytes)
			addr = netip.AddrFrom4(raw)
		}
		prefix := netip.PrefixFrom(addr, int(bits)).Masked()
		count, err := cursor.u16()
		if err != nil {
			return err
		}
		for i := 0; i < int(count); i++ {
			records++
			if records > limits.Records {
				return errors.New("MRT record budget exceeded")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			peer, err := cursor.u16()
			if err != nil || int(peer) >= peerCount {
				return errors.New("MRT peer index invalid")
			}
			observed, err := cursor.u32()
			if err != nil {
				return err
			}
			if addPath {
				if _, err := cursor.take(4); err != nil {
					return err
				}
			}
			attributeLength, err := cursor.u16()
			if err != nil {
				return err
			}
			attributes, err := cursor.take(int(attributeLength))
			if err != nil {
				return err
			}
			segments, err := parseMRTAttributes(attributes)
			if err != nil {
				return err
			}
			origin := uint32(0)
			if len(segments) > 0 {
				last := segments[len(segments)-1]
				if last.Type == ASSequence && len(last.ASNs) > 0 {
					origin = last.ASNs[len(last.ASNs)-1]
				}
			}
			// An AS_SET terminal has no chosen linear origin; keep the typed
			// observation with origin zero for private review, never invent one.
			if err := sink(MRTRecord{prefix, origin, segments, time.Unix(int64(observed), 0).UTC()}); err != nil {
				return err
			}
		}
		if cursor.offset != len(payload) {
			return errors.New("MRT RIB trailing bytes")
		}
	}
}

func parseMRTAttributes(data []byte) ([]PathSegment, error) {
	cursor := mrtCursor{data: data}
	var segments []PathSegment
	seenPath := false
	for cursor.offset < len(data) {
		flags, err := cursor.u8()
		if err != nil {
			return nil, err
		}
		kind, err := cursor.u8()
		if err != nil {
			return nil, err
		}
		var length uint16
		if flags&0x10 != 0 {
			length, err = cursor.u16()
		} else {
			var small uint8
			small, err = cursor.u8()
			length = uint16(small)
		}
		if err != nil {
			return nil, err
		}
		payload, err := cursor.take(int(length))
		if err != nil {
			return nil, err
		}
		if kind != 2 {
			continue
		}
		if flags&^0x10 != 0x40 {
			return nil, errors.New("MRT AS_PATH flags invalid")
		}
		if seenPath {
			return nil, errors.New("duplicate MRT AS_PATH")
		}
		seenPath = true
		// RFC6396 section 4.3.4: TABLE_DUMP_V2 AS_PATH always uses FOUR
		// octets, even when the peer-table ASN happens to use two octets.
		path := mrtCursor{data: payload}
		total := 0
		for path.offset < len(payload) {
			kind, err := path.u8()
			if err != nil {
				return nil, err
			}
			count, err := path.u8()
			if err != nil || count == 0 || kind < 1 || kind > 4 {
				return nil, errors.New("MRT path segment invalid")
			}
			total += int(count)
			if total > 4096 || len(segments) >= 255 {
				return nil, errors.New("MRT AS path budget exceeded")
			}
			values := make([]uint32, int(count))
			for i := range values {
				value, err := path.u32()
				if err != nil || value == 0 {
					return nil, errors.New("MRT four-octet ASN invalid")
				}
				values[i] = value
			}
			segmentType := SegmentType(kind)
			// Wire BGP uses 1=AS_SET, 2=AS_SEQUENCE; VIA3 uses the reverse.
			if kind == 1 {
				segmentType = ASSet
			} else if kind == 2 {
				segmentType = ASSequence
			}
			segments = append(segments, PathSegment{segmentType, values})
		}
	}
	if !seenPath {
		return nil, errors.New("MRT AS_PATH missing")
	}
	return segments, nil
}

// MRTUpdate is private replay input, never a public fact. Session is an opaque
// transport-session key; peer/local addresses, next hops and attributes are
// discarded. ADDPATH identity is retained until withdrawal/replacement replay.
// Callers must transactionally reduce events before materializing a snapshot.
// Segments are immutable and may be shared by announcements in one UPDATE;
// a sink that edits a path must first copy its segment and ASN slices.
type MRTUpdateKind uint8

const (
	MRTAnnounce MRTUpdateKind = iota + 1
	MRTWithdraw
	MRTSessionReset
	MRTEndOfRIB
)

type MRTUpdate struct {
	Kind       MRTUpdateKind
	Session    [32]byte
	Prefix     netip.Prefix
	AFI        uint16
	PathID     uint32
	AddPath    bool
	Local      bool
	Origin     uint32
	Segments   []PathSegment
	ObservedAt time.Time
}

type mrtNLRI struct {
	prefix netip.Prefix
	pathID uint32
}

type mrtBGPAttributes struct {
	path                      []PathSegment
	pathSeen, origin, nextHop bool
	mpReach, mpUnreach        []mrtNLRI
	mpReachAFI, mpUnreachAFI  uint16
	mpEnd                     bool
}

// ParseBGP4MP streams RFC6396/8050 BGP4MP and BGP4MP_ET events separately from
// TABLE_DUMP_V2. ParseMRT intentionally continues to reject these event feeds:
// treating announcements as a RIB would retain withdrawals and closed sessions.
// Supported NLRI is IPv4/IPv6 unicast, including ADDPATH; unsupported AFI/SAFI,
// message/subtype and malformed framing fail closed. No source is activated.
func ParseBGP4MP(ctx context.Context, r io.Reader, limits MRTLimits, sink func(MRTUpdate) error) error {
	if limits.Bytes <= 0 || limits.Bytes > 3<<30 || limits.FrameBytes == 0 || limits.FrameBytes > 16<<20 || limits.Records <= 0 || limits.Peers <= 0 || limits.Peers > 65535 || sink == nil {
		return errors.New("invalid MRT update parser limits")
	}
	reader := &io.LimitedReader{R: contextReader{ctx, r}, N: limits.Bytes + 1}
	peers := make(map[[32]byte]struct{})
	frames, events := 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var header [12]byte
		n, err := io.ReadFull(reader, header[:])
		if err == io.EOF && n == 0 {
			if reader.N <= 0 || frames == 0 {
				return errors.New("MRT update stream empty or byte budget exceeded")
			}
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("MRT update header truncated")
		}
		frames++
		if frames > limits.Records {
			return errors.New("MRT update frame budget exceeded")
		}
		kind, subtype := binary.BigEndian.Uint16(header[4:6]), binary.BigEndian.Uint16(header[6:8])
		length := binary.BigEndian.Uint32(header[8:12])
		if kind != 16 && kind != 17 {
			return errors.New("unsupported MRT update type")
		}
		if length > limits.FrameBytes || int64(length) > reader.N-1 {
			return errors.New("MRT update frame budget exceeded")
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(reader, payload); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("MRT update payload truncated")
		}
		cursor := mrtCursor{data: payload}
		observed := time.Unix(int64(binary.BigEndian.Uint32(header[:4])), 0).UTC()
		if kind == 17 {
			micros, err := cursor.u32()
			if err != nil || micros >= 1000000 {
				return errors.New("MRT microsecond timestamp invalid")
			}
			observed = observed.Add(time.Duration(micros) * time.Microsecond)
		}
		width, addPath, local, state := 2, false, false, false
		switch subtype {
		case 0:
			state = true
		case 1:
		case 4:
			width = 4
		case 5:
			width, state = 4, true
		case 6:
			local = true
		case 7:
			width, local = 4, true
		case 8:
			addPath = true
		case 9:
			width, addPath = 4, true
		case 10:
			local, addPath = true, true
		case 11:
			width, local, addPath = 4, true, true
		default:
			return errors.New("unsupported BGP4MP subtype")
		}
		if _, err := cursor.take(2 * width); err != nil {
			return err
		}
		// ASN widths and optional zero peer-AS state fields must not change
		// session identity. The transport tuple identifies both directions.
		sessionStart := cursor.offset
		if _, err := cursor.u16(); err != nil {
			return err
		}
		afi, err := cursor.u16()
		if err != nil || afi != 1 && afi != 2 {
			return errors.New("unsupported BGP4MP transport AFI")
		}
		addressBytes := 4
		if afi == 2 {
			addressBytes = 16
		}
		if _, err := cursor.take(2 * addressBytes); err != nil {
			return err
		}
		session := sha256.Sum256(payload[sessionStart:cursor.offset])
		if _, seen := peers[session]; !seen {
			if len(peers) >= limits.Peers {
				return errors.New("MRT update peer budget exceeded")
			}
			peers[session] = struct{}{}
		}
		emit := func(event MRTUpdate) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			events++
			if events > limits.Records {
				return errors.New("MRT update event budget exceeded")
			}
			event.Session, event.ObservedAt, event.Local, event.AddPath = session, observed, local, addPath
			return sink(event)
		}
		if state {
			oldState, oldErr := cursor.u16()
			newState, newErr := cursor.u16()
			if oldErr != nil || newErr != nil || oldState < 1 || oldState > 6 || newState < 1 || newState > 6 || cursor.offset != len(payload) {
				return errors.New("invalid BGP4MP session state")
			}
			if oldState != newState {
				if err := emit(MRTUpdate{Kind: MRTSessionReset}); err != nil {
					return err
				}
			}
			continue
		}
		message := payload[cursor.offset:]
		if len(message) < 19 || int(binary.BigEndian.Uint16(message[16:18])) != len(message) {
			return errors.New("invalid BGP message length")
		}
		for _, marker := range message[:16] {
			if marker != 0xff {
				return errors.New("invalid BGP marker")
			}
		}
		body := message[19:]
		switch message[18] {
		case 1:
			if err := validateBGPOpen(body); err != nil {
				return err
			}
			if err := emit(MRTUpdate{Kind: MRTSessionReset}); err != nil {
				return err
			}
		case 2:
			if err := parseBGPUpdate(body, width, addPath, limits.Records-events, emit); err != nil {
				return err
			}
		case 3:
			if len(body) < 2 {
				return errors.New("truncated BGP notification")
			}
			if err := emit(MRTUpdate{Kind: MRTSessionReset}); err != nil {
				return err
			}
		case 4:
			if len(body) != 0 {
				return errors.New("invalid BGP keepalive")
			}
		case 5:
			// Enhanced refresh requires stale-route replay semantics; do not
			// silently discard its begin/end markers as ordinary refreshes.
			if len(body) != 4 || body[3] != 1 || binary.BigEndian.Uint16(body[:2]) != 1 && binary.BigEndian.Uint16(body[:2]) != 2 || body[2] != 0 {
				return errors.New("unsupported BGP route refresh")
			}
		default:
			return errors.New("unsupported BGP message type")
		}
	}
}

func validateBGPOpen(body []byte) error {
	if len(body) < 10 || body[0] != 4 {
		return errors.New("invalid BGP OPEN")
	}
	length, offset, extended := int(body[9]), 10, false
	if length != 0 && len(body) > 10 && body[10] == 255 {
		if len(body) < 13 {
			return errors.New("truncated extended BGP OPEN")
		}
		length, offset, extended = int(binary.BigEndian.Uint16(body[11:13])), 13, true
	}
	if length != len(body)-offset {
		return errors.New("BGP OPEN optional-parameter bounds invalid")
	}
	cursor := mrtCursor{data: body[offset:]}
	for cursor.offset < len(cursor.data) {
		if _, err := cursor.u8(); err != nil {
			return err
		}
		var length uint16
		var err error
		if extended {
			length, err = cursor.u16()
		} else {
			var small uint8
			small, err = cursor.u8()
			length = uint16(small)
		}
		if err != nil {
			return err
		}
		if _, err := cursor.take(int(length)); err != nil {
			return err
		}
	}
	return nil
}

func parseBGPUpdate(data []byte, width int, addPath bool, remaining int, emit func(MRTUpdate) error) error {
	cursor := mrtCursor{data: data}
	withdrawLength, err := cursor.u16()
	if err != nil {
		return err
	}
	withdrawn, err := cursor.take(int(withdrawLength))
	if err != nil {
		return err
	}
	attributeLength, err := cursor.u16()
	if err != nil {
		return err
	}
	attributeBytes, err := cursor.take(int(attributeLength))
	if err != nil {
		return err
	}
	attributes, err := parseBGPAttributes(attributeBytes, width, addPath, remaining)
	if err != nil {
		return err
	}
	withdrawals, err := parseBGPNLRI(withdrawn, 1, addPath, remaining)
	if err != nil {
		return err
	}
	announcements, err := parseBGPNLRI(data[cursor.offset:], 1, addPath, remaining)
	if err != nil {
		return err
	}
	if len(announcements)+len(attributes.mpReach) > 0 && (!attributes.pathSeen || !attributes.origin || len(announcements) > 0 && !attributes.nextHop) {
		return errors.New("BGP announcement mandatory attributes missing")
	}
	empty := len(data) == 4 && withdrawLength == 0 && attributeLength == 0
	mpEnd := attributes.mpEnd && len(withdrawals) == 0 && len(announcements) == 0
	count := len(withdrawals) + len(attributes.mpUnreach) + len(announcements) + len(attributes.mpReach)
	if empty {
		count++
	}
	if mpEnd {
		count++
	}
	if count > remaining {
		return errors.New("MRT update event budget exceeded")
	}
	for _, group := range []struct {
		rows []mrtNLRI
		afi  uint16
	}{{withdrawals, 1}, {attributes.mpUnreach, attributes.mpUnreachAFI}} {
		for _, row := range group.rows {
			if err := emit(MRTUpdate{Kind: MRTWithdraw, Prefix: row.prefix, AFI: group.afi, PathID: row.pathID}); err != nil {
				return err
			}
		}
	}
	origin := uint32(0)
	if len(attributes.path) > 0 {
		last := attributes.path[len(attributes.path)-1]
		if last.Type == ASSequence && len(last.ASNs) > 0 {
			origin = last.ASNs[len(last.ASNs)-1]
		}
	}
	for _, group := range []struct {
		rows []mrtNLRI
		afi  uint16
	}{{announcements, 1}, {attributes.mpReach, attributes.mpReachAFI}} {
		for _, row := range group.rows {
			if err := emit(MRTUpdate{Kind: MRTAnnounce, Prefix: row.prefix, AFI: group.afi, PathID: row.pathID, Origin: origin, Segments: attributes.path}); err != nil {
				return err
			}
		}
	}
	if empty {
		if err := emit(MRTUpdate{Kind: MRTEndOfRIB, AFI: 1}); err != nil {
			return err
		}
	}
	if mpEnd {
		return emit(MRTUpdate{Kind: MRTEndOfRIB, AFI: attributes.mpUnreachAFI})
	}
	return nil
}

func parseBGPNLRI(data []byte, afi uint16, addPath bool, limit int) ([]mrtNLRI, error) {
	if afi != 1 && afi != 2 {
		return nil, errors.New("unsupported BGP NLRI AFI")
	}
	cursor := mrtCursor{data: data}
	var rows []mrtNLRI
	for cursor.offset < len(data) {
		if len(rows) >= limit {
			return nil, errors.New("BGP NLRI record budget exceeded")
		}
		var id uint32
		var err error
		if addPath {
			id, err = cursor.u32()
			if err != nil {
				return nil, err
			}
		}
		bits, err := cursor.u8()
		maxBits := 32
		if afi == 2 {
			maxBits = 128
		}
		if err != nil || int(bits) > maxBits {
			return nil, errors.New("BGP NLRI length invalid")
		}
		value, err := cursor.take((int(bits) + 7) / 8)
		if err != nil {
			return nil, err
		}
		var address netip.Addr
		if afi == 1 {
			var raw [4]byte
			copy(raw[:], value)
			address = netip.AddrFrom4(raw)
		} else {
			var raw [16]byte
			copy(raw[:], value)
			address = netip.AddrFrom16(raw)
		}
		rows = append(rows, mrtNLRI{netip.PrefixFrom(address, int(bits)).Masked(), id})
	}
	return rows, nil
}

func parseBGPAttributes(data []byte, width int, addPath bool, limit int) (mrtBGPAttributes, error) {
	var out mrtBGPAttributes
	cursor := mrtCursor{data: data}
	var seen [256]bool
	attributeCount := 0
	var as4 []PathSegment
	var aggregator uint32
	var aggregatorSeen, as4Aggregator bool
	for cursor.offset < len(data) {
		flags, err := cursor.u8()
		if err != nil {
			return out, err
		}
		kind, err := cursor.u8()
		if err != nil {
			return out, err
		}
		if flags&0x0f != 0 || seen[kind] {
			return out, errors.New("BGP attribute flags or duplicate invalid")
		}
		seen[kind] = true
		attributeCount++
		var length uint16
		if flags&0x10 != 0 {
			length, err = cursor.u16()
		} else {
			var small uint8
			small, err = cursor.u8()
			length = uint16(small)
		}
		if err != nil {
			return out, err
		}
		payload, err := cursor.take(int(length))
		if err != nil {
			return out, err
		}
		switch kind {
		case 1:
			if flags&^0x10 != 0x40 || len(payload) != 1 || payload[0] > 2 {
				return out, errors.New("invalid BGP ORIGIN")
			}
			out.origin = true
		case 2:
			if flags&^0x10 != 0x40 {
				return out, errors.New("invalid BGP AS_PATH flags")
			}
			out.path, err = parseBGPPath(payload, width)
			if err != nil {
				return out, err
			}
			out.pathSeen = true
		case 3:
			if flags&^0x10 != 0x40 || len(payload) != 4 {
				return out, errors.New("invalid BGP NEXT_HOP")
			}
			out.nextHop = true
		case 5, 6:
			want := 4
			if kind == 6 {
				want = 0
			}
			if flags&^0x10 != 0x40 || len(payload) != want {
				return out, errors.New("invalid BGP well-known attribute")
			}
		case 7:
			if flags&^0x30 != 0xc0 || len(payload) != width+4 {
				return out, errors.New("invalid BGP AGGREGATOR")
			}
			if width == 2 {
				aggregator = uint32(binary.BigEndian.Uint16(payload[:2]))
			} else {
				aggregator = binary.BigEndian.Uint32(payload[:4])
			}
			aggregatorSeen = true
		case 17:
			// RFC6793: NEW-to-NEW AS4_PATH is discarded. Malformed OLD
			// AS4_PATH is discarded rather than substituted for AS_PATH.
			if width == 2 && flags&^0x30 == 0xc0 {
				parsed, pathErr := parseBGPPath(payload, 4)
				if pathErr == nil && len(payload) >= 6 {
					for _, segment := range parsed {
						if segment.Type == ASSequence || segment.Type == ASSet {
							as4 = append(as4, segment)
						}
					}
				}
			}
		case 18:
			as4Aggregator = width == 2 && flags&^0x30 == 0xc0 && len(payload) == 8
		case 14, 15:
			if flags&^0x10 != 0x80 || len(payload) < 3 {
				return out, errors.New("invalid BGP multiprotocol attribute")
			}
			afi := binary.BigEndian.Uint16(payload[:2])
			if (afi != 1 && afi != 2) || payload[2] != 1 {
				return out, errors.New("unsupported BGP NLRI AFI/SAFI")
			}
			nlri := payload[3:]
			if kind == 14 {
				if len(nlri) < 2 {
					return out, errors.New("truncated MP_REACH next hop")
				}
				n := int(nlri[0])
				if (afi == 1 && n != 4 && n != 16 && n != 32) || (afi == 2 && n != 16 && n != 32) || len(nlri) < n+2 {
					return out, errors.New("invalid MP_REACH next hop length")
				}
				nlri = nlri[n+2:]
				out.mpReachAFI = afi
				out.mpReach, err = parseBGPNLRI(nlri, afi, addPath, limit)
			} else {
				out.mpUnreachAFI = afi
				out.mpEnd = len(nlri) == 0
				out.mpUnreach, err = parseBGPNLRI(nlri, afi, addPath, limit)
			}
			if err != nil {
				return out, err
			}
		default:
			if flags&0x80 == 0 {
				return out, errors.New("unsupported mandatory BGP attribute")
			}
		}
	}
	if width == 2 && len(as4) > 0 && !(aggregatorSeen && as4Aggregator && aggregator != 23456) {
		var err error
		out.path, err = reconstructAS4Path(out.path, as4)
		if err != nil {
			return out, err
		}
	}
	out.mpEnd = out.mpEnd && attributeCount == 1
	return out, nil
}

func parseBGPPath(data []byte, width int) ([]PathSegment, error) {
	cursor := mrtCursor{data: data}
	var out []PathSegment
	total := 0
	for cursor.offset < len(data) {
		kind, err := cursor.u8()
		if err != nil {
			return nil, err
		}
		count, err := cursor.u8()
		if err != nil || count == 0 || kind < 1 || kind > 4 {
			return nil, errors.New("invalid BGP path segment")
		}
		total += int(count)
		if total > 4096 || len(out) >= 255 {
			return nil, errors.New("BGP path budget exceeded")
		}
		segment := PathSegment{Type: SegmentType(kind), ASNs: make([]uint32, int(count))}
		if kind == 1 {
			segment.Type = ASSet
		} else if kind == 2 {
			segment.Type = ASSequence
		}
		for i := range segment.ASNs {
			var value uint32
			if width == 2 {
				var small uint16
				small, err = cursor.u16()
				value = uint32(small)
			} else {
				value, err = cursor.u32()
			}
			if err != nil || value == 0 {
				return nil, errors.New("invalid BGP ASN")
			}
			segment.ASNs[i] = value
		}
		out = append(out, segment)
	}
	return out, nil
}

// RFC6793 section 4.2.3 uses route-selection length: AS_SET counts once,
// sequences count each ASN, and confederations do not consume that length.
// Preserve original boundaries, prepends, sets and adjacent confederations.
func reconstructAS4Path(old, as4 []PathSegment) ([]PathSegment, error) {
	pathLength := func(path []PathSegment) int {
		n := 0
		for _, s := range path {
			if s.Type == ASSequence {
				n += len(s.ASNs)
			} else if s.Type == ASSet {
				n++
			}
		}
		return n
	}
	keep := pathLength(old) - pathLength(as4)
	if keep < 0 {
		return old, nil
	}
	var out []PathSegment
	for _, segment := range old {
		if segment.Type == ConfederationSequence || segment.Type == ConfederationSet {
			out = append(out, segment)
			continue
		}
		if keep == 0 {
			break
		}
		if segment.Type == ASSet {
			out = append(out, segment)
			keep--
			continue
		}
		count := len(segment.ASNs)
		if count > keep {
			count = keep
		}
		out = append(out, PathSegment{segment.Type, segment.ASNs[:count]})
		keep -= count
	}
	out = append(out, as4...)
	total := 0
	for _, segment := range out {
		total += len(segment.ASNs)
	}
	if len(out) > 255 || total > 4096 {
		return nil, errors.New("reconstructed BGP path budget exceeded")
	}
	return out, nil
}
