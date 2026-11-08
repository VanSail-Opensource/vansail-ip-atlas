package via3

import (
	"bytes"
	"net/netip"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
	"vansail-ip-atlas/internal/facts"
)

func sectionWidth(id uint16, recordWidth int) int {
	switch id {
	case 1, 8:
		return 32
	case 2:
		return 8
	case 3:
		return recordWidth
	case 4, 5:
		return 4
	case 6:
		return 1
	case 7:
		return 40
	case 9:
		return 12
	case 10:
		return 32
	case 11:
		return 24
	case 12:
		return 16
	}
	return 0
}
func rangeOK(first, count uint32, rows int) bool { return uint64(first)+uint64(count) <= uint64(rows) }
func bits(values ...uint) uint32 {
	var b uint32
	for _, v := range values {
		b |= 1 << v
	}
	return b
}
func present(row []byte, bit uint) bool { return u32(row, 0)&(1<<bit) != 0 }
func allowed(kind uint16) uint32 {
	switch kind {
	case 2:
		return bits(0, 1, 2, 3)
	case 3:
		return bits(4)
	case 4:
		return bits(15, 16, 17, 18, 19)
	case 5:
		return bits(5, 6, 7, 8)
	case 6:
		return bits(9, 10, 11, 12, 13, 14)
	case 7:
		return bits(21, 22)
	case 8:
		return bits(14, 16, 17, 23, 24, 25, 26, 27, 28, 31)
	case 9:
		return bits(20)
	case 10:
		return bits(19)
	case 11:
		return bits(29)
	case 12:
		return bits(30)
	case 13:
		return bits(27, 28)
	}
	return 0
}
func safeLabel(s string) bool {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) || !norm.NFC.IsNormalString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	// Public labels are names, never URLs, mailboxes, domain names or credentials.
	for _, token := range strings.Fields(s) {
		if unsafeLabelToken(token) {
			return false
		}
	}
	return true
}
func unsafeLabelToken(token string) bool {
	if strings.ContainsAny(token, "@:/\\") {
		return true
	}
	token = strings.Trim(token, ".,;!()[]{}\"'")
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return false
	}
	last := parts[len(parts)-1]
	if len(last) < 2 || len(last) > 63 || last[0] < 'A' || last[0] > 'Z' && last[0] < 'a' || last[0] > 'z' {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func keyCompare(a, b []byte) int {
	if a[0] != b[0] {
		return int(a[0]) - int(b[0])
	}
	if c := bytes.Compare(a[4:20], b[4:20]); c != 0 {
		return c
	}
	if a[1] != b[1] {
		return int(a[1]) - int(b[1])
	}
	return int(u16(a, 2)) - int(u16(b, 2))
}
func keyAddr(row []byte) (netip.Addr, bool) {
	var a [16]byte
	copy(a[:], row[4:20])
	if row[0] == 4 {
		if !zero(a[:12]) {
			return netip.Addr{}, false
		}
		var v4 [4]byte
		copy(v4[:], a[12:])
		return netip.AddrFrom4(v4), true
	}
	if row[0] == 6 {
		addr := netip.AddrFrom16(a)
		if addr.Is4In6() {
			return netip.Addr{}, false
		}
		return addr, true
	}
	return netip.Addr{}, false
}
func validKey(row []byte) bool {
	a, ok := keyAddr(row)
	if !ok || int(row[1]) > a.BitLen() || u16(row, 2) > 1 || !zero(row[24:32]) {
		return false
	}
	if u16(row, 2) == 1 && int(row[1]) != a.BitLen() {
		return false
	}
	return netip.PrefixFrom(a, int(row[1])).Masked().Addr() == a
}

func Validate(s Shard) error {
	width, ids := schema(s.Kind)
	if ids == nil || len(ids) != len(s.Sections) {
		return fail("schema")
	}
	var total int
	for i, section := range s.Sections {
		if section.ID != ids[i] || len(section.Data) < 8 || len(section.Data) > MaxSection {
			return fail("schema")
		}
		w := sectionWidth(section.ID, width)
		if int(u32(section.Data, 4)) != w || uint64(u32(section.Data, 0))*uint64(w) != uint64(len(section.Data)-8) {
			return fail("schema")
		}
		total += len(section.Data)
		if total > MaxTotal {
			return fail("bounds")
		}
	}
	records, rw := s.Rows(3)
	recordCount := 0
	if rw > 0 {
		recordCount = len(records) / rw
	}
	objects, _ := s.Rows(7)
	for p := 0; p < len(objects); p += 40 {
		kind := u16(objects, p)
		if kind < 1 || kind > 14 || u16(objects, p+2) != 0 || u32(objects, p+4) < 64 || u32(objects, p+4) >= MaxFile {
			return fail("record")
		}
		if p > 0 {
			previous := objects[p-40 : p]
			current := objects[p : p+40]
			if u16(previous, 0) > kind || (u16(previous, 0) == kind && bytes.Compare(previous[8:40], current[8:40]) >= 0) {
				return fail("record")
			}
		}
	}
	ref := func(r []byte, p int, bit uint, expected uint16) bool {
		a, b := u32(r, p), u32(r, p+4)
		if !present(r, bit) {
			return a == None && b == None
		}
		return a != None && b != None && uint64(a) < uint64(len(objects)/40) && u16(objects, int(a)*40) == expected
	}
	for _, id := range []uint16{1, 8} {
		index, _ := s.Rows(id)
		for p := 0; p < len(index); p += 32 {
			key := index[p : p+32]
			if !validKey(key) || int(u32(key, 20)) >= recordCount {
				return fail("record")
			}
			if s.Kind == 9 {
				r := s.Record(u32(key, 20))
				max := byte(128)
				if key[0] == 4 {
					max = 32
				}
				if r[9] > max || r[8] == 1 && r[9] < key[1] || (r[8] == 0 || r[8] == 3) && r[9] != 0 {
					return fail("record")
				}
			}
			if s.Kind == 7 && (key[0] != 4 || key[1] != 24 || u16(key, 2) != 0) {
				return fail("record")
			}
			if (s.Kind == 9 || s.Kind == 10) && u16(key, 2) != 0 {
				return fail("record")
			}
			if s.Kind == 6 && key[0] == 6 {
				r := s.Record(u32(key, 20))
				if present(r, 9) || present(r, 13) {
					return fail("record")
				}
			}
			if p > 0 {
				c := keyCompare(index[p-32:p], key)
				if c > 0 || c == 0 && s.Kind != 9 {
					return fail("record")
				}
				if c == 0 && (u32(s.Record(u32(index[p-32:p], 20)), 4) >= u32(s.Record(u32(key, 20)), 4)) {
					return fail("record")
				}
			}
		}
	}
	local, _ := s.Rows(1)
	overlays, _ := s.Rows(8)
	for p := 0; p < len(overlays); p += 32 {
		k := overlays[p : p+32]
		i := sort.Search(len(local)/32, func(i int) bool { return keyCompare(local[i*32:(i+1)*32], k) >= 0 })
		if i < len(local)/32 && keyCompare(local[i*32:(i+1)*32], k) == 0 {
			return fail("record")
		}
	}
	asnIndex, _ := s.Rows(2)
	for p := 0; p < len(asnIndex); p += 8 {
		if u32(asnIndex, p) == 0 || uint64(u32(asnIndex, p+4)) >= uint64(recordCount) {
			return fail("record")
		}
		if p > 0 && (u32(asnIndex, p-8) >= u32(asnIndex, p) || u32(asnIndex, p-4) > u32(asnIndex, p+4) || s.Kind != 1 && u32(asnIndex, p-4) == u32(asnIndex, p+4)) {
			return fail("record")
		}
		if s.Kind == 8 || s.Kind >= 11 {
			first := u32(asnIndex, p+4)
			end := uint32(recordCount)
			if p+8 < len(asnIndex) {
				end = u32(asnIndex, p+12)
			}
			if first >= end || end > uint32(recordCount) || p == 0 && first != 0 || s.Kind == 11 && end-first > 12 || (s.Kind == 8 || s.Kind == 13) && end-first != 1 {
				return fail("record")
			}
			var previousTo uint32
			for j := first; j < end; j++ {
				r := s.Record(j)
				if u32(r, 4) != u32(asnIndex, p) {
					return fail("record")
				}
				if s.Kind == 12 {
					to := u32(r, 8)
					if j > first && to <= previousTo {
						return fail("record")
					}
					previousTo = to
				}
			}
		}
	}
	if (s.Kind == 8 || s.Kind >= 11) && recordCount > 0 && len(asnIndex) == 0 {
		return fail("record")
	}
	ints, _ := s.Rows(4)
	segments, _ := s.Rows(9)
	cells, _ := s.Rows(10)
	pages, _ := s.Rows(12)
	for p := 0; p < len(records); p += rw {
		r := records[p : p+rw]
		if s.Kind != 1 && u32(r, 0)&^allowed(s.Kind) != 0 {
			return fail("record")
		}
		switch s.Kind {
		case 1:
			if !zero(r[6:16]) || !rangeOK(u32(r, 0), uint32(u16(r, 4)), len(ints)/4) {
				return fail("record")
			}
			prev := uint16(0)
			for j := uint32(0); j < uint32(u16(r, 4)); j++ {
				o := u32(ints, int(u32(r, 0)+j)*4)
				if uint64(o) >= uint64(len(objects)/40) {
					return fail("record")
				}
				k := u16(objects, int(o)*40)
				if k == 1 || k <= prev {
					return fail("record")
				}
				prev = k
			}
		case 2:
			for bit, p := range []int{4, 6} {
				v := u16(r, p)
				if present(r, uint(bit)) {
					if v == 0 || v > 676 || !facts.CountryValid(*country(v)) {
						return fail("record")
					}
				} else if v != 0 {
					return fail("record")
				}
			}
			if !ref(r, 8, 2, 14) || !ref(r, 16, 3, 14) {
				return fail("record")
			}
		case 3:
			lat, lon := int32(u32(r, 4)), int32(u32(r, 8))
			if !zero(r[13:]) || lat < -90000 || lat > 90000 || lon < -180000 || lon > 180000 || r[12] > 4 {
				return fail("record")
			}
			if !present(r, 4) && !zero(r[4:13]) {
				return fail("record")
			}
			if present(r, 4) && r[12] == 0 {
				return fail("record")
			}
		case 4:
			if !zero(r[12:16]) || !ref(r, 16, 16, 14) || !ref(r, 24, 17, 14) || !ref(r, 32, 18, 14) || !rangeOK(u32(r, 4), u32(r, 8), len(ints)/4) {
				return fail("record")
			}
			if !present(r, 19) && (u32(r, 4) != 0 || u32(r, 8) != 0) {
				return fail("record")
			}
			if !sortedASNs(ints, u32(r, 4), u32(r, 8)) {
				return fail("record")
			}
		case 5:
			if r[4] > 7 || r[5] > 2 || r[6] > 3 || r[7] != 0 || (!present(r, 5) && r[4] != 0) || (!present(r, 6) && r[5] != 0) || (!present(r, 7) && r[6]&1 != 0) || (!present(r, 8) && r[6]&2 != 0) {
				return fail("record")
			}
		case 6:
			if u32(r, 4) > 0x3fff || r[8] > 1 || r[9] > 100 || r[10] > 3 || r[11] != 0 || !zero(r[28:]) || (!present(r, 14) && u32(r, 4) != 0) {
				return fail("record")
			}
			if (r[8] == 1) != present(r, 9) || (!present(r, 9) && (r[9] != 0 || r[10] != 0)) || (r[8] == 1 && (r[10] == 0 || u32(r, 0)&bits(10, 11, 12, 13) != bits(10, 11, 12, 13))) {
				return fail("record")
			}
			caps := []uint32{550000, 180000, 150000, 120000}
			var contributionSum uint32
			for i, cap := range caps {
				v := u32(r, 12+i*4)
				contributionSum += v
				if v > cap || (!present(r, uint(10+i)) && v != 0) {
					return fail("record")
				}
			}
			if present(r, 9) {
				lowRisk := uint32(0)
				if contributionSum > 2 {
					lowRisk = contributionSum - 2
				}
				highRisk := contributionSum + 2
				if highRisk > 1000000 {
					highRisk = 1000000
				}
				lowScore := (1000000 - highRisk + 5000) / 10000
				highScore := (1000000 - lowRisk + 5000) / 10000
				if uint32(r[9]) < lowScore || uint32(r[9]) > highScore {
					return fail("record")
				}
			}
		case 7:
			if !zero(r[14:16]) || !zero(r[22:]) || !rangeOK(u32(r, 4), uint32(u16(r, 8)), len(cells)/32) || u16(r, 8) > 256 || u16(r, 10) > u16(r, 8) || u16(r, 12) > u16(r, 8) || r[20] > 100 || r[21] > 3 {
				return fail("record")
			}
			if present(r, 22) {
				if u16(r, 8) != 256 || u16(r, 10) != 256 || r[21] == 0 {
					return fail("record")
				}
			} else if r[20] != 0 || r[21] != 0 {
				return fail("record")
			}
			start, count := u32(r, 4), u32(r, 4)+uint32(u16(r, 8))
			var previous int = -1
			var assessed, positive uint16
			for j := start; j < count; j++ {
				c := cells[j*32 : (j+1)*32]
				if int(c[0]) <= previous || u32(c, 4) > 0x3fff || c[2] > 7 || c[3] > 2 || c[8] > 100 || c[9] > 3 || u16(c, 10) != 0 || u32(c, 12) > 1000000 || c[24] > 3 || !zero(c[25:]) {
					return fail("record")
				}
				previous = int(c[0])
				if c[1]&8 != 0 {
					if c[9] == 0 {
						return fail("record")
					}
					assessed++
				} else if c[8] != 0 || c[9] != 0 {
					return fail("record")
				}
				if u32(c, 4) > 0 {
					positive++
				}
				for bit, pos := range []int{2, 3, 4, -1, 12} {
					if pos >= 0 && c[1]&(1<<bit) == 0 {
						n := 1
						if pos == 4 || pos == 12 {
							n = 4
						}
						if !zero(c[pos : pos+n]) {
							return fail("record")
						}
					}
				}
				a, b := u32(c, 16), u32(c, 20)
				if c[1]&32 == 0 {
					if a != None || b != None {
						return fail("record")
					}
				} else if a == None || b == None || uint64(a) >= uint64(len(objects)/40) || u16(objects, int(a)*40) != 4 {
					return fail("record")
				}
				if c[1]&64 == 0 && c[24]&1 != 0 || c[1]&128 == 0 && c[24]&2 != 0 {
					return fail("record")
				}
			}
			if assessed != u16(r, 10) || positive != u16(r, 12) {
				return fail("record")
			}
		case 8:
			if !ref(r, 8, 16, 14) || !ref(r, 16, 17, 14) || u16(r, 24) > 676 || r[26] > 3 || r[27] > 3 || u32(r, 28) > 1000000 || u32(r, 32) > 0x3fff || r[52] > 4 || r[53] > 2 || !zero(r[54:]) || !rangeOK(u32(r, 36), u32(r, 40), len(pages)/16) {
				return fail("record")
			}
			if !present(r, 23) && !zero(r[26:32]) {
				return fail("record")
			}
			if present(r, 23) {
				band := byte(1)
				if u32(r, 28) >= 333334 {
					band = 2
				}
				if u32(r, 28) >= 666667 {
					band = 3
				}
				if r[26] != band {
					return fail("record")
				}
			}
			if !present(r, 31) && u16(r, 24) != 0 {
				return fail("record")
			}
			if present(r, 31) && (u16(r, 24) == 0 || !facts.CountryValid(*country(u16(r, 24)))) {
				return fail("record")
			}
			for bit, pos := range map[uint]int{14: 32, 24: 36, 25: 44, 26: 48, 27: 52, 28: 53} {
				n := 4
				if pos >= 52 {
					n = 1
				}
				if !present(r, bit) && !zero(r[pos:pos+n]) {
					return fail("record")
				}
			}
			if !present(r, 24) && u32(r, 40) != 0 {
				return fail("record")
			}
		case 9:
			if u32(r, 4) == 0 || r[8] > 3 || r[9] > 128 || !zero(r[10:]) || !present(r, 20) && (r[8] != 0 || r[9] != 0) {
				return fail("record")
			}
		case 10:
			if !zero(r[12:]) || !rangeOK(u32(r, 4), u32(r, 8), len(ints)/4) || !sortedASNs(ints, u32(r, 4), u32(r, 8)) {
				return fail("record")
			}
			if !present(r, 19) && (u32(r, 4) != 0 || u32(r, 8) != 0) {
				return fail("record")
			}
		case 11:
			if u32(r, 4) == 0 || u16(r, 12) == 0 || u16(r, 12) > 255 || r[14] > 1 || r[15] > 3 || !zero(r[16:]) || !rangeOK(u32(r, 8), uint32(u16(r, 12)), len(segments)/12) || !present(r, 29) {
				return fail("record")
			}
			var asns uint32
			seen := make(map[uint32]bool)
			var previousASN uint32
			for j := u32(r, 8); j < u32(r, 8)+uint32(u16(r, 12)); j++ {
				seg := segments[j*12 : (j+1)*12]
				if seg[0] < 1 || seg[0] > 4 || !zero(seg[1:4]) || u32(seg, 8) == 0 || !rangeOK(u32(seg, 4), u32(seg, 8), len(ints)/4) {
					return fail("record")
				}
				if r[14]&1 != 0 && seg[0] != 1 {
					return fail("record")
				}
				if seg[0] == 2 || seg[0] == 4 {
					if !sortedASNs(ints, u32(seg, 4), u32(seg, 8)) {
						return fail("record")
					}
				}
				for k := uint32(0); k < u32(seg, 8); k++ {
					asn := u32(ints, int(u32(seg, 4)+k)*4)
					if asn == 0 {
						return fail("record")
					}
					if r[14]&1 != 0 {
						if !facts.PublicASN(asn) || asns == 0 && k == 0 && asn != u32(r, 4) || asn != previousASN && seen[asn] {
							return fail("record")
						}
						seen[asn] = true
						previousASN = asn
					}
				}
				asns += u32(seg, 8)
			}
			if asns > 4096 {
				return fail("record")
			}
		case 12:
			if u32(r, 4) == 0 || u32(r, 8) == 0 || u32(r, 4) == u32(r, 8) || r[12] > 4 || r[13] > 3 || u16(r, 14) != 0 || r[12] != 0 && r[13]&2 == 0 {
				return fail("record")
			}
			if !present(r, 30) {
				return fail("record")
			}
		case 13:
			if u32(r, 4) == 0 || r[8] > 4 || r[9] > 2 || !zero(r[10:]) || r[8] == 1 && r[9] != 2 {
				return fail("record")
			}
			if !present(r, 27) && r[8] != 0 || !present(r, 28) && r[9] != 0 {
				return fail("record")
			}
		}
	}
	for p := 0; p < len(pages); p += 16 {
		o := u32(pages, p)
		if uint64(o) >= uint64(len(objects)/40) || u16(objects, int(o)*40) != 8 || u32(pages, p+8) > 256 || u32(pages, p+8) == 0 || u32(pages, p+12) != 0 {
			return fail("record")
		}
	}
	prefixes, _ := s.Rows(11)
	for p := 0; p < len(prefixes); p += 24 {
		r := prefixes[p : p+24]
		k := make([]byte, 32)
		copy(k[:20], r[:20])
		if !validKey(k) || u16(r, 2) != 0 || u32(r, 20) != 0 {
			return fail("record")
		}
		if p > 0 && keyCompare(prefixes[p-24:p], r) >= 0 {
			return fail("record")
		}
	}
	if s.Kind == 14 {
		offsets, _ := s.Rows(5)
		text, _ := s.Rows(6)
		if len(offsets) < 4 || u32(offsets, 0) != 0 || u32(offsets, len(offsets)-4) != uint32(len(text)) {
			return fail("record")
		}
		var previous string
		for p := 0; p < len(offsets)-4; p += 4 {
			a, b := u32(offsets, p), u32(offsets, p+4)
			if a >= b || uint64(b) > uint64(len(text)) {
				return fail("record")
			}
			label := string(text[a:b])
			if !safeLabel(label) || p > 0 && label <= previous {
				return fail("record")
			}
			previous = label
		}
	}
	return nil
}
func sortedASNs(b []byte, first, count uint32) bool {
	if !rangeOK(first, count, len(b)/4) {
		return false
	}
	for j := uint32(0); j < count; j++ {
		v := u32(b, int(first+j)*4)
		if v == 0 || j > 0 && u32(b, int(first+j-1)*4) >= v {
			return false
		}
	}
	return true
}

func PrefixKey(prefix netip.Prefix, exact bool, record uint32) []byte {
	row := make([]byte, 32)
	fillPrefixKey(row, prefix, exact, record)
	return row
}
func fillPrefixKey(row []byte, prefix netip.Prefix, exact bool, record uint32) {
	clear(row)
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
	}
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		row[0] = 4
		a := addr.As4()
		copy(row[16:20], a[:])
	} else {
		row[0] = 6
		a := addr.As16()
		copy(row[4:20], a[:])
	}
	row[1] = byte(prefix.Bits())
	if exact {
		p16(row, 2, 1)
	}
	p32(row, 20, record)
}
func (s *Shard) FindPrefix(addr netip.Addr) ([]byte, string, bool) {
	row, prefix, ok := s.findPrefix(addr)
	if !ok {
		return nil, "", false
	}
	return row, prefix.String(), true
}
func (s *Shard) findPrefix(addr netip.Addr) ([]byte, netip.Prefix, bool) {
	return s.findPrefixWithin(addr, addr.Unmap().BitLen())
}

// findPrefixWithin resolves a complete prefix entity, excluding all descendants.
// It is used to validate fused boundary rows without a base-address point lookup.
func (s *Shard) findPrefixWithin(addr netip.Addr, maxBits int) ([]byte, netip.Prefix, bool) {
	addr = addr.Unmap()
	if maxBits < 0 || maxBits > addr.BitLen() {
		return nil, netip.Prefix{}, false
	}
	var keyBytes [32]byte
	key := keyBytes[:]
	for length := maxBits; length >= 0; length-- {
		prefix := netip.PrefixFrom(addr, length).Masked()
		for _, exact := range []bool{true, false} {
			if exact && length != addr.BitLen() {
				continue
			}
			fillPrefixKey(key, prefix, exact, 0)
			for _, id := range []uint16{1, 8} {
				index, _ := s.Rows(id)
				i := sort.Search(len(index)/32, func(i int) bool { return keyCompare(index[i*32:(i+1)*32], key) >= 0 })
				if i < len(index)/32 && keyCompare(index[i*32:(i+1)*32], key) == 0 {
					return s.Record(u32(index, i*32+20)), prefix, true
				}
			}
		}
	}
	return nil, netip.Prefix{}, false
}
func (s *Shard) ASNRun(asn uint32) ([][]byte, bool) {
	first, end, ok := s.asnBounds(asn)
	if !ok || s.Kind == 12 || s.Kind == 11 && end-first > 12 || (s.Kind == 8 || s.Kind == 13) && end-first > 1 {
		return nil, false
	}
	out := make([][]byte, 0, end-first)
	for j := first; j < end; j++ {
		out = append(out, s.Record(j))
	}
	return out, true
}
func (s *Shard) asnBounds(asn uint32) (uint32, uint32, bool) {
	index, _ := s.Rows(2)
	i := sort.Search(len(index)/8, func(i int) bool { return u32(index, i*8) >= asn })
	if i == len(index)/8 || u32(index, i*8) != asn {
		return 0, 0, false
	}
	first := u32(index, i*8+4)
	records, w := s.Rows(3)
	end := uint32(len(records) / w)
	if i+1 < len(index)/8 {
		end = u32(index, (i+1)*8+4)
	}
	return first, end, true
}
func (s *Shard) FindRelationship(from, to uint32) ([]byte, bool) {
	first, end, ok := s.asnBounds(from)
	if !ok {
		return nil, false
	}
	i := sort.Search(int(end-first), func(i int) bool { return u32(s.Record(first+uint32(i)), 8) >= to })
	if first+uint32(i) >= end {
		return nil, false
	}
	row := s.Record(first + uint32(i))
	return row, u32(row, 8) == to
}
func (s *Shard) FindRPKI(addr netip.Addr, origin uint32, announcement netip.Prefix) ([]byte, bool) {
	addr = addr.Unmap()
	if !addr.IsValid() || !announcement.IsValid() || !announcement.Contains(addr) {
		return nil, false
	}
	var keyBytes [32]byte
	target := keyBytes[:]
	// RPKI is keyed by the selected actual announcement, not by an LPM over
	// other announcements that happen to contain this query address.
	fillPrefixKey(target, announcement.Masked(), false, 0)
	for _, id := range []uint16{1, 8} {
		index, _ := s.Rows(id)
		count := len(index) / 32
		first := sort.Search(count, func(i int) bool { return keyCompare(index[i*32:(i+1)*32], target) >= 0 })
		if first == count || keyCompare(index[first*32:(first+1)*32], target) != 0 {
			continue
		}
		end := sort.Search(count-first, func(i int) bool { return keyCompare(index[(first+i)*32:(first+i+1)*32], target) > 0 }) + first
		i := sort.Search(end-first, func(i int) bool { return u32(s.Record(u32(index, (first+i)*32+20)), 4) >= origin })
		if first+i >= end {
			return nil, false
		}
		row := s.Record(u32(index, (first+i)*32+20))
		return row, u32(row, 4) == origin
	}
	return nil, false
}
