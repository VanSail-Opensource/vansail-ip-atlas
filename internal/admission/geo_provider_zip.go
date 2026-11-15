package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sort"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

type geoZIPMember struct {
	name                            string
	extra                           []byte
	flags, method, dosTime, dosDate uint16
	crc, compressed, decoded        uint32
	localOffset, dataStart, dataEnd int64
	published                       time.Time
}

func geoReadAt(ctx context.Context, file *os.File, offset int64, size int, total int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if offset < 0 || size < 0 || int64(size) > total-offset {
		return nil, errors.New("IPAPI ZIP metadata bounds invalid")
	}
	data := make([]byte, size)
	_, err := file.ReadAt(data, offset)
	return data, err
}
func zipUT(extra []byte, local bool) (time.Time, error) {
	var published time.Time
	seen := false
	for offset := 0; offset < len(extra); {
		if len(extra)-offset < 4 {
			return time.Time{}, errors.New("ZIP extra field truncated")
		}
		tag := binary.LittleEndian.Uint16(extra[offset:])
		n := int(binary.LittleEndian.Uint16(extra[offset+2:]))
		offset += 4
		if n > len(extra)-offset {
			return time.Time{}, errors.New("ZIP extra field invalid")
		}
		value := extra[offset : offset+n]
		offset += n
		if tag != 0x5455 {
			continue
		}
		if seen || n < 5 || value[0]&1 == 0 || value[0]&^byte(7) != 0 {
			return time.Time{}, errors.New("unique ZIP UTC modification timestamp required")
		}
		seen = true
		if local {
			count := 0
			for _, mask := range []byte{1, 2, 4} {
				if value[0]&mask != 0 {
					count++
				}
			}
			if n != 1+4*count {
				return time.Time{}, errors.New("local ZIP UTC timestamp fields invalid")
			}
		} else if n != 5 {
			return time.Time{}, errors.New("central ZIP UTC timestamp shape invalid")
		}
		published = time.Unix(int64(binary.LittleEndian.Uint32(value[1:5])), 0).UTC()
	}
	if !seen || published.IsZero() {
		return time.Time{}, errors.New("DOS-only ZIP clock is not publication proof")
	}
	return published, nil
}
func consistentZIPDOS(date, clock uint16, published time.Time) bool {
	year := 1980 + int(date>>9)
	month := time.Month((date >> 5) & 15)
	day := int(date & 31)
	hour := int(clock >> 11)
	minute := int((clock >> 5) & 63)
	second := int(clock&31) * 2
	if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59 {
		return false
	}
	wall := time.Date(year, month, day, hour, minute, second, 0, time.UTC)
	if wall.Year() != year || wall.Month() != month || wall.Day() != day {
		return false
	}
	delta := int64(wall.Sub(published) / time.Second)
	if delta < -(14*3600+2) || delta > 14*3600+2 {
		return false
	}
	remainder := delta % 900
	if remainder < 0 {
		remainder = -remainder
	}
	return remainder <= 2 || remainder >= 898
}
func ipapiZIPMembers(ctx context.Context, file *os.File, size int64, source Source) ([]geoZIPMember, error) {
	member, ok := ipapiCSVMember(source)
	if !ok || size < 22 || size > source.MaxCompressedBytes {
		return nil, errors.New("IPAPI ZIP source or size invalid")
	}
	tailSize := int(min(size, int64(65557)))
	tail, err := geoReadAt(ctx, file, size-int64(tailSize), tailSize, size)
	if err != nil {
		return nil, err
	}
	end := bytes.LastIndex(tail, []byte{0x50, 0x4b, 0x05, 0x06})
	if end < 0 || end+22 > len(tail) {
		return nil, errors.New("IPAPI ZIP end record missing")
	}
	record := tail[end:]
	if int(binary.LittleEndian.Uint16(record[20:22]))+22 != len(record) || binary.LittleEndian.Uint16(record[4:6]) != 0 || binary.LittleEndian.Uint16(record[6:8]) != 0 || binary.LittleEndian.Uint16(record[8:10]) != 2 || binary.LittleEndian.Uint16(record[10:12]) != 2 {
		return nil, errors.New("IPAPI ZIP requires exactly two single-disk members")
	}
	directory := int64(binary.LittleEndian.Uint32(record[16:20]))
	directoryBytes := int64(binary.LittleEndian.Uint32(record[12:16]))
	endOffset := size - int64(tailSize) + int64(end)
	if directory < 0 || directoryBytes < 92 || directory+directoryBytes != endOffset {
		return nil, errors.New("IPAPI ZIP directory framing invalid")
	}
	offset := directory
	seen := map[string]bool{}
	var members []geoZIPMember
	for i := 0; i < 2; i++ {
		header, err := geoReadAt(ctx, file, offset, 46, size)
		if err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint32(header) != 0x02014b50 {
			return nil, errors.New("IPAPI ZIP central header invalid")
		}
		nameBytes, extraBytes, commentBytes := int(binary.LittleEndian.Uint16(header[28:])), int(binary.LittleEndian.Uint16(header[30:])), int(binary.LittleEndian.Uint16(header[32:]))
		if nameBytes == 0 || nameBytes > 4096 || int64(46+nameBytes+extraBytes+commentBytes) > directory+directoryBytes-offset || binary.LittleEndian.Uint16(header[34:]) != 0 {
			return nil, errors.New("IPAPI ZIP central member bounds invalid")
		}
		data, err := geoReadAt(ctx, file, offset+46, nameBytes+extraBytes, size)
		if err != nil {
			return nil, err
		}
		name := string(data[:nameBytes])
		if name != member && name != ipapiNoticeName || seen[name] {
			return nil, errors.New("IPAPI ZIP contains an unexpected or duplicate member")
		}
		seen[name] = true
		value := geoZIPMember{name: name, extra: append([]byte(nil), data[nameBytes:]...), flags: binary.LittleEndian.Uint16(header[8:]), method: binary.LittleEndian.Uint16(header[10:]), dosTime: binary.LittleEndian.Uint16(header[12:]), dosDate: binary.LittleEndian.Uint16(header[14:]), crc: binary.LittleEndian.Uint32(header[16:]), compressed: binary.LittleEndian.Uint32(header[20:]), decoded: binary.LittleEndian.Uint32(header[24:]), localOffset: int64(binary.LittleEndian.Uint32(header[42:]))}
		if value.flags&^uint16(0x0800) != 0 || value.method != 0 && value.method != 8 || value.compressed == 0 || value.decoded == 0 || uint64(value.decoded) > 3<<30 || name == ipapiNoticeName && value.decoded > 16<<10 {
			return nil, errors.New("IPAPI ZIP member profile invalid")
		}
		value.published, err = zipUT(value.extra, false)
		if err != nil {
			return nil, err
		}
		local, err := geoReadAt(ctx, file, value.localOffset, 30, size)
		if err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint32(local) != 0x04034b50 || binary.LittleEndian.Uint16(local[6:]) != value.flags || binary.LittleEndian.Uint16(local[8:]) != value.method || binary.LittleEndian.Uint16(local[10:]) != value.dosTime || binary.LittleEndian.Uint16(local[12:]) != value.dosDate || binary.LittleEndian.Uint32(local[14:]) != value.crc || binary.LittleEndian.Uint32(local[18:]) != value.compressed || binary.LittleEndian.Uint32(local[22:]) != value.decoded {
			return nil, errors.New("IPAPI ZIP local/central headers differ")
		}
		localName, localExtra := int(binary.LittleEndian.Uint16(local[26:])), int(binary.LittleEndian.Uint16(local[28:]))
		localData, err := geoReadAt(ctx, file, value.localOffset+30, localName+localExtra, size)
		if err != nil {
			return nil, err
		}
		if string(localData[:localName]) != name {
			return nil, errors.New("IPAPI ZIP local member name differs")
		}
		localClock, err := zipUT(localData[localName:], true)
		if err != nil || !localClock.Equal(value.published) || !consistentZIPDOS(value.dosDate, value.dosTime, value.published) {
			return nil, errors.New("IPAPI ZIP UTC timestamps inconsistent")
		}
		value.dataStart = value.localOffset + 30 + int64(localName+localExtra)
		value.dataEnd = value.dataStart + int64(value.compressed)
		if value.localOffset < 0 || value.dataEnd > directory {
			return nil, errors.New("IPAPI ZIP local data crosses directory")
		}
		members = append(members, value)
		offset += int64(46 + nameBytes + extraBytes + commentBytes)
	}
	if offset != directory+directoryBytes {
		return nil, errors.New("IPAPI ZIP central trailing records")
	}
	sort.Slice(members, func(i, j int) bool { return members[i].localOffset < members[j].localOffset })
	if members[0].localOffset != 0 || members[0].dataEnd != members[1].localOffset || members[1].dataEnd != directory {
		return nil, errors.New("IPAPI ZIP overlap or unexplained data")
	}
	return members, nil
}

func walkIPAPIArchive(ctx context.Context, file *os.File, size int64, source Source, consume func(string, io.Reader) error) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := ipapiZIPMembers(ctx, file, size, source); err != nil {
		return err
	}
	return acquire.WalkArchive(ctx, acquire.ArchiveInput{Reader: file, ReaderAt: file, Size: size}, "zip", acquire.ArchiveLimits{CompressedBytes: source.MaxCompressedBytes, DecodedBytes: 3 << 30, EntryBytes: 3 << 30, Entries: 2, NameBytes: 4096}, consume)
}
func verifyIPAPIArchive(ctx context.Context, file *os.File, size int64, source Source, now time.Time) (*intelligence.GeoSourceProof, error) {
	members, err := ipapiZIPMembers(ctx, file, size, source)
	if err != nil {
		return nil, err
	}
	csvName, _ := ipapiCSVMember(source)
	var published time.Time
	for _, member := range members {
		if member.name == csvName {
			published = member.published
		}
	}
	if published.IsZero() || published.After(now.Add(24*time.Hour)) {
		return nil, errors.New("IPAPI CSV UTC clock invalid")
	}
	proof := &intelligence.GeoSourceProof{Version: 1, AssetURL: source.URL, CSVMember: csvName, UpstreamClock: published}
	seenCSV, seenNotice := false, false
	err = walkIPAPIArchive(ctx, file, size, source, func(name string, input io.Reader) error {
		hash := sha256.New()
		size, err := io.Copy(hash, input)
		if err != nil {
			return err
		}
		if name == csvName {
			if seenCSV {
				return errors.New("duplicate IPAPI CSV")
			}
			seenCSV = true
			proof.DecodedBytes = size
			copy(proof.DecodedSHA256[:], hash.Sum(nil))
		} else if name == ipapiNoticeName {
			if seenNotice || size > 16<<10 {
				return errors.New("IPAPI notice invalid")
			}
			seenNotice = true
			copy(proof.LicenseSHA256[:], hash.Sum(nil))
			if hashString(proof.LicenseSHA256) != approvedIPAPINoticeSHA256 {
				return errors.New("IPAPI notice changed; new rights review required")
			}
		} else {
			return errors.New("unexpected IPAPI archive member")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !seenCSV || !seenNotice || proof.DecodedBytes <= 0 {
		return nil, errors.New("complete IPAPI CSV and reviewed notice required")
	}
	return proof, nil
}
func parseIPAPIArchive(ctx context.Context, file *os.File, size int64, source Source, maximum int, emit func(intelligence.NormalizedRecord) error) error {
	csvName, _ := ipapiCSVMember(source)
	seen := false
	return walkIPAPIArchive(ctx, file, size, source, func(name string, input io.Reader) error {
		if name == csvName {
			if seen {
				return errors.New("duplicate IPAPI CSV")
			}
			seen = true
			return parseIPAPIFreeCSV(ctx, input, source, maximum, emit)
		}
		if name == ipapiNoticeName {
			hash := sha256.New()
			size, err := io.Copy(hash, io.LimitReader(input, (16<<10)+1))
			if err != nil {
				return err
			}
			var digest [32]byte
			copy(digest[:], hash.Sum(nil))
			if size > 16<<10 || hashString(digest) != approvedIPAPINoticeSHA256 {
				return errors.New("IPAPI license notice not reviewed")
			}
			return nil
		}
		return errors.New("unexpected IPAPI member")
	})
}
