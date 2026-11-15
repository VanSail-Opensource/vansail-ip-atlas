package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

type bulkPrefixRange struct {
	offset int64
	count  uint64
}

const bulkPrefixFrameBytes = 52 // 12-byte lengths, 4-byte ASN, two identical 18-byte prefix keys.
func prefixSortKey(prefix netip.Prefix) []byte {
	key := via3.PrefixKey(prefix, false, 0)
	out := make([]byte, 0, 18)
	out = append(out, key[0])
	out = append(out, key[4:20]...)
	return append(out, key[1])
}
func (s *bulkSpool) preparePrefixes(ctx context.Context) error {
	s.prefixIndex = map[uint32]bulkPrefixRange{}
	if len(s.prefixParts) == 0 {
		return nil
	}
	path, err := s.sortKeyedRows(ctx, func(emit func(bulkPathRow) error) error {
		return s.walk(ctx, s.prefixParts, func(record intelligence.NormalizedRecord) error {
			if record.Origins == nil {
				return errors.New("invalid ASN-prefix source spool")
			}
			prefix, err := canonicalMappingPrefix(record.Origins.Prefix)
			if err != nil {
				return err
			}
			key := prefixSortKey(prefix)
			for _, asn := range record.Origins.Origins {
				var group [4]byte
				binary.BigEndian.PutUint32(group[:], asn)
				if err = emit(bulkPathRow{group: string(group[:]), family: string(key), data: key}); err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	if path == "" {
		s.prefixParts = nil
		return s.gc(ctx)
	}
	reader, err := openPathRun(path)
	if err != nil {
		return err
	}
	defer reader.file.Close()
	var offset int64
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		err = reader.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		row := reader.row
		if len(row.group) != 4 || len(row.family) != 18 || len(row.data) != 18 || !bytes.Equal([]byte(row.family), row.data) {
			return errors.New("ASN-prefix sort frame invalid")
		}
		asn := binary.BigEndian.Uint32([]byte(row.group))
		entry, ok := s.prefixIndex[asn]
		if !ok {
			if len(s.prefixIndex) >= 200000 {
				return errors.New("ASN-prefix index population exceeded")
			}
			entry.offset = offset
		}
		entry.count++
		s.prefixIndex[asn] = entry
		offset += bulkPrefixFrameBytes
	}
	if err = reader.file.Close(); err != nil {
		return err
	}
	s.prefixFile, err = os.Open(path)
	if err != nil {
		return err
	}
	s.prefixParts = nil
	return s.gc(ctx)
}
func (s *bulkSpool) providePrefixes(ctx context.Context, asn uint32, emit func(netip.Prefix) error) (bool, error) {
	entry, ok := s.prefixIndex[asn]
	if !ok {
		return false, nil
	}
	if s.prefixFile == nil || emit == nil {
		return false, errors.New("ASN-prefix provider unavailable")
	}
	var buffer [bulkPrefixFrameBytes * 256]byte
	for first := uint64(0); first < entry.count; first += 256 {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		count := min(uint64(256), entry.count-first)
		data := buffer[:int(count)*bulkPrefixFrameBytes]
		if _, err := s.prefixFile.ReadAt(data, entry.offset+int64(first)*bulkPrefixFrameBytes); err != nil {
			return false, err
		}
		for i := 0; i < int(count); i++ {
			row := data[i*bulkPrefixFrameBytes : (i+1)*bulkPrefixFrameBytes]
			if binary.LittleEndian.Uint32(row[:4]) != 4 || binary.LittleEndian.Uint32(row[4:8]) != 18 || binary.LittleEndian.Uint32(row[8:12]) != 18 || binary.BigEndian.Uint32(row[12:16]) != asn || !bytes.Equal(row[16:34], row[34:]) {
				return false, errors.New("ASN-prefix stream changed")
			}
			key := row[16:34]
			var addr netip.Addr
			if key[0] == 4 {
				if !bytes.Equal(key[1:13], make([]byte, 12)) {
					return false, errors.New("ASN-prefix IPv4 key invalid")
				}
				var raw [4]byte
				copy(raw[:], key[13:17])
				addr = netip.AddrFrom4(raw)
			} else if key[0] == 6 {
				var raw [16]byte
				copy(raw[:], key[1:17])
				addr = netip.AddrFrom16(raw)
			} else {
				return false, errors.New("ASN-prefix address family invalid")
			}
			prefix := netip.PrefixFrom(addr, int(key[17]))
			if !prefix.IsValid() || prefix != prefix.Masked() {
				return false, errors.New("ASN-prefix key invalid")
			}
			if err := emit(prefix); err != nil {
				return false, err
			}
		}
	}
	return true, nil
}
