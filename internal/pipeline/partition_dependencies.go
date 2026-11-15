package pipeline

import (
	"context"
	"errors"
	"sort"
)

// The prefix provider can add ASN page objects not present in the public row
// payload. Bind its actual sorted file and lookup ranges separately; source
// fingerprints and the top-level routing capability are insufficient keys.
func (s *bulkSpool) compiledDependencies(ctx context.Context) ([32]byte, error) {
	type prefixRange struct {
		ASN    uint32
		Offset int64
		Count  uint64
	}
	var fileHash [32]byte
	if s.prefixFile != nil {
		var err error
		fileHash, err = cacheFileHash(ctx, s.prefixFile.Name(), int64(s.maximum))
		if err != nil {
			return [32]byte{}, err
		}
	} else if len(s.prefixIndex) != 0 {
		return [32]byte{}, errors.New("ASN prefix provider inventory differs")
	}
	ranges := make([]prefixRange, 0, len(s.prefixIndex))
	for asn, value := range s.prefixIndex {
		ranges = append(ranges, prefixRange{asn, value.offset, value.count})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].ASN < ranges[j].ASN })
	return spatialReuseKey("compiled-prefix-provider", struct {
		File   [32]byte
		Ranges []prefixRange
	}{fileHash, ranges})
}
