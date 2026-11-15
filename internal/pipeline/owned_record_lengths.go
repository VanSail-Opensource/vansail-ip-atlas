package pipeline

import (
	"encoding/json"
	"errors"

	"vansail-ip-atlas/internal/intelligence"
)

// These lengths are process-local bookkeeping for the same owned records passed
// from the bulk collector to materialization, then to its mapping subset. They
// never replace semantic validation, source qualification, or an on-disk bound.
// A nil slice means an exported entry point must measure its actual input.
func checkOwnedRecordLengths(state intelligence.BuildState, lengths []int) error {
	if lengths == nil {
		return nil
	}
	count := 0
	for _, source := range state.Sources {
		for _, record := range source.Records {
			// Joining ASN usage changes the record sequence and must happen before
			// any exact sizes are captured by the owning collector.
			if record.Usage != nil && record.Usage.ASN != 0 {
				return errors.New("owned record lengths precede ASN usage join")
			}
			count++
		}
	}
	if count != len(lengths) {
		return errors.New("owned record lengths do not match materialization state")
	}
	for _, size := range lengths {
		if size <= 0 || size > 1<<20 {
			return errors.New("owned record length exceeds normalized frame bound")
		}
	}
	return nil
}

func normalizedRecordBytes(record intelligence.NormalizedRecord, lengths []int, index int) (int, error) {
	if lengths != nil {
		if index >= len(lengths) {
			return 0, errors.New("owned record lengths exhausted")
		}
		return lengths[index], nil
	}
	encoded, err := json.Marshal(record)
	return len(encoded), err
}
