package via3

import "strings"

type pendingLookupLabel struct {
	bytes  []byte
	target *string
}

// Pending labels borrow validated dictionary bytes only while the current query
// pins their shards. finish copies exactly the referenced bytes into one fresh
// answer-owned string; no substring can retain an entire decoded dictionary.
// Mutable string headers still belong to independent answer value blocks.
type lookupLabels struct {
	inline            [16]pendingLookupLabel
	spill             []pendingLookupLabel
	count             int
	known, knownBytes int
	bytes             int
}

func (b *lookupLabels) add(value []byte, target *string) (*string, error) {
	if len(value) > 256 || b.count+b.known >= 5+2*PublicOrigins || len(value) > PublicAnswerBytes-b.bytes-b.knownBytes {
		return nil, fail("resource_limit")
	}
	entry := pendingLookupLabel{bytes: value, target: target}
	if b.count < len(b.inline) {
		b.inline[b.count] = entry
	} else {
		b.spill = append(b.spill, entry)
	}
	b.count++
	b.bytes += len(value)
	return target, nil
}

func (b *lookupLabels) finish() {
	b.known, b.knownBytes = 0, 0
	if b.count == 0 {
		return
	}
	var packed strings.Builder
	packed.Grow(b.bytes)
	for i := 0; i < b.count; i++ {
		var entry *pendingLookupLabel
		if i < len(b.inline) {
			entry = &b.inline[i]
		} else {
			entry = &b.spill[i-len(b.inline)]
		}
		start := packed.Len()
		packed.Write(entry.bytes)
		// Grow above reserved the complete capacity. Later writes append only
		// beyond this immutable substring; they never overwrite its bytes.
		*entry.target = packed.String()[start:packed.Len()]
		*entry = pendingLookupLabel{}
	}
	b.spill, b.count, b.bytes = nil, 0, 0
}

func (b *lookupLabels) addKnown(value string, target *string) (*string, error) {
	if len(value) > 256 || b.count+b.known >= 5+2*PublicOrigins || len(value) > PublicAnswerBytes-b.bytes-b.knownBytes {
		return nil, fail("resource_limit")
	}
	b.known++
	b.knownBytes += len(value)
	*target = value
	return target, nil
}
