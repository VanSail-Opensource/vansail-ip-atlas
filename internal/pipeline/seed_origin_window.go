package pipeline

import (
	"net/netip"
	"slices"

	"vansail-ip-atlas/internal/intelligence"
)

type seedOriginIdentity struct {
	present bool
	version uint16
	prefix  netip.Prefix
	origins []uint32
}

// Each category remembers only its last emitted OriginMapping. Source records
// are still fully walked and seedRecord performs every side effect before this
// optional suppression. A path in another category cannot erase the spatial
// window, but an intervening spatial fact or original input boundary does.
type seedOriginAppender struct {
	previous [6]seedOriginIdentity
	emit     func(int, intelligence.NormalizedRecord) error
}

func (a *seedOriginAppender) reset() { a.previous = [6]seedOriginIdentity{} }

func (a *seedOriginAppender) append(category int, record intelligence.NormalizedRecord) error {
	previous := &a.previous[category]
	if record.Kind != intelligence.RecordOrigins {
		*previous = seedOriginIdentity{}
		return a.emit(category, record)
	}
	mapping := record.Origins
	if previous.present && previous.version == record.Version && previous.prefix == mapping.Prefix &&
		(previous.origins == nil) == (mapping.Origins == nil) && slices.Equal(previous.origins, mapping.Origins) {
		return nil
	}
	if err := a.emit(category, record); err != nil {
		return err
	}
	*previous = seedOriginIdentity{present: true, version: record.Version, prefix: mapping.Prefix, origins: slices.Clone(mapping.Origins)}
	return nil
}
