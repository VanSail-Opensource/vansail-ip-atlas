package intelligence

import (
	"errors"
	"strings"
	"time"
)

// CAIDASourceProof binds a complete serial-2 body and its conservative input
// clock to the selected monthly asset. These details remain build-private.
type CAIDASourceProof struct {
	Version                         uint16
	AssetURL                        string
	IndexSHA256, PayloadSHA256      [32]byte
	Rows, Headers, BGPHeaders       uint64
	FirstObservedAt, LastObservedAt time.Time
}

const CAIDASerial2Index = "https://publicdata.caida.org/datasets/as-relationships/serial-2/"

func CAIDASerial2AssetMonth(asset string) (time.Time, error) {
	name := strings.TrimPrefix(asset, CAIDASerial2Index)
	if asset == name || len(name) != len("20060102.as-rel2.txt.bz2") || name[8:] != ".as-rel2.txt.bz2" {
		return time.Time{}, errors.New("CAIDA asset outside canonical serial-2 archive")
	}
	month, err := time.Parse("20060102", name[:8])
	if err != nil || month.Year() < 1970 || month.Day() != 1 {
		return time.Time{}, errors.New("CAIDA asset month invalid")
	}
	return month, nil
}

func (p *CAIDASourceProof) Validate(now, published time.Time, payload [32]byte) error {
	if p == nil || p.Version != 1 || p.IndexSHA256 == ([32]byte{}) || p.PayloadSHA256 == ([32]byte{}) || p.PayloadSHA256 != payload || p.Rows == 0 || p.Rows > 100_000_000 || p.Headers == 0 || p.Headers > 10_000 || p.BGPHeaders == 0 || p.BGPHeaders > p.Headers || now.IsZero() || published.IsZero() || p.FirstObservedAt.IsZero() || p.FirstObservedAt.After(p.LastObservedAt) || p.LastObservedAt.After(now.Add(24*time.Hour)) || published.After(p.FirstObservedAt) {
		return errors.New("complete CAIDA snapshot proof invalid")
	}
	month, err := CAIDASerial2AssetMonth(p.AssetURL)
	if err != nil || month.After(now.Add(24*time.Hour)) {
		return errors.New("CAIDA selected asset invalid")
	}
	for _, date := range []time.Time{p.FirstObservedAt, p.LastObservedAt} {
		if date.Year() < 1970 || date.Location() != time.UTC || !date.Equal(date.Truncate(24*time.Hour)) {
			return errors.New("CAIDA observation date invalid")
		}
	}
	return nil
}

func cloneCAIDAProof(p *CAIDASourceProof) *CAIDASourceProof {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}
