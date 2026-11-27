package pipeline

import (
	"errors"
	"math"
	"net/netip"

	"vansail-ip-atlas/internal/via3"
)

// The authenticated final merge visits unique exact K6 observations in IPv6
// address order. Reduce one /64 bucket and one /48 summary at a time, even
// when the source observations came from different spatial/cache leaves.
// Prefix, ASN and neighboring evidence are not additional /64 observations.
type ipv6RiskProfiles struct {
	block, bucket netip.Prefix
	value         via3.IPv6ProfileData
	maximum       float64
}

func (a *ipv6RiskProfiles) finishBucket() {
	if a.bucket.IsValid() {
		a.value.ObservedCount++
		if a.maximum > 0 {
			a.value.PositiveCount++
			a.value.ScoreSum += uint32(math.Floor(100*a.maximum + .5))
		}
		a.bucket, a.maximum = netip.Prefix{}, 0
	}
}

func (a *ipv6RiskProfiles) flush(emit func(via3.PublicRecord) error) error {
	if !a.block.IsValid() {
		return nil
	}
	a.finishBucket()
	value := a.value
	record := via3.PublicRecord{Version: 3, Kind: 7, Prefix: a.block,
		Profile: &via3.ProfileData{IPv6: &value}}
	*a = ipv6RiskProfiles{}
	return emit(record)
}

func (a *ipv6RiskProfiles) add(r *runReader, emit func(via3.PublicRecord) error) error {
	record := r.record
	if record.Quality == nil && r.owner != nil {
		var err error
		_, record, err = decodeCompactRunBody(record, r.row.data, r.limit)
		if err != nil {
			return err
		}
	}
	if record.Prefix.Bits() != 128 || record.Inherited || record.Quality == nil {
		return errors.New("invalid exact IPv6 profile input")
	}
	addr := record.Prefix.Addr()
	block := netip.PrefixFrom(addr, 48).Masked()
	bucket := netip.PrefixFrom(addr, 64).Masked()
	if block != a.block {
		if a.block.IsValid() && !a.block.Addr().Less(block.Addr()) {
			return errors.New("unordered IPv6 profiles")
		}
		if err := a.flush(emit); err != nil {
			return err
		}
		a.block = block
	}
	if bucket != a.bucket {
		if a.bucket.IsValid() && !a.bucket.Addr().Less(bucket.Addr()) {
			return errors.New("unordered IPv6 profile buckets")
		}
		a.finishBucket()
		a.bucket = bucket
	}
	if exact := record.Quality.Exact; exact != nil {
		if !(*exact >= 0 && *exact <= .55) {
			return errors.New("invalid IPv6 exact risk contribution")
		}
		a.maximum = max(a.maximum, *exact)
	}
	return nil
}
