package admission

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

const latestCompleteMRTPolicy = "latest-complete-v1"

// This explicit policy reviews only the two qualified collector schedules.
// The configured dated locator is a stable collector/codec anchor, not a clock.
// Thirty minutes allows publication lag; one older slot is the only fallback,
// and only after HTTP 404. Successful bytes still require full framing and EOF.
func validMRTArchivePolicy(source Source) bool {
	if source.MRTArchivePolicy == "" {
		return true
	}
	if source.MRTArchivePolicy != latestCompleteMRTPolicy || source.Parser.ID != "mrt-table-dump-v2" || source.Parser.Schema != "mrt-table-dump-v2-unicast-v1" || source.Parser.Version != 1 || source.Category != "bgp" || source.Scope != "path" || source.Publication.Kind != "embedded" || source.Publication.Field != "mrt_frame_capture_timestamp" || source.Publication.Locator != source.URL {
		return false
	}
	location, err := mrtArchiveURL(source.URL)
	if err != nil || !location.rib {
		return false
	}
	u, _ := url.Parse(source.URL)
	return u.Host == "data.ris.ripe.net" && strings.HasPrefix(u.Path, "/rrc18/") && source.Format == "mrt-gz" ||
		u.Host == "archive.routeviews.org" && strings.HasPrefix(u.Path, "/route-views.wide/bgpdata/") && source.Format == "mrt-bz2"
}

func mrtRIBCandidates(source Source, now time.Time) ([]string, error) {
	if !validMRTArchivePolicy(source) || now.IsZero() || now.Year() < 1970 {
		return nil, errors.New("reviewed MRT archive rotation required")
	}
	if source.MRTArchivePolicy == "" {
		return []string{source.URL}, nil
	}
	base, _ := mrtArchiveURL(source.URL)
	period := base.until.Sub(base.from)
	stamp := now.UTC().Add(-30 * time.Minute).Truncate(period)
	u, _ := url.Parse(source.URL)
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	var result []string
	for i := 0; i < 2; i++ {
		if u.Host == "data.ris.ripe.net" {
			parts[1] = stamp.Format("2006.01")
			parts[2] = "bview." + stamp.Format("20060102.1504") + ".gz"
		} else {
			parts[2] = stamp.Format("2006.01")
			parts[4] = "rib." + stamp.Format("20060102.1504") + ".bz2"
		}
		u.Path = "/" + strings.Join(parts, "/")
		raw := u.String()
		selected, err := mrtArchiveURL(raw)
		if err != nil || !selected.rib || selected.collector != base.collector || selected.format != base.format {
			return nil, errors.New("MRT archive rotation changed collector or codec")
		}
		result = append(result, raw)
		stamp = stamp.Add(-period)
	}
	return result, nil
}

// The seal binds the actual selected URL as well as the payload hash. Replay
// inherits that URL; later evaluation clocks never relabel an older capture.
func validMRTArchiveBinding(source Source, proof *intelligence.MRTSourceProof, evaluated time.Time) bool {
	if !validMRTArchivePolicy(source) || proof == nil {
		return false
	}
	if source.MRTArchivePolicy == "" {
		return proof.BaseArchiveURL == "" && proof.BaseArchiveSelectedAt.IsZero() // fixed and legacy generic captures retain their existing contract
	}
	if proof.BaseArchiveSelectedAt.IsZero() || proof.BaseArchiveSelectedAt.After(evaluated) {
		return false
	}
	candidates, err := mrtRIBCandidates(source, proof.BaseArchiveSelectedAt)
	if err != nil || len(candidates) != 2 || proof.BaseArchiveURL != candidates[0] && proof.BaseArchiveURL != candidates[1] {
		return false
	}
	base, err := mrtArchiveURL(source.URL)
	actual, actualErr := mrtArchiveURL(proof.BaseArchiveURL)
	return err == nil && actualErr == nil && actual.rib && actual.collector == base.collector && actual.format == base.format && proof.Collector == actual.collector &&
		!proof.CapturedAt.Before(actual.from) && proof.CaptureEnd().Before(actual.until) && !proof.CaptureEnd().After(proof.BaseArchiveSelectedAt)
}

func mrtReplayBaseURL(source Source, proof *intelligence.MRTSourceProof) string {
	if source.MRTArchivePolicy != "" && proof != nil {
		return proof.BaseArchiveURL
	}
	return source.URL
}
