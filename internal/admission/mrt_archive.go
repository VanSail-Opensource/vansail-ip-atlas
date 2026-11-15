package admission

import (
	"crypto/sha256"
	"errors"
	"net/url"
	"strings"
	"time"
)

type mrtArchiveLocation struct {
	collector   [32]byte
	from, until time.Time
	format      string
	rib         bool
}

// Provider naming establishes collector identity and archive continuity only.
// It never establishes freshness: every selected payload must separately pass
// full frame-capture validation and SHA-256 binding. Published schedules:
// https://www.ris.ripe.net/docs/mrt/ (5-minute UPDATE archives)
// https://api.routeviews.org/docs/ (900-second UPDATE dumpDuration)
func mrtArchiveURL(raw string) (mrtArchiveLocation, error) {
	var out mrtArchiveLocation
	if !safeHTTPS(raw) {
		return out, errors.New("MRT archive URL invalid")
	}
	u, err := url.Parse(raw)
	if err != nil || u.RawPath != "" || u.Host != u.Hostname() {
		return out, errors.New("canonical MRT archive URL required")
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	var file, month, collector string
	var period time.Duration
	switch u.Host {
	case "data.ris.ripe.net":
		if len(parts) != 3 || len(parts[0]) != 5 || parts[0][:3] != "rrc" || parts[0][3] < '0' || parts[0][3] > '9' || parts[0][4] < '0' || parts[0][4] > '9' {
			return out, errors.New("RIS collector path invalid")
		}
		collector, month, file = "ris/"+parts[0], parts[1], parts[2]
		out.format = "gzip"
		if strings.HasPrefix(file, "bview.") {
			out.rib, period = true, 8*time.Hour
			file = strings.TrimPrefix(file, "bview.")
		} else if strings.HasPrefix(file, "updates.") {
			period = 5 * time.Minute
			file = strings.TrimPrefix(file, "updates.")
		} else {
			return out, errors.New("RIS archive type invalid")
		}
		if !strings.HasSuffix(file, ".gz") {
			return out, errors.New("RIS archive codec invalid")
		}
		file = strings.TrimSuffix(file, ".gz")
	case "archive.routeviews.org":
		start := 0
		if len(parts) == 5 {
			collector = parts[0]
			start = 1
		} else if len(parts) == 4 {
			collector = "default"
		} else {
			return out, errors.New("RouteViews collector path invalid")
		}
		if collector == "" || collector == "." || collector == ".." || strings.ContainsAny(collector, "%\\?#") || parts[start] != "bgpdata" {
			return out, errors.New("RouteViews collector path invalid")
		}
		month, file = parts[start+1], parts[start+3]
		if parts[start+2] == "RIBS" && strings.HasPrefix(file, "rib.") {
			out.rib, period = true, 2*time.Hour
			file = strings.TrimPrefix(file, "rib.")
		} else if parts[start+2] == "UPDATES" && strings.HasPrefix(file, "updates.") {
			period = 15 * time.Minute
			file = strings.TrimPrefix(file, "updates.")
		} else {
			return out, errors.New("RouteViews archive type invalid")
		}
		if !strings.HasSuffix(file, ".bz2") {
			return out, errors.New("RouteViews archive codec invalid")
		}
		file = strings.TrimSuffix(file, ".bz2")
		collector = "routeviews/" + collector
		out.format = "bzip2"
	default:
		return out, errors.New("MRT provider archive continuity unreviewed")
	}
	stamp, err := time.Parse("20060102.1504", file)
	if err != nil || stamp.Format("20060102.1504") != file || stamp.Format("2006.01") != month || stamp.Unix()%int64(period/time.Second) != 0 {
		return out, errors.New("MRT archive interval invalid")
	}
	out.from, out.until = stamp.UTC(), stamp.UTC().Add(period)
	out.collector = sha256.Sum256([]byte(collector))
	return out, nil
}

func nextMRTUpdateURL(base string, at time.Time) (string, mrtArchiveLocation, error) {
	location, err := mrtArchiveURL(base)
	if err != nil || !location.rib {
		return "", mrtArchiveLocation{}, errors.New("reviewed base collector URL required")
	}
	u, _ := url.Parse(base)
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	period := 5 * time.Minute
	if u.Host == "archive.routeviews.org" {
		period = 15 * time.Minute
	}
	stamp := at.UTC().Truncate(period)
	if u.Host == "data.ris.ripe.net" {
		parts[1] = stamp.Format("2006.01")
		parts[2] = "updates." + stamp.Format("20060102.1504") + ".gz"
	} else {
		start := 0
		if len(parts) == 5 {
			start = 1
		}
		parts[start+1] = stamp.Format("2006.01")
		parts[start+2] = "UPDATES"
		parts[start+3] = "updates." + stamp.Format("20060102.1504") + ".bz2"
	}
	u.Path = "/" + strings.Join(parts, "/")
	raw := u.String()
	archive, err := mrtArchiveURL(raw)
	return raw, archive, err
}
