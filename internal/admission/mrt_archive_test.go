package admission

import (
	"testing"
	"time"
)

func TestMRTArchiveURLBindsCollectorIntervalAndCodec(t *testing.T) {
	for _, row := range []struct {
		url, format string
		rib         bool
		period      time.Duration
	}{
		{"https://data.ris.ripe.net/rrc00/2026.11/bview.20261109.0000.gz", "gzip", true, 8 * time.Hour},
		{"https://data.ris.ripe.net/rrc01/2026.11/updates.20261109.0005.gz", "gzip", false, 5 * time.Minute},
		{"https://archive.routeviews.org/bgpdata/2026.11/RIBS/rib.20261109.0000.bz2", "bzip2", true, 2 * time.Hour},
		{"https://archive.routeviews.org/route-views2/bgpdata/2026.11/UPDATES/updates.20261109.0015.bz2", "bzip2", false, 15 * time.Minute},
	} {
		location, err := mrtArchiveURL(row.url)
		if err != nil || location.rib != row.rib || location.format != row.format || location.until.Sub(location.from) != row.period || location.collector == ([32]byte{}) {
			t.Fatal("valid provider archive rejected", row.url, location, err)
		}
	}
	base, _ := mrtArchiveURL("https://data.ris.ripe.net/rrc00/2026.11/bview.20261109.0000.gz")
	update, _ := mrtArchiveURL("https://data.ris.ripe.net/rrc00/2026.11/updates.20261109.0005.gz")
	other, _ := mrtArchiveURL("https://data.ris.ripe.net/rrc01/2026.11/updates.20261109.0005.gz")
	if base.collector != update.collector || base.collector == other.collector {
		t.Fatal("provider/collector identity was not stable and distinct")
	}
}

func TestMRTArchiveURLRejectsUnreviewedOrAmbiguousNames(t *testing.T) {
	for _, raw := range []string{
		"http://data.ris.ripe.net/rrc00/2026.11/updates.20261109.0000.gz",
		"https://data.ris.ripe.net:443/rrc00/2026.11/updates.20261109.0000.gz",
		"https://data.ris.ripe.net/rrc00/2026.11/updates.20261109.0000.gz?x=1",
		"https://data.ris.ripe.net/rrc00/2026.11/updates.20261109.0000.gz#x",
		"https://data.ris.ripe.net/rrcAA/2026.11/updates.20261109.0000.gz",
		"https://data.ris.ripe.net/rrc00/2026.10/updates.20261109.0000.gz",
		"https://data.ris.ripe.net/rrc00/2026.11/updates.20261109.0001.gz",
		"https://data.ris.ripe.net/rrc00/2026.11/bview.20261109.0100.gz",
		"https://data.ris.ripe.net/rrc00/2026.11/updates.20261109.0000.bz2",
		"https://archive.routeviews.org/bgpdata/2026.11/UPDATES/updates.20261109.0005.bz2",
		"https://archive.routeviews.org/../bgpdata/2026.11/RIBS/rib.20261109.0000.bz2",
		"https://archive.routeviews.org/bgpdata/2026.11/RIBS/rib.20261131.0000.bz2",
		"https://example.com/bgpdata/2026.11/RIBS/rib.20261109.0000.bz2",
	} {
		if _, err := mrtArchiveURL(raw); err == nil {
			t.Fatal("ambiguous archive admitted", raw)
		}
	}
}

func TestMRTAutomaticUpdatePlanCrossesMonthWithoutChangingCollector(t *testing.T) {
	for _, row := range []struct {
		base, next string
		minute     int
	}{
		{"https://data.ris.ripe.net/rrc00/2026.11/bview.20261130.1600.gz", "https://data.ris.ripe.net/rrc00/2026.12/updates.20261201.0000.gz", 5},
		{"https://archive.routeviews.org/route-views2/bgpdata/2026.11/RIBS/rib.20261130.2200.bz2", "https://archive.routeviews.org/route-views2/bgpdata/2026.12/UPDATES/updates.20261201.0000.bz2", 15},
	} {
		clock := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
		actual, location, err := nextMRTUpdateURL(row.base, clock)
		base, _ := mrtArchiveURL(row.base)
		if err != nil || actual != row.next || location.collector != base.collector || !location.from.Equal(clock) || !location.until.Equal(clock.Add(time.Duration(row.minute)*time.Minute)) {
			t.Fatal("month rollover broke continuity", actual, location, err)
		}
	}
}
