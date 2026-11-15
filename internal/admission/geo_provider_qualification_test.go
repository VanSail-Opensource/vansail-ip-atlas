package admission

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// This opt-in qualification uses full private captures and never downloads or
// publishes dataset rows. Normal CI exercises the tiny container regressions.
func TestGeoProviderCompletePrivateCaptures(t *testing.T) {
	base := os.Getenv("ATLAS_GEO_CAPTURE_DIR")
	if base == "" {
		t.Skip("complete captures remain build-private")
	}
	type measurement struct {
		Name                        string
		CompressedBytes             int64
		Proof                       *intelligence.GeoSourceProof
		CSVStats                    geoCSVStats
		NormalizedRecords           uint64
		ElapsedSeconds              float64
		AllocatedBytes, Allocations uint64
	}
	var results []measurement
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"dbip-city-gz.bin", "ipapi-v4-zip.bin", "ipapi-v6-zip.bin"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			source := dbipTestSource()
			if name != "dbip-city-gz.bin" {
				source = ipapiTestSource(name == "ipapi-v6-zip.bin")
			}
			source.MaxCompressedBytes = 1 << 30
			file, err := os.Open(filepath.Join(base, name))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			started := time.Now()
			m := measurement{Name: name, CompressedBytes: info.Size()}
			if name == "dbip-city-gz.bin" {
				page, err := os.ReadFile(filepath.Join(base, "dbip-page.bin"))
				if err != nil {
					t.Fatal(err)
				}
				plan, err := resolveDBIPMonthlyPage(page, now)
				if err != nil {
					t.Fatal(err)
				}
				m.Proof, err = verifyDBIPGzip(ctx, file, info.Size(), source, plan)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = file.Seek(0, io.SeekStart); err != nil {
					t.Fatal(err)
				}
				err = parsePayloadTo(ctx, file, info.Size(), source, bulkAdapter, m.Proof.UpstreamClock, 100_000_000, func(r intelligence.NormalizedRecord) error { m.NormalizedRecords++; return r.Validate() })
				if err != nil {
					t.Fatal(m.NormalizedRecords, err)
				}
				m.CSVStats.Rows = plan.Rows
			} else {
				m.Proof, err = verifyIPAPIArchive(ctx, file, info.Size(), source, now)
				if err != nil {
					t.Fatal(err)
				}
				csvName, _ := ipapiCSVMember(source)
				err = walkIPAPIArchive(ctx, file, info.Size(), source, func(name string, input io.Reader) error {
					if name != csvName {
						_, err := io.Copy(io.Discard, input)
						return err
					}
					var parseErr error
					m.CSVStats, parseErr = parseIPAPIFreeCSVStats(ctx, input, source, 100_000_000, func(r intelligence.NormalizedRecord) error { m.NormalizedRecords++; return r.Validate() })
					return parseErr
				})
				if err != nil {
					t.Fatal(m.NormalizedRecords, err)
				}
			}
			runtime.ReadMemStats(&after)
			m.ElapsedSeconds = time.Since(started).Seconds()
			m.AllocatedBytes = after.TotalAlloc - before.TotalAlloc
			m.Allocations = after.Mallocs - before.Mallocs
			results = append(results, m)
			t.Logf("complete capture verified: rows=%d normalized=%d elapsed=%.3fs decoded=%d", m.CSVStats.Rows, m.NormalizedRecords, m.ElapsedSeconds, m.Proof.DecodedBytes)
		})
	}
	if output := os.Getenv("ATLAS_GEO_REPORT"); output != "" {
		data, err := json.MarshalIndent(struct {
			Version      int
			RecordedAt   time.Time
			Measurements []measurement
		}{1, time.Now().UTC(), results}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
