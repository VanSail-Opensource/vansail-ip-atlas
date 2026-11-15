package admission

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// This opt-in benchmark replays a bounded prefix of an existing private capture.
// It performs no download and is not source qualification. Country cases only
// project that same observed sample to the existing three-column range schema.
func BenchmarkBulkCSVPrivateDBIP(b *testing.B) {
	base := os.Getenv("ATLAS_GEO_CAPTURE_DIR")
	if base == "" {
		b.Skip("private complete capture not selected")
	}
	for _, rows := range []int{100_000, 500_000} {
		file, err := os.Open(filepath.Join(base, "dbip-city-gz.bin"))
		if err != nil {
			b.Fatal(err)
		}
		decoded, err := gzip.NewReader(file)
		if err != nil {
			_ = file.Close()
			b.Fatal(err)
		}
		scanner := bufio.NewScanner(decoded)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		var city, country bytes.Buffer
		count := 0
		for count < rows && scanner.Scan() {
			line := scanner.Bytes()
			city.Write(line)
			city.WriteByte('\n')
			reader := csv.NewReader(bytes.NewReader(line))
			reader.FieldsPerRecord = 8
			fields, err := reader.Read()
			if err != nil {
				b.Fatal(err)
			}
			if _, err = reader.Read(); err != io.EOF {
				b.Fatal("private sample row framing changed", err)
			}
			fmt.Fprintf(&country, "%s,%s,%s\n", fields[0], fields[1], fields[3])
			count++
		}
		if err = scanner.Err(); err != nil {
			b.Fatal(err)
		}
		_ = decoded.Close()
		_ = file.Close()
		if count != rows {
			b.Fatal("complete capture smaller than selected sample")
		}
		for _, scenario := range []struct {
			name   string
			input  []byte
			source Source
		}{
			{"city", city.Bytes(), bulkSource("city-range-csv", "dbip-city-eight-columns-v1")},
			{"country_projection", country.Bytes(), bulkSource("country-range-csv", "start-end-country-csv-v1")},
		} {
			b.Run(fmt.Sprintf("%s/%d", scenario.name, rows), func(b *testing.B) {
				samples := make([]int64, 0, b.N)
				var records uint64
				b.SetBytes(int64(len(scenario.input)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					records = 0
					start := time.Now()
					err := parseBulkPayload(context.Background(), bytes.NewReader(scenario.input), scenario.source, time.Time{}, 100_000_000, func(r intelligence.NormalizedRecord) error { records++; return r.Validate() })
					if err != nil {
						b.Fatal(err)
					}
					samples = append(samples, time.Since(start).Nanoseconds())
				}
				b.StopTimer()
				sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
				for _, percentile := range []int{50, 95, 99} {
					b.ReportMetric(float64(samples[(len(samples)*percentile+99)/100-1]), fmt.Sprintf("p%d-ns", percentile))
				}
				b.ReportMetric(float64(rows), "input-rows")
				b.ReportMetric(float64(records), "normalized-records")
				b.ReportMetric(0, "temporary-disk-B")
				b.Logf("private sample only; input_sha256=%x; samples=%d", sha256.Sum256(scenario.input), b.N)
			})
		}
	}
}
