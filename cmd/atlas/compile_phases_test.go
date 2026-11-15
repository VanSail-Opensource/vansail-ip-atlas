package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func phaseRecords(t *testing.T, data string) []compilePhaseRecord {
	t.Helper()
	var records []compilePhaseRecord
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if !strings.HasPrefix(line, "ATLAS_COMPILE_PHASE ") {
			t.Fatal("diagnostic prefix differs")
		}
		decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, "ATLAS_COMPILE_PHASE ")))
		decoder.DisallowUnknownFields()
		var record compilePhaseRecord
		if err := decoder.Decode(&record); err != nil || decoder.Decode(new(json.RawMessage)) != io.EOF || record.ElapsedMS < 0 {
			t.Fatal("diagnostic schema differs", err)
		}
		records = append(records, record)
	}
	return records
}

func TestCompilePhaseDiagnosticsReportFailureWithoutDetails(t *testing.T) {
	var output bytes.Buffer
	ctx := withCompilePhases(context.Background(), &output)
	want := errors.New("private-source-id /private/path raw parser details")
	if err := runCompilePhase(ctx, phaseBuild, func() error { return want }); err != want {
		t.Fatal("diagnostics changed build failure")
	}
	records := phaseRecords(t, output.String())
	if len(records) != 2 || records[0] != (compilePhaseRecord{phaseBuild, "begin", 0, true}) || records[1].Phase != phaseBuild || records[1].Event != "end" || records[1].OK || strings.Contains(output.String(), "private") {
		t.Fatal("failure diagnostics missing or exposed details")
	}
	output.Reset()
	finish := beginCompilePhase(ctx, phaseTier1)
	if records := phaseRecords(t, output.String()); len(records) != 1 || records[0].Event != "begin" {
		t.Fatal("phase begin was not written before work")
	}
	finish(true)
	finish(false)
	if records := phaseRecords(t, output.String()); len(records) != 2 || !records[1].OK {
		t.Fatal("phase completion was not exactly once")
	}
}

func TestCompilePhaseDiagnosticsAreOptionalFixedAndBounded(t *testing.T) {
	beginCompilePhase(context.Background(), phaseBuild)(true)
	var output bytes.Buffer
	ctx := withCompilePhases(context.Background(), &output)
	beginCompilePhase(ctx, compilePhase("private-input-value"))(true)
	if output.Len() != 0 {
		t.Fatal("nonfixed phase reached diagnostics")
	}
	for i := 0; i < 100; i++ {
		beginCompilePhase(ctx, phaseBoundary)(true)
	}
	if records := phaseRecords(t, output.String()); len(records) != 64 {
		t.Fatal("phase record budget differs", len(records))
	}
}
