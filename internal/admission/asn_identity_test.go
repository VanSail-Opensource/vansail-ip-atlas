package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func TestASNIdentityCSVAdapterRequiresExactFieldsAndBindsPrivateCounts(t *testing.T) {
	payload := []byte("asn,handle,description,country-code\n13335,EDGE,Example Network,US\n64512,PRIVATE,Unknown,ZZ\n")
	e, source, fetch, now, hash := prepared(t, payload, "csv")
	source.Category = "asn"
	source.Scope = "asn"
	source.Parser = Parser{"asn-identity-csv", "asn-handle-description-country-csv-v1", 1}
	source.Fixture.Parser = source.Parser.ID
	source.Fixture.Schema = source.Parser.Schema
	source.Fields = []string{"asn", "handle", "description", "country-code"}
	source.PublicFields = []string{"asn", "as_name", "organization", "asn_country"}
	source.FieldMappings = map[string][]string{"asn": {"asn"}, "handle": {"as_name"}, "description": {"organization"}, "country-code": {"asn_country"}}
	implementation, err := implementationHash(context.Background(), e.workspace)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ledger{1, []certification{{source.ID, source.Parser.ID, source.Parser.Schema, 1, source.Fixture.SHA256, source.Fixture.TestedAt, hashString(implementation)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.workspace, "fixtures/source-certification/adapter-certifications.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := e.Ingest(context.Background(), source, now, hash)
	if err != nil || result.Snapshot == nil || len(result.Snapshot.Records) != 1 || result.Snapshot.ASNIdentityStats == nil || result.Snapshot.ASNIdentityStats.SkippedReservedASNs != 1 {
		t.Fatal("typed identity intake/counts changed", result.Decision, err)
	}
	plan, err := intelligence.Reconcile(intelligence.BuildState{}, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, now, hash)
	if err != nil || len(plan.State.Sources) != 1 || plan.State.Sources[0].Records[0].ASNIdentity == nil {
		t.Fatal(err)
	}
	v := plan.State.Sources[0].Records[0].ASNIdentity
	if !v.Current || v.Family != source.Family || v.Weight != source.Weight || v.Name != "EDGE" {
		t.Fatal("identity escaped source policy binding", v)
	}
	before := fetch.calls
	source.FieldMappings["country-code"] = []string{"physical_country"}
	source.PublicFields[3] = "physical_country"
	bad, err := e.Ingest(context.Background(), source, now, hash)
	if err != nil || bad.Snapshot != nil || fetch.calls != before {
		t.Fatal("identity country mapping bypassed IP field ownership", bad.Decision, err)
	}
}

func TestASNIdentityPartitionedIntakeExceedsOldWholeSourceLimit(t *testing.T) {
	var payload strings.Builder
	payload.WriteString("asn,handle,description,country-code\n")
	const rows = 125830
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&payload, "%d,NET,Example Network,US\n", 131072+i)
	}
	e, source, _, now, binding := prepared(t, []byte(payload.String()), "csv")
	source.MaxCompressedBytes = 64 << 20
	source.Category = "asn"
	source.Scope = "asn"
	source.Parser = Parser{"asn-identity-csv", "asn-handle-description-country-csv-v1", 1}
	source.Fixture.Parser = source.Parser.ID
	source.Fixture.Schema = source.Parser.Schema
	source.Fields = []string{"asn", "handle", "description", "country-code"}
	source.PublicFields = []string{"asn", "as_name", "organization", "asn_country"}
	source.FieldMappings = map[string][]string{"asn": {"asn"}, "handle": {"as_name"}, "description": {"organization"}, "country-code": {"asn_country"}}
	implementation, err := implementationHash(context.Background(), e.workspace)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ledger{1, []certification{{source.ID, source.Parser.ID, source.Parser.Schema, 1, source.Fixture.SHA256, source.Fixture.TestedAt, hashString(implementation)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(e.workspace, "fixtures/source-certification/adapter-certifications.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := e.IngestPartitioned(context.Background(), source, now, binding)
	if err != nil || result.Snapshot == nil {
		t.Fatalf("partitioned intake %v %v", result.Decision, err)
	}
	if len(result.Snapshot.Records) != 0 || len(result.Snapshot.RecordPartitions) != 2 || result.Snapshot.ASNIdentityStats.ReadRows != rows {
		t.Fatal("whole source buffered or truncated")
	}
	var count uint64
	for _, part := range result.Snapshot.RecordPartitions {
		if part.Records > 100000 || part.Bytes > 64<<20 {
			t.Fatal("partition bounds raised")
		}
		count += part.Records
	}
	if count != rows {
		t.Fatalf("accepted=%d", count)
	}
	plan, err := intelligence.ReconcilePartitioned(context.Background(), e.workspace, intelligence.BuildState{}, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	count = 0
	err = intelligence.WalkStoredSource(context.Background(), e.workspace, plan.State.Sources[0], func(record intelligence.NormalizedRecord) error {
		count++
		if !record.ASNIdentity.Current || record.ASNIdentity.Family != source.Family {
			t.Fatal("policy binding lost")
		}
		return nil
	})
	if err != nil || count != rows {
		t.Fatalf("walk=%d err=%v", count, err)
	}
}
