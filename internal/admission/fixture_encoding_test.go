package admission

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestObservedFixtureCompressionPreservesPayloadAndCurrentAdapterChecks(t *testing.T) {
	payload := []byte("asn,prefix,maxLength\n13335,8.8.8.0/24,24\n")
	e, s, _, now, binding := prepared(t, payload, "csv")
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	s.Fixture.ContentEncoding = "gzip"
	s.Fixture.SHA256 = hashString(sha256.Sum256(encoded.Bytes()))
	if err := os.WriteFile(filepath.Join(e.workspace, filepath.FromSlash(s.Fixture.Path)), encoded.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	implementation, err := implementationHash(context.Background(), e.workspace)
	if err != nil {
		t.Fatal(err)
	}
	ledgerBytes, _ := json.Marshal(ledger{1, []certification{{s.ID, s.Parser.ID, s.Parser.Schema, 1, s.Fixture.SHA256, s.Fixture.TestedAt, hashString(implementation)}}})
	if err = os.WriteFile(filepath.Join(e.workspace, "fixtures/source-certification/adapter-certifications.json"), ledgerBytes, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := e.Ingest(context.Background(), s, now, binding)
	if err != nil || result.Snapshot == nil || len(result.Snapshot.Records) != 1 {
		t.Fatal("exact decoded observed fixture did not parse", result, err)
	}
	s.Fixture.ContentEncoding = "identity"
	result, err = e.Ingest(context.Background(), s, now, binding)
	if err != nil || result.Snapshot != nil {
		t.Fatal("wrong fixture envelope was certified", result, err)
	}
}

func TestDecodedCSVFixtureIsBoundToReviewedGeoAdapter(t *testing.T) {
	payload := []byte(ipapiHeader + "\n" + ipapiTestRow("1") + "\n")
	e, base, _, now, _ := prepared(t, payload, "csv")
	source := ipapiTestSource(false)
	source.Fixture = base.Fixture
	source.Fixture.Parser, source.Fixture.Schema = source.Parser.ID, source.Parser.Schema
	source.Fixture.PayloadFormat = "decoded-csv"
	code, err := implementationHash(context.Background(), e.workspace)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ledger{1, []certification{{source.ID, source.Parser.ID, source.Parser.Schema, 1, source.Fixture.SHA256, source.Fixture.TestedAt, hashString(code)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(e.workspace, "fixtures/source-certification/adapter-certifications.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = e.certify(context.Background(), source, ipapiCityZIP, now); err != nil {
		t.Fatal("reviewed decoded CSV syntax did not certify", err)
	}
	if err = e.certify(context.Background(), source, vrpCSV, now); err == nil {
		t.Fatal("decoded CSV fixture bypassed the selected adapter")
	}
	source.Fixture.ContentEncoding = "gzip"
	if err = e.certify(context.Background(), source, ipapiCityZIP, now); err == nil {
		t.Fatal("decoded CSV accepted a second unreviewed envelope")
	}

	// An ordinary VRP fixture cannot opt into provider-specific decoded mode.
	e2, ordinary, _, now2, _ := prepared(t, []byte("asn,prefix,maxLength\n13335,8.8.8.0/24,24\n"), "csv")
	ordinary.Fixture.PayloadFormat = "decoded-csv"
	if err = e2.certify(context.Background(), ordinary, vrpCSV, now2); err == nil {
		t.Fatal("arbitrary source opted into Geo decoded fixture mode")
	}
}
