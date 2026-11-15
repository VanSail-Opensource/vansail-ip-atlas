package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestSparseRunCodecRetainsDenseLengthAndValues(t *testing.T) {
	kinds := map[uint16]bool{}
	for _, input := range sparseRunParityRows() {
		record, err := normalize(input)
		if err != nil {
			t.Fatal(err)
		}
		dense, err := encodeRunRecord(record, false)
		if err != nil {
			t.Fatal(err)
		}
		sparse, err := encodeRunRecord(record, true)
		if err != nil {
			t.Fatal(err)
		}
		if sparse.logicalBytes != int64(len(dense.data)) || sparse.logicalBytes != dense.logicalBytes || sparse.frameBytes() >= dense.frameBytes() {
			t.Fatal("sparse encoding changed original logical bytes or did not omit nil unions", record.Kind)
		}
		for _, row := range []encoded{dense, sparse} {
			var frame bytes.Buffer
			if err = writeRunFrame(&frame, row); err != nil {
				t.Fatal(err)
			}
			if int64(frame.Len()) != row.frameBytes() || int(binary.LittleEndian.Uint32(frame.Bytes()[:4])) != frame.Len()-4 {
				t.Fatal("physical frame count changed")
			}
			gotRow, got, err := decodeRunPayload(frame.Bytes()[4:], row.logicalBytes)
			if err != nil || !reflect.DeepEqual(got, record) || !equalEncoded(gotRow, row) || gotRow.logicalBytes != row.logicalBytes {
				t.Fatal("nil, empty or zero-valued payload changed", record.Kind, err)
			}
			if _, _, err = decodeRunPayload(frame.Bytes()[4:], row.logicalBytes-1); err == nil {
				t.Fatal("reader accepted a row above its original dense limit")
			}
		}
		kinds[record.Kind] = true
	}
	if len(kinds) != 12 {
		t.Fatal("fixture does not cover every public union kind")
	}
}

func TestSparseRunCodecRejectsUnknownOrTruncatedFrames(t *testing.T) {
	valid, err := encodeRunRecord(sparseRunParityRows()[0], true)
	if err != nil {
		t.Fatal(err)
	}
	unknown := []byte(sparseRunMarker)
	unknown[4]++
	reserved := []byte(sparseRunMarker)
	reserved[7] = 1
	for _, payload := range [][]byte{
		[]byte("ATSP"), []byte(sparseRunMarker[:7]), []byte(sparseRunMarker),
		append(unknown, valid.data...), append(reserved, valid.data...),
		append([]byte(sparseRunMarker), []byte(`{"Version":3,"Kind":2,"Unexpected":true}`)...),
		append([]byte(sparseRunMarker), []byte(`{"Version":3,"Geo":{"Unexpected":true}}`)...),
		append([]byte(sparseRunMarker), append(append([]byte(nil), valid.data...), []byte(" {}")...)...),
		append([]byte(sparseRunMarker), valid.data[:len(valid.data)-1]...),
	} {
		if _, _, err := decodeRunPayload(payload, DefaultLimits().RecordBytes); err == nil {
			t.Fatal("invalid private sparse frame accepted")
		}
	}
}

func TestSparseRunCodecPreservesByteConflicts(t *testing.T) {
	record := sparseRunParityRows()[0]
	canonical, err := encodeRunRecord(record, true)
	if err != nil {
		t.Fatal(err)
	}
	dense, err := encodeRunRecord(record, false)
	if err != nil {
		t.Fatal(err)
	}
	variants := map[string]encoded{
		"legacy-dense":     dense,
		"legacy-same-json": {data: canonical.data, logicalBytes: int64(len(canonical.data))},
		"whitespace":       {data: append([]byte(" \n"), canonical.data...), sparse: true},
		"case":             {data: bytes.Replace(canonical.data, []byte(`"Version"`), []byte(`"version"`), 1), sparse: true},
		"explicit-null":    {data: append(append([]byte(nil), canonical.data[:len(canonical.data)-1]...), []byte(`,"Coordinates":null}`)...), sparse: true},
		"duplicate":        {data: bytes.Replace(canonical.data, []byte(`"Version":3`), []byte(`"Version":2,"Version":3`), 1), sparse: true},
		"merged-object":    {data: append(append([]byte(nil), canonical.data[:len(canonical.data)-1]...), []byte(`,"Geo":{"Country":"US"}}`)...), sparse: true},
	}
	for name, variant := range variants {
		t.Run(name, func(t *testing.T) {
			var frame bytes.Buffer
			if err := writeRunFrame(&frame, variant); err != nil {
				t.Fatal(err)
			}
			parsed, got, err := decodeRunPayload(frame.Bytes()[4:], DefaultLimits().RecordBytes)
			if err != nil || !reflect.DeepEqual(got, record) || equalEncoded(parsed, canonical) {
				t.Fatal("private frame was canonicalized or a distinct byte conflict vanished", err)
			}
			if variant.sparse && parsed.logicalBytes < canonical.logicalBytes {
				t.Fatal("noncanonical spelling reduced the logical byte charge")
			}
			c := &compiler{ctx: context.Background(), options: Options{Limits: DefaultLimits()}, scratch: t.TempDir()}
			var paths []string
			for _, row := range []encoded{canonical, variant} {
				path := c.next()
				file, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				err = c.writeRow(file, row)
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
				paths = append(paths, path)
			}
			if _, err = c.mergeGroup(paths); err == nil {
				t.Fatal("same-identity private bytes or codec changes did not fail merge")
			}
		})
	}
}

func TestSparseRunCodecChargesPhysicalBytesAndHashesMarker(t *testing.T) {
	row, err := encodeRunRecord(sparseRunParityRows()[0], true)
	if err != nil {
		t.Fatal(err)
	}
	c := &compiler{ctx: context.Background(), options: Options{Limits: DefaultLimits()}, scratch: t.TempDir()}
	path := c.next()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.writeRow(file, row); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != row.frameBytes() || c.used != uint64(info.Size()) {
		t.Fatal("scratch charge differs from actual sparse frame bytes", err)
	}
	reader, err := openRun(path, row.logicalBytes-1)
	if err != nil {
		t.Fatal(err)
	}
	err = reader.next()
	reader.file.Close()
	if err == nil || err == io.EOF {
		t.Fatal("framed reader admitted a row above the original byte limit")
	}
	if err = c.remove(path); err != nil || c.used != 0 {
		t.Fatal("removal did not release the exact physical charge", err)
	}
	dense := row
	dense.sparse = false
	h1, h2 := sha256.New(), sha256.New()
	hashRunFrame(h1, row)
	hashRunFrame(h2, dense)
	if bytes.Equal(h1.Sum(nil), h2.Sum(nil)) {
		t.Fatal("scatter identity omitted the private codec marker")
	}
}

func TestSparseRunCodecPreservesCanonicalByteOrdering(t *testing.T) {
	var variants [][2]via3.PublicRecord
	for _, record := range sparseRunParityRows()[:12] {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		var changed via3.PublicRecord
		if err = json.Unmarshal(data, &changed); err != nil {
			t.Fatal(err)
		}
		// Keep the same identity and union presence; payload values and nested
		// nil/empty arrays may differ without changing the omitted field mask.
		value := reflect.ValueOf(&changed).Elem().Field(int(record.Kind) + 5)
		value.Set(reflect.New(value.Type().Elem()))
		variants = append(variants, [2]via3.PublicRecord{record, changed})
	}
	for _, pair := range variants {
		a, err := encodeRunRecord(pair[0], false)
		if err != nil {
			t.Fatal(err)
		}
		b, err := encodeRunRecord(pair[1], false)
		if err != nil {
			t.Fatal(err)
		}
		x, err := encodeRunRecord(pair[0], true)
		if err != nil {
			t.Fatal(err)
		}
		y, err := encodeRunRecord(pair[1], true)
		if err != nil {
			t.Fatal(err)
		}
		if lessEncoded(a, b) != lessEncoded(x, y) || lessEncoded(b, a) != lessEncoded(y, x) || equalEncoded(a, b) != equalEncoded(x, y) {
			t.Fatal("omitted nil fields changed canonical same-identity ordering", pair[0].Kind)
		}
	}
}
