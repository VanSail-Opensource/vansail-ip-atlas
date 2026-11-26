package intelligence

import (
	"bytes"
	"encoding/json"
	"errors"
)

// CanonicalRecordDecoder checks exact default RecordWriter encodings outside
// the normalized store. It does not authenticate a stream or approve source
// semantics. Decoded values own their bytes and the input can be reused after
// each call. Use a separate zero-value decoder per stream, not concurrently.
type CanonicalRecordDecoder struct {
	buffer  bytes.Buffer
	encoder *json.Encoder
}

func (d *CanonicalRecordDecoder) Decode(data []byte) (NormalizedRecord, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return NormalizedRecord{}, errors.New("canonical record frame exceeds limit")
	}
	record, err := decodeRecordFrame(data)
	if err != nil {
		return NormalizedRecord{}, err
	}
	if (record.Geo != nil && canonicalWriterGeo(data, record.Geo)) || canonicalWriterRouting(data, record) {
		return record, nil
	}
	if d.encoder == nil {
		d.encoder = json.NewEncoder(&d.buffer)
	}
	d.buffer.Reset()
	if err := d.encoder.Encode(record); err != nil {
		return NormalizedRecord{}, err
	}
	encoded := d.buffer.Bytes()[:d.buffer.Len()-1]
	if !bytes.Equal(data, encoded) {
		return NormalizedRecord{}, errors.New("canonical record frame differs from writer")
	}
	return record, nil
}
