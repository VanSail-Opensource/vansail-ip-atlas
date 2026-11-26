package intelligence

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestCanonicalRecordDecoderRetainsIndependentValues(t *testing.T) {
	var decoder CanonicalRecordDecoder
	rows := append(writerMRTRows(), NormalizedRecord{Version: 3, Kind: RecordNetworkName, NetworkName: &NetworkNameRecord{
		Prefix: netip.MustParsePrefix("2001:db8::/32"), Name: "Example", ModifiedAt: time.Unix(1795488300, 0).UTC(),
	}})
	var retained []NormalizedRecord
	for _, row := range rows {
		data, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		if actual, err := decoder.Decode(data); err != nil {
			t.Fatalf("did not recognize default writer row: %v", err)
		} else {
			retained = append(retained, actual)
		}
		for _, noncanonical := range [][]byte{
			append(bytes.Clone(data), '\n'),
			append(bytes.Clone(data), '{', '}'),
			bytes.Replace(data, []byte(`{"Version":3,`), []byte(`{"Version":3,"Version":3,`), 1),
			bytes.Replace(data, []byte(`{"Version":3,`), []byte(`{"Version":3, `), 1),
		} {
			if _, err := decoder.Decode(noncanonical); err == nil {
				t.Fatal("decoder accepted noncanonical or trailing data")
			}
		}
		clear(data)
	}
	if !reflect.DeepEqual(retained, rows) {
		t.Fatal("a later decode or input reuse modified an owned record")
	}
}
