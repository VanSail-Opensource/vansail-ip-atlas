package pipeline

import (
	"bytes"
	"context"
	"math"
	"net/netip"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestOwnedRunFrameConstructionAndMetadataParity(t *testing.T) {
	c := &compiler{}
	kinds := map[uint16]bool{}
	rows := sparseRunParityRows()
	for _, prefix := range []string{"0.0.0.0/0", "::/0", "8.8.8.8/32", "2001:4860::1/128", "::ffff:8.8.8.0/120"} {
		r := rows[0]
		r.Prefix = netip.MustParsePrefix(prefix)
		rows = append(rows, r)
	}
	for _, r := range sparseRunParityRows() {
		switch r.Kind {
		case 12:
			relationship := *r.Relationship
			relationship.To = 1299
			r.Relationship = &relationship
			rows = append(rows, r)
		case 11:
			r.Rank = 11
			rows = append(rows, r)
		}
	}
	for _, input := range rows {
		frame, err := c.newCanonicalRunFrame(input)
		if err != nil || !frame.ownedBy(c) || frame.ownedBy(&compiler{}) {
			t.Fatalf("canonical frame ownership differs: %v", err)
		}
		normalized, err := normalize(input)
		if err != nil {
			t.Fatal(err)
		}
		strict, decoded, err := decodeCompactRunPayload(frame.row.data, frame.row.logicalBytes)
		if err != nil || !equalEncoded(strict, frame.row) || !reflect.DeepEqual(decoded, normalized) {
			t.Fatalf("canonical constructor does not imply the existing strict transport invariant, kind%d: %v", input.Kind, err)
		}
		var wire bytes.Buffer
		if err := writeRunFrame(&wire, frame.row); err != nil {
			t.Fatal(err)
		}
		metadata, common, err := decodeOwnedRunPayload(wire.Bytes()[4:], frame.row.logicalBytes)
		if err != nil || !equalEncoded(metadata, strict) || metadata.key != strict.key || frame.row.key != strict.key || metadata.logicalBytes != strict.logicalBytes ||
			common.Version != decoded.Version || common.Kind != decoded.Kind || common.Prefix != decoded.Prefix ||
			common.ASN != decoded.ASN || common.Rank != decoded.Rank || common.Exact != decoded.Exact || common.Inherited != decoded.Inherited {
			t.Fatalf("authenticated metadata changed a key or original logical bytes: %v", err)
		}
		if input.Kind == 12 && (common.Relationship == nil || common.Relationship.To != decoded.Relationship.To) {
			t.Fatal("relationship target was lost from the sort identity")
		}
		if _, _, err := decodeOwnedRunPayload(wire.Bytes()[4:], frame.row.logicalBytes-1); err == nil {
			t.Fatal("owned metadata bypassed original dense record limit")
		}
		kinds[input.Kind] = true
	}
	if len(kinds) != 12 || (ownedRunFrame{}).ownedBy(c) {
		t.Fatal("missing union coverage or zero frame accepted")
	}
}

func TestOwnedRunFrameCallerOwnership(t *testing.T) {
	c := &compiler{}
	for _, input := range sparseRunParityRows() {
		frame, err := c.newCanonicalRunFrame(input)
		if err != nil {
			t.Fatal(err)
		}
		before := bytes.Clone(frame.row.data)
		borrowed := frame.cloneEncoded()
		for i := range borrowed.data {
			borrowed.data[i] ^= 255
		}
		if !bytes.Equal(frame.row.data, before) {
			t.Fatal("cache callback could mutate canonical frame bytes")
		}

	}
	geo := &via3.GeoData{Country: "US", City: "Original"}
	frame, err := c.newCanonicalRunFrame(via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("8.8.8.0/24"), Geo: geo})
	if err != nil {
		t.Fatal(err)
	}
	geo.City = "Caller changed"
	_, decoded, err := decodeCompactRunPayload(frame.row.data, frame.row.logicalBytes)
	if err != nil || decoded.Geo.City != "Original" {
		t.Fatal("caller payload still aliases canonical transport")
	}
}

func TestOwnedRunFrameIsNotFinalSemanticApproval(t *testing.T) {
	c := &compiler{}
	prefix := netip.MustParsePrefix("8.8.8.0/24")
	for _, input := range []via3.PublicRecord{
		{Version: 3, Kind: 2, Prefix: prefix, Geo: &via3.GeoData{Country: "1?"}},
		{Version: 3, Kind: 9, Prefix: prefix, ASN: 13335, RPKI: &via3.RPKIData{Status: 255}},
		{Version: 3, Kind: 3, Prefix: prefix, Coordinates: &via3.CoordinateData{Latitude: 1000}},
	} {
		frame, err := c.newCanonicalRunFrame(input)
		if err != nil {
			t.Fatalf("fixture should reach the unchanged final semantic boundary: %v", err)
		}
		_, decoded, err := decodeCompactRunPayload(frame.row.data, frame.row.logicalBytes)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := via3.CompilePartition(context.Background(), via3.PartitionInput{Partition: "all", Records: []via3.PublicRecord{decoded}}); err == nil {
			t.Fatal("canonical transport was mistaken for final public semantic approval")
		}
	}
	if _, err := c.newCanonicalRunFrame(via3.PublicRecord{Version: 3, Kind: 3, Prefix: prefix, Coordinates: &via3.CoordinateData{Latitude: math.NaN()}}); err == nil {
		t.Fatal("non-JSON numeric value minted a canonical frame")
	}
}
