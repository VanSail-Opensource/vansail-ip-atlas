package querycontract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"unicode/utf8"
)

type corpus struct {
	Revision  int  `json:"contract_revision"`
	Synthetic bool `json:"synthetic"`
	Inputs    []struct {
		Input    string `json:"input"`
		Expected Input  `json:"expected"`
		Error    string `json:"error"`
	} `json:"inputs"`
	URLs []struct {
		Route    string `json:"route"`
		Raw      string `json:"raw"`
		Expected Result `json:"expected"`
	} `json:"urls"`
	Origins []struct {
		Requested uint32   `json:"requested"`
		Origins   []uint32 `json:"origins"`
		Valid     bool     `json:"valid"`
	} `json:"origin_membership"`
}

func readFixture(t *testing.T, name string, target any) {
	t.Helper()
	data, err := os.ReadFile("../../fixtures/contracts/" + name)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
}

func TestSharedQueryContract(t *testing.T) {
	var data corpus
	readFixture(t, "queries.json", &data)
	if data.Revision != 1 || !data.Synthetic || len(data.Inputs) < 70 || len(data.URLs) < 40 {
		t.Fatal("incomplete shared corpus")
	}
	for index, test := range data.Inputs {
		t.Run(fmt.Sprintf("input_%d", index), func(t *testing.T) {
			got, err := ParseInput(test.Input)
			if test.Error != "" {
				if err == nil || err.Error() != test.Error {
					t.Fatalf("expected %s, got %+v, %v", test.Error, got, err)
				}
				return
			}
			if err != nil || got != test.Expected {
				t.Fatalf("got %+v, %v; want %+v", got, err, test.Expected)
			}
			again, err := ParseInput(got.Canonical)
			if err != nil || again != got {
				t.Fatal("canonical form is not idempotent")
			}
		})
	}
	for index, test := range data.URLs {
		t.Run(fmt.Sprintf("url_%d", index), func(t *testing.T) {
			if got := Resolve(test.Route, test.Raw); got != test.Expected {
				t.Fatalf("got %+v; want %+v", got, test.Expected)
			}
		})
	}
	for _, test := range data.Origins {
		err := ValidateOrigin(test.Requested, test.Origins)
		if (err == nil) != test.Valid {
			t.Fatalf("origin membership mismatch: %+v", test)
		}
	}
}

func TestInvalidUTF8IsNeverNormalized(t *testing.T) {
	if _, err := ParseInput(string([]byte{0xff})); err == nil {
		t.Fatal("invalid UTF-8 input accepted")
	}
	if got := Resolve("/ip/bgp", "q=1.1.1.1&origin="+string([]byte{0xff})); got.Error != "invalid_query" {
		t.Fatalf("invalid UTF-8 query accepted: %+v", got)
	}
}

type layoutCorpus struct {
	Format       int            `json:"format_version"`
	Schema       int            `json:"schema_version"`
	Revision     int            `json:"contract_revision"`
	Synthetic    bool           `json:"synthetic"`
	FileLimit    int            `json:"max_file_exclusive"`
	SectionLimit int            `json:"max_decoded_section"`
	TotalLimit   int            `json:"max_decoded_total"`
	WindowLimit  int            `json:"max_window"`
	Presence     map[string]int `json:"presence_bits"`
	Reasons      map[string]int `json:"reason_bits"`
	Shards       []struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		Sections []int  `json:"sections"`
		Width    int    `json:"record_bytes"`
		Fields   []struct {
			Name   string `json:"name"`
			Offset int    `json:"offset"`
			Bytes  int    `json:"bytes"`
		} `json:"fields"`
		Record   string `json:"record_hex"`
		Section3 string `json:"section3_hex"`
	} `json:"shards"`
	Keys []struct {
		Address string `json:"address"`
		Bits    int    `json:"bits"`
		Flags   int    `json:"flags"`
		Hex     string `json:"hex"`
	} `json:"prefix_keys"`
	Cell       string `json:"cell_hex"`
	Dictionary struct {
		Strings []string `json:"strings"`
		Offsets []int    `json:"offsets"`
		Hex     string   `json:"utf8_hex"`
	} `json:"dictionary"`
	Corruption []string `json:"required_corruption_vectors"`
}

// This validates the initial record-layout contract, not the P1 container reader.
func TestFrozenBinaryLayoutCorpus(t *testing.T) {
	var data layoutCorpus
	readFixture(t, "via3-layouts.json", &data)
	if data.Format != 3 || data.Schema != 3 || data.Revision != 1 || !data.Synthetic || len(data.Shards) != 14 {
		t.Fatal("wrong contract version or missing shard layout")
	}
	if data.FileLimit != 24<<20 || data.SectionLimit != 64<<20 || data.TotalLimit != 256<<20 || data.WindowLimit != 8<<20 {
		t.Fatal("changed bounds require reviewed amendment")
	}
	seen := uint32(0)
	for _, bit := range data.Presence {
		if bit < 0 || bit > 31 || seen&(1<<bit) != 0 {
			t.Fatal("duplicate/invalid presence bit")
		}
		seen |= 1 << bit
	}
	if seen != ^uint32(0) {
		t.Fatal("presence contract must define all 32 positions")
	}
	expectedReasons := []string{"malware", "botnet", "command_control", "abuse", "fraud", "scanning", "spam", "tor", "vpn", "proxy", "datacenter", "hosting", "asn_context", "subnet_context"}
	if len(data.Reasons) != len(expectedReasons) {
		t.Fatal("changed reason enum")
	}
	for bit, name := range expectedReasons {
		if got, ok := data.Reasons[name]; !ok || got != bit {
			t.Fatalf("reason bit %s changed", name)
		}
	}
	for i, shard := range data.Shards {
		if shard.ID != i+1 {
			t.Fatal("noncanonical shard IDs")
		}
		previous := 0
		for _, section := range shard.Sections {
			if section <= previous || section > 12 {
				t.Fatal("noncanonical section IDs")
			}
			previous = section
		}
		offset := 0
		record, err := hex.DecodeString(shard.Record)
		if err != nil || len(record) != shard.Width {
			t.Fatalf("%s record width mismatch", shard.Name)
		}
		for _, field := range shard.Fields {
			if field.Offset != offset || field.Bytes <= 0 {
				t.Fatalf("%s field offset mismatch", shard.Name)
			}
			if field.Name == "reserved" && !bytes.Equal(record[offset:offset+field.Bytes], make([]byte, field.Bytes)) {
				t.Fatalf("%s nonzero reserved bytes", shard.Name)
			}
			offset += field.Bytes
		}
		if offset != shard.Width {
			t.Fatalf("%s incomplete field table", shard.Name)
		}
		if shard.Width == 0 {
			continue
		}
		section, err := hex.DecodeString(shard.Section3)
		if err != nil || len(section) != 8+shard.Width || binary.LittleEndian.Uint32(section[:4]) != 1 || int(binary.LittleEndian.Uint32(section[4:8])) != shard.Width || !bytes.Equal(section[8:], record) {
			t.Fatalf("%s record vector mismatch", shard.Name)
		}
	}
	for _, key := range data.Keys {
		data, err := hex.DecodeString(key.Hex)
		if err != nil || len(data) != 32 {
			t.Fatal("bad key bytes")
		}
		addr := netip.MustParseAddr(key.Address)
		var expected [16]byte
		if addr.Is4() {
			octets := addr.As4()
			copy(expected[12:], octets[:])
		} else {
			expected = addr.As16()
		}
		family := byte(6)
		if addr.Is4() {
			family = 4
		}
		if data[0] != family || int(data[1]) != key.Bits || int(binary.LittleEndian.Uint16(data[2:4])) != key.Flags || !bytes.Equal(data[4:20], expected[:]) {
			t.Fatalf("wrong address encoding: %s", key.Address)
		}
	}
	stringsData, err := hex.DecodeString(data.Dictionary.Hex)
	if err != nil || !utf8.Valid(stringsData) || len(data.Dictionary.Offsets) != len(data.Dictionary.Strings)+1 {
		t.Fatal("invalid dictionary fixture")
	}
	for i, text := range data.Dictionary.Strings {
		if got := string(stringsData[data.Dictionary.Offsets[i]:data.Dictionary.Offsets[i+1]]); got != text {
			t.Fatal("dictionary offsets changed")
		}
	}
	cell, err := hex.DecodeString(data.Cell)
	if err != nil || len(cell) != 32 || cell[1] != 0xff || cell[8] != 0 {
		t.Fatal("explicit-zero cell fixture lost presence")
	}
	if !reflect.DeepEqual(data.Shards[5].Sections, []int{1, 3, 8}) {
		t.Fatal("quality section contract changed")
	}
	if len(data.Corruption) < 20 {
		t.Fatal("missing planned corruption cases")
	}
}
