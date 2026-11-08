package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestGoldenFramesDecodeWithReference(t *testing.T) {
	data, err := os.ReadFile("../fixtures/zstd.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderMaxWindow(8<<20), zstd.WithDecoderMaxMemory(64<<20), zstd.WithDecoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	for _, test := range vectors {
		t.Run(test.Name, func(t *testing.T) {
			encoded, err := base64.StdEncoding.DecodeString(test.Encoded)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decoder.DecodeAll(encoded, nil)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(decoded)
			if len(decoded) != test.DecodedBytes || hex.EncodeToString(hash[:]) != test.DecodedHash {
				t.Fatal("golden decoded bytes/hash mismatch")
			}
		})
	}
}
