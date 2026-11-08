// Command golden regenerates the build-private native-codec acceptance corpus.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/klauspost/compress/zstd"
)

type vector struct {
	Name         string `json:"name"`
	Encoded      string `json:"encoded_base64"`
	DecodedBytes int    `json:"decoded_bytes"`
	DecodedHash  string `json:"decoded_sha256"`
}

func main() {
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(3)),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(8<<20),
		zstd.WithEncoderCRC(true),
		zstd.WithSingleSegment(true),
		zstd.WithZeroFrames(true))
	if err != nil {
		panic(err)
	}
	defer encoder.Close()
	inputs := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"utf8", []byte("VIA3 synthetic codec corpus 香港\n")},
		{"bounded", bytes.Repeat([]byte("VIA3"), 256*1024)},
	}
	vectors := make([]vector, 0, len(inputs))
	for _, input := range inputs {
		encoded := encoder.EncodeAll(input.data, nil)
		if len(input.data) == 0 {
			// The compressor's empty-frame special case omits its checksum. VIA3
			// requires it, so use the standard empty raw block + XXH64(empty).
			encoded = []byte{0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x01, 0x00, 0x00, 0x99, 0xe9, 0xd8, 0x51}
		}
		hash := sha256.Sum256(input.data)
		vectors = append(vectors, vector{input.name, base64.StdEncoding.EncodeToString(encoded), len(input.data), hex.EncodeToString(hash[:])})
	}
	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll("tools/hosted/fixtures", 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile("tools/hosted/fixtures/zstd.json", append(data, '\n'), 0o644); err != nil {
		panic(err)
	}
}
