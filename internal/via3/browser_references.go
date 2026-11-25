package via3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"slices"
)

const browserProofMinimum = 8
const browserReferenceDomain = "VIA3-REFERENCES-1\x00"

type browserReferenceProof struct {
	count int
	hash  string
}

// Reconstruct each ordinal independently from the canonical release inventory.
// The digest binds that ordering, its vector header, the source and the release.
// Publishers cannot attest an unrecognized, duplicated, or differently typed
// target by copying the digest already present in the source container.
func browserReferenceDigest(manifest, owner string, section []byte, inventory map[string]ObjectInfo) (browserReferenceProof, error) {
	var proof browserReferenceProof
	if !validHash(manifest) || !validHash(owner) || len(section) < 8 || u32(section, 4) != 40 || (len(section)-8)%40 != 0 {
		return proof, fail("record")
	}
	count := (len(section) - 8) / 40
	if count < browserProofMinimum || count >= 18500 || int(u32(section, 0)) != count {
		return proof, fail("record")
	}
	sum := sha256.New()
	sum.Write([]byte(browserReferenceDomain))
	for _, id := range []string{manifest, owner} {
		digest, _ := hex.DecodeString(id)
		sum.Write(digest)
	}
	var header [8]byte
	p32(header[:], 0, uint32(count))
	p32(header[:], 4, 40)
	sum.Write(header[:])
	previousKind := uint16(0)
	previousHash := ""
	for p := 8; p < len(section); p += 40 {
		row := section[p : p+40]
		hash := hex.EncodeToString(row[8:40])
		target, ok := inventory[hash]
		if !ok || target.SHA256 != hash || hash == owner || target.Kind < 1 || target.Kind > 14 || target.Bytes < 64 || target.Bytes >= MaxFile || target.Kind < previousKind || target.Kind == previousKind && hash <= previousHash {
			return proof, fail("record")
		}
		var expected [40]byte
		p16(expected[:], 0, target.Kind)
		p32(expected[:], 4, uint32(target.Bytes))
		if _, err := hex.Decode(expected[8:], []byte(target.SHA256)); err != nil || !bytes.Equal(row, expected[:]) {
			return proof, fail("record")
		}
		sum.Write(expected[:])
		previousKind, previousHash = target.Kind, hash
	}
	return browserReferenceProof{count, hex.EncodeToString(sum.Sum(nil))}, nil
}

// Small directories retain the existing per-target browser check. Inspect the
// authenticated frame directory first so a release does not need every small
// fact shard decompressed just to qualify the large fan-outs.
func browserReferenceProofs(ctx context.Context, dir, manifest string, objects []ObjectInfo) (map[string]browserReferenceProof, error) {
	inventory := make(map[string]ObjectInfo, len(objects))
	for _, o := range objects {
		inventory[o.SHA256] = o
	}
	proofs := make(map[string]browserReferenceProof)
	for _, owner := range objects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// The original authenticated router supplies projected routes.
		if owner.Kind == 1 {
			continue
		}
		_, ids := schema(owner.Kind)
		ordinal := slices.Index(ids, uint16(7))
		if ordinal < 0 {
			continue
		}
		raw, err := browserReadFile(filepath.Join(dir, "objects", owner.SHA256+".via3"), owner.Bytes)
		if err != nil {
			return nil, err
		}
		at := 64 + 64*ordinal
		if len(raw) != owner.Bytes || Hash(raw) != owner.SHA256 {
			return nil, fail("hash")
		}
		if len(raw) < at+64 || u16(raw, 10) != owner.Kind || u16(raw, at) != 7 || u64(raw, 36) > PublicObjectDecoded {
			return nil, fail("schema")
		}
		decoded := u64(raw, at+24)
		if decoded < 8 || (decoded-8)%40 != 0 || (decoded-8)/40 >= 18500 {
			return nil, fail("record")
		}
		if decoded < 8+40*browserProofMinimum {
			continue
		}
		shard, err := Read(ctx, raw)
		if err != nil {
			return nil, err
		}
		if err = ValidatePublicProfile(shard); err != nil {
			return nil, err
		}
		proof, err := browserReferenceDigest(manifest, owner.SHA256, shard.Section(7), inventory)
		if err != nil {
			return nil, err
		}
		proofs[owner.SHA256] = proof
	}
	return proofs, nil
}
