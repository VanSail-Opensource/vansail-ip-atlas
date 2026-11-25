package via3

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestBrowserReferenceDigestIsCanonicalAndReleaseBound(t *testing.T) {
	manifest, owner := strings.Repeat("a", 64), strings.Repeat("b", 64)
	inventory := map[string]ObjectInfo{}
	var targets []BuiltObject
	for i := 0; i < 8; i++ {
		target := ObjectInfo{Kind: 14, Bytes: 100 + i, Partition: "all", SHA256: fmt.Sprintf("%064x", i+1)}
		inventory[target.SHA256] = target
		targets = append(targets, BuiltObject{Info: target})
	}
	vector, _ := makeObjectDir(targets...)
	proof, err := browserReferenceDigest(manifest, owner, vector, inventory)
	if err != nil || proof.count != 8 || proof.hash != "06e2b292c41a6172991fc1eddcf8732cefd2de7cc3c418c02f111e90b37330b6" {
		t.Fatalf("independent tuple hash differs: %v %v", proof, err)
	}
	for _, roots := range [][2]string{{owner, manifest}, {manifest, manifest}} {
		other, err := browserReferenceDigest(roots[0], roots[1], vector, inventory)
		if err != nil || other.hash == proof.hash {
			t.Fatal("manifest or source identity was not bound")
		}
	}
	for _, op := range []string{"count", "truncated", "width", "padding", "order", "duplicate", "unknown", "self", "kind", "size", "substitution"} {
		t.Run(op, func(t *testing.T) {
			b := bytes.Clone(vector)
			src := owner
			catalog := inventory
			switch op {
			case "count":
				p32(b, 0, 9)
			case "truncated":
				b = b[:len(b)-40]
			case "width":
				p32(b, 4, 39)
			case "padding":
				b[10] = 1
			case "order":
				first := bytes.Clone(b[8:48])
				copy(b[8:48], b[48:88])
				copy(b[48:88], first)
			case "duplicate":
				copy(b[48:88], b[8:48])
			case "unknown":
				b[47] = 222
			case "self":
				src = targets[0].Info.SHA256
			case "kind":
				p16(b, 8, 8)
			case "size":
				p32(b, 12, uint32(targets[0].Info.Bytes+1))
			case "substitution":
				catalog = map[string]ObjectInfo{}
				for k, v := range inventory {
					catalog[k] = v
				}
				catalog[targets[0].Info.SHA256] = targets[1].Info
			}
			if _, err := browserReferenceDigest(manifest, src, b, catalog); err == nil {
				t.Fatal("invalid reference directory accepted")
			}
		})
	}
}

func TestBrowserLargeDirectoryFromManifestAndOldRoots(t *testing.T) {
	ctx := context.Background()
	r, err := Synthetic(ctx, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	shard := newShard(8)
	directory, _ := makeObjectDir(slices.Clone(r.Objects[:8])...)
	shard.set(7, directory)
	raw, err := Write(ctx, shard)
	if err != nil {
		t.Fatal(err)
	}
	owner := ObjectInfo{Bytes: len(raw), Kind: 8, Partition: "all", SHA256: Hash(raw)}
	r.Objects = append(r.Objects, BuiltObject{Info: owner, Bytes: raw, Shard: shard})
	objects := append(slices.Clone(r.Manifest.Objects), owner)
	sort.Slice(objects, func(i, j int) bool { return objects[i].SHA256 < objects[j].SHA256 })
	r.Descriptor.Objects = objects
	r.Manifest.Objects = objects
	r.Manifest.ReleaseID = Hash(canonical(r.Descriptor))
	r.Pointer.ReleaseID = r.Manifest.ReleaseID
	r.Pointer.ManifestPath = "/_atlas/releases/" + r.Manifest.ReleaseID + "/manifest.json"
	r.Pointer.ManifestSHA256 = Hash(canonical(r.Manifest))
	atlas := t.TempDir()
	if err = r.Write(atlas); err != nil {
		t.Fatal(err)
	}
	p, m, router, refs, err := browserInputs(ctx, atlas)
	if err != nil {
		t.Fatal(err)
	}
	old, oldHash, err := projectBrowserControls(ctx, p, m, router, refs, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	oldDir := t.TempDir()
	for hash, b := range old.pages {
		if err = os.WriteFile(filepath.Join(oldDir, hash+".json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	hash, err := GenerateBrowserIndex(ctx, atlas, dir)
	if err != nil || hash == oldHash {
		t.Fatal("no separate v2 root", err)
	}
	if err = VerifyBrowserIndex(ctx, atlas, dir, hash); err != nil {
		t.Fatal(err)
	}
	proofs, err := browserReferenceProofs(ctx, atlas, p.ManifestSHA256, m.Objects)
	if err != nil || proofs[owner.SHA256].count != 8 {
		t.Fatal("missing independently reconstructed proof", err)
	}
	found := false
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var leaf browserObjectLeaf
		if strictJSON(b, &leaf) != nil || leaf.Type != "objects" {
			continue
		}
		for _, item := range leaf.References {
			idx := int(item[0].(float64))
			if leaf.Objects[idx] == owner && item[2] == proofs[owner.SHA256].hash {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("proof does not identify its source in the authenticated metadata tree")
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(filepath.Join(atlas, "objects", owner.SHA256+".via3"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if VerifyBrowserIndex(ctx, atlas, dir, hash) == nil {
		t.Fatal("v2 reconstruction accepted altered source bytes")
	}
	if err = VerifyBrowserIndex(ctx, atlas, oldDir, oldHash); err != nil {
		t.Fatalf("v1 verification changed: %v", err)
	}
}
