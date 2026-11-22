package via3

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const (
	browserRootLimit   = 1024
	browserBranchLimit = 1280
	browserRouteLimit  = 4096
	browserObjectLimit = 2048
	browserPageLimit   = 18500
	browserTotalLimit  = 64 << 20
)

type browserPointer struct {
	BrowserSHA256  string `json:"browser_sha256,omitempty"`
	FormatVersion  int    `json:"format_version"`
	ManifestPath   string `json:"manifest_path"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ReleaseID      string `json:"release_id"`
}

type browserRoots struct {
	ASN     string `json:"asn"`
	IPv4    string `json:"ipv4"`
	IPv6    string `json:"ipv6"`
	Objects string `json:"objects"`
}

type browserRoot struct {
	FormatVersion  int          `json:"format_version"`
	ManifestSHA256 string       `json:"manifest_sha256"`
	Mode           string       `json:"mode"`
	ReleaseID      string       `json:"release_id"`
	Roots          browserRoots `json:"roots"`
	ValidFrom      int64        `json:"valid_from"`
	ValidUntil     int64        `json:"valid_until"`
}

type browserBranch struct {
	Children [][2]any `json:"children"`
	Type     string   `json:"type"`
}

type browserObjectLeaf struct {
	Objects    []ObjectInfo `json:"objects"`
	References [][3]any     `json:"references,omitempty"`
	Type       string       `json:"type"`
}

type browserRouteLeaf struct {
	Objects []ObjectInfo `json:"objects"`
	Routes  [][3]any     `json:"routes"`
	Sets    [][]int      `json:"sets"`
	Type    string       `json:"type"`
}

type browserControlTree struct {
	proofs map[string]browserReferenceProof
	ctx    context.Context
	pages  map[string][]byte
	size   int
}

func (tree *browserControlTree) add(body []byte, limit int) (string, error) {
	if err := tree.ctx.Err(); err != nil {
		return "", err
	}
	if len(body) > limit {
		return "", errors.New("browser route control exceeds its size limit")
	}
	sum := Hash(body)
	if _, exists := tree.pages[sum]; !exists {
		if len(tree.pages) >= browserPageLimit || tree.size+len(body) > browserTotalLimit {
			return "", errors.New("browser control inventory exceeds its size limit")
		}
		tree.pages[sum] = body
		tree.size += len(body)
	}
	return sum, nil
}

func browserReadFile(path string, limit int) ([]byte, error) {
	stat, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > int64(limit) {
		return nil, errors.New("invalid browser control input file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit || int64(len(b)) != stat.Size() {
		return nil, errors.New("browser control input changed")
	}
	return b, nil
}

// Route selection and target identities come from the original router and manifest. Private diagnostic releases keep their
// original engineering mode and identity in their private browser controls.
func browserInputs(ctx context.Context, dir string) (browserPointer, Manifest, *Shard, []ObjectInfo, error) {
	var p browserPointer
	var m Manifest
	input, err := browserReadFile(filepath.Join(dir, "current.json"), 4096)
	if err != nil {
		return p, m, nil, nil, err
	}
	if strictJSON(input, &p) != nil || p.FormatVersion != 3 || !validHash(p.ReleaseID) || !validHash(p.ManifestSHA256) ||
		p.BrowserSHA256 != "" && !validHash(p.BrowserSHA256) || p.ManifestPath != "/_atlas/releases/"+p.ReleaseID+"/manifest.json" {
		return p, m, nil, nil, fail("manifest")
	}
	input, err = browserReadFile(filepath.Join(dir, "releases", p.ReleaseID, "manifest.json"), 4<<20)
	if err != nil {
		return p, m, nil, nil, err
	}
	if Hash(input) != p.ManifestSHA256 || strictJSON(input, &m) != nil || m.ReleaseID != p.ReleaseID || m.FormatVersion != 3 || m.SchemaVersion != 5 ||
		m.Codec != "zstd-1" || m.Mode != "production" && m.Mode != "synthetic" && m.Mode != "engineering" ||
		m.ValidFrom < 0 || m.ValidUntil <= m.ValidFrom || m.ValidUntil-m.ValidFrom > 720*3600 || m.ValidUntil > 9007199254740991 ||
		len(m.Objects) == 0 || len(m.Objects) >= 18500 {
		return p, m, nil, nil, fail("manifest")
	}
	descriptor := Descriptor{Codec: m.Codec, FormatVersion: m.FormatVersion, Mode: m.Mode, Objects: m.Objects, SchemaVersion: m.SchemaVersion, ValidFrom: m.ValidFrom, ValidUntil: m.ValidUntil}
	if Hash(canonical(descriptor)) != m.ReleaseID {
		return p, m, nil, nil, fail("manifest")
	}
	var router ObjectInfo
	byHash := make(map[string]ObjectInfo, len(m.Objects))
	previous := ""
	for _, o := range m.Objects {
		if !validHash(o.SHA256) || o.SHA256 <= previous || !validPartition(o.Partition) || o.Kind < 1 || o.Kind > 14 || o.Bytes < 64 || o.Bytes >= MaxFile {
			return p, m, nil, nil, fail("manifest")
		}
		if o.Kind == 1 {
			if router.Kind != 0 || o.Partition != "all" {
				return p, m, nil, nil, fail("manifest")
			}
			router = o
		}
		previous = o.SHA256
		byHash[o.SHA256] = o
	}
	if router.Kind == 0 {
		return p, m, nil, nil, fail("manifest")
	}
	raw, err := browserReadFile(filepath.Join(dir, "objects", router.SHA256+".via3"), router.Bytes)
	if err != nil {
		return p, m, nil, nil, err
	}
	if len(raw) != router.Bytes || Hash(raw) != router.SHA256 {
		return p, m, nil, nil, fail("hash")
	}
	if u64(raw, 36) > PublicObjectDecoded {
		return p, m, nil, nil, fail("resource_limit")
	}
	s, err := Read(ctx, raw)
	if err != nil {
		return p, m, nil, nil, err
	}
	if s.Kind != 1 {
		return p, m, nil, nil, fail("schema")
	}
	if err = ValidatePublicProfile(s); err != nil {
		return p, m, nil, nil, err
	}
	directory, _ := s.Rows(7)
	refs := make([]ObjectInfo, 0, len(directory)/40)
	for n := 0; n < len(directory); n += 40 {
		o, ok := byHash[hex.EncodeToString(directory[n+8:n+40])]
		if !ok || o.SHA256 == router.SHA256 || o.Kind != u16(directory, n) || o.Bytes != int(u32(directory, n+4)) {
			return p, m, nil, nil, fail("record")
		}
		refs = append(refs, o)
	}
	s.lookup = shardLookupMetadata(&s, nil)
	return p, m, &s, refs, nil
}

func (tree *browserControlTree) objectTree(objects []ObjectInfo, depth int) (string, error) {
	if err := tree.ctx.Err(); err != nil {
		return "", err
	}
	if len(objects) <= 20 {
		leaf := browserObjectLeaf{Objects: objects, Type: "objects"}
		for i, o := range objects {
			if proof, ok := tree.proofs[o.SHA256]; ok {
				leaf.References = append(leaf.References, [3]any{i, proof.count, proof.hash})
			}
		}
		b := canonical(leaf)
		if len(b) <= browserObjectLimit {
			return tree.add(b, browserObjectLimit)
		}
	}
	if depth >= 64 {
		return "", fail("resource_limit")
	}
	var node browserBranch
	node.Type = "branch"
	for i := 0; i < len(objects); {
		key := objects[i].SHA256[depth]
		j := i + 1
		for j < len(objects) && objects[j].SHA256[depth] == key {
			j++
		}
		hash, err := tree.objectTree(objects[i:j], depth+1)
		if err != nil {
			return "", err
		}
		node.Children = append(node.Children, [2]any{strings.IndexByte(browserDigits, key), hash})
		i = j
	}
	return tree.add(canonical(node), browserBranchLimit)
}

func buildBrowserControls(ctx context.Context, atlasRoot, expectedRoot string) (*browserControlTree, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	p, m, router, refs, err := browserInputs(ctx, atlasRoot)
	if err != nil {
		return nil, "", err
	}
	if expectedRoot != "" && p.BrowserSHA256 != "" && p.BrowserSHA256 != expectedRoot {
		return nil, "", fail("manifest")
	}
	if expectedRoot == "" {
		expectedRoot = p.BrowserSHA256
	}
	// Previously staged v1 roots are still verified byte for byte using only
	// their original router and manifest, independent of new proof availability.
	if expectedRoot != "" {
		tree, hash, err := projectBrowserControls(ctx, p, m, router, refs, nil, 1)
		if err != nil || hash == expectedRoot {
			return tree, hash, err
		}
	}
	proofs, err := browserReferenceProofs(ctx, atlasRoot, p.ManifestSHA256, m.Objects)
	if err != nil {
		return nil, "", err
	}
	tree, hash, err := projectBrowserControls(ctx, p, m, router, refs, proofs, 2)
	if err == nil && expectedRoot != "" && expectedRoot != hash {
		return nil, "", fail("manifest")
	}
	return tree, hash, err
}

func projectBrowserControls(ctx context.Context, p browserPointer, m Manifest, router *Shard, refs []ObjectInfo, proofs map[string]browserReferenceProof, version int) (*browserControlTree, string, error) {
	tree := &browserControlTree{ctx: ctx, pages: make(map[string][]byte), proofs: proofs}
	routes := browserRoutes{router: router, refs: refs, setIDs: make(map[string]int)}
	v4, v6, asns, err := routes.intervals(ctx)
	if err != nil {
		return nil, "", err
	}
	var root browserRoots
	if root.IPv4, err = routes.routeTree(tree, v4, "", 8); err != nil {
		return nil, "", err
	}
	if root.IPv6, err = routes.routeTree(tree, v6, "", 32); err != nil {
		return nil, "", err
	}
	if root.ASN, err = routes.routeTree(tree, asns, "", 8); err != nil {
		return nil, "", err
	}
	if root.Objects, err = tree.objectTree(m.Objects, 0); err != nil {
		return nil, "", err
	}
	hash, err := tree.add(canonical(browserRoot{version, p.ManifestSHA256, m.Mode, p.ReleaseID, root, m.ValidFrom, m.ValidUntil}), browserRootLimit)
	return tree, hash, err
}

// VerifyBrowserIndex re-derives the complete control inventory from the
// canonical release inputs and compares every file in its directory.
func VerifyBrowserIndex(ctx context.Context, atlasRoot, outputDir, rootHash string) error {
	if !validHash(rootHash) {
		return fail("manifest")
	}
	tree, hash, err := buildBrowserControls(ctx, atlasRoot, rootHash)
	if err != nil {
		return err
	}
	if rootHash != hash {
		return errors.New("incorrect browser control root")
	}
	return tree.verify(outputDir)
}

func (tree *browserControlTree) verify(dir string) error {
	stat, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return errors.New("browser control directory required")
	}
	items, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(items) != len(tree.pages) {
		return errors.New("browser control inventory differs")
	}
	for _, item := range items {
		if err := tree.ctx.Err(); err != nil {
			return err
		}
		key, ok := strings.CutSuffix(item.Name(), ".json")
		body, exists := tree.pages[key]
		if !ok || !exists {
			return errors.New("unexpected browser control file")
		}
		actual, err := browserReadFile(filepath.Join(dir, item.Name()), len(body))
		if err != nil {
			return err
		}
		if !bytes.Equal(body, actual) {
			return fmt.Errorf("browser control differs: %s", key)
		}
	}
	return nil
}

// GenerateBrowserIndex installs a complete, deterministic directory of
// immutable browser controls. Existing controls are revalidated in place.
func GenerateBrowserIndex(ctx context.Context, atlasRoot, outputDir string) (string, error) {
	tree, hash, err := buildBrowserControls(ctx, atlasRoot, "")
	if err != nil {
		return "", err
	}
	if stat, err := os.Lstat(outputDir); err == nil {
		if !stat.IsDir() {
			return "", errors.New("browser control directory required")
		}
		entries, err := os.ReadDir(outputDir)
		if err != nil {
			return "", err
		}
		if len(entries) > 0 {
			if err := tree.verify(outputDir); err != nil {
				return "", err
			}
			return hash, nil
		}
		// Removing an empty directory cannot erase any existing controls.
		if err := os.Remove(outputDir); err != nil {
			if verifyErr := tree.verify(outputDir); verifyErr == nil {
				return hash, nil
			}
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(outputDir)
	if err = os.MkdirAll(parent, 0755); err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(parent, ".browser-controls-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	keys := make([]string, 0, len(tree.pages))
	for k := range tree.pages {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		if err = os.WriteFile(filepath.Join(staging, k+".json"), tree.pages[k], 0644); err != nil {
			return "", err
		}
	}
	if err = os.Chmod(staging, 0755); err != nil {
		return "", err
	}
	if err = os.Rename(staging, outputDir); err != nil {
		if existingErr := tree.verify(outputDir); existingErr != nil {
			return "", err
		}
	}
	return hash, nil
}

const browserDigits = "0123456789abcdef"

type browserSpan struct {
	first, last string
	set         int
}
type browserRoutes struct {
	router *Shard
	refs   []ObjectInfo
	sets   [][]int
	setIDs map[string]int
}

func (routes *browserRoutes) leaf(spans []browserSpan, low, high string) []byte {
	leaf := browserRouteLeaf{Objects: []ObjectInfo{}, Routes: [][3]any{}, Sets: [][]int{}, Type: "routes"}
	globalSets := make([]int, 0)
	setIDs := map[int]int{}
	ordinals := map[int]int{}
	for _, s := range spans {
		local, seen := setIDs[s.set]
		if !seen {
			local = len(globalSets)
			setIDs[s.set] = local
			globalSets = append(globalSets, s.set)
			for _, ordinal := range routes.sets[s.set] {
				ordinals[ordinal] = 0
			}
		}
		leaf.Routes = append(leaf.Routes, [3]any{max(low, s.first), min(high, s.last), local})
	}
	keys := make([]int, 0, len(ordinals))
	for k := range ordinals {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return routes.refs[keys[i]].SHA256 < routes.refs[keys[j]].SHA256 })
	for i, k := range keys {
		ordinals[k] = i
		leaf.Objects = append(leaf.Objects, routes.refs[k])
	}
	for _, set := range globalSets {
		local := make([]int, 0, len(routes.sets[set]))
		for _, o := range routes.sets[set] {
			local = append(local, ordinals[o])
		}
		leaf.Sets = append(leaf.Sets, local)
	}
	return canonical(leaf)
}

func (routes *browserRoutes) routeTree(tree *browserControlTree, spans []browserSpan, prefix string, width int) (string, error) {
	if err := tree.ctx.Err(); err != nil {
		return "", err
	}
	low := prefix + strings.Repeat("0", width-len(prefix))
	high := prefix + strings.Repeat("f", width-len(prefix))
	if len(spans) <= 128 {
		b := routes.leaf(spans, low, high)
		if len(b) <= browserRouteLimit {
			return tree.add(b, browserRouteLimit)
		}
	}
	if len(prefix) >= width {
		return "", fail("resource_limit")
	}
	branch := browserBranch{Type: "branch"}
	for digit, char := range browserDigits {
		next := prefix + string(char)
		first := next + low[len(next):]
		last := next + high[len(next):]
		from := sort.Search(len(spans), func(i int) bool { return spans[i].last >= first })
		to := sort.Search(len(spans), func(i int) bool { return spans[i].first > last })
		if from == to {
			continue
		}
		h, err := routes.routeTree(tree, spans[from:to], next, width)
		if err != nil {
			return "", err
		}
		branch.Children = append(branch.Children, [2]any{digit, h})
	}
	return tree.add(canonical(branch), browserBranchLimit)
}
