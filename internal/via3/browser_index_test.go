package via3

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type testBrowserControl struct {
	Children [][2]json.RawMessage `json:"children"`
	Objects  []ObjectInfo         `json:"objects"`
	Routes   [][3]json.RawMessage `json:"routes"`
	Sets     [][]int              `json:"sets"`
	Type     string               `json:"type"`
}

func readBrowserTestPage(t *testing.T, dir, hash string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, hash+".json"))
	if err != nil || Hash(raw) != hash {
		t.Fatalf("invalid content-addressed page: %v", err)
	}
	return raw
}

func browserValue[T any](t *testing.T, b json.RawMessage) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func browserLookupForTest(t *testing.T, dir, hash, key string) []ObjectInfo {
	t.Helper()
	for depth := 0; depth <= len(key); depth++ {
		raw := readBrowserTestPage(t, dir, hash)
		var node testBrowserControl
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatal(err)
		}
		switch node.Type {
		case "branch":
			if len(raw) > browserBranchLimit || depth == len(key) {
				t.Fatal("invalid branch")
			}
			next := ""
			for _, child := range node.Children {
				if browserValue[int](t, child[0]) == strings.IndexByte(browserDigits, key[depth]) {
					next = browserValue[string](t, child[1])
					break
				}
			}
			if next == "" {
				return nil
			}
			hash = next
		case "routes":
			if len(raw) > browserRouteLimit {
				t.Fatal("oversize route leaf")
			}
			for _, r := range node.Routes {
				if browserValue[string](t, r[0]) <= key && key <= browserValue[string](t, r[1]) {
					var out []ObjectInfo
					for _, idx := range node.Sets[browserValue[int](t, r[2])] {
						out = append(out, node.Objects[idx])
					}
					return out
				}
			}
			return nil
		case "objects":
			if len(raw) > browserObjectLimit {
				t.Fatal("oversize descriptor leaf")
			}
			for _, o := range node.Objects {
				if o.SHA256 == key {
					return []ObjectInfo{o}
				}
			}
			return nil
		default:
			t.Fatal("unexpected control page")
		}
	}
	t.Fatal("unterminated branch")
	return nil
}

func nativeBrowserTestTargets(r *Release, row []byte, ok bool) []ObjectInfo {
	if !ok {
		return nil
	}
	ints, _ := r.router.Rows(4)
	var targets []ObjectInfo
	for i := uint32(0); i < uint32(u16(row, 4)); i++ {
		ordinal := u32(ints, int(u32(row, 0)+i)*4)
		targets = append(targets, r.router.lookup.references[ordinal].info)
	}
	return targets
}

func TestBrowserIndexRoutedParityAndReproducibility(t *testing.T) {
	ctx := context.Background()
	release, err := SyntheticGraph24(ctx, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	atlas := t.TempDir()
	if err := release.Write(atlas); err != nil {
		t.Fatal(err)
	}
	native, err := OpenRelease(atlas, func() int64 { return release.Manifest.ValidFrom })
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	hash, err := GenerateBrowserIndex(ctx, atlas, dest)
	if err != nil {
		t.Fatal(err)
	}
	originalPointer, err := os.ReadFile(filepath.Join(atlas, "current.json"))
	if err != nil || !bytes.Equal(originalPointer, canonical(release.Pointer)) {
		t.Fatal("canonical release pointer was modified")
	}
	secondDir := filepath.Join(t.TempDir(), "browser")
	second, err := GenerateBrowserIndex(ctx, atlas, secondDir)
	if err != nil || second != hash {
		t.Fatal("nondeterministic control root", err)
	}
	if err := VerifyBrowserIndex(ctx, atlas, secondDir, hash); err != nil {
		t.Fatal(err)
	}
	rootRaw := readBrowserTestPage(t, dest, hash)
	var root browserRoot
	if len(rootRaw) > browserRootLimit || strictJSON(rootRaw, &root) != nil || root.ManifestSHA256 != release.Pointer.ManifestSHA256 || root.ReleaseID != release.Manifest.ReleaseID || root.Mode != release.Manifest.Mode || root.ValidFrom != release.Manifest.ValidFrom || root.ValidUntil != release.Manifest.ValidUntil || root.FormatVersion != 2 {
		t.Fatal("browser root changed release identity")
	}
	for _, s := range []string{"0.0.0.0", "203.0.112.255", "203.0.113.0", "203.0.113.1", "203.0.113.255", "203.0.114.0", "203.0.114.21", "203.0.114.255", "203.0.115.0", "255.255.255.255", "::", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::", "2001:db8::1", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db9::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		addr := netip.MustParseAddr(s)
		row, _, ok := native.router.findPrefix(addr)
		plane := root.Roots.IPv4
		if addr.Is6() {
			plane = root.Roots.IPv6
		}
		got := browserLookupForTest(t, dest, plane, browserAddrKey(addr))
		if !slices.Equal(got, nativeBrowserTestTargets(native, row, ok)) {
			t.Fatal("native IP route differs", s)
		}
	}
	for _, asn := range []uint32{1, 13334, 13335, 13336, 15168, 15169, 15170, 424239, 424240, 424241, 4294967295} {
		row, ok := native.router.ASNRecord(asn)
		if !slices.Equal(browserLookupForTest(t, dest, root.Roots.ASN, browserASNKey(asn)), nativeBrowserTestTargets(native, row, ok)) {
			t.Fatal("native ASN route differs", asn)
		}
	}
	for _, o := range native.Manifest.Objects {
		if !slices.Equal(browserLookupForTest(t, dest, root.Roots.Objects, o.SHA256), []ObjectInfo{o}) {
			t.Fatal("incorrect manifest descriptor", o)
		}
	}
	if len(browserLookupForTest(t, dest, root.Roots.Objects, strings.Repeat("0", 64))) != 0 {
		t.Fatal("unknown descriptor manufactured")
	}
	// The current pointer may adopt the digest after a successful projection.
	p := browserPointer{hash, 3, release.Pointer.ManifestPath, release.Pointer.ManifestSHA256, release.Pointer.ReleaseID}
	if err := os.WriteFile(filepath.Join(atlas, "current.json"), canonical(p), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBrowserIndex(ctx, atlas, dest, hash); err != nil {
		t.Fatal(err)
	}
	p.BrowserSHA256 = strings.Repeat("1", 64)
	if err := os.WriteFile(filepath.Join(atlas, "current.json"), canonical(p), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBrowserIndex(ctx, atlas, dest, hash); err == nil {
		t.Fatal("substituted pointer anchor accepted")
	}
}

func TestBrowserControlsRejectMissingAlteredAndOrphanFiles(t *testing.T) {
	ctx := context.Background()
	r, err := Synthetic(ctx, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	atlas := t.TempDir()
	if err = r.Write(atlas); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"missing", "altered", "orphan", "symlink", "digest", "router", "manifest", "cancel"} {
		t.Run(op, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "browser")
			hash, err := GenerateBrowserIndex(ctx, atlas, dir)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, hash+".json")
			active := ctx
			switch op {
			case "missing":
				err = os.Remove(path)
			case "altered":
				b := readBrowserTestPage(t, dir, hash)
				b[0] ^= 1
				err = os.WriteFile(path, b, 0600)
			case "orphan":
				err = os.WriteFile(filepath.Join(dir, strings.Repeat("0", 64)+".json"), []byte("{}"), 0600)
			case "symlink":
				b := readBrowserTestPage(t, dir, hash)
				outside := filepath.Join(t.TempDir(), "target")
				if err = os.WriteFile(outside, b, 0600); err == nil {
					if err = os.Remove(path); err == nil {
						err = os.Symlink(outside, path)
					}
				}
			case "digest":
				hash = strings.Repeat("3", 64)
			case "router", "manifest":
				target := filepath.Join(atlas, "releases", r.Manifest.ReleaseID, "manifest.json")
				if op == "router" {
					for _, o := range r.Manifest.Objects {
						if o.Kind == 1 {
							target = filepath.Join(atlas, "objects", o.SHA256+".via3")
						}
					}
				}
				b, readErr := os.ReadFile(target)
				if readErr != nil {
					t.Fatal(readErr)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(target, b, 0600); err != nil {
						t.Fatal(err)
					}
				})
				changed := slices.Clone(b)
				changed[len(changed)-1] ^= 1
				err = os.WriteFile(target, changed, 0600)
			case "cancel":
				var cancel context.CancelFunc
				active, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyBrowserIndex(active, atlas, dir, hash); err == nil {
				t.Fatal("invalid projected input accepted")
			}
		})
	}
}

func TestBrowserIntervalsUseNativeLongestMatchAndExactTies(t *testing.T) {
	rows := make([][]byte, 5)
	var ids []uint32
	for i := range rows {
		row := make([]byte, 16)
		p32(row, 0, uint32(i))
		p16(row, 4, 1)
		rows[i] = row
		ids = append(ids, uint32(i))
	}
	r := newShard(1, rows...)
	r.set(1, prefixRows(key("0.0.0.0/0", false, 0), key("10.0.0.0/8", false, 1), key("10.255.255.255/32", false, 2), key("10.255.255.255/32", true, 3), key("::/0", false, 4)))
	asnKeys := asnKeys(10, 11, 13, 14, 15)
	for i, record := range []uint32{0, 0, 0, 1, 1} {
		p32(asnKeys, 8+i*8+4, record)
	}
	r.set(2, asnKeys)
	r.set(4, intVector(ids...))
	r.lookup = shardLookupMetadata(&r, nil)
	routes := browserRoutes{router: &r, setIDs: map[string]int{}}
	ip, ipv6, asns, err := routes.intervals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip string
		id int
	}{{"0.0.0.0", 0}, {"9.255.255.255", 0}, {"10.0.0.0", 1}, {"10.255.255.254", 1}, {"10.255.255.255", 3}, {"11.0.0.0", 0}, {"255.255.255.255", 0}, {"::", 4}, {"::1:0:0:0", 4}, {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 4}} {
		a := netip.MustParseAddr(tc.ip)
		key := browserAddrKey(a)
		list := ip
		if a.Is6() {
			list = ipv6
		}
		var set []int
		for _, s := range list {
			if s.first <= key && key <= s.last {
				set = routes.sets[s.set]
				break
			}
		}
		if !reflect.DeepEqual(set, []int{tc.id}) {
			t.Fatal(tc.ip, set)
		}
	}
	if len(asns) != 3 || asns[0].first != browserASNKey(10) || asns[0].last != browserASNKey(11) ||
		asns[1].first != browserASNKey(13) || asns[1].last != browserASNKey(13) ||
		asns[2].first != browserASNKey(14) || asns[2].last != browserASNKey(15) {
		t.Fatal("consecutive ASN destinations or the gap changed")
	}
}

func TestBrowserRadixBranchesClipWideRangesAndKeepNarrowHoles(t *testing.T) {
	ctx := context.Background()
	var refs []ObjectInfo
	var sets [][]int
	for i := 0; i < 3; i++ {
		refs = append(refs, ObjectInfo{SHA256: Hash([]byte{byte(i)}), Kind: uint16(i + 2), Bytes: 99, Partition: "all"})
		sets = append(sets, []int{i})
	}
	routes := browserRoutes{refs: refs, sets: sets}
	spans := []browserSpan{{"00000000", "7fffffff", 2}}
	for n := uint32(0); n < 600; n += 2 {
		key := browserASNKey(0x80000000 + n)
		spans = append(spans, browserSpan{key, key, int(n / 2 % 2)})
	}
	spans = append(spans, browserSpan{"90000000", "ffffffff", 2})
	tree := browserControlTree{ctx: ctx, pages: make(map[string][]byte)}
	root, err := routes.routeTree(&tree, spans, "", 8)
	if err != nil {
		t.Fatal(err)
	}
	var top browserBranch
	if err := json.Unmarshal(tree.pages[root], &top); err != nil || top.Type != "branch" {
		t.Fatal("expected a split route tree")
	}
	out := t.TempDir()
	for hash, b := range tree.pages {
		if err = os.WriteFile(filepath.Join(out, hash+".json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for n := uint32(0); n < 600; n++ {
		got := browserLookupForTest(t, out, root, browserASNKey(0x80000000+n))
		if n%2 == 1 && len(got) != 0 || n%2 == 0 && !slices.Equal(got, []ObjectInfo{refs[n/2%2]}) {
			t.Fatal("split leaf altered a sparse destination", n)
		}
	}
	for _, key := range []string{"00000000", "12345678", "456789ab", "7fffffff", "90000000", "bfffffff", "ffffffff"} {
		if !slices.Equal(browserLookupForTest(t, out, root, key), []ObjectInfo{refs[2]}) {
			t.Fatal("inherited destination missing", key)
		}
	}
}
