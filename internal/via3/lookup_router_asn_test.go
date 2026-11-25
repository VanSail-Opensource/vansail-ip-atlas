package via3

import (
	"bytes"
	"crypto/sha256"
	"os"
	"testing"
)

func TestRouterASNDirectoryKeepsEveryExactKeyAndRecord(t *testing.T) {
	var keys []byte
	for _, high := range []uint32{1, 3, 65000} {
		for _, band := range []uint32{0, 33, 166, 255} {
			for low := uint32(0); low < 256; low++ {
				if low%7 == 4 {
					continue
				}
				var row [8]byte
				p32(row[:], 0, high<<16|band<<8|low)
				p32(row[:], 4, uint32(len(keys)/8/3))
				keys = append(keys, row[:]...)
			}
		}
	}
	shape := routerASNLayout(keys)
	idx := shape.build(keys)
	reference := map[uint32]uint32{}
	for p := 0; p < len(keys); p += 8 {
		reference[u32(keys, p)] = uint32(p / 8)
	}
	for _, high := range []uint32{0, 1, 2, 3, 4, 64999, 65000, 65001, 65535} {
		for sub := uint32(0); sub <= 65535; sub++ {
			asn := high<<16 | sub
			ordinal, present := idx.ordinal(asn)
			expected, ok := reference[asn]
			if present != ok || present && ordinal != expected {
				t.Fatal("presence or ordinal differs", asn, ordinal, present, expected, ok)
			}
		}
	}
}

func TestRouterASNDirectoryReleasesForRequiredInput(t *testing.T) {
	keys := make([]byte, 4096*8)
	for i := 0; i < len(keys)/8; i++ {
		p32(keys, i*8, uint32(i*2))
		p32(keys, i*8+4, uint32(i/5))
	}
	records := make([]byte, 1024*16)
	for i := 0; i < 1024; i++ {
		p32(records, i*16, uint32(i))
	}
	router := &Shard{Kind: 1, lookup: &shardLookup{}}
	router.lookup.rows[2], router.lookup.widths[2] = keys, 8
	router.lookup.rows[3], router.lookup.widths[3] = records, 16
	ref := &objectReference{size: len(keys) + len(records), shard: router, query: true}
	release := &Release{residentBytes: ref.size, activeBytes: ref.size}
	release.prepareRouterASNs(ref, router)
	if router.lookup.routerASNs == nil {
		t.Fatal("dense router directory not installed")
	}
	release.router = router
	release.routerBytes = ref.size
	ref.router = true
	release.usedReferences = []*objectReference{ref}
	release.cacheReference(ref)
	release.endQuery()
	selected, ok := router.ASNRecord(48)
	if !ok || u32(selected, 0) != 4 {
		t.Fatal("shared router row differs")
	}
	if _, ok := router.ASNRecord(49); ok {
		t.Fatal("missing ASN admitted")
	}
	retained := append([]byte(nil), selected...)
	old := ref.size
	// Fill the remaining live capacity with already pinned facts and admit a
	// single additional byte. The optional router directory must give way.
	release.residentBytes = PublicLiveDecoded
	if err := release.admitReference(&objectReference{}, 1); err != nil {
		t.Fatal(err)
	}
	if router.lookup.routerASNs != nil || ref.size >= old || release.routerBytes != ref.size {
		t.Fatal("optional directory remained charged")
	}
	selected, ok = router.ASNRecord(48)
	if !ok || !bytes.Equal(selected, retained) {
		t.Fatal("binary fallback changed matching row")
	}
}

func TestRequiredNativePageReclaimsOptionalRouterData(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "pages")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data := make([]byte, 2*rowPageSize)
	if _, err = file.Write(data); err != nil {
		t.Fatal(err)
	}
	for _, joined := range []bool{false, true} {
		dir := make([]nativePageEntry, 2)
		for i := range dir {
			dir[i].digest = sha256.Sum256(data[i*rowPageSize : (i+1)*rowPageSize])
		}
		full := 2
		if joined {
			full = 3
		}
		ref := &objectReference{size: 1024, router: true}
		router := &Shard{lookup: &shardLookup{owner: ref, routerASNs: &routerASNDirectory{bytes: 1024}}}
		release := &Release{router: router, routerBytes: PublicLiveDecoded - full*rowPageSize + 1024, residentBytes: PublicLiveDecoded}
		pages := &nativePages{file: file, total: int64(len(data)), dir: dir, routerBytes: release.routerBytes, owner: release}
		pages.setMetadata(0)
		release.native = &nativeIndex{pages: pages}
		if pages.live != full-1 {
			t.Fatal("unexpected initial page headroom")
		}
		pages.page(0)
		pages.page(1)
		if joined {
			if pages.live != 2 || router.lookup.routerASNs == nil {
				t.Fatal("unneeded eviction")
			}
			if len(pages.span(rowPageSize-1, 2)) != 2 {
				t.Fatal("joined read differs")
			}
		}
		if pages.live != full || pages.pages != 2 || router.lookup.routerASNs != nil {
			t.Fatal("required read did not recover its capacity")
		}
	}
}
