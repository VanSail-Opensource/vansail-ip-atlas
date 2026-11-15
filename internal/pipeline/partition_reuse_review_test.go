package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func compiledReviewFixture(t *testing.T, records []via3.PublicRecord, s scope) (*compiler, *compiledPartitionEntry, []via3.BuiltObject) {
	t.Helper()
	root := t.TempDir()
	compiled, err := via3.CompilePartition(context.Background(), via3.PartitionInput{Partition: s.name(), Records: records})
	if err != nil {
		t.Fatal(err)
	}
	entry := &compiledPartitionEntry{}
	files := make(map[[32]byte]string)
	for _, object := range compiled.Objects {
		entry.Objects = append(entry.Objects, object.Info)
		path := filepath.Join(root, object.Info.SHA256+".via3")
		if err := os.WriteFile(path, object.Bytes, 0600); err != nil {
			t.Fatal(err)
		}
		files[sha256.Sum256(object.Bytes)] = path
	}
	sort.Slice(entry.Objects, func(i, j int) bool { return entry.Objects[i].SHA256 < entry.Objects[j].SHA256 })
	route := compiledRoute{Prefix: s.prefix}
	for _, object := range compiled.Destinations {
		route.Destinations = append(route.Destinations, object.Info)
	}
	sort.Slice(route.Destinations, func(i, j int) bool { return route.Destinations[i].Kind < route.Destinations[j].Kind })
	if s.asn {
		seen := make(map[uint32]bool)
		for _, record := range records {
			if !seen[record.ASN] {
				route.ASNs = append(route.ASNs, record.ASN)
				seen[record.ASN] = true
			}
		}
		sort.Slice(route.ASNs, func(i, j int) bool { return route.ASNs[i] < route.ASNs[j] })
	}
	entry.Routes = []compiledRoute{route}
	cache, err := openSpatialCache(context.Background(), root, [32]byte{1}, 64<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Abort() })
	if retained, err := cache.Retain(context.Background(), spatialCacheEntry{Domain: "compiled", Key: [32]byte{2}, Compiled: entry}, files); err != nil || !retained {
		t.Fatal("valid compiled fixture was not retained", retained, err)
	}
	c := &compiler{ctx: context.Background(), options: Options{Workspace: root, Limits: DefaultLimits(), compiledReuse: cache}, output: filepath.Join(root, "candidate"), scratch: filepath.Join(root, "scratch"), objects: map[string]via3.ObjectInfo{}}
	return c, entry, compiled.Objects
}

func compiledReviewGeo() (scope, []via3.PublicRecord) {
	s := scope{prefix: netip.MustParsePrefix("11.0.0.0/24")}
	return s, []via3.PublicRecord{{Version: 3, Kind: 2, Prefix: s.prefix, Geo: &via3.GeoData{Country: "US", City: "Synthetic City"}}}
}

func TestCompiledReviewOriginDestinationIsAnIPRoute(t *testing.T) {
	s := scope{prefix: netip.MustParsePrefix("11.0.0.0/24")}
	rows := []via3.PublicRecord{{Version: 3, Kind: 10, Prefix: s.prefix, Origins: &via3.OriginsData{ASNs: []uint32{13335}}}}
	c, entry, _ := compiledReviewFixture(t, rows, s)
	if err := c.restoreCompiledPartition(entry, s); err != nil {
		t.Fatal("legitimate origin-set destination rejected", err)
	}
}

func TestCompiledReviewRejectsScopeAndReferenceMutation(t *testing.T) {
	for _, mutation := range []string{"object-scope", "route-outside-parent", "duplicate-route", "missing-dictionary", "orphan-object", "object-kind", "destination-kind", "noncanonical-scope"} {
		t.Run(mutation, func(t *testing.T) {
			s, records := compiledReviewGeo()
			if mutation == "orphan-object" {
				records = append(records, via3.PublicRecord{Version: 3, Kind: 3, Prefix: s.prefix, Coordinates: &via3.CoordinateData{Unknown: true}})
			}
			c, original, _ := compiledReviewFixture(t, records, s)
			entry := cloneCompiledPartition(original)
			switch mutation {
			case "object-scope":
				for i := range entry.Objects {
					if entry.Objects[i].Kind == 2 {
						entry.Objects[i].Partition = (scope{prefix: netip.MustParsePrefix("12.0.0.0/24")}).name()
					}
				}
			case "route-outside-parent":
				entry.Routes[0].Prefix = netip.MustParsePrefix("12.0.0.0/24")
				for i := range entry.Routes[0].Destinations {
					entry.Routes[0].Destinations[i].Partition = (scope{prefix: entry.Routes[0].Prefix}).name()
				}
			case "duplicate-route":
				entry.Routes = append(entry.Routes, entry.Routes[0])
			case "missing-dictionary":
				var objects []via3.ObjectInfo
				for _, info := range entry.Objects {
					if info.Kind != 14 {
						objects = append(objects, info)
					}
				}
				entry.Objects = objects
			case "orphan-object":
				var destinations []via3.ObjectInfo
				for _, info := range entry.Routes[0].Destinations {
					if info.Kind != 3 {
						destinations = append(destinations, info)
					}
				}
				entry.Routes[0].Destinations = destinations
			case "object-kind":
				for i := range entry.Objects {
					if entry.Objects[i].Kind == 14 {
						entry.Objects[i].Kind = 3
					}
				}
			case "destination-kind":
				entry.Routes[0].Destinations[0].Kind = 8
			case "noncanonical-scope":
				entry.Routes[0].Destinations[0].Partition += "0"
			}
			if err := c.restoreCompiledPartition(entry, s); err == nil {
				t.Fatal("mutated compiled subtree restored")
			}
		})
	}
}

func TestCompiledReviewRejectsDuplicateASNAndWrongFamilyRoutes(t *testing.T) {
	s := scope{asn: true, first: 13000, last: 16000}
	records := []via3.PublicRecord{{Version: 3, Kind: 8, ASN: 13335, ASNAggregate: &via3.ASNData{Name: "Synthetic Network"}}}
	for _, mutation := range []string{"duplicate-asn", "outside-parent", "ip-parent", "wide-destination-scope"} {
		t.Run(mutation, func(t *testing.T) {
			c, original, _ := compiledReviewFixture(t, records, s)
			entry := cloneCompiledPartition(original)
			parent := s
			switch mutation {
			case "duplicate-asn":
				entry.Routes = append(entry.Routes, entry.Routes[0])
			case "outside-parent":
				parent.first = 14000
			case "ip-parent":
				parent = scope{prefix: netip.MustParsePrefix("0.0.0.0/0")}
			case "wide-destination-scope":
				wide := (scope{asn: true, last: ^uint32(0)}).name()
				for i := range entry.Objects {
					if entry.Objects[i].Partition != "all" {
						entry.Objects[i].Partition = wide
					}
				}
				for i := range entry.Routes[0].Destinations {
					entry.Routes[0].Destinations[i].Partition = wide
				}
			}
			if err := c.restoreCompiledPartition(entry, parent); err == nil {
				t.Fatal("invalid ASN route scope restored")
			}
		})
	}
}

func TestCompiledReviewRehashesCachedAndAlreadyWrittenObjects(t *testing.T) {
	for _, target := range []string{"cache", "output"} {
		t.Run(target, func(t *testing.T) {
			s, records := compiledReviewGeo()
			c, entry, objects := compiledReviewFixture(t, records, s)
			object := objects[len(objects)-1]
			var path string
			if target == "output" {
				if err := c.object(object); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(c.output, "objects", object.Info.SHA256+".via3")
			} else {
				var err error
				path, err = c.options.compiledReuse.ObjectPath(sha256.Sum256(object.Bytes))
				if err != nil {
					t.Fatal(err)
				}
			}
			changed := append([]byte(nil), object.Bytes...)
			changed[len(changed)-1] ^= 1
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if err := c.restoreCompiledPartition(entry, s); err == nil {
				t.Fatal("changed bytes bypassed compiled restoration integrity")
			}
		})
	}
}

func TestCompiledReviewCapturePreservesLocalScopeAcrossGlobalDedup(t *testing.T) {
	s, records := compiledReviewGeo()
	c, entry, objects := compiledReviewFixture(t, records, s)
	var geo via3.BuiltObject
	for _, object := range objects {
		if object.Info.Kind == 2 {
			geo = object
		}
	}
	old := geo
	old.Info.Partition = (scope{prefix: netip.MustParsePrefix("12.0.0.0/24")}).name()
	if err := c.object(old); err != nil {
		t.Fatal(err)
	}
	before := c.stats.OutputBytes
	budget := &compiledCaptureBudget{}
	ancestor := &compiledPartitionCapture{objects: map[string]via3.ObjectInfo{}, budget: budget}
	local := &compiledPartitionCapture{objects: map[string]via3.ObjectInfo{}, budget: budget}
	c.compiledCaptures = []*compiledPartitionCapture{ancestor, local}
	if err := c.restoreCompiledPartition(entry, s); err != nil {
		t.Fatal(err)
	}
	for _, capture := range c.compiledCaptures {
		if capture.objects[geo.Info.SHA256].Partition != s.name() || len(capture.objects) != len(entry.Objects) {
			t.Fatal("global dedup lost an object or contaminated subtree-local scope")
		}
	}
	if c.objects[geo.Info.SHA256].Partition != "all" {
		t.Fatal("global shared object scope was not promoted")
	}
	var added uint64
	for _, object := range objects {
		if object.Info.SHA256 != geo.Info.SHA256 {
			added += uint64(len(object.Bytes))
		}
	}
	if c.stats.OutputBytes != before+added || c.stats.Partitions != 1 || c.routerBytes != uint64(48+4*len(entry.Routes[0].Destinations)) {
		t.Fatal("compiled replay changed normal output or route accounting")
	}
	for _, info := range entry.Objects {
		data, err := os.ReadFile(filepath.Join(c.output, "objects", info.SHA256+".via3"))
		if err != nil || via3.Hash(data) != info.SHA256 {
			t.Fatal("captured shared object was absent from output", err)
		}
	}
}

func TestCompiledReviewCaptureCapacityIsSharedAndOptional(t *testing.T) {
	budget := &compiledCaptureBudget{used: compiledCaptureBytes - 1}
	capture := &compiledPartitionCapture{objects: map[string]via3.ObjectInfo{}, budget: budget}
	c := &compiler{options: Options{Limits: DefaultLimits()}, compiledCaptures: []*compiledPartitionCapture{capture}}
	hash := sha256.Sum256([]byte("synthetic object"))
	c.captureCompiledObject(via3.ObjectInfo{Bytes: 128, Kind: 2, Partition: "all", SHA256: hex.EncodeToString(hash[:])})
	if !capture.disabled || capture.objects != nil || capture.bytes != 0 || budget.used != compiledCaptureBytes-1 {
		t.Fatal("optional capture exceeded its shared bound or uncharged another capture")
	}
}

func compiledReviewRun(t *testing.T, c *compiler, records []via3.PublicRecord) string {
	t.Helper()
	if err := os.MkdirAll(c.scratch, 0700); err != nil {
		t.Fatal(err)
	}
	path := c.next()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	var size partitionSize
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.writeRecord(file, data); err != nil {
			t.Fatal(err)
		}
		size.records++
		size.bytes += int64(len(data)) + 512
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	c.rememberPartitionSize(path, size)
	return path
}

func compiledReviewNext(c *compiler, name string) *compiler {
	return &compiler{ctx: context.Background(), options: c.options,
		output: filepath.Join(c.options.Workspace, name), scratch: filepath.Join(c.options.Workspace, name+"-scratch"), objects: map[string]via3.ObjectInfo{}}
}

func TestCompiledReviewCommittedHitBindsActualInputAndPrefixProvider(t *testing.T) {
	s := scope{asn: true, first: 13000, last: 16000}
	records := []via3.PublicRecord{{Version: 3, Kind: 8, ASN: 13335, ASNAggregate: &via3.ASNData{Name: "Synthetic Network"}}}
	cold, _, _ := compiledReviewFixture(t, records, s)
	provider := func(prefix string, calls *int) via3.ASNPrefixProvider {
		return func(ctx context.Context, asn uint32, emit func(netip.Prefix) error) (bool, error) {
			*calls++
			return true, emit(netip.MustParsePrefix(prefix))
		}
	}
	var coldCalls int
	cold.options.prefixProvider = provider("11.0.0.0/24", &coldCalls)
	cold.options.partitionDependencies = func(context.Context) ([32]byte, error) { return [32]byte{3}, nil }
	if err := cold.partition(compiledReviewRun(t, cold, records), s); err != nil || coldCalls == 0 {
		t.Fatal("initial compiled miss failed", err)
	}
	cache := cold.options.compiledReuse
	if err := cache.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cache.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cache.Abort(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openSpatialCache(context.Background(), cold.options.Workspace, cache.contract, 64<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Abort() })
	warm := compiledReviewNext(cold, "warm")
	warm.options.compiledReuse = reopened
	var warmCalls int
	warm.options.prefixProvider = provider("11.0.0.0/24", &warmCalls)
	path := compiledReviewRun(t, warm, records)
	if err := warm.partition(path, s); err != nil || warmCalls != 0 {
		t.Fatal("exact committed subtree did not hit", err, warmCalls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("restored subtree left its consumed input", err)
	}
	if err := cold.router(); err != nil {
		t.Fatal(err)
	}
	if err := warm.router(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(warm.objects, cold.objects) || !reflect.DeepEqual(warm.routes, cold.routes) || warm.stats.OutputBytes != cold.stats.OutputBytes || warm.stats.Partitions != cold.stats.Partitions || warm.used != cold.used || warm.routerBytes != cold.routerBytes {
		t.Fatal("compiled hit changed public metadata or current work accounting")
	}
	for hash := range cold.objects {
		original, err := os.ReadFile(filepath.Join(cold.output, "objects", hash+".via3"))
		if err != nil {
			t.Fatal(err)
		}
		restored, err := os.ReadFile(filepath.Join(warm.output, "objects", hash+".via3"))
		if err != nil || !bytes.Equal(restored, original) {
			t.Fatal("compiled replay or rebuilt router bytes differ", err)
		}
	}
	for _, mutation := range []string{"provider", "input", "unbound-provider"} {
		t.Run(mutation, func(t *testing.T) {
			current := compiledReviewNext(warm, mutation)
			var calls int
			current.options.prefixProvider = provider("11.0.0.0/24", &calls)
			rows := append([]via3.PublicRecord(nil), records...)
			switch mutation {
			case "provider":
				current.options.prefixProvider = provider("12.0.0.0/24", &calls)
				current.options.partitionDependencies = func(context.Context) ([32]byte, error) { return [32]byte{4}, nil }
			case "input":
				rows[0].ASNAggregate = &via3.ASNData{Name: "Different Network"}
			case "unbound-provider":
				current.options.partitionDependencies = nil
			}
			if err := current.partition(compiledReviewRun(t, current, rows), s); err != nil || calls == 0 {
				t.Fatal("changed or unbound semantic input reused compiled output", err, calls)
			}
			if err := current.router(); err != nil {
				t.Fatal(err)
			}
			if mutation != "unbound-provider" && reflect.DeepEqual(current.objects, cold.objects) {
				t.Fatal("changed provider or input produced stale objects")
			}
		})
	}
}

func TestCompiledReviewPrefixDependencyBindsFileAndRanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prefixes")
	if err := os.WriteFile(path, []byte("synthetic prefix frame"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	spool := &bulkSpool{maximum: 1 << 20, prefixFile: file, prefixIndex: map[uint32]bulkPrefixRange{13335: {offset: 0, count: 1}}}
	original, err := spool.compiledDependencies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"file", "offset", "count", "asn"} {
		t.Run(mutation, func(t *testing.T) {
			if err := os.WriteFile(path, []byte("synthetic prefix frame"), 0600); err != nil {
				t.Fatal(err)
			}
			spool.prefixIndex = map[uint32]bulkPrefixRange{13335: {offset: 0, count: 1}}
			switch mutation {
			case "file":
				if err := os.WriteFile(path, []byte("different prefix frame"), 0600); err != nil {
					t.Fatal(err)
				}
			case "offset":
				spool.prefixIndex[13335] = bulkPrefixRange{offset: 1, count: 1}
			case "count":
				spool.prefixIndex[13335] = bulkPrefixRange{offset: 0, count: 2}
			case "asn":
				spool.prefixIndex = map[uint32]bulkPrefixRange{15169: {offset: 0, count: 1}}
			}
			actual, err := spool.compiledDependencies(context.Background())
			if err != nil || actual == original {
				t.Fatal("provider semantic dependency did not change", err)
			}
		})
	}
	spool.prefixFile = nil
	if _, err := spool.compiledDependencies(context.Background()); err == nil {
		t.Fatal("prefix ranges without their actual backing file were accepted")
	}
}

func TestCompiledReviewRejectsRunMutationBeforeMissOrHitRemoval(t *testing.T) {
	for _, mode := range []string{"miss", "hit"} {
		t.Run(mode, func(t *testing.T) {
			s, records := compiledReviewGeo()
			c, _, _ := compiledReviewFixture(t, records, s)
			if mode == "hit" {
				if err := c.partition(compiledReviewRun(t, c, records), s); err != nil {
					t.Fatal(err)
				}
				c = compiledReviewNext(c, "hit")
			}
			path := compiledReviewRun(t, c, records)
			before := len(c.options.compiledReuse.entries)
			ctx := &hostileSpatialMutation{Context: context.Background(), ready: func() bool {
				if mode == "miss" {
					return len(c.compiledCaptures) > 0
				}
				_, err := os.Stat(filepath.Join(c.output, "objects"))
				return err == nil
			}, mutate: func() error {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				changed := bytes.Replace(data, []byte(`"US"`), []byte(`"DE"`), 1)
				if bytes.Equal(changed, data) {
					t.Fatal("fixture lacks the intended equal-length mutation")
				}
				return os.WriteFile(path, changed, 0600)
			}}
			c.ctx = ctx
			if err := c.partition(path, s); err == nil || !ctx.fired || ctx.err != nil {
				t.Fatal("changed run survived the consumption boundary", err, ctx.fired, ctx.err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("changed original run was removed", err)
			}
			if len(c.options.compiledReuse.entries) != before {
				t.Fatal("failed input binding retained a compiled result")
			}
		})
	}
}

type compiledReviewRestoreContext struct {
	context.Context
	ready           func() bool
	mutate, restore func() error
	phase           int
	err             error
}

func (c *compiledReviewRestoreContext) Err() error {
	if c.phase == 0 && c.ready() {
		c.phase = 1
		c.err = c.mutate()
	} else if c.phase == 1 {
		c.phase = 2
		c.err = errors.Join(c.err, c.restore())
	}
	return c.Context.Err()
}

func compiledReviewRunBytes(t *testing.T, record via3.PublicRecord, compressed bool) ([]byte, partitionSize) {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	row := encoded{data: data, logicalBytes: int64(len(data))}
	var output bytes.Buffer
	if compressed {
		writer, err := newPrivateRunWriterWithBudget(context.Background(), func(uint64) error { return nil }, &output)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		if err := writeRunFrame(writer, row); err != nil {
			t.Fatal(err)
		}
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
	} else if err := writeRunFrame(&output, row); err != nil {
		t.Fatal(err)
	}
	return output.Bytes(), partitionSize{records: 1, bytes: int64(len(data)) + 512}
}

func TestCompiledReviewRejectsConsumedMutationAfterOriginalRunRestored(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		name := "raw"
		if compressed {
			name = "compressed"
		}
		t.Run(name, func(t *testing.T) {
			s, records := compiledReviewGeo()
			c, _, _ := compiledReviewFixture(t, records, s)
			original, total := compiledReviewRunBytes(t, records[0], compressed)
			var changed []byte
			// Preserve inode and exact stored length. Both candidates are fully
			// valid containers; compressed CRC and decoded hashes are recomputed.
			for _, country := range []string{"DE", "FR", "GB", "CA", "JP"} {
				record := records[0]
				geo := *record.Geo
				geo.Country = country
				record.Geo = &geo
				candidate, _ := compiledReviewRunBytes(t, record, compressed)
				if len(candidate) == len(original) {
					changed = candidate
					break
				}
			}
			if changed == nil || bytes.Equal(changed, original) {
				t.Fatal("fixture lacks a distinct valid equal-length run")
			}
			if err := os.MkdirAll(c.scratch, 0700); err != nil {
				t.Fatal(err)
			}
			path := c.next()
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := c.reserve(uint64(len(original))); err != nil {
				t.Fatal(err)
			}
			c.rememberPartitionSize(path, total)
			before := len(c.options.compiledReuse.entries)
			ctx := &compiledReviewRestoreContext{Context: context.Background(),
				ready:   func() bool { return len(c.compiledCaptures) != 0 },
				mutate:  func() error { return os.WriteFile(path, changed, 0600) },
				restore: func() error { return os.WriteFile(path, original, 0600) }}
			c.ctx = ctx
			if err := c.partition(path, s); !errors.Is(err, errSpatialCache) || ctx.phase != 2 || ctx.err != nil {
				t.Fatal("changed consumed bytes escaped original-run binding", err, ctx.phase, ctx.err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, original) {
				t.Fatal("original path was not restored before rejection", err)
			}
			if len(c.options.compiledReuse.entries) != before {
				t.Fatal("changed consumed run retained a compiled subtree")
			}
		})
	}
}

func TestCompiledReviewReadAheadDoesNotAuthorizePartialConsumption(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		name := "raw"
		if compressed {
			name = "compressed"
		}
		t.Run(name, func(t *testing.T) {
			s, records := compiledReviewGeo()
			c, _, _ := compiledReviewFixture(t, records, s)
			data, total := compiledReviewRunBytes(t, records[0], compressed)
			if err := os.MkdirAll(c.scratch, 0700); err != nil {
				t.Fatal(err)
			}
			path := c.next()
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := c.reserve(uint64(len(data))); err != nil {
				t.Fatal(err)
			}
			c.rememberPartitionSize(path, total)
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			capture := &compiledPartitionCapture{inputPath: path, inputHash: sha256.Sum256(data), inputBytes: int64(len(data)), inputInfo: info}
			c.compiledCaptures = []*compiledPartitionCapture{capture}
			reader, err := c.openCompiledRun(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.file.Close()
			if err := reader.next(); err != nil {
				t.Fatal(err)
			}
			offset, err := reader.file.Seek(0, io.SeekCurrent)
			if err != nil || offset != int64(len(data)) {
				t.Fatal("fixture did not read ahead through the entire raw file", offset, err)
			}
			if capture.inputVerified || !errors.Is(c.remove(path), errSpatialCache) {
				t.Fatal("raw read-ahead authorized consumption before strict EOF")
			}
			if err := reader.next(); err != io.EOF || !capture.inputVerified {
				t.Fatal("full strict EOF did not verify actual input", err)
			}
			if err := reader.file.Close(); err != nil {
				t.Fatal(err)
			}
			if err := c.remove(path); err != nil || c.used != 0 {
				t.Fatal("verified input removal failed or changed accounting", err)
			}
		})
	}
}
