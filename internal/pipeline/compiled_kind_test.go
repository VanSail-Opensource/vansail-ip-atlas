package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func buildWithStaticKindCache(ctx context.Context, options Options, rows []via3.PublicRecord) (Candidate, error) {
	cache, err := openSpatialCache(ctx, options.Workspace, [32]byte{45}, 256<<20, func(uint64) bool { return true })
	if err != nil {
		return Candidate{}, err
	}
	defer cache.Abort()
	options.compiledReuse = cache
	// Direct synthetic facts have no normalized input store. Keep the
	// ordinary final input check active and disable whole-result retention.
	options.materializationCache = &materializationCache{workspace: options.Workspace}
	options.prepareSpatialCache = cache.Prepare
	options.commitSpatialCache = cache.Commit
	return Build(ctx, options, producer(rows))
}

func TestCompiledStaticKindMatchesUncachedAcrossUsageAndProfileChanges(t *testing.T) {
	ctx := context.Background()
	warm := testOptions(t)
	warm.Limits.PartitionRecords = 24
	rows := groupedFactRows(96)
	for _, r := range rows {
		if r.Kind == 4 {
			r.Network.Name = "Synthetic Network"
		}
	}
	old, err := buildWithStaticKindCache(ctx, warm, rows)
	if err != nil {
		t.Fatal(err)
	}
	// The combined leaves must miss both the location and network keys.
	score, risk := uint8(18), 0.18
	for _, r := range rows {
		switch r.Kind {
		case 5:
			r.Usage.Type = 5
		case 6:
			r.Quality.Score, r.Quality.Exact = &score, &risk
		case 7:
			r.Profile.Cells[0].Score, r.Profile.Cells[0].ExactRisk = &score, &risk
		}
	}
	warm.Output = filepath.Join(warm.Workspace, "build-private", "warm")
	got, err := buildWithStaticKindCache(ctx, warm, rows)
	if err != nil || got.Pointer == old.Pointer {
		t.Fatal("changed facts unexpectedly kept the old release", err)
	}
	cold := testOptions(t)
	cold.Limits = warm.Limits
	want, err := Build(ctx, cold, producer(rows))
	if err != nil || got.Pointer != want.Pointer {
		t.Fatal("partial reuse changed the exact updated release", err)
	}
	classC := func(o Options) *via3.ClassCAnswer {
		t.Helper()
		reader, err := via3.OpenRelease(o.Output, func() int64 { return o.Clock })
		if err != nil {
			t.Fatal(err)
		}
		answer, err := reader.ClassC(ctx, "11.0.5.0")
		if err != nil || answer == nil {
			t.Fatal("expected new profile to use reused network object", err)
		}
		return answer
	}
	if !reflect.DeepEqual(classC(warm), classC(cold)) {
		t.Fatal("profile attachment changed across the cache path")
	}
}

func TestCompiledStaticKindKeepsCrossKindAnycastValidation(t *testing.T) {
	ctx := context.Background()
	opt := testOptions(t)
	rows := groupedFactRows(4)
	if _, err := buildWithStaticKindCache(ctx, opt, rows); err != nil {
		t.Fatal(err)
	}
	yes := true
	for _, r := range rows {
		if r.Kind == 5 {
			r.Usage.Anycast = &yes
		}
	}
	opt.Output = filepath.Join(opt.Workspace, "build-private", "invalid")
	if _, err := buildWithStaticKindCache(ctx, opt, rows); via3.ErrorCode(err) != "record" {
		t.Fatal("new anycast facts failed to recheck retained location", err)
	}
	if _, err := os.Lstat(opt.Output); !os.IsNotExist(err) {
		t.Fatal("failed combined validation published a candidate")
	}
}

func TestCompiledStaticKindRejectsTamperedObjectOnPartialHit(t *testing.T) {
	ctx := context.Background()
	opt := testOptions(t)
	rows := groupedFactRows(4)
	initial, err := buildWithStaticKindCache(ctx, opt, rows)
	if err != nil {
		t.Fatal(err)
	}
	var geo string
	for _, object := range initial.Manifest.Objects {
		if object.Kind == 2 {
			geo = object.SHA256
			break
		}
	}
	if geo == "" {
		t.Fatal("fixture did not compile location object")
	}
	path := filepath.Join(opt.Workspace, ".atlas-private", "spatial-cache-v1", "objects", geo+".cache")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Kind == 5 {
			r.Usage.Type = 5
		}
	}
	opt.Output = filepath.Join(opt.Workspace, "build-private", "warm-damaged")
	if _, err = buildWithStaticKindCache(ctx, opt, rows); err == nil {
		t.Fatal("the new leaf failed to verify its unchanged static bytes")
	}
	if _, err = os.Lstat(opt.Output); !os.IsNotExist(err) {
		t.Fatal("damaged partial hit published a candidate")
	}
}
