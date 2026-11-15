package via3

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMemoryProfileLegalBoundaries(t *testing.T) {
	release, profile, err := BuildMemoryProfile(context.Background(), 1794000000)
	if err != nil {
		t.Fatal(err)
	}
	if release.Manifest.Mode != "synthetic" || profile.Coverage != profile.Budgets || profile.Coverage.AnswerBytes != 8<<20 || profile.Coverage.LiveDecodedBytes != 96<<20 {
		t.Fatalf("incomplete profile: %+v", profile)
	}
	if len(profile.Cases) != 3 || !profile.Cases[0].RetainAnswer || profile.Cases[0].AnswerBytes != PublicAnswerBytes || profile.Cases[2].ExpectedError != "resource_limit" {
		t.Fatal("missing successful boundary or rejection exercise")
	}
	byHash := make(map[string]MemoryProfileObject)
	for _, object := range profile.Objects {
		byHash[object.SHA256] = object
	}
	var live int
	for _, hash := range profile.Cases[1].RequiredObjects {
		object, ok := byHash[hash]
		if !ok {
			t.Fatal("unbound live object")
		}
		live += object.DecodedBytes
	}
	if live != PublicLiveDecoded {
		t.Fatalf("live population %d", live)
	}
	for _, object := range release.Objects {
		if object.Info.Kind == 2 || object.Info.Kind == 5 {
			index, _ := object.Shard.Rows(1)
			if len(index)/32 < 1000000 {
				t.Fatal("boundary must contain real indexed records")
			}
		}
	}
}

func TestMemoryProfileAnswerCalibration(t *testing.T) {
	for _, clock := range []int64{0, 1794000000, 9000000000000} {
		answer, _, err := profileAnswer(clock)
		if err != nil {
			t.Fatal(err)
		}
		bytes, err := json.Marshal(answer)
		if err != nil {
			t.Fatal(err)
		}
		if len(bytes) != PublicAnswerBytes {
			t.Fatalf("clock %d: answer %d", clock, len(bytes))
		}
		if len(answer.Network.Origins) != PublicOrigins || len(answer.BGP.Paths) != PublicPathASNs {
			t.Fatal("missing complete semantic populations")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := BuildMemoryProfile(ctx, 1794000000); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
}
