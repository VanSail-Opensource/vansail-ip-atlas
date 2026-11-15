package pipeline

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestBuildStagesReportAggregateWorkWithoutChangingRelease(t *testing.T) {
	baseline, err := Build(context.Background(), testOptions(t), producer(fusedFixture()))
	if err != nil {
		t.Fatal(err)
	}
	type event struct {
		stage Stage
		end   bool
		ok    bool
	}
	var events []event
	options := testOptions(t)
	options.ObserveStage = func(ctx context.Context, stage Stage) func(bool) {
		if ctx == nil {
			t.Fatal("stage context missing")
		}
		events = append(events, event{stage: stage})
		return func(ok bool) { events = append(events, event{stage, true, ok}) }
	}
	got, err := Build(context.Background(), options, producer(fusedFixture()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Pointer != baseline.Pointer {
		t.Fatal("timing observer changed immutable release")
	}
	var want []event
	for _, stage := range []Stage{StageSort, StageMerge, StageClassify, StagePartition, StagePublish} {
		want = append(want, event{stage: stage}, event{stage, true, true})
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("phases must describe aggregate work once: got %+v, want %+v", events, want)
	}
	options = testOptions(t)
	events = nil
	options.ObserveStage = func(_ context.Context, stage Stage) func(bool) {
		events = append(events, event{stage: stage})
		return func(ok bool) { events = append(events, event{stage, true, ok}) }
	}
	_, err = Build(context.Background(), options, func(context.Context, func(via3.PublicRecord) error) error {
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(events, []event{{stage: StageSort}, {StageSort, true, false}}) {
		t.Fatal("failed producer did not end its aggregate phase", events, err)
	}
}
