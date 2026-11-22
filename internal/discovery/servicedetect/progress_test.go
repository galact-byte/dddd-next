package servicedetect

import (
	"context"
	"sync/atomic"
	"testing"
)

func TestCompletionIncludesUnresolvableEndpoints(t *testing.T) {
	var completed atomic.Int64
	opts := DefaultOptions()
	opts.OnComplete = func(err error) {
		if err == nil {
			t.Error("unresolvable endpoint has no error")
		}
		completed.Add(1)
	}
	for range New(opts).Detect(context.Background(), []Endpoint{{Host: "", Port: 80}}) {
	}
	if completed.Load() != 1 {
		t.Fatalf("completed=%d", completed.Load())
	}
}

func TestCanceledDetectionDoesNotReportUnstartedEndpoints(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var completed atomic.Int64
	opts := DefaultOptions()
	opts.OnComplete = func(error) { completed.Add(1) }
	for range New(opts).Detect(ctx, []Endpoint{{Host: "", Port: 80}}) {
	}
	if completed.Load() != 0 {
		t.Fatalf("unstarted endpoints counted after cancellation: %d", completed.Load())
	}
}
