package app

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type progressTimeout struct{}

func (progressTimeout) Error() string   { return "fixture timeout" }
func (progressTimeout) Timeout() bool   { return true }
func (progressTimeout) Temporary() bool { return true }

func TestStageProgressCancellationDoesNotInventCompletedWork(t *testing.T) {
	var out bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	p := newStageProgress(ctx, &out, "TCP", "端点", 3)
	p.Advance(progressTimeout{})
	cancel()
	p.Close()
	p.Close()
	text := out.String()
	for _, part := range []string{"TCP", "1/3", "已取消", "超时 1"} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %q in %s", part, text)
		}
	}
	if strings.Contains(text, "3/3") {
		t.Fatalf("invented completed work: %s", text)
	}
}

func TestStageProgressConcurrentUpdatesAndUnknownTotal(t *testing.T) {
	var out bytes.Buffer
	p := newStageProgress(context.Background(), &out, "HTTP", "结果事件", -1)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				p.Advance(nil)
			}
		}()
	}
	wg.Wait()
	p.Close()
	if text := out.String(); !strings.Contains(text, "200") || strings.Contains(text, "/-1") || strings.Contains(text, "NaN") {
		t.Fatalf("progress=%s", text)
	}
}

func TestProgressRateHandlesZeroElapsed(t *testing.T) {
	text := progressLine("phase", "items", 0, 0, 0, 0, 0, false, true)
	if strings.Contains(text, "NaN") || strings.Contains(text, "Inf") || !strings.Contains(text, "0/0") {
		t.Fatalf("line=%s", text)
	}
}

type progressNotifyWriter struct {
	mu     sync.Mutex
	output bytes.Buffer
	notify chan struct{}
}

func (w *progressNotifyWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.output.Write(b)
	select {
	case w.notify <- struct{}{}:
	default:
	}
	return n, err
}
func TestStageProgressReportsWhileWaitingAndStops(t *testing.T) {
	out := &progressNotifyWriter{notify: make(chan struct{}, 4)}
	p := newStageProgress(context.Background(), out, "slow", "items", 10)
	select {
	case <-out.notify:
	case <-time.After(4 * time.Second):
		p.Close()
		t.Fatal("no progress update while waiting")
	}
	p.Close()
	// Close waits for the ticker goroutine; no concurrent writer remains.
	out.mu.Lock()
	text := out.output.String()
	out.mu.Unlock()
	if !strings.Contains(text, "0/10") {
		t.Fatalf("progress=%s", text)
	}
}
