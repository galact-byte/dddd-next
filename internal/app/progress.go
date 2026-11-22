package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type stageProgress struct {
	completed atomic.Int64
	failed    atomic.Int64
	timeouts  atomic.Int64
	stop      chan struct{}
	stopped   chan struct{}
	once      sync.Once
}

func newStageProgress(ctx context.Context, out io.Writer, stage, unit string, total int64) *stageProgress {
	p := &stageProgress{stop: make(chan struct{}), stopped: make(chan struct{})}
	start := time.Now()
	go func() {
		defer close(p.stopped)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		print := func(final bool) {
			fmt.Fprintln(out, progressLine(stage, unit, p.completed.Load(), total, p.failed.Load(), p.timeouts.Load(), time.Since(start), ctx.Err() != nil, final))
		}
		for {
			select {
			case <-ticker.C:
				print(false)
			case <-p.stop:
				print(true)
				return
			}
		}
	}()
	return p
}

func (p *stageProgress) Advance(err error) {
	p.completed.Add(1)
	if err != nil && !errors.Is(err, context.Canceled) {
		p.failed.Add(1)
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			p.timeouts.Add(1)
		}
	}
}

func (p *stageProgress) Close() {
	if p == nil {
		return
	}
	p.once.Do(func() { close(p.stop) })
	<-p.stopped
}

func progressLine(stage, unit string, completed, total, failed, timeouts int64, elapsed time.Duration, canceled, final bool) string {
	state := "进行中"
	if final {
		state = "已结束"
	}
	if canceled {
		if final {
			state = "已取消"
		} else {
			state = "取消中，等待在途操作"
		}
	}
	count := fmt.Sprintf("%d", completed)
	if total >= 0 {
		count = fmt.Sprintf("%d/%d", completed, total)
	}
	rate := 0.0
	if elapsed > 0 {
		rate = float64(completed) / elapsed.Seconds()
	}
	return fmt.Sprintf("[进度] %s | %s | %s %s | 耗时 %s | %.1f/s | 未成功 %d | 已识别超时 %d", stage, state, unit, count, elapsed.Round(100*time.Millisecond), rate, failed, timeouts)
}

func (p *Pipeline) progress(ctx context.Context, stage, unit string, total int64) *stageProgress {
	return newStageProgress(ctx, os.Stderr, stage, unit, total)
}
