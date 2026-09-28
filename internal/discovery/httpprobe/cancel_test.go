package httpprobe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCancelStopsRemainingHTTPWork(t *testing.T) {
	for _, paths := range []bool{false, true} {
		t.Run(fmt.Sprintf("paths=%v", paths), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var pages atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/favicon.ico" {
					w.WriteHeader(404)
					return
				}
				if pages.Add(1) == 1 {
					cancel()
					time.Sleep(30 * time.Millisecond)
				}
				fmt.Fprint(w, "page")
			}))
			defer srv.Close()
			opts := Options{Threads: 1, TimeoutSeconds: 1}
			if paths {
				opts.Targets = []string{srv.URL}
			}
			for i := 0; i < 20; i++ {
				p := fmt.Sprintf("/page-%d", i)
				if paths {
					opts.RequestPaths = append(opts.RequestPaths, p)
				} else {
					opts.Targets = append(opts.Targets, srv.URL+p)
				}
			}
			out, err := New(opts).Run(ctx)
			if err != nil {
				t.Fatal(err)
			}
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			for {
				select {
				case _, ok := <-out:
					if !ok {
						if n := pages.Load(); n == 0 || n > 3 {
							t.Fatalf("取消后仍处理队列: pages=%d", n)
						}
						return
					}
				case <-timer.C:
					t.Fatal("取消后未释放结果通道")
				}
			}
		})
	}
}
