package httpprobe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestAuditCancelledHTTPProbeSendsNoRequests(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); fmt.Fprint(w, "audit") }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := New(Options{Targets: []string{srv.URL + "/one", srv.URL + "/two", srv.URL + "/three"}, Threads: 1, TimeoutSeconds: 1})
	out, err := p.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled Run: out=%v err=%v", out, err)
	}
	if out != nil {
		t.Fatal("已取消的探测不应创建扫描结果通道")
	}
	t.Logf("context 已取消后请求数=%d", requests.Load())
	if requests.Load() != 0 {
		t.Error("取消后仍发送 HTTP 探测请求")
	}
}

func TestAuditHTTPProbeCollectsFavicon(t *testing.T) {
	var icons atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			icons.Add(1)
			w.Header().Set("Content-Type", "image/x-icon")
			w.Write([]byte{0, 0, 1, 0, 1, 0, 16, 16, 0, 0})
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><link rel="icon" href="/favicon.ico"></head><body>audit</body></html>`)
	}))
	defer srv.Close()
	out, err := New(Options{Targets: []string{srv.URL}, Threads: 1, TimeoutSeconds: 1}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for response := range out {
		count++
		t.Logf("favicon hash=%q", response.FavIconMMH3)
		if response.FavIconMMH3 == "" {
			t.Error("HTTP 指纹上下文缺少 favicon hash")
		}
	}
	if count == 0 {
		t.Fatal("未获得页面响应")
	}
	t.Logf("favicon 请求数=%d", icons.Load())
	if icons.Load() == 0 {
		t.Error("HTTP 探测未请求 favicon")
	}
}
