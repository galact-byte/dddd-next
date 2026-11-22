package httpprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestCompletionIncludesFailedHTTPResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("fixture")) }))
	defer srv.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	var success, failed atomic.Int64
	opts := Options{Targets: []string{srv.URL, "http://127.0.0.1:" + strconv.Itoa(port)}, Threads: 1, TimeoutSeconds: 1}
	opts.OnComplete = func(err error) {
		if err != nil {
			failed.Add(1)
		} else {
			success.Add(1)
		}
	}
	ch, err := New(opts).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	received := 0
	for range ch {
		received++
	}
	if received < 1 || success.Load() < 1 || failed.Load() < 1 {
		t.Fatalf("responses=%d success=%d failed=%d", received, success.Load(), failed.Load())
	}
}
