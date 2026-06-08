package servicedetect

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestResolveAddrIPLiteral(t *testing.T) {
	addr, ok := resolveAddr("127.0.0.1")
	if !ok || addr.String() != "127.0.0.1" {
		t.Errorf("resolveAddr(127.0.0.1) = %v,%v; want 127.0.0.1,true", addr, ok)
	}
	addr6, ok := resolveAddr("::1")
	if !ok || addr6.String() != "::1" {
		t.Errorf("resolveAddr(::1) = %v,%v; want ::1,true", addr6, ok)
	}
}

// TestDetectLocalHTTP exercises the full fingerprintx wrapper against a real
// local HTTP server, confirming a non-standard port still resolves to "http".
func TestDetectLocalHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	d := New(DefaultOptions())
	var results []Result
	for r := range d.Detect(context.Background(), []Endpoint{{Host: host, Port: port}}) {
		results = append(results, r)
	}

	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d: %v", len(results), results)
	}
	if results[0].Service != "http" {
		t.Errorf("Service = %q, want http", results[0].Service)
	}
}
