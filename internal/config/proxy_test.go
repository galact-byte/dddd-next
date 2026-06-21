package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTestProxyUsesConfiguredProxy(t *testing.T) {
	used := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		used <- r.URL.String()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := TestProxy(ctx, proxy.URL, "http://example.invalid/proxy-test"); err != nil {
		t.Fatalf("TestProxy returned error: %v", err)
	}

	select {
	case got := <-used:
		if got != "http://example.invalid/proxy-test" {
			t.Fatalf("proxy saw URL %q", got)
		}
	default:
		t.Fatal("proxy server was not used")
	}
}

func TestTestProxyRejectsMissingProxyURL(t *testing.T) {
	if err := TestProxy(context.Background(), "", "http://example.com"); err == nil {
		t.Fatal("expected error for empty proxy URL")
	}
}

func TestRedactURLCredentials(t *testing.T) {
	got := RedactURLCredentials("http://user:secret@127.0.0.1:8080")
	want := "http://user:xxxxx@127.0.0.1:8080"
	if got != want {
		t.Fatalf("RedactURLCredentials = %q, want %q", got, want)
	}
	if got := RedactURLCredentials("socks5://127.0.0.1:1080"); got != "socks5://127.0.0.1:1080" {
		t.Fatalf("URL without credentials should be unchanged, got %q", got)
	}
}
