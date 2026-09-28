package httpprobe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestProductPathsKeepURLAndOriginalInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, "page")
	}))
	defer srv.Close()
	target := srv.URL + "/base?root=1"
	out, err := New(Options{Targets: []string{target}, RequestPaths: []string{"/api?view=2", "/login"}, Threads: 1, TimeoutSeconds: 1}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for response := range out {
		u, err := url.Parse(response.URL)
		if err != nil {
			t.Fatal(err)
		}
		if response.Input != target || u.Query().Get("root") != "1" {
			t.Errorf("lost input/query: %+v", response)
		}
		if u.Path == "/base/api" && u.Query().Get("view") != "2" {
			t.Errorf("lost path query: %s", response.URL)
		}
		seen[u.Path] = true
	}
	if len(seen) != 2 || !seen["/base/api"] || !seen["/base/login"] {
		t.Fatalf("product paths=%v", seen)
	}
}
