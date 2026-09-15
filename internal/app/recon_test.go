package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"dddd-next/internal/audit"
	"dddd-next/internal/config"
)

func TestReconFofaServerPreservesAssetsOnLaterFailure(t *testing.T) {
	t.Setenv("FOFA_EMAIL", "test@example.com")
	t.Setenv("FOFA_KEY", "test-key")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path != "/fofa/api/v1/search/all" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("page") == "1" {
			fmt.Fprint(w, `{"error":false,"size":101,"results":[["192.0.2.1","8443","https://example.com:8443/"]]}`)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()
	t.Setenv("FOFA_SERVER", server.URL+"/fofa")
	p := &Pipeline{cfg: config.Config{ReconAgents: []string{"fofa"}, ReconLimit: 101, ProxyURL: server.URL}, auditor: audit.Disabled()}
	assets := p.recon(context.Background(), []string{`port="8443"`})
	if len(assets) != 1 {
		t.Fatalf("assets = %+v", assets)
	}
	if assets[0].Host != "example.com" || assets[0].Port != 8443 {
		t.Fatalf("asset = %+v", assets[0])
	}
}
