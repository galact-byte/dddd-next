package uncover

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func setFofaKeys(t *testing.T) {
	t.Helper()
	t.Setenv("FOFA_EMAIL", "test@example.com")
	t.Setenv("FOFA_KEY", "test-key+/=&")
}

func TestQueryFofaPagination(t *testing.T) {
	setFofaKeys(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		q := r.URL.Query()
		if q.Get("size") != "100" {
			t.Errorf("page size changed: %s", q.Get("size"))
		}
		page, _ := strconv.Atoi(q.Get("page"))
		rows := make([][]string, 100)
		for i := range rows {
			rows[i] = []string{fmt.Sprintf("192.0.2.%d", (page-1)*100+i+1), "80", ""}
		}
		json.NewEncoder(w).Encode(map[string]any{"error": false, "size": 200, "results": rows})
	}))
	defer server.Close()
	assets, err := New(Options{Agents: []string{"fofa"}, FofaServer: server.URL}).Query(context.Background(), `port="80"`, 101)
	if err != nil || len(assets) != 101 || calls.Load() != 2 {
		t.Fatalf("assets=%d calls=%d err=%v", len(assets), calls.Load(), err)
	}
	if assets[100].IP != "192.0.2.101" {
		t.Fatalf("page boundary duplicated or skipped: %+v", assets[100])
	}
}

func TestQueryFofaFailurePreservesFirstPage(t *testing.T) {
	setFofaKeys(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			fmt.Fprint(w, `{"error":false,"size":101,"results":[["192.0.2.1","80",""]]}`)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()
	assets, err := New(Options{Agents: []string{"fofa"}, FofaServer: server.URL}).Query(context.Background(), `port="80"`, 101)
	if len(assets) != 1 || err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("assets=%+v err=%v", assets, err)
	}
}

func TestQueryFofaResponseErrors(t *testing.T) {
	setFofaKeys(t)
	for _, tt := range []struct {
		name, body, want string
		status, assets   int
	}{
		{name: "zero", body: `{"error":false,"size":0,"results":[]}`},
		{name: "api", body: `{"error":true,"errmsg":"bad test-key+/=& test-key%2B%2F%3D%26 test@example.com"}`, want: "API error"},
		{name: "unauthorized", status: 401, want: "HTTP 401"},
		{name: "html", body: `<html>proxy error</html>`, want: "invalid FOFA JSON"},
		{name: "empty object", body: `{}`, want: "invalid FOFA response"},
		{name: "null", body: `null`, want: "invalid FOFA response"},
		{name: "missing results", body: `{"error":false,"size":5}`, want: "invalid FOFA response"},
		{name: "negative size", body: `{"error":false,"size":-1,"results":[]}`, want: "invalid FOFA response"},
		{name: "malformed rows", body: `{"error":false,"size":4,"results":[[],["192.0.2.1","70000",""],["not-ip","80",""],["192.0.2.2","80","example.com:80"]]}`, want: "3 invalid result rows", assets: 1},
		{name: "oversize", body: strings.Repeat(" ", (4<<20)+1), want: "exceeds 4 MiB"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if tt.status != 0 {
					w.WriteHeader(tt.status)
				}
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			assets, err := New(Options{Agents: []string{"fofa"}, FofaServer: server.URL}).Query(context.Background(), `port="80"`, 5)
			if len(assets) != tt.assets {
				t.Fatalf("assets = %+v", assets)
			}
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
			if err != nil {
				for _, secret := range []string{"test-key+/=&", "test-key%2B%2F%3D%26", "test@example.com"} {
					if strings.Contains(err.Error(), secret) {
						t.Fatal("credential leaked in error")
					}
				}
			}
			if requests.Load() != 1 {
				t.Errorf("unexpected retry or extra page: %d", requests.Load())
			}
		})
	}
}

func TestQueryFofaInvalidServerAndMissingKeys(t *testing.T) {
	setFofaKeys(t)
	for _, address := range []string{"ftp://example.com", "example.com", "http://", "https://user:password@example.com", "https://example.com?key=secret", "https://example.com/#fragment", "https://example.com:99999"} {
		_, err := New(Options{Agents: []string{"fofa"}, FofaServer: address}).Query(context.Background(), `port="80"`, 1)
		if err == nil || !strings.Contains(err.Error(), "FOFA_SERVER") {
			t.Errorf("address %q: %v", address, err)
		}
	}
	t.Setenv("FOFA_KEY", "")
	_, err := New(Options{Agents: []string{"fofa"}, FofaServer: "http://127.0.0.1:1"}).Query(context.Background(), `port="80"`, 1)
	if err == nil || !strings.Contains(err.Error(), "FOFA_EMAIL and FOFA_KEY") {
		t.Fatalf("missing credentials: %v", err)
	}
}

func TestQueryFofaOfficialDefaultThroughProxy(t *testing.T) {
	setFofaKeys(t)
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "CONNECT" || r.Host != "fofa.info:443" {
			t.Errorf("official default: %s %s", r.Method, r.Host)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxy.Close()
	_, err := New(Options{Agents: []string{"fofa"}, Proxy: proxy.URL, Timeout: 1}).Query(context.Background(), `port="80"`, 1)
	if err == nil || calls.Load() == 0 {
		t.Fatalf("no request to official endpoint via proxy: calls=%d err=%v", calls.Load(), err)
	}
}

func TestQueryFofaCancellationAndTimeout(t *testing.T) {
	setFofaKeys(t)
	for _, cancelled := range []bool{true, false} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if cancelled {
					cancel()
				}
				<-r.Context().Done()
			}))
			defer server.Close()
			started := time.Now()
			_, err := New(Options{Agents: []string{"fofa"}, FofaServer: server.URL, Timeout: 1}).Query(ctx, `port="80"`, 1)
			if err == nil {
				t.Fatal("expected request failure")
			}
			if cancelled && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation = %v", err)
			}
			if !cancelled && !strings.Contains(err.Error(), "timed out") {
				t.Fatalf("timeout = %v", err)
			}
			if time.Since(started) > 6*time.Second {
				t.Fatal("request did not stop promptly")
			}
		})
	}
}

func TestQueryFofaRejectsCrossOriginRedirectAndInvalidTLS(t *testing.T) {
	setFofaKeys(t)
	var reached atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"?key="+url.QueryEscape("test-key+/=&"), http.StatusFound)
	}))
	defer server.Close()
	_, err := New(Options{Agents: []string{"fofa"}, FofaServer: server.URL}).Query(context.Background(), `port="80"`, 1)
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") || reached.Load() != 0 {
		t.Fatalf("redirect reached=%d err=%v", reached.Load(), err)
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer tlsServer.Close()
	_, err = New(Options{Agents: []string{"fofa"}, FofaServer: tlsServer.URL, Timeout: 1}).Query(context.Background(), `port="80"`, 1)
	if err == nil || reached.Load() != 0 {
		t.Fatalf("untrusted TLS reached=%d err=%v", reached.Load(), err)
	}
}

func TestQueryFofaRetriesTransientStatus(t *testing.T) {
	setFofaKeys(t)
	for _, status := range []int{429, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) < 3 {
					w.WriteHeader(status)
					return
				}
				fmt.Fprint(w, `{"error":false,"size":1,"results":[["192.0.2.1","80",""]]}`)
			}))
			defer server.Close()
			assets, err := New(Options{Agents: []string{"fofa"}, FofaServer: server.URL}).Query(context.Background(), `port="80"`, 1)
			if err != nil || len(assets) != 1 || calls.Load() != 3 {
				t.Fatalf("assets=%+v calls=%d err=%v", assets, calls.Load(), err)
			}
		})
	}
}

func TestQueryFofaFailureKeepsOtherEngineResults(t *testing.T) {
	setFofaKeys(t)
	t.Setenv("QUAKE_TOKEN", "test-quake-token")
	// A local CONNECT proxy routes only the fixed Quake host to this TLS fixture.
	// No real search engine is contacted and no real credentials are used.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/search/quake_service" {
			t.Errorf("Quake path: %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"code":0,"data":[{"ip":"192.0.2.3","port":443,"hostname":"other.example.com"}],"meta":{"pagination":{"count":1,"total":1}}}`)
	}))
	defer upstream.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "quake.360.net:443" {
			http.Error(w, "unexpected destination", 400)
			return
		}
		dst, err := net.Dial("tcp", upstream.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			http.Error(w, "fixture unavailable", 500)
			return
		}
		defer dst.Close()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		done := make(chan struct{})
		go func() { io.Copy(dst, conn); dst.Close(); close(done) }()
		io.Copy(conn, dst)
		conn.Close()
		<-done
	}))
	defer proxy.Close()
	assets, err := New(Options{Agents: []string{"fofa", "quake"}, FofaServer: "invalid", Proxy: proxy.URL}).Query(context.Background(), `port="443"`, 1)
	if len(assets) != 1 || assets[0].Source != "quake" || err == nil || !strings.Contains(err.Error(), "FOFA_SERVER") {
		t.Fatalf("assets=%+v err=%v", assets, err)
	}
	assets, err = New(Options{Agents: []string{"quake"}, FofaServer: "invalid", Proxy: proxy.URL}).Query(context.Background(), `port="443"`, 1)
	if len(assets) != 1 || err != nil {
		t.Fatalf("unused FOFA setting affected Quake: assets=%+v err=%v", assets, err)
	}
}

func TestQueryFofaReportsExhaustedRetries(t *testing.T) {
	setFofaKeys(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(429) }))
	defer server.Close()
	_, err := New(Options{Agents: []string{"fofa"}, FofaServer: server.URL}).Query(context.Background(), `port="80"`, 1)
	if err == nil || !strings.Contains(err.Error(), "HTTP 429") || calls.Load() != 3 {
		t.Fatalf("calls=%d err=%v", calls.Load(), err)
	}
}

func TestQueryFofaCustomServer(t *testing.T) {
	setFofaKeys(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/gateway/api/v1/search/all" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		q := r.URL.Query()
		decoded, err := base64.StdEncoding.DecodeString(q.Get("qbase64"))
		if err != nil || string(decoded) != `title="中文 + / = &"` {
			t.Errorf("query = %q, %v", decoded, err)
		}
		for key, want := range map[string]string{"key": "test-key+/=&", "fields": "ip,port,host", "page": "1", "size": "2", "full": "false"} {
			if q.Get(key) != want {
				t.Errorf("%s = %q, want %q", key, q.Get(key), want)
			}
		}
		fmt.Fprint(w, `{"error":false,"size":2,"results":[["192.0.2.1","8443","https://example.com:8443/path"],["2001:db8::1","80",""]]}`)
	}))
	defer server.Close()
	assets, err := New(Options{Agents: []string{"fofa"}, FofaServer: server.URL + "/gateway/"}).Query(context.Background(), `title="中文 + / = &"`, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 {
		t.Fatalf("assets = %+v", assets)
	}
	if assets[0].Host != "example.com" || assets[0].URL != "https://example.com:8443/path" || assets[0].Port != 8443 || assets[0].Source != "fofa" {
		t.Errorf("first asset = %+v", assets[0])
	}
	if assets[1].Host != "2001:db8::1" {
		t.Errorf("fallback host = %+v", assets[1])
	}
}
