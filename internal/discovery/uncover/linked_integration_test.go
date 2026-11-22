package uncover

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestQueryHunterFofaAdapters(t *testing.T) {
	setFofaKeys(t)
	t.Setenv("HUNTER_API_KEY", "fixture-hunter-key")
	var hunterCalls, fofaCalls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hunterCalls.Add(1)
		q, _ := base64.URLEncoding.DecodeString(r.URL.Query().Get("search"))
		if string(q) != `icp.name="公司"` {
			t.Errorf("Hunter query=%q", q)
		}
		fmt.Fprint(w, `{"code":200,"data":{"total":1,"arr":[{"ip":"192.0.2.1","port":80,"domain":"seed.example.com"}]}}`)
	}))
	defer upstream.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			fofaCalls.Add(1)
			q, _ := base64.StdEncoding.DecodeString(r.URL.Query().Get("qbase64"))
			if r.Host != "fofa.fixture" || string(q) != `ip="192.0.2.1"` {
				t.Errorf("FOFA request %s %q", r.Host, q)
			}
			fmt.Fprint(w, `{"error":false,"size":1,"results":[["192.0.2.1","8443",""]]}`)
			return
		}
		if r.Host != "hunter.qianxin.com:443" {
			http.Error(w, "unexpected host", 400)
			return
		}
		dst, err := net.Dial("tcp", upstream.Listener.Addr().String())
		if err != nil {
			t.Error(err)
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
	assets, err := New(Options{Agents: []string{"hunter", "fofa"}, HunterFofa: true, FofaServer: "http://fofa.fixture", Proxy: proxy.URL}).Query(context.Background(), `icp.name="公司"`, 1)
	if err != nil || len(assets) != 2 || assets[0].Port != 80 || assets[1].Port != 8443 || hunterCalls.Load() != 1 || fofaCalls.Load() != 1 {
		t.Fatalf("assets=%+v err=%v Hunter=%d FOFA=%d", assets, err, hunterCalls.Load(), fofaCalls.Load())
	}
}
