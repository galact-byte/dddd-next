package hunter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseBanner(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nServer: nginx/1.20.1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><title>Login</title></html>"
	b := ParseBanner(raw)

	if b.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", b.StatusCode)
	}
	if b.Server != "nginx/1.20.1" {
		t.Errorf("Server = %q, want nginx/1.20.1", b.Server)
	}
	if b.ContentType != "text/html; charset=utf-8" {
		t.Errorf("ContentType = %q", b.ContentType)
	}
	if b.Body != "<html><title>Login</title></html>" {
		t.Errorf("Body = %q", b.Body)
	}
}

func TestParseBannerLFOnly(t *testing.T) {
	b := ParseBanner("HTTP/1.1 404 Not Found\nServer: Apache\n\nnope")
	if b.StatusCode != 404 || b.Server != "Apache" || b.Body != "nope" {
		t.Errorf("LF parse failed: %+v", b)
	}
}

func TestSearchParsesBanner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("is_web") != "3" {
			t.Errorf("is_web = %q, want 3", r.URL.Query().Get("is_web"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"code": 200,
			"data": {
				"total": 1,
				"arr": [{
					"url": "http://1.2.3.4:8080",
					"ip": "1.2.3.4",
					"port": 8080,
					"domain": "demo.example.com",
					"protocol": "http",
					"is_web": "是",
					"status_code": 200,
					"web_title": "Demo",
					"banner": "HTTP/1.1 200 OK\r\nServer: Jetty\r\n\r\n<html>hi</html>"
				}]
			}
		}`))
	}))
	defer srv.Close()

	c, err := New(Options{APIKey: "test", MaxPages: 1})
	if err != nil {
		t.Fatal(err)
	}
	c.baseURL = srv.URL

	assets, err := c.Search(context.Background(), `app="demo"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 {
		t.Fatalf("got %d assets, want 1", len(assets))
	}
	a := assets[0]
	if !a.IsWeb {
		t.Error("IsWeb = false, want true")
	}
	if a.Banner == "" {
		t.Error("Banner is empty — the whole point of -lpm is to carry it")
	}
	if b := ParseBanner(a.Banner); b.Server != "Jetty" {
		t.Errorf("banner Server = %q, want Jetty", b.Server)
	}
}

func TestNewRequiresKey(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("New with no API key should error")
	}
}
