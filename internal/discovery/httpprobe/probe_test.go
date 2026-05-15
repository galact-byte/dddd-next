package httpprobe

import (
	"context"
	"errors"
	"testing"

	"github.com/projectdiscovery/httpx/runner"
)

func TestNewDefaults(t *testing.T) {
	p := New(Options{Targets: []string{"http://example.com"}})
	if p.opts.Threads != 50 {
		t.Errorf("Threads default = %d, want 50", p.opts.Threads)
	}
	if p.opts.TimeoutSeconds != 10 {
		t.Errorf("Timeout default = %d, want 10", p.opts.TimeoutSeconds)
	}
	if p.opts.Methods != "GET" {
		t.Errorf("Methods default = %q, want GET", p.opts.Methods)
	}
	if p.opts.MaxBodyBytes != 2<<20 {
		t.Errorf("MaxBodyBytes default = %d, want 2 MiB", p.opts.MaxBodyBytes)
	}
}

func TestNewExplicitValuesRespected(t *testing.T) {
	p := New(Options{
		Targets:        []string{"x"},
		Threads:        10,
		TimeoutSeconds: 5,
		Methods:        "POST",
		MaxBodyBytes:   1024,
	})
	if p.opts.Threads != 10 || p.opts.TimeoutSeconds != 5 ||
		p.opts.Methods != "POST" || p.opts.MaxBodyBytes != 1024 {
		t.Errorf("explicit opts not respected: %+v", p.opts)
	}
}

func TestRunRejectsEmptyTargets(t *testing.T) {
	p := New(Options{})
	if _, err := p.Run(context.Background()); err == nil {
		t.Error("expected error for empty targets")
	}
}

func TestToResponseMapping(t *testing.T) {
	src := runner.Result{
		Input:         "http://example.com",
		URL:           "http://example.com/",
		FinalURL:      "http://example.com/final",
		Scheme:        "http",
		Host:          "example.com",
		Port:          "80",
		Path:          "/",
		StatusCode:    200,
		ContentLength: 1234,
		ContentType:   "text/html",
		Title:         "Hello",
		WebServer:     "nginx",
		ResponseBody:  "<html>welcome</html>",
		RawHeaders:    "Server: nginx\r\n",
		FavIconMMH3:   "abc123",
		Technologies:  []string{"WordPress", "PHP"},
		A:             []string{"1.2.3.4"},
		CDN:           true,
		Failed:        false,
		Err:           nil,
	}

	got := toResponse(src)

	checks := map[string]bool{
		"Input":         got.Input == "http://example.com",
		"URL":           got.URL == "http://example.com/",
		"FinalURL":      got.FinalURL == "http://example.com/final",
		"Scheme":        got.Scheme == "http",
		"Host":          got.Host == "example.com",
		"Port":          got.Port == "80",
		"Path":          got.Path == "/",
		"StatusCode":    got.StatusCode == 200,
		"ContentLength": got.ContentLength == 1234,
		"ContentType":   got.ContentType == "text/html",
		"Title":         got.Title == "Hello",
		"WebServer":     got.WebServer == "nginx",
		"Body":          got.Body == "<html>welcome</html>",
		"RawHeaders":    got.RawHeaders == "Server: nginx\r\n",
		"FavIconMMH3":   got.FavIconMMH3 == "abc123",
		"TechCount":     len(got.Technologies) == 2 && got.Technologies[0] == "WordPress",
		"ACount":        len(got.A) == 1 && got.A[0] == "1.2.3.4",
		"CDN":           got.CDN,
		"Failed":        got.Failed == false,
		"Err":           got.Err == "",
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("field %s mismatch (got %+v)", name, got)
		}
	}
}

func TestToResponseErrSerialization(t *testing.T) {
	src := runner.Result{Err: errors.New("dial timeout")}
	got := toResponse(src)
	if got.Err != "dial timeout" {
		t.Errorf("Err = %q, want dial timeout", got.Err)
	}
}

func TestToResponseSliceIsolation(t *testing.T) {
	tech := []string{"Apache"}
	src := runner.Result{Technologies: tech}
	got := toResponse(src)
	tech[0] = "MUTATED"
	if got.Technologies[0] != "Apache" {
		t.Errorf("Response.Technologies aliases source slice — mutation leaked: %v", got.Technologies)
	}
}

func TestToFingerprintContext(t *testing.T) {
	resp := Response{
		Body:        "wp-content stuff",
		Title:       "WordPress Site",
		RawHeaders:  "Server: nginx\r\nX-Powered-By: PHP/7\r\n",
		WebServer:   "nginx",
		Scheme:      "https",
		FavIconMMH3: "12345",
	}
	ctx := ToFingerprintContext(resp)
	cases := map[string]string{
		"body":         "wp-content stuff",
		"title":        "WordPress Site",
		"header":       "Server: nginx\r\nX-Powered-By: PHP/7\r\n",
		"banner":       "nginx",
		"protocol":     "https",
		"icon_hash":    "12345",
		"favicon_hash": "12345",
	}
	for k, want := range cases {
		if ctx[k] != want {
			t.Errorf("ctx[%q] = %q, want %q", k, ctx[k], want)
		}
	}
}
