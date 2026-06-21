package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"dddd-next/internal/discovery/httpprobe"
	"dddd-next/internal/fingerprint"
)

// TestNacosFingerprintEndToEnd guards the full fingerprint pipeline (httpprobe
// product-path -> ToFingerprintContext -> engine.Match): a nacos page must tag
// as Alibaba-Nacos. Proves the engine isn't silently dropping title=/body= rules.
func TestNacosFingerprintEndToEnd(t *testing.T) {
	const nacosHTML = `<!DOCTYPE html><html><head><title>Nacos</title>` +
		`<link rel="icon" href="console-ui/public/img/nacos-logo.png">` +
		`<link href="console-ui/public/css/bootstrap.css" rel="stylesheet">` +
		`<script src="console-ui/public/js/jquery.min.js"></script>` +
		`</head><body><div id="app">Nacos</div></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Root 404 like real nacos; console lives under /nacos/.
		if r.URL.Path == "/nacos/" || r.URL.Path == "/nacos" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(nacosHTML))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	eng, _, err := fingerprint.LoadYAML("../../configs/fingers/finger.yaml")
	if err != nil {
		t.Fatalf("load finger.yaml: %v", err)
	}

	// Probe the product path the same way dirProbe does.
	probe := httpprobe.New(httpprobe.Options{
		Targets:      []string{srv.URL},
		RequestPaths: []string{"/nacos/"},
		TechDetect:   true,
	})
	ch, err := probe.Run(context.Background())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	var got []string
	for resp := range ch {
		t.Logf("URL=%s Title=%q BodyLen=%d Tech=%v", resp.URL, resp.Title, len(resp.Body), resp.Technologies)
		ctx := httpprobe.ToFingerprintContext(resp)
		t.Logf("ctx title=%q bodyHasLogo=%v", ctx["title"], strings.Contains(ctx["body"], "nacos-logo.png"))
		for _, fp := range eng.Match(ctx) {
			got = append(got, fp.Name)
		}
	}
	t.Logf("fingerprints matched: %v", got)

	if !contains(got, "Alibaba-Nacos") {
		t.Errorf("Alibaba-Nacos not matched; got %v", got)
	}
}

func TestDVWAFingerprintEndToEnd(t *testing.T) {
	const dvwaHTML = `<!DOCTYPE html><html><head>` +
		`<title>Login :: Damn Vulnerable Web Application (DVWA) v1.9</title>` +
		`<link rel="stylesheet" type="text/css" href="dvwa/css/login.css" />` +
		`</head><body><img src="dvwa/images/login_logo.png" /></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(dvwaHTML))
	}))
	defer srv.Close()

	eng, _, err := fingerprint.LoadYAML("../../configs/fingers/finger.yaml")
	if err != nil {
		t.Fatalf("load finger.yaml: %v", err)
	}

	probe := httpprobe.New(httpprobe.Options{
		Targets:    []string{srv.URL},
		TechDetect: true,
	})
	ch, err := probe.Run(context.Background())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	var got []string
	for resp := range ch {
		t.Logf("URL=%s Title=%q BodyLen=%d BodyHasDVWA=%v", resp.URL, resp.Title, len(resp.Body), strings.Contains(resp.Body, "dvwa/css/login.css"))
		for _, fp := range eng.Match(httpprobe.ToFingerprintContext(resp)) {
			got = append(got, fp.Name)
		}
	}

	if !contains(got, "DVWA") {
		t.Errorf("DVWA not matched; got %v", got)
	}
}

func TestWebGoatFingerprintEndToEnd(t *testing.T) {
	const webGoatHTML = `<!DOCTYPE html><html><head>` +
		`<title>Login Page</title>` +
		`<link rel="stylesheet" type="text/css" href="/WebGoat/css/main.css"/>` +
		`</head><body><a href="/WebGoat/start.mvc" class="logo"><span>Web</span>Goat</a></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(webGoatHTML))
	}))
	defer srv.Close()

	eng, _, err := fingerprint.LoadYAML("../../configs/fingers/finger.yaml")
	if err != nil {
		t.Fatalf("load finger.yaml: %v", err)
	}

	probe := httpprobe.New(httpprobe.Options{
		Targets:    []string{srv.URL},
		TechDetect: true,
	})
	ch, err := probe.Run(context.Background())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	var got []string
	for resp := range ch {
		for _, fp := range eng.Match(httpprobe.ToFingerprintContext(resp)) {
			got = append(got, fp.Name)
		}
	}

	if !contains(got, "WebGoat") {
		t.Errorf("WebGoat not matched; got %v", got)
	}
}

func TestLiveDVWAProbeDiagnostic(t *testing.T) {
	target := os.Getenv("DDDD_LIVE_DVWA_URL")
	if target == "" {
		t.Skip("set DDDD_LIVE_DVWA_URL to run live DVWA probe diagnostic")
	}

	eng, _, err := fingerprint.LoadYAML("../../configs/fingers/finger.yaml")
	if err != nil {
		t.Fatalf("load finger.yaml: %v", err)
	}
	probe := httpprobe.New(httpprobe.Options{
		Targets:         []string{target},
		TechDetect:      true,
		FollowRedirects: true,
	})
	ch, err := probe.Run(context.Background())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	for resp := range ch {
		t.Logf("URL=%s Status=%d Title=%q BodyLen=%d BodyHasDVWA=%v BodyHasCSS=%v Headers=%q",
			resp.URL, resp.StatusCode, resp.Title, len(resp.Body),
			strings.Contains(strings.ToLower(resp.Body), "damn vulnerable"),
			strings.Contains(resp.Body, "dvwa/css/login.css"),
			resp.RawHeaders,
		)
		var names []string
		for _, fp := range eng.Match(httpprobe.ToFingerprintContext(resp)) {
			names = append(names, fp.Name)
		}
		t.Logf("fingerprints=%v", names)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
