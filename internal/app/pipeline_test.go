package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"dddd-next/internal/audit"
	"dddd-next/internal/config"
	"dddd-next/internal/discovery/httpprobe"
	"dddd-next/internal/discovery/portscan"
	"dddd-next/internal/fingerprint"
	"dddd-next/internal/reporter"
	"dddd-next/internal/types"
)

func TestHostPort(t *testing.T) {
	if got := hostPort(types.Target{Host: "1.2.3.4"}); got != "1.2.3.4" {
		t.Errorf("hostPort no-port = %q, want 1.2.3.4", got)
	}
	if got := hostPort(types.Target{Host: "1.2.3.4", Port: 8080}); got != "1.2.3.4:8080" {
		t.Errorf("hostPort with-port = %q, want 1.2.3.4:8080", got)
	}
}

func TestDedup(t *testing.T) {
	got := dedup([]string{"a", "b", "a", "", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("dedup = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dedup[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseTargetsClassification(t *testing.T) {
	p := &Pipeline{cfg: config.Config{Targets: []string{
		"http://example.com", // URL  -> probe
		"1.2.3.4",            // IP   -> port scan
		"1.2.3.4:8080",       // IP:Port -> probe
		"sub.example.com",    // domain -> enum/resolve
		"192.168.0.0/24",     // CIDR -> port scan
		`app="seeyon"`,       // search query -> recon
		"[FP] http://1.2.3.4:9090 | Nacos | confidence=90", // resume -> POC直接
	}}}
	probeInputs, directPorts, domains, portscanSpecs, searchQueries, fingerImports := p.parseTargets()

	if len(fingerImports) != 1 || len(fingerImports["http://1.2.3.4:9090"]) != 1 {
		t.Errorf("fingerImports = %v, want 1 import with 1 finger", fingerImports)
	}

	if len(domains) != 1 || domains[0] != "sub.example.com" {
		t.Errorf("domains = %v, want [sub.example.com]", domains)
	}
	if len(probeInputs) != 1 || probeInputs[0] != "http://example.com" {
		t.Errorf("probeInputs = %v, want only direct URL", probeInputs)
	}
	if len(directPorts) != 1 || directPorts[0].Host != "1.2.3.4" || directPorts[0].Port != 8080 {
		t.Errorf("directPorts = %v, want 1.2.3.4:8080", directPorts)
	}
	if len(portscanSpecs) != 2 {
		t.Errorf("portscanSpecs = %v, want [1.2.3.4 192.168.0.0/24]", portscanSpecs)
	}
	if len(searchQueries) != 1 {
		t.Errorf("searchQueries = %v, want 1 entry", searchQueries)
	}
}

func TestWebProbeInputsSkipKnownNonWebServices(t *testing.T) {
	open := []portscan.Result{
		{Host: "192.168.1.10", Port: 22},
		{Host: "192.168.1.10", Port: 3306},
		{Host: "192.168.1.10", Port: 8848},
		{Host: "192.168.1.10", Port: 8080},
	}
	services := map[string]string{
		"192.168.1.10:22":   "ssh",
		"192.168.1.10:3306": "mysql",
		"192.168.1.10:8848": "http",
	}

	got := webProbeInputs(open, services)
	want := []string{"192.168.1.10:8848", "192.168.1.10:8080"}
	if len(got) != len(want) {
		t.Fatalf("webProbeInputs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("webProbeInputs = %v, want %v", got, want)
		}
	}
}

func TestShouldHTTPProbeIncludesNacosFallbackPort(t *testing.T) {
	if !shouldHTTPProbe(8848, "192.168.1.10:8848", nil) {
		t.Fatal("8848 should be treated as a web probe candidate for Nacos")
	}
}

func TestHostDiscoveryHonorsNoICMPPing(t *testing.T) {
	cfg := config.Defaults()
	cfg.PingFirst = true
	cfg.NoICMPPing = true
	p := &Pipeline{cfg: cfg}

	got := p.hostDiscovery(context.Background(), []string{"127.0.0.1"})
	if len(got) != 0 {
		t.Fatalf("hostDiscovery with NoICMPPing = %v, want no ICMP-only result", got)
	}
}

func TestDirProbeSkipsNotFoundResponses(t *testing.T) {
	resp := httpprobe.Response{
		URL:        "http://example.test/smartbi/vision/index.jsp",
		StatusCode: 404,
		Body:       "The requested URL /smartbi/vision/index.jsp was not found on this server.",
	}
	if shouldFingerprintDirProbeResponse(resp) {
		t.Fatal("product-path probing should not fingerprint 404 responses")
	}
}

func TestShiroTargetsDeduplicateRedirectSessionURLs(t *testing.T) {
	got := shiroTargets([]string{
		"http://example.test:8080",
		"http://example.test:8080/login;jsessionid=ABCDEF",
		"http://other.test/app/login;jsessionid=123456?next=/",
	})
	want := []string{
		"http://example.test:8080",
		"http://other.test/app/login",
	}
	if len(got) != len(want) {
		t.Fatalf("shiroTargets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("shiroTargets = %v, want %v", got, want)
		}
	}
}

func TestDeduplicateSessionRedirectPOCTargetsPreferRootWithSameTemplates(t *testing.T) {
	got := deduplicateSessionRedirectPOCTargets(map[string][]string{
		"http://example.test:8080":                         {"shiro-detect.yaml"},
		"http://example.test:8080/login;jsessionid=ABCDEF": {"shiro-detect.yaml"},
		"http://nacos.test:8848":                           {"CVE-2021-29441.yaml"},
		"http://nacos.test:8848/nacos/":                    {"CVE-2021-29441.yaml"},
		"http://app.test/admin;jsessionid=123":             {"path-only.yaml"},
	})

	if _, ok := got["http://example.test:8080/login"]; ok {
		t.Fatalf("session redirect target should collapse into root; got targets %v", keysOfStringSlices(got))
	}
	if _, ok := got["http://example.test:8080"]; !ok {
		t.Fatalf("root target missing after collapse; got targets %v", keysOfStringSlices(got))
	}
	if _, ok := got["http://nacos.test:8848/nacos/"]; !ok {
		t.Fatalf("non-session product path should be preserved; got targets %v", keysOfStringSlices(got))
	}
	if _, ok := got["http://app.test/admin"]; !ok {
		t.Fatalf("session path without matching root templates should be preserved; got targets %v", keysOfStringSlices(got))
	}
}

func TestProbeAndFingerprintFollowsRelativeLoginRedirect(t *testing.T) {
	const dvwaLogin = `<!DOCTYPE html><html><head>` +
		`<title>Login :: Damn Vulnerable Web Application (DVWA) v1.9</title>` +
		`<link rel="stylesheet" type="text/css" href="dvwa/css/login.css" />` +
		`</head><body><img src="dvwa/images/login_logo.png" /></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "login.php", http.StatusFound)
		case "/login.php":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(dvwaLogin))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	eng, _, err := fingerprint.LoadYAML("../../configs/fingers/finger.yaml")
	if err != nil {
		t.Fatalf("load finger.yaml: %v", err)
	}
	p := &Pipeline{
		cfg:      config.Config{OutputType: "text", Output: filepath.Join(t.TempDir(), "r.txt")},
		finger:   eng,
		reporter: reporter.NewTextWriter(io.Discard),
		auditor:  audit.Disabled(),
	}

	live, hits := p.probeAndFingerprint(context.Background(), []string{srv.URL})
	loginURL := srv.URL + "/login.php"
	if !contains(live, loginURL) {
		t.Fatalf("live URLs = %v, want redirected login URL %s", live, loginURL)
	}
	if !contains(hits[loginURL], "DVWA") {
		t.Fatalf("fingerprint hits for %s = %v, want DVWA", loginURL, hits[loginURL])
	}
}

func TestBuildReporterText(t *testing.T) {
	cfg := config.Config{OutputType: "text", Output: filepath.Join(t.TempDir(), "r.txt")}
	rep, err := buildReporter(cfg)
	if err != nil {
		t.Fatalf("buildReporter: %v", err)
	}
	if err := rep.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestBuildReporterJSONWithHTML(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		OutputType: "json",
		Output:     filepath.Join(dir, "r.json"),
		HTMLOutput: filepath.Join(dir, "r.html"),
	}
	rep, err := buildReporter(cfg)
	if err != nil {
		t.Fatalf("buildReporter: %v", err)
	}
	if err := rep.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNewMissingFingerprints(t *testing.T) {
	cfg := config.Config{OutputType: "text", Output: filepath.Join(t.TempDir(), "r.txt")}
	// An empty configDir has no fingers/finger.yaml, so New must fail loudly
	// rather than silently scanning with zero fingerprints.
	if _, err := New(cfg, t.TempDir()); err == nil {
		t.Error("expected error when fingerprint DB is missing")
	}
}

func TestNewUsesConfiguredFingerYAML(t *testing.T) {
	dir := t.TempDir()
	fingerPath := filepath.Join(dir, "custom-finger.yaml")
	if err := os.WriteFile(fingerPath, []byte("Custom-App:\n  - 'title=\"Custom\"'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		OutputType:           "text",
		Output:               filepath.Join(dir, "r.txt"),
		FingerConfigFilePath: fingerPath,
	}

	p, err := New(cfg, filepath.Join(dir, "missing-default-configs"))
	if err != nil {
		t.Fatalf("New with custom finger yaml: %v", err)
	}
	defer p.Close()
	if p.finger.Size() != 1 {
		t.Fatalf("finger engine size = %d, want 1", p.finger.Size())
	}
}

func keysOfStringSlices(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
