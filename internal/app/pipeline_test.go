package app

import (
	"path/filepath"
	"testing"

	"dddd-next/internal/config"
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
	probeInputs, domains, portscanSpecs, searchQueries, fingerImports := p.parseTargets()

	if len(fingerImports) != 1 || len(fingerImports["http://1.2.3.4:9090"]) != 1 {
		t.Errorf("fingerImports = %v, want 1 import with 1 finger", fingerImports)
	}

	if len(domains) != 1 || domains[0] != "sub.example.com" {
		t.Errorf("domains = %v, want [sub.example.com]", domains)
	}
	if len(probeInputs) != 2 {
		t.Errorf("probeInputs = %v, want 2 entries (URL + IP:Port)", probeInputs)
	}
	if len(portscanSpecs) != 2 {
		t.Errorf("portscanSpecs = %v, want [1.2.3.4 192.168.0.0/24]", portscanSpecs)
	}
	if len(searchQueries) != 1 {
		t.Errorf("searchQueries = %v, want 1 entry", searchQueries)
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
