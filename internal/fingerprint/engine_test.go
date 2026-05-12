package fingerprint

import (
	"os"
	"path/filepath"
	"testing"

	"dddd-next/pkg/fingerdsl"
)

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "finger.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write tmp yaml: %v", err)
	}
	return p
}

func TestLoadYAMLBasic(t *testing.T) {
	p := writeTempYAML(t, `Apache-HTTP:
  - 'header="Server: Apache"'
  - 'banner="Apache/2.4"'
Nginx:
  - title="Welcome to nginx"
`)
	e, stats, err := LoadYAML(p)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}
	if stats.Compiled != 3 {
		t.Errorf("Compiled = %d, want 3", stats.Compiled)
	}
	if stats.Failed != 0 {
		t.Errorf("Failed = %d, want 0 (%+v)", stats.Failed, stats.Failures)
	}
	if e.Size() != 3 {
		t.Errorf("Engine.Size = %d, want 3", e.Size())
	}
}

func TestMatch(t *testing.T) {
	p := writeTempYAML(t, `Apache:
  - 'header="Server: Apache"'
Nginx:
  - 'header="Server: nginx"'
WordPress:
  - 'body="wp-content"'
`)
	e, _, err := LoadYAML(p)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}

	hits := e.Match(fingerdsl.Context{
		"header": "Server: nginx/1.20",
		"body":   "<html>welcome</html>",
	})
	if len(hits) != 1 {
		t.Fatalf("hits = %d (%+v)", len(hits), hits)
	}
	if hits[0].Name != "Nginx" {
		t.Errorf("hit name = %q, want Nginx", hits[0].Name)
	}

	// Multi-hit case
	hits2 := e.Match(fingerdsl.Context{
		"header": "Server: Apache",
		"body":   "<a href='/wp-content/themes/x'>",
	})
	if len(hits2) != 2 {
		t.Errorf("expected 2 hits, got %d", len(hits2))
	}
}

func TestLoadYAMLBadExpressionsCounted(t *testing.T) {
	p := writeTempYAML(t, `Good:
  - 'title="hello"'
Bad:
  - 'title='
Another:
  - 'banner="ok"'
`)
	e, stats, err := LoadYAML(p)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if stats.Total != 3 || stats.Compiled != 2 || stats.Failed != 1 {
		t.Errorf("stats = %+v, want total=3 compiled=2 failed=1", stats)
	}
	if e.Size() != 2 {
		t.Errorf("Engine.Size = %d, want 2", e.Size())
	}
	if len(stats.Failures) != 1 || stats.Failures[0].Name != "Bad" {
		t.Errorf("Failures = %+v", stats.Failures)
	}
}

func TestLoadYAMLEmpty(t *testing.T) {
	p := writeTempYAML(t, "")
	e, stats, err := LoadYAML(p)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if e.Size() != 0 || stats.Total != 0 {
		t.Errorf("expected empty engine")
	}
}

func TestNilEngine(t *testing.T) {
	var e *Engine
	if e.Size() != 0 {
		t.Error("nil Size should be 0")
	}
	if e.Match(fingerdsl.Context{}) != nil {
		t.Error("nil Match should return nil")
	}
}

func TestLoadRealFingerYAML(t *testing.T) {
	candidates := []string{
		"../../configs/fingers/finger.yaml",
		"configs/fingers/finger.yaml",
	}
	var path string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		t.Skip("finger.yaml not located relative to test cwd")
	}

	e, stats, err := LoadYAML(path)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	t.Logf("real finger.yaml: total=%d compiled=%d failed=%d engine_size=%d",
		stats.Total, stats.Compiled, stats.Failed, e.Size())
	if stats.Total < 1000 {
		t.Errorf("expected thousands of rules, got %d", stats.Total)
	}
	if rate := float64(stats.Failed) / float64(stats.Total); rate > 0.01 {
		t.Errorf("failure rate %.3f%% exceeds 1%% — DSL/loader drift", rate*100)
	}
}
