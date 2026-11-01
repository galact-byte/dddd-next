package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dddd-next/internal/types"
)

// TestReleaseBinarySmoke exercises a built executable without downloading templates
// or scanning anything outside the loopback fixture.
func TestReleaseBinarySmoke(t *testing.T) {
	binary := os.Getenv("DDDD_SMOKE_BINARY")
	if binary == "" {
		t.Skip("set DDDD_SMOKE_BINARY to test a built executable")
	}
	payload, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	binDir, workDir, homeDir := t.TempDir(), t.TempDir(), t.TempDir()
	binary = filepath.Join(binDir, filepath.Base(binary))
	if err := os.WriteFile(binary, payload, 0755); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"} {
		t.Setenv(key, homeDir)
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "")
	}
	run := func(wantCode int, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir = workDir
		output, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("run %v: %v\n%s", args, err, output)
			}
			code = exit.ExitCode()
		}
		if code != wantCode {
			t.Fatalf("run %v: exit %d, want %d\n%s", args, code, wantCode, output)
		}
		t.Logf("run %v: exit %d\n%s", args, code, output)
		return string(output)
	}
	if output := run(0, "version"); !strings.HasPrefix(output, "dddd-next ") {
		t.Fatalf("unexpected version: %q", output)
	}
	run(0, "help")
	run(2)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Login :: Damn Vulnerable Web Application (DVWA) v1.9</title></head><body><img src="dvwa/images/login_logo.png">dddd-ci-smoke-marker</body></html>`)
	}))
	defer server.Close()
	templates := t.TempDir()
	for _, tc := range []struct{ id, marker string }{
		{"ci-smoke-positive", "dddd-ci-smoke-marker"},
		{"ci-smoke-negative", "dddd-ci-smoke-absent"},
	} {
		template := fmt.Sprintf(`id: %s
info:
  name: Local CI smoke fixture
  author: dddd-next
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "%s"
`, tc.id, tc.marker)
		if err := os.WriteFile(filepath.Join(templates, tc.id+".yaml"), []byte(template), 0644); err != nil {
			t.Fatal(err)
		}
	}
	run(0, "-t", server.URL, "-no-dir", "-poc", "ci-smoke", "-nt", templates,
		"-ni", "-o", "result.json", "-ot", "json", "-ho", "report.html")
	matches, err := filepath.Glob(filepath.Join(workDir, "output", "*", "result.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("JSON reports = %v, %v", matches, err)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var fingerprinted bool
	var findings []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var record struct {
			Kind        string            `json:"kind"`
			Fingerprint types.Fingerprint `json:"fingerprint"`
			Finding     types.Finding     `json:"finding"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("invalid JSON record: %v\n%s", err, line)
		}
		if record.Kind == "fingerprint" && record.Fingerprint.Name == "DVWA" {
			fingerprinted = true
		}
		if record.Kind == "finding" {
			findings = append(findings, record.Finding.ID)
		}
	}
	if !fingerprinted || len(findings) != 1 || findings[0] != "ci-smoke-positive" {
		t.Fatalf("DVWA fingerprint=%v, findings=%v\n%s", fingerprinted, findings, data)
	}
	html, err := os.ReadFile(filepath.Join(filepath.Dir(matches[0]), "report.html"))
	if err != nil || !strings.Contains(string(html), "ci-smoke-positive") {
		t.Fatalf("HTML report missing positive finding: %v", err)
	}
	if _, err := os.Stat(filepath.Join(binDir, "configs", "fingers", "finger.yaml")); err != nil {
		t.Fatalf("embedded configs not materialized beside executable: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, "configs")); !os.IsNotExist(err) {
		t.Fatalf("unexpected working-directory configs: %v", err)
	}
}
