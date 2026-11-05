package main

import (
	"bytes"
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
	t.Setenv("NUCLEI_CONFIG_DIR", "")
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
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	standalone := filepath.Join(userConfigDir, "nuclei")
	if _, err := os.Stat(standalone); !os.IsNotExist(err) {
		t.Fatalf("version command touched standalone Nuclei directory: %v", err)
	}
	preserved := make(map[string][]byte)
	for _, dir := range []string{standalone, filepath.Join(homeDir, "external-nuclei")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{
			".templates-config.json": []byte("invalid JSON sentinel\n"),
			".nuclei-ignore":         []byte("tags: [dddd-ci-smoke]\nfiles: []\n"),
		} {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			preserved[path] = data
		}
	}
	t.Setenv("NUCLEI_CONFIG_DIR", filepath.Join(homeDir, "external-nuclei"))
	run(0, "help")
	run(2)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Login :: Damn Vulnerable Web Application (DVWA) v1.9</title></head><body><img src="dvwa/images/login_logo.png">dddd-ci-smoke-marker</body></html>`)
	}))
	defer server.Close()
	templates := t.TempDir()
	for _, dir := range []string{"http", "helpers"} {
		if err := os.MkdirAll(filepath.Join(templates, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(templates, "helpers", "smoke.txt"), []byte("ci-root-resource\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, marker string }{
		{"ci-smoke-positive", "dddd-ci-smoke-marker"},
		{"ci-smoke-negative", "dddd-ci-smoke-absent"},
	} {
		template := fmt.Sprintf(`id: %s
info:
  name: Local CI smoke fixture
  author: dddd-next
  severity: info
  tags: dddd-ci-smoke
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{word}}"
    payloads:
      word: helpers/smoke.txt
    matchers:
      - type: word
        words:
          - "%s"
`, tc.id, tc.marker)
		if err := os.WriteFile(filepath.Join(templates, "http", tc.id+".yaml"), []byte(template), 0644); err != nil {
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
	privateIgnore := filepath.Join(userConfigDir, "dddd-next", "nuclei", ".nuclei-ignore")
	privateRules := []byte("tags: [dddd-ci-smoke]\nfiles: []\n")
	if err := os.WriteFile(privateIgnore, privateRules, 0600); err != nil {
		t.Fatal(err)
	}
	run(0, "-t", server.URL, "-no-dir", "-poc", "ci-smoke", "-nt", templates,
		"-ni", "-o", "ignored.json", "-ot", "json", "-ho", "")
	ignored, err := filepath.Glob(filepath.Join(workDir, "output", "*", "ignored.json"))
	if err != nil || len(ignored) != 1 {
		t.Fatalf("ignored reports = %v, %v", ignored, err)
	}
	ignoredData, err := os.ReadFile(ignored[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(ignoredData)), "\n") {
		var record struct{ Kind string }
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.Kind == "finding" {
			t.Fatalf("private ignore rules did not exclude template: %s", line)
		}
	}
	if got, err := os.ReadFile(privateIgnore); err != nil || !bytes.Equal(got, privateRules) {
		t.Fatalf("private ignore rules changed: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(binDir, "configs", "fingers", "finger.yaml")); err != nil {
		t.Fatalf("embedded configs not materialized beside executable: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, "configs")); !os.IsNotExist(err) {
		t.Fatalf("unexpected working-directory configs: %v", err)
	}
	for path, want := range preserved {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("standalone Nuclei configuration changed at %s: %q, %v", path, got, err)
		}
	}
	for _, name := range []string{".templates-config.json", ".nuclei-ignore"} {
		if _, err := os.Stat(filepath.Join(userConfigDir, "dddd-next", "nuclei", name)); err != nil {
			t.Errorf("private SDK configuration %s missing: %v", name, err)
		}
	}
}
