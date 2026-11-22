package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This checks the released CLI boundary: flags must reach the pipeline and
// generated files, rather than only passing unit tests of their helpers.
func TestPriorityBinarySmoke(t *testing.T) {
	binary := os.Getenv("DDDD_SMOKE_BINARY")
	if binary == "" {
		t.Skip("set DDDD_SMOKE_BINARY to test a built executable")
	}
	root := t.TempDir()
	payload, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	binary = filepath.Join(root, filepath.Base(binary))
	if err := os.WriteFile(binary, payload, 0755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	for _, key := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"} {
		t.Setenv(key, home)
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "")
	}
	run := func(wantCode int, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir = root
		output, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			if cmd.ProcessState == nil {
				t.Fatalf("start: %v", err)
			}
			code = cmd.ProcessState.ExitCode()
		}
		if code != wantCode {
			t.Fatalf("args=%v exit=%d want=%d\n%s", args, code, wantCode, output)
		}
		t.Logf("args=%v exit=%d\n%s", args, code, output)
		return string(output)
	}
	configDir := filepath.Join(root, "rules")
	template := filepath.Join(configDir, "pocs", "legacy", "demo.yaml")
	files := map[string]string{
		"fingers/finger.yaml": "Demo:\n  - 'body=\"fixture\"'\n",
		"pocs/mapping.yaml":   "Demo:\n  pocs: [demo]\n",
		"pocs/legacy/demo.yaml": `id: demo
info:
  name: Demo
  author: test
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["fixture"]
`,
	}
	for name, data := range files {
		path := filepath.Join(configDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run(0, "doctor", "-config-dir", configDir)
	if err := os.Remove(template); err != nil {
		t.Fatal(err)
	}
	run(1, "doctor", "-config-dir", configDir)
	missing := filepath.Join(root, "missing")
	run(1, "doctor", "-config-dir", missing)
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("doctor created configuration: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>Local asset fixture</title>fixture</html>`)
	}))
	defer server.Close()
	port := server.Listener.Addr().(*net.TCPAddr).Port
	output := run(0, "-t", "127.0.0.1", "-p", strconv.Itoa(port), "-Pn", "-no-poc", "-no-dir", "-nhb", "-ns", "-csv", "assets.csv", "-o", "result.json", "-ot", "json", "-ho", "")
	for _, stage := range []string{"TCP 端口扫描", "服务识别", "HTTP 探测", "1/1"} {
		if !strings.Contains(output, stage) {
			t.Fatalf("missing progress %q\n%s", stage, output)
		}
	}
	matches, err := filepath.Glob(filepath.Join(root, "output", "*", "assets.csv"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("CSV files=%v error=%v", matches, err)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range records[1:] {
		if row[0] == "127.0.0.1" && row[2] == strconv.Itoa(port) && strings.Contains(row[4], server.URL) && row[5] == "Local asset fixture" && strings.Contains(row[7], "portscan") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing merged web asset: %s", data)
	}

	if err := os.WriteFile(template, []byte(strings.Replace(files["pocs/legacy/demo.yaml"], `words: ["fixture"]`, `words: ["absent-marker"]`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	scan := func(code int, query string) string {
		return run(code, "-t", server.URL, "-poc", query, "-nt", filepath.Dir(template), "-ni", "-no-dir", "-nhb", "-ho", "")
	}
	if text := scan(0, "demo"); !strings.Contains(text, "nuclei outcome: completed with no findings") {
		t.Fatalf("missing no-findings outcome: %s", text)
	}
	if err := os.WriteFile(template, []byte("invalid yaml: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if text := scan(1, "demo"); !strings.Contains(text, "nuclei outcome: failed") {
		t.Fatalf("invalid template reported as no findings: %s", text)
	}
	if text := scan(0, "not-present"); !strings.Contains(text, "no matched POC or target") {
		t.Fatalf("missing no-applicable-template outcome: %s", text)
	}
}
