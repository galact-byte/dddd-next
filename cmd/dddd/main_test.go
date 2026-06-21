package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dddd-next/internal/config"
)

func TestVersionLineUsesMutableAppVersion(t *testing.T) {
	orig := appVersion
	appVersion = "test-version"
	t.Cleanup(func() { appVersion = orig })

	if got := strings.TrimSpace(versionLine()); got != "dddd-next test-version" {
		t.Fatalf("versionLine() = %q", got)
	}
}

func TestPrepareOutputPathsRespectsHTMLDisable(t *testing.T) {
	cfg := config.Config{Output: "result.txt", HTMLOutput: ""}

	got := prepareOutputPaths(cfg, "out")

	if got.Output != filepath.Join("out", "result.txt") {
		t.Fatalf("Output = %q", got.Output)
	}
	if got.HTMLOutput != "" {
		t.Fatalf("HTMLOutput = %q, want disabled empty value", got.HTMLOutput)
	}
}

func TestPrepareOutputPathsPlacesEnabledReportsUnderRunDir(t *testing.T) {
	cfg := config.Config{
		Output:       "result.txt",
		HTMLOutput:   "report.html",
		AuditLog:     true,
		AuditLogFile: "audit.log",
	}

	got := prepareOutputPaths(cfg, "out")

	if got.Output != filepath.Join("out", "result.txt") {
		t.Fatalf("Output = %q", got.Output)
	}
	if got.HTMLOutput != filepath.Join("out", "report.html") {
		t.Fatalf("HTMLOutput = %q", got.HTMLOutput)
	}
	if got.AuditLogFile != filepath.Join("out", "audit.log") {
		t.Fatalf("AuditLogFile = %q", got.AuditLogFile)
	}
}

func TestCreateOutputDirAvoidsTimestampCollision(t *testing.T) {
	base := t.TempDir()
	stamp := "2026-06-20_191545"
	existing := filepath.Join(base, stamp)
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}

	got := createOutputDir(base, stamp)

	want := filepath.Join(base, stamp+"-2")
	if got != want {
		t.Fatalf("createOutputDir = %q, want %q", got, want)
	}
	if info, err := os.Stat(got); err != nil || !info.IsDir() {
		t.Fatalf("created dir stat = %v, %v", info, err)
	}
}

func TestResolveConfigDirPrefersConfigsBesideExecutable(t *testing.T) {
	exeDir := t.TempDir()
	cwd := t.TempDir()
	home := t.TempDir()
	exeConfig := filepath.Join(exeDir, "configs")
	if err := os.Mkdir(exeConfig, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "configs"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveConfigDirWith(filepath.Join(exeDir, "dddd.exe"), cwd, home, nil, "test-version")
	if err != nil {
		t.Fatal(err)
	}

	if got != exeConfig {
		t.Fatalf("resolveConfigDirWith = %q, want executable config %q", got, exeConfig)
	}
}

func TestResolveConfigDirPrefersWorkingDirConfigsWhenExecutableHasNone(t *testing.T) {
	exeDir := t.TempDir()
	cwd := t.TempDir()
	home := t.TempDir()
	cwdConfig := filepath.Join(cwd, "configs")
	if err := os.Mkdir(cwdConfig, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveConfigDirWith(filepath.Join(exeDir, "dddd.exe"), cwd, home, nil, "test-version")
	if err != nil {
		t.Fatal(err)
	}

	if got != cwdConfig {
		t.Fatalf("resolveConfigDirWith = %q, want cwd config %q", got, cwdConfig)
	}
}

func TestResolveConfigDirMaterializesBuiltinConfigsUnderDownloads(t *testing.T) {
	exeDir := t.TempDir()
	cwd := t.TempDir()
	home := t.TempDir()
	builtin := zipFixture(t, map[string]string{
		"dir.yaml":             "paths: []\n",
		"dict/shirokeys.txt":   "kPH+bIxk5D2deZiIxcaaaA==\n",
		"fingers/finger.yaml":  "fingerprint: []\n",
		"pocs/mapping.yaml":    "mappings: []\n",
		"pocs/legacy/test.yml": "id: test\n",
	})

	got, err := resolveConfigDirWith(filepath.Join(exeDir, "dddd.exe"), cwd, home, builtin, "test-version")
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(home, "Downloads", "dddd-next", "configs")
	if got != want {
		t.Fatalf("resolveConfigDirWith = %q, want materialized config %q", got, want)
	}
	for _, rel := range []string{"dir.yaml", "dict/shirokeys.txt", "fingers/finger.yaml", "pocs/mapping.yaml", "pocs/legacy/test.yml"} {
		if _, err := os.Stat(filepath.Join(want, rel)); err != nil {
			t.Fatalf("materialized %s: %v", rel, err)
		}
	}
	if gotVersion, err := os.ReadFile(filepath.Join(want, ".builtin-version")); err != nil || strings.TrimSpace(string(gotVersion)) != "test-version" {
		t.Fatalf("builtin version marker = %q, %v", gotVersion, err)
	}
}

func TestResolveConfigDirRejectsUnsafeBuiltinConfigPaths(t *testing.T) {
	exeDir := t.TempDir()
	cwd := t.TempDir()
	home := t.TempDir()
	builtin := zipFixture(t, map[string]string{
		"../escape.txt": "bad\n",
	})

	if _, err := resolveConfigDirWith(filepath.Join(exeDir, "dddd.exe"), cwd, home, builtin, "test-version"); err == nil {
		t.Fatal("resolveConfigDirWith accepted unsafe built-in config path")
	}
	if _, err := os.Stat(filepath.Join(home, "Downloads", "escape.txt")); !os.IsNotExist(err) {
		t.Fatalf("unsafe file escaped materialized config dir: %v", err)
	}
}

func zipFixture(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
