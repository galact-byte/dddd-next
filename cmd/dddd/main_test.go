package main

import (
	"os"
	"path/filepath"
	"testing"

	"dddd-next/internal/config"
)

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
