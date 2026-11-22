package main

import (
	"dddd-next/internal/config"
	"path/filepath"
	"testing"
)

func TestPrepareCSVOutputUnderRunDirectory(t *testing.T) {
	cfg := config.Defaults()
	cfg.CSVOutput = "assets.csv"
	got := prepareOutputPaths(cfg, "out")
	if got.CSVOutput != filepath.Join("out", "assets.csv") {
		t.Fatalf("CSV output=%q", got.CSVOutput)
	}
	cfg.CSVOutput = ""
	if got := prepareOutputPaths(cfg, "out"); got.CSVOutput != "" {
		t.Fatalf("disabled CSV created: %q", got.CSVOutput)
	}
}
