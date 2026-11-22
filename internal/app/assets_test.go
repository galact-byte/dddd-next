package app

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dddd-next/internal/config"
)

func TestPipelineExportsHTTPAssetWithoutFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>CSV Fixture</title>fixture</html>"))
	}))
	defer srv.Close()
	root := t.TempDir()
	finger := filepath.Join(root, "finger.yaml")
	if err := os.WriteFile(finger, []byte("Other:\n  - 'body=\"never-match-93712\"'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Targets = []string{srv.URL}
	cfg.NoPoc = true
	cfg.SkipDir = true
	cfg.NoHostBind = true
	cfg.FingerConfigFilePath = finger
	cfg.Output = filepath.Join(root, "result.txt")
	cfg.HTMLOutput = ""
	cfg.CSVOutput = filepath.Join(root, "assets.csv")
	p, err := New(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.CSVOutput)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows[1:] {
		if strings.HasPrefix(row[4], srv.URL) && row[5] == "CSV Fixture" && row[6] == "" && row[8] == "http:200" {
			found = true
		}
	}
	if !found {
		t.Fatalf("HTTP asset without fingerprints missing: %v", rows)
	}
}
