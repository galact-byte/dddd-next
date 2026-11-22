package app

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dddd-next/internal/config"
)

func TestCancelDuringRequestFinalizesAssetCSV(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { cancel(); w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Targets = []string{srv.URL}
	cfg.NoPoc, cfg.SkipDir, cfg.NoHostBind = true, true, true
	cfg.FingerConfigFilePath = filepath.Join(root, "finger.yaml")
	cfg.Output = filepath.Join(root, "result.txt")
	cfg.CSVOutput = filepath.Join(root, "assets.csv")
	cfg.HTMLOutput = ""
	if err := os.WriteFile(cfg.FingerConfigFilePath, []byte("Demo:\n  - 'body=\"fixture\"'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	runErr := p.Run(ctx)
	closeErr := p.Close()
	if !errors.Is(runErr, context.Canceled) || closeErr != nil {
		t.Fatalf("run=%v close=%v", runErr, closeErr)
	}
	data, err := os.ReadFile(cfg.CSVOutput)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff"))).ReadAll()
	if err != nil || len(rows) == 0 || len(rows[0]) != 9 {
		t.Fatalf("CSV=%v err=%v", rows, err)
	}
}

func TestCanceledPipelineReturnsCancellationAndClosesReports(t *testing.T) {
	root := t.TempDir()
	finger := filepath.Join(root, "finger.yaml")
	if err := os.WriteFile(finger, []byte("Demo:\n  - 'body=\"fixture\"'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.FingerConfigFilePath = finger
	cfg.Output = filepath.Join(root, "result.txt")
	cfg.CSVOutput = filepath.Join(root, "assets.csv")
	cfg.HTMLOutput = ""
	cfg.Targets = []string{"http://127.0.0.1:1"}
	cfg.NoPoc = true
	p, err := New(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Run(ctx); !errors.Is(err, context.Canceled) {
		p.Close()
		t.Fatalf("canceled pipeline returned %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(cfg.CSVOutput); err != nil || len(data) == 0 {
		t.Fatalf("CSV not finalized: %q %v", data, err)
	}
}
