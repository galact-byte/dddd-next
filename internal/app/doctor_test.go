package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dddd-next/internal/config"
)

func TestCheckRulesReportsMissingMappedTemplate(t *testing.T) {
	root := t.TempDir()
	write := func(path, data string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("fingers/finger.yaml", "Demo:\n  - 'body=\"fixture\"'\n")
	write("pocs/mapping.yaml", "Demo:\n  type: [root]\n  pocs: [demo]\nGeneral-Poc-local:\n  pocs: [missing-general]\n")
	write("pocs/legacy/demo.yaml", `id: demo
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
`)
	report := CheckRules(context.Background(), config.Defaults(), root)
	if report.Rules != 1 || report.Templates != 1 || !strings.Contains(strings.Join(report.Problems, "\n"), "missing-general") {
		t.Fatalf("report=%+v", report)
	}
	write("pocs/mapping.yaml", "Demo:\n  type: [root]\n  pocs: [demo]\n")
	report = CheckRules(context.Background(), config.Defaults(), root)
	if len(report.Problems) != 0 {
		t.Fatalf("report=%+v", report)
	}
	write("fingers/finger.yaml", "Demo:\n  - 'invalid-expression'\n")
	report = CheckRules(context.Background(), config.Defaults(), root)
	if !strings.Contains(strings.Join(report.Problems, "\n"), "finger.yaml") {
		t.Fatalf("invalid DSL accepted: %+v", report)
	}
}

func TestCheckRulesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report := CheckRules(ctx, config.Defaults(), t.TempDir())
	if !strings.Contains(strings.Join(report.Problems, "\n"), "canceled") {
		t.Fatalf("report=%+v", report)
	}
}
