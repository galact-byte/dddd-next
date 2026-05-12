package fingerdsl

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLintRealFingerYAML runs every expression from configs/fingers/finger.yaml
// through Parse and reports the success rate.
//
// This is an integration check, not a strict gate: parse failures > 10%
// of total mean the DSL is missing real-world syntax we should support.
// Below 10% is "noise" — usually malformed YAML escapes from the upstream
// project itself, which we'll filter when implementing the YAML loader.
func TestLintRealFingerYAML(t *testing.T) {
	paths := []string{
		"../../configs/fingers/finger.yaml",
		"configs/fingers/finger.yaml",
	}
	var path string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		t.Skip("finger.yaml not found relative to test working dir")
	}

	abs, _ := filepath.Abs(path)
	t.Logf("linting %s", abs)

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	var total, ok, fail int
	var samples []string

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")

		// Lines we care about look like:   "  - 'expr'"   or   "  - expr"
		trimmed := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(trimmed, "- ") {
			continue
		}
		expr := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))

		// Unwrap YAML single-quoted form  'foo ''bar'' baz'
		if len(expr) >= 2 && expr[0] == '\'' && expr[len(expr)-1] == '\'' {
			expr = expr[1 : len(expr)-1]
			expr = strings.ReplaceAll(expr, "''", "'")
		}

		if expr == "" {
			continue
		}

		total++
		if _, err := Parse(expr); err != nil {
			fail++
			if len(samples) < 6 {
				samples = append(samples, expr+"  ← "+err.Error())
			}
		} else {
			ok++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	t.Logf("fingerprint lint: total=%d ok=%d fail=%d", total, ok, fail)
	for _, s := range samples {
		t.Logf("  fail sample: %s", s)
	}

	if total == 0 {
		t.Fatal("scanned no fingerprint rules — parser/scanner mismatch")
	}
	if rate := float64(fail) / float64(total); rate > 0.10 {
		t.Errorf("parse failure rate %.1f%% exceeds 10%% threshold", rate*100)
	}
}
