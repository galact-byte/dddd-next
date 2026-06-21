package app

import (
	"bytes"
	"strings"
	"testing"

	"dddd-next/internal/reporter"
	"dddd-next/internal/types"
)

func TestCountingReporterDeduplicatesFindings(t *testing.T) {
	var buf bytes.Buffer
	r := newCountingReporter(reporter.NewTextWriter(&buf))
	f := types.Finding{
		ID:       "CVE-2021-29441",
		Name:     "Nacos auth bypass",
		Severity: types.SeverityCritical,
		Target:   "http://nacos.local/nacos/v1/cs/configs",
		Template: "CVE-2021-29441.yaml",
	}

	if err := r.WriteFinding(f); err != nil {
		t.Fatalf("first WriteFinding: %v", err)
	}
	if err := r.WriteFinding(f); err != nil {
		t.Fatalf("duplicate WriteFinding: %v", err)
	}

	if r.findings != 1 {
		t.Fatalf("findings count = %d, want 1", r.findings)
	}
	if got := strings.Count(buf.String(), "CVE-2021-29441.yaml"); got != 1 {
		t.Fatalf("report lines = %d, want 1; output=%q", got, buf.String())
	}
}
