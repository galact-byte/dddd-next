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

func TestFormatFindingShowsDetail(t *testing.T) {
	f := types.Finding{
		ID:       "weak-credential-mysql",
		Severity: types.SeverityHigh,
		Target:   "192.0.2.10:3306",
		Detail:   `username="root" password="123456"`,
	}
	line := formatFinding(f)
	if !strings.Contains(line, "weak-credential-mysql") {
		t.Errorf("missing id: %q", line)
	}
	if !strings.Contains(line, "192.0.2.10:3306") {
		t.Errorf("missing target: %q", line)
	}
	if !strings.Contains(line, `username="root" password="123456"`) {
		t.Errorf("key detail not shown on terminal line: %q", line)
	}
}

func TestFormatFindingNoDetailNoTrailingSeparator(t *testing.T) {
	f := types.Finding{ID: "CVE-x", Severity: types.SeverityInfo, Target: "t"}
	line := formatFinding(f)
	if strings.HasSuffix(line, " ") {
		t.Errorf("line should not end with a dangling separator when Detail empty: %q", line)
	}
	if !strings.HasSuffix(line, "t") {
		t.Errorf("line should end with the target when no Detail: %q", line)
	}
}

func TestFormatFindingFallsBackToDescription(t *testing.T) {
	// Findings without a structured Detail (memcached/JDWP/NetBIOS unauth POCs)
	// should still surface their description on the terminal like the original.
	f := types.Finding{
		ID:          "unauth-memcached",
		Severity:    types.SeverityHigh,
		Target:      "10.0.0.5:11211",
		Description: "Memcached answers the stats command without authentication",
	}
	line := formatFinding(f)
	if !strings.Contains(line, "Memcached answers the stats command") {
		t.Errorf("description not surfaced on terminal: %q", line)
	}
}

func TestFormatFindingPrefersDetailOverDescription(t *testing.T) {
	f := types.Finding{
		ID:          "weak-credential-mysql",
		Severity:    types.SeverityHigh,
		Target:      "h:3306",
		Detail:      `username="root" password="123456"`,
		Description: `mysql accepts weak credential "root:123456"`,
	}
	line := formatFinding(f)
	if !strings.Contains(line, `username="root"`) {
		t.Errorf("should show structured Detail: %q", line)
	}
	if strings.Contains(line, "accepts weak credential") {
		t.Errorf("should not also dump Description when Detail present: %q", line)
	}
}

func TestTruncateRunesAddsEllipsis(t *testing.T) {
	if got := truncateRunes("abcdef", 3); got != "abc…" {
		t.Errorf("truncateRunes = %q, want abc…", got)
	}
	if got := truncateRunes("ab", 3); got != "ab" {
		t.Errorf("truncateRunes should not touch short strings, got %q", got)
	}
}

func TestSanitizeInlineNeutralizesControlChars(t *testing.T) {
	got := sanitizeInline("a\nb\tc\x1b[31md\x00e")
	if strings.ContainsAny(got, "\n\t\x1b\x00") {
		t.Errorf("control chars leaked: %q", got)
	}
	for _, want := range []string{"a", "b", "c", "d", "e"} {
		if !strings.Contains(got, want) {
			t.Errorf("dropped visible content %q from %q", want, got)
		}
	}
}

func TestFormatFindingSanitizesInjectedDetail(t *testing.T) {
	f := types.Finding{ID: "x", Severity: types.SeverityInfo, Target: "t", Detail: "pass=\"a\nb\""}
	line := formatFinding(f)
	// A newline injected via Detail must not produce a raw multi-line terminal record.
	if strings.Count(line, "\n") != 0 {
		t.Errorf("injected newline leaked into finding line: %q", line)
	}
}
