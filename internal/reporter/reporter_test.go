package reporter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dddd-next/internal/types"
)

func sampleFinding() types.Finding {
	return types.Finding{
		ID:           "CVE-2024-1234",
		Name:         "Test RCE",
		Severity:     types.SeverityHigh,
		Target:       "http://example.com",
		Template:     "http/cves/2024/CVE-2024-1234.yaml",
		Description:  "demo",
		DiscoveredAt: time.Now(),
	}
}

func TestTextReporter(t *testing.T) {
	var buf bytes.Buffer
	r := NewTextWriter(&buf)
	if err := r.WriteFingerprint("http://example.com", types.Fingerprint{Name: "Apache", Confidence: 90}); err != nil {
		t.Fatalf("WriteFingerprint: %v", err)
	}
	if err := r.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[FP] http://example.com | Apache") {
		t.Errorf("FP line missing: %q", out)
	}
	if !strings.Contains(out, "[HIGH]") || !strings.Contains(out, "Test RCE") {
		t.Errorf("Finding line missing: %q", out)
	}
}

func TestJSONReporter(t *testing.T) {
	var buf bytes.Buffer
	r := NewJSONWriter(&buf)
	if err := r.WriteFingerprint("http://example.com", types.Fingerprint{Name: "Nginx"}); err != nil {
		t.Fatalf("WriteFingerprint: %v", err)
	}
	if err := r.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d (%q)", len(lines), buf.String())
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal line 1: %v", err)
	}
	if first["kind"] != "fingerprint" {
		t.Errorf("line 1 kind = %v, want fingerprint", first["kind"])
	}
}

func TestHTMLReporter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	r := NewHTML(path)
	if err := r.WriteFingerprint("http://x.com", types.Fingerprint{Name: "WordPress"}); err != nil {
		t.Fatalf("WriteFingerprint: %v", err)
	}
	if err := r.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	s := string(data)
	for _, want := range []string{"dddd-next 扫描报告", "WordPress", "Test RCE", "high"} {
		if !strings.Contains(s, want) {
			t.Errorf("report missing %q (len=%d)", want, len(s))
		}
	}
}

func TestMultiReporter(t *testing.T) {
	var txtBuf, jsonBuf bytes.Buffer
	multi := NewMulti(NewTextWriter(&txtBuf), NewJSONWriter(&jsonBuf))

	if err := multi.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := multi.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !strings.Contains(txtBuf.String(), "Test RCE") {
		t.Error("text branch missed finding")
	}
	if !strings.Contains(jsonBuf.String(), "Test RCE") {
		t.Error("json branch missed finding")
	}
}
