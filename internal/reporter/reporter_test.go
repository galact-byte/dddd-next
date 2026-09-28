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

func TestHTMLReporterInteractiveLayout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	r := NewHTML(path)
	if err := r.WriteFingerprint("http://example.com", types.Fingerprint{Name: "Apache", Source: "active", Confidence: 90}); err != nil {
		t.Fatalf("WriteFingerprint: %v", err)
	}
	f := sampleFinding()
	f.Request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	f.Response = "HTTP/1.1 200 OK\r\nServer: test\r\n\r\nbody"
	if err := r.WriteFinding(f); err != nil {
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
	for _, want := range []string{
		`class="report-shell"`,
		`data-filter="critical"`,
		`data-filter="high"`,
		`data-severity="high"`,
		`class="finding-card finding-high"`,
		`copyText('request-1')`,
		`copyText('response-1')`,
		`指纹资产`,
		`漏洞清单`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("interactive report missing %q (len=%d)", want, len(s))
		}
	}
}

func TestCopyButtonsFor(t *testing.T) {
	cases := []struct {
		raw  string
		want []htmlCopyButton
	}{
		{"192.0.2.10", []htmlCopyButton{{"复制IP", "192.0.2.10"}}},
		{"192.0.2.10:3306", []htmlCopyButton{{"复制IP", "192.0.2.10"}}},
		{"http://192.0.2.10:8080/x", []htmlCopyButton{{"复制IP", "192.0.2.10"}}},
		{"example.com", []htmlCopyButton{{"复制地址", "example.com"}}},
		{"example.com:8443", []htmlCopyButton{{"复制地址", "example.com:8443"}}},
		{"http://example.com/a?b=1", []htmlCopyButton{{"复制地址", "http://example.com/a?b=1"}}},
	}
	for _, c := range cases {
		got := copyButtonsFor(c.raw)
		if len(got) != len(c.want) {
			t.Errorf("%q: got %d buttons %+v, want %d", c.raw, len(got), got, len(c.want))
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q button[%d] = %+v, want %+v", c.raw, i, got[i], c.want[i])
			}
		}
	}
}

func TestHTMLReporterCopyTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	r := NewHTML(path)
	if err := r.WriteFingerprint("http://asset.example.com/login", types.Fingerprint{Name: "WordPress"}); err != nil {
		t.Fatalf("WriteFingerprint: %v", err)
	}
	f := sampleFinding()
	f.Target = "192.0.2.10:3306"
	if err := r.WriteFinding(f); err != nil {
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
	for _, want := range []string{
		"window.copyValue",                           // shared literal-copy handler
		`class="finding-actions"`,                    // copy buttons live in the always-visible header
		`data-copy="192.0.2.10"`,                     // IP-based finding: bare IP
		`>复制IP<`,                                     // IP label present
		`data-copy="http://asset.example.com/login"`, // domain asset: full address kept
		`>复制地址<`,                                     // address label present
	} {
		if !strings.Contains(s, want) {
			t.Errorf("copy-target report missing %q (len=%d)", want, len(s))
		}
	}
	// Only one button per target: no redundant full-address for IP, no separate hostname for domain.
	if strings.Contains(s, `data-copy="192.0.2.10:3306"`) {
		t.Errorf("IP:port target should not render a redundant 复制地址 button")
	}
	if strings.Contains(s, "复制主机名") {
		t.Errorf("hostname button should be gone; only one button per target")
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
