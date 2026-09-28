package reporter

import (
	"bytes"
	"encoding/json"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dddd-next/internal/types"
)

func TestFindingDetailSurvivesAllReports(t *testing.T) {
	f := sampleFinding()
	f.Detail = "extracted=<script>alert('x')</script> & value=\"" + strings.Repeat("关键值", 100) + "\""
	t.Run("TXT", func(t *testing.T) {
		var b bytes.Buffer
		r := NewTextWriter(&b)
		if err := r.WriteFinding(f); err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{f.Detail, f.Template} {
			if !strings.Contains(b.String(), value) {
				t.Fatalf("TXT missing full detail or existing template: %q", b.String())
			}
		}
	})
	t.Run("HTML", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "report.html")
		r := NewHTML(path)
		if err := r.WriteFinding(f); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		for _, value := range []string{f.Detail, f.Template, f.Description} {
			if !strings.Contains(html.UnescapeString(s), value) {
				t.Fatalf("HTML missing complete value %q", value)
			}
		}
		if strings.Contains(s, "<script>alert('x')</script>") {
			t.Fatal("untrusted detail rendered as executable HTML")
		}
	})
	t.Run("JSON", func(t *testing.T) {
		var b bytes.Buffer
		r := NewJSONWriter(&b)
		if err := r.WriteFinding(f); err != nil {
			t.Fatal(err)
		}
		var rec struct{ Finding types.Finding }
		if err := json.Unmarshal(b.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Finding.Detail != f.Detail {
			t.Fatal("JSON lost full detail")
		}
	})
}

func TestTextFindingWithoutDetailRetainsExistingOutput(t *testing.T) {
	var b bytes.Buffer
	f := sampleFinding()
	r := NewTextWriter(&b)
	if err := r.WriteFinding(f); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(b.String(), " | "+f.Template+"\n") {
		t.Fatalf("changed legacy output: %q", b.String())
	}
}
