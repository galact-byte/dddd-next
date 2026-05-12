package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRecordAndDisabled(t *testing.T) {
	var buf bytes.Buffer
	a := NewWriter(&buf)
	if err := a.LogInfo("scan-start", map[string]any{"targets": 3}); err != nil {
		t.Fatalf("LogInfo: %v", err)
	}
	if err := a.LogRequest("http://x.com", "GET", map[string]any{"headers": "..."}); err != nil {
		t.Fatalf("LogRequest: %v", err)
	}
	if err := a.LogError("http://x.com", "GET", errors.New("boom")); err != nil {
		t.Fatalf("LogError: %v", err)
	}
	if err := a.LogError("", "", nil); err != nil {
		t.Errorf("nil error should be no-op, got %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 NDJSON lines, got %d (%q)", len(lines), buf.String())
	}

	var first Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal first: %v", err)
	}
	if first.Type != EventInfo || first.Action != "scan-start" {
		t.Errorf("first event = %+v", first)
	}

	// Disabled auditor must produce no output and no error.
	var buf2 bytes.Buffer
	dis := Disabled()
	if err := dis.LogInfo("nope", nil); err != nil {
		t.Errorf("disabled LogInfo: %v", err)
	}
	if buf2.Len() != 0 {
		t.Errorf("disabled wrote %q", buf2.String())
	}
	if err := dis.Close(); err != nil {
		t.Errorf("disabled Close: %v", err)
	}
}

func TestNilSafe(t *testing.T) {
	var a *Auditor
	if err := a.Record(Event{Type: EventInfo}); err != nil {
		t.Errorf("nil receiver Record: %v", err)
	}
	if err := a.LogInfo("x", nil); err != nil {
		t.Errorf("nil receiver LogInfo: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("nil receiver Close: %v", err)
	}
}
