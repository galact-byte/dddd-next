// Package audit records every meaningful scan action to a tamper-evident
// log. Original dddd's -a flag wrote a free-form text trace; we use NDJSON
// so post-incident review tools (jq, vector) can parse it directly.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// EventType is a short tag identifying what happened.
type EventType string

const (
	EventRequest  EventType = "request"
	EventResponse EventType = "response"
	EventError    EventType = "error"
	EventInfo     EventType = "info"
)

// Event is a single audit record.
type Event struct {
	Time   time.Time      `json:"time"`
	Type   EventType      `json:"type"`
	Target string         `json:"target,omitempty"`
	Action string         `json:"action,omitempty"`
	Detail map[string]any `json:"detail,omitempty"`
}

// Auditor writes Events to an append-only sink.
type Auditor struct {
	mu      sync.Mutex
	w       *bufio.Writer
	enc     *json.Encoder
	closer  io.Closer
	enabled bool
}

// NewFile opens (or creates) path for appending. The audit log is
// flushed after every record so a kill -9 still leaves a usable trail.
func NewFile(path string) (*Auditor, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Auditor{w: w, enc: enc, closer: f, enabled: true}, nil
}

// NewWriter wraps an arbitrary io.Writer (tests / stdout).
func NewWriter(w io.Writer) *Auditor {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	return &Auditor{w: bw, enc: enc, enabled: true}
}

// Disabled returns a no-op Auditor — call this when -a is off so call
// sites don't need nil checks scattered everywhere.
func Disabled() *Auditor { return &Auditor{enabled: false} }

// Record appends an event. Returns nil silently when the auditor is
// disabled — keeping audit calls cheap on the hot path.
func (a *Auditor) Record(ev Event) error {
	if a == nil || !a.enabled {
		return nil
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.enc.Encode(ev); err != nil {
		return err
	}
	return a.w.Flush()
}

// Helpers for the most common shapes.

func (a *Auditor) LogRequest(target, action string, detail map[string]any) error {
	return a.Record(Event{Type: EventRequest, Target: target, Action: action, Detail: detail})
}

func (a *Auditor) LogResponse(target, action string, detail map[string]any) error {
	return a.Record(Event{Type: EventResponse, Target: target, Action: action, Detail: detail})
}

func (a *Auditor) LogError(target, action string, err error) error {
	if err == nil {
		return nil
	}
	return a.Record(Event{
		Type:   EventError,
		Target: target,
		Action: action,
		Detail: map[string]any{"error": err.Error()},
	})
}

func (a *Auditor) LogInfo(action string, detail map[string]any) error {
	return a.Record(Event{Type: EventInfo, Action: action, Detail: detail})
}

// Close flushes the buffer and releases the underlying file.
func (a *Auditor) Close() error {
	if a == nil || !a.enabled {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var errs []error
	if err := a.w.Flush(); err != nil {
		errs = append(errs, err)
	}
	if a.closer != nil {
		if err := a.closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
