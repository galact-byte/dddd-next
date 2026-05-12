package reporter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"dddd-next/internal/types"
)

// JSONReporter emits one JSON object per line (NDJSON), making the file
// streamable and tail-friendly. Each record carries a Kind discriminator
// so downstream consumers can route fingerprints vs findings cleanly.
type JSONReporter struct {
	mu     sync.Mutex
	w      *bufio.Writer
	enc    *json.Encoder
	closer io.Closer
}

type jsonRecord struct {
	Kind       string             `json:"kind"`
	Timestamp  time.Time          `json:"timestamp"`
	Target     string             `json:"target,omitempty"`
	Fingerprint *types.Fingerprint `json:"fingerprint,omitempty"`
	Finding    *types.Finding     `json:"finding,omitempty"`
}

// NewJSONFile opens (or creates) path for append.
func NewJSONFile(path string) (*JSONReporter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("reporter: open %s: %w", path, err)
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONReporter{w: w, enc: enc, closer: f}, nil
}

// NewJSONWriter wraps an arbitrary io.Writer.
func NewJSONWriter(w io.Writer) *JSONReporter {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	return &JSONReporter{w: bw, enc: enc}
}

func (r *JSONReporter) WriteFingerprint(target string, fp types.Fingerprint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := jsonRecord{
		Kind:        "fingerprint",
		Timestamp:   time.Now().UTC(),
		Target:      target,
		Fingerprint: &fp,
	}
	if err := r.enc.Encode(rec); err != nil {
		return err
	}
	return r.w.Flush()
}

func (r *JSONReporter) WriteFinding(f types.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := jsonRecord{
		Kind:      "finding",
		Timestamp: time.Now().UTC(),
		Target:    f.Target,
		Finding:   &f,
	}
	if err := r.enc.Encode(rec); err != nil {
		return err
	}
	return r.w.Flush()
}

func (r *JSONReporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.w.Flush(); err != nil {
		return err
	}
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}
