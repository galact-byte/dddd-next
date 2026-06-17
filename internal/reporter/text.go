package reporter

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sync"

	"dddd-next/internal/types"
)

// TextReporter writes plain-text lines to a file/Writer.
// Every write is flushed immediately so interrupted scans still leave
// recoverable output — matches the behaviour of the original dddd.
type TextReporter struct {
	mu     sync.Mutex
	w      *bufio.Writer
	closer io.Closer
}

// NewTextFile opens (or creates) path for append.
func NewTextFile(path string) (*TextReporter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("reporter: open %s: %w", path, err)
	}
	return &TextReporter{w: bufio.NewWriter(f), closer: f}, nil
}

// NewTextWriter wraps any io.Writer (handy for tests / stdout).
func NewTextWriter(w io.Writer) *TextReporter {
	return &TextReporter{w: bufio.NewWriter(w)}
}

func (r *TextReporter) WriteFingerprint(target string, fp types.Fingerprint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := fmt.Fprintf(r.w, "[FP] %s | %s | confidence=%d\n", target, fp.Name, fp.Confidence)
	if err != nil {
		return err
	}
	return r.w.Flush()
}

func (r *TextReporter) WriteFinding(f types.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	detail := f.Template
	if detail == "" {
		detail = f.Description
	}
	_, err := fmt.Fprintf(r.w, "%s %s | %s | %s\n", severityTag(f.Severity), f.Target, f.Name, detail)
	if err != nil {
		return err
	}
	return r.w.Flush()
}

func (r *TextReporter) Close() error {
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

func severityTag(s types.Severity) string {
	var c string
	switch s {
	case types.SeverityCritical, types.SeverityHigh:
		c = "\033[31m" // red
	case types.SeverityMedium:
		c = "\033[33m" // yellow
	case types.SeverityLow:
		c = "\033[32m" // green
	default:
		c = "\033[37m" // white
	}
	return fmt.Sprintf("%s[%s]%s", c, upper(string(s)), "\033[0m")
}

func upper(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out[i] = c
	}
	return string(out)
}
