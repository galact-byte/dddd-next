// Package reporter writes scan results to one or more sinks (text, JSON,
// HTML, audit log). Reporters are designed to be wire-safe — callers can
// fan out a finding to many reporters concurrently.
package reporter

import (
	"errors"
	"sync"

	"dddd-next/internal/types"
)

// Reporter is the sink contract used by the workflow layer.
type Reporter interface {
	WriteFingerprint(target string, fp types.Fingerprint) error
	WriteFinding(f types.Finding) error
	Close() error
}

// MultiReporter fans every write out to all child reporters.
// Errors from children are joined; one child's failure does not abort the
// others — partial result preservation is more valuable than transactional
// purity for a long-running scan.
type MultiReporter struct {
	mu    sync.Mutex
	kids  []Reporter
}

// NewMulti groups any number of reporters together.
func NewMulti(rs ...Reporter) *MultiReporter { return &MultiReporter{kids: rs} }

// Add attaches another reporter after construction.
func (m *MultiReporter) Add(r Reporter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kids = append(m.kids, r)
}

func (m *MultiReporter) WriteFingerprint(target string, fp types.Fingerprint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, r := range m.kids {
		if err := r.WriteFingerprint(target, fp); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *MultiReporter) WriteFinding(f types.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, r := range m.kids {
		if err := r.WriteFinding(f); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *MultiReporter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, r := range m.kids {
		if err := r.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
