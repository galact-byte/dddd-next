package subfinder

import (
	"context"
	"strings"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	if o.Threads != 10 {
		t.Errorf("Threads = %d, want 10", o.Threads)
	}
	if o.TimeoutSeconds != 30 {
		t.Errorf("TimeoutSeconds = %d, want 30", o.TimeoutSeconds)
	}
	if o.MaxEnumMinutes != 10 {
		t.Errorf("MaxEnumMinutes = %d, want 10", o.MaxEnumMinutes)
	}
	if !o.Silent {
		t.Error("Silent should default to true")
	}
	if !o.DisableUpdateCheck {
		t.Error("DisableUpdateCheck should default to true — dddd owns tooling lifecycle")
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	e := New(Options{Domains: []string{"example.com"}})
	if e.opts.Threads != 10 {
		t.Errorf("Threads default not applied: %d", e.opts.Threads)
	}
	if e.opts.TimeoutSeconds != 30 {
		t.Errorf("TimeoutSeconds default not applied: %d", e.opts.TimeoutSeconds)
	}
	if e.opts.MaxEnumMinutes != 10 {
		t.Errorf("MaxEnumMinutes default not applied: %d", e.opts.MaxEnumMinutes)
	}
}

func TestNewKeepsExplicitValues(t *testing.T) {
	e := New(Options{
		Domains:        []string{"x.com"},
		Threads:        5,
		TimeoutSeconds: 15,
		MaxEnumMinutes: 3,
	})
	if e.opts.Threads != 5 || e.opts.TimeoutSeconds != 15 || e.opts.MaxEnumMinutes != 3 {
		t.Errorf("explicit values overwritten: %+v", e.opts)
	}
}

func TestToResult(t *testing.T) {
	h := &resolve.HostEntry{Host: "api.example.com", Domain: "example.com", Source: "crtsh"}
	r := toResult(h)
	if r.Host != "api.example.com" {
		t.Errorf("Host = %q", r.Host)
	}
	if r.Domain != "example.com" {
		t.Errorf("Domain = %q", r.Domain)
	}
	if r.Source != "crtsh" {
		t.Errorf("Source = %q", r.Source)
	}
}

func TestRunRejectsEmptyDomains(t *testing.T) {
	// DefaultOptions sets no Domains, so Run must reject before touching the
	// network or constructing a real subfinder runner.
	e := New(DefaultOptions())
	_, _, err := e.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no domains") {
		t.Errorf("expected 'no domains' error, got %v", err)
	}
}
