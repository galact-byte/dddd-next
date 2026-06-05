package dnsx

import (
	"context"
	"testing"
)

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	if o.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", o.MaxRetries)
	}
	if o.TimeoutSeconds != 3 {
		t.Errorf("TimeoutSeconds = %d, want 3", o.TimeoutSeconds)
	}
	if o.Threads != 50 {
		t.Errorf("Threads = %d, want 50", o.Threads)
	}
}

func TestNew(t *testing.T) {
	// New must not touch the network — it only configures the dnsx client.
	r, err := New(DefaultOptions())
	if err != nil {
		t.Fatalf("New(DefaultOptions) failed: %v", err)
	}
	if r == nil || r.client == nil {
		t.Fatal("New returned a nil resolver/client")
	}
	if r.threads != 50 {
		t.Errorf("threads = %d, want 50", r.threads)
	}
}

func TestNewAppliesThreadDefault(t *testing.T) {
	r, err := New(Options{}) // all-zero
	if err != nil {
		t.Fatalf("New(zero) failed: %v", err)
	}
	if r.threads != 50 {
		t.Errorf("threads default not applied: %d", r.threads)
	}
}

func TestNewCustomThreads(t *testing.T) {
	r, err := New(Options{Threads: 10, Resolvers: []string{"udp:1.1.1.1:53"}})
	if err != nil {
		t.Fatalf("New(custom) failed: %v", err)
	}
	if r.threads != 10 {
		t.Errorf("threads = %d, want 10", r.threads)
	}
}

func TestResolveRejectsEmpty(t *testing.T) {
	r, err := New(DefaultOptions())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if _, err := r.Resolve(""); err == nil {
		t.Error("Resolve(\"\") should return an error")
	}
}

func TestResolveManyEmptyInput(t *testing.T) {
	// Empty input must close the channel immediately with zero results —
	// exercises the goroutine/close path without any DNS traffic.
	r, err := New(DefaultOptions())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	ch := r.ResolveMany(context.Background(), nil)
	count := 0
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 results for empty input, got %d", count)
	}
}
