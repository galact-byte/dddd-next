// Package subfinder wraps projectdiscovery/subfinder/v2 with a channel-based
// API for passive subdomain enumeration, mirroring internal/discovery/httpprobe.
package subfinder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Result is dddd-next's narrowed view of a discovered subdomain.
type Result struct {
	Host   string
	Domain string
	Source string
}

// Options configures passive enumeration; zero values are filled by New.
type Options struct {
	Domains        []string
	Threads        int
	TimeoutSeconds int
	MaxEnumMinutes int
	Sources        []string
	ExcludeSources []string
	All            bool
	Proxy          string
	Silent         bool
	DisableUpdateCheck bool // default true — dddd update owns tooling, no phone-home
}

func DefaultOptions() Options {
	return Options{
		Threads:            10,
		TimeoutSeconds:     30,
		MaxEnumMinutes:     10,
		Silent:             true,
		DisableUpdateCheck: true,
	}
}

type Enumerator struct {
	opts Options
}

func New(opts Options) *Enumerator {
	if opts.Threads <= 0 {
		opts.Threads = 10
	}
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 30
	}
	if opts.MaxEnumMinutes <= 0 {
		opts.MaxEnumMinutes = 10
	}
	return &Enumerator{opts: opts}
}

// Run streams discovered subdomains on the result channel, which closes when
// enumeration finishes or ctx is cancelled. Fatal errors arrive once on errCh.
func (e *Enumerator) Run(ctx context.Context) (results <-chan Result, errCh <-chan error, err error) {
	if len(e.opts.Domains) == 0 {
		return nil, nil, errors.New("subfinder: no domains")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	out := make(chan Result, 64)
	errs := make(chan error, 1)

	sfOpts := &runner.Options{
		Threads:            e.opts.Threads,
		Timeout:            e.opts.TimeoutSeconds,
		MaxEnumerationTime: e.opts.MaxEnumMinutes,
		Silent:             e.opts.Silent,
		All:                e.opts.All,
		Proxy:              e.opts.Proxy,
		Sources:            e.opts.Sources,
		ExcludeSources:     e.opts.ExcludeSources,
		DisableUpdateCheck: e.opts.DisableUpdateCheck,
		Output:             io.Discard, // results come via ResultCallback
		ResultCallback: func(hostEntry *resolve.HostEntry) {
			if hostEntry == nil {
				return
			}
			select {
			case out <- toResult(hostEntry):
			case <-ctx.Done():
			}
		},
	}

	sfRunner, nerr := runner.NewRunner(sfOpts)
	if nerr != nil {
		close(out)
		close(errs)
		return nil, nil, fmt.Errorf("subfinder: create runner: %w", nerr)
	}

	go func() {
		defer close(out)
		defer close(errs)
		reader := strings.NewReader(strings.Join(e.opts.Domains, "\n"))
		if eerr := sfRunner.EnumerateMultipleDomainsWithCtx(ctx, reader, []io.Writer{io.Discard}); eerr != nil {
			errs <- fmt.Errorf("subfinder: enumerate: %w", eerr)
		}
	}()

	return out, errs, nil
}

func toResult(h *resolve.HostEntry) Result {
	return Result{Host: h.Host, Domain: h.Domain, Source: h.Source}
}
