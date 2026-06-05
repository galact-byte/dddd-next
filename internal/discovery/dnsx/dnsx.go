// Package dnsx wraps projectdiscovery/dnsx/libs/dnsx for DNS resolution. The
// upstream library is aliased dnsxlib so this package keeps the name dnsx
// (same convention as internal/scanner/nuclei wrapping nucleilib).
package dnsx

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	dnsxlib "github.com/projectdiscovery/dnsx/libs/dnsx"
)

// Result is the outcome of resolving one hostname; Err is set (not dropped)
// on failure so a single bad host never aborts a batch.
type Result struct {
	Host string
	IPs  []string
	Err  string
}

// Options configures the resolver; zero values fall back to library defaults.
type Options struct {
	Resolvers      []string
	MaxRetries     int
	TimeoutSeconds int
	Threads        int // ResolveMany concurrency
	Proxy          string
}

func DefaultOptions() Options {
	return Options{MaxRetries: 5, TimeoutSeconds: 3, Threads: 50}
}

type Resolver struct {
	client  *dnsxlib.DNSX
	threads int
}

// New configures a resolver without performing any network I/O.
func New(opts Options) (*Resolver, error) {
	libOpts := dnsxlib.DefaultOptions
	if len(opts.Resolvers) > 0 {
		libOpts.BaseResolvers = opts.Resolvers
	}
	if opts.MaxRetries > 0 {
		libOpts.MaxRetries = opts.MaxRetries
	}
	if opts.TimeoutSeconds > 0 {
		libOpts.Timeout = time.Duration(opts.TimeoutSeconds) * time.Second
	}
	libOpts.Proxy = opts.Proxy

	client, err := dnsxlib.New(libOpts)
	if err != nil {
		return nil, fmt.Errorf("dnsx: init client: %w", err)
	}

	threads := opts.Threads
	if threads <= 0 {
		threads = 50
	}
	return &Resolver{client: client, threads: threads}, nil
}

// Resolve returns the A-record IPs for a single hostname (IP literals pass through).
func (r *Resolver) Resolve(hostname string) ([]string, error) {
	if hostname == "" {
		return nil, errors.New("dnsx: empty hostname")
	}
	return r.client.Lookup(hostname)
}

// ResolveMany resolves hostnames concurrently (bounded by Threads), emitting one
// Result each. The channel closes when all hosts finish or ctx is cancelled.
func (r *Resolver) ResolveMany(ctx context.Context, hostnames []string) <-chan Result {
	out := make(chan Result, 64)
	if ctx == nil {
		ctx = context.Background()
	}

	go func() {
		defer close(out)

		sem := make(chan struct{}, r.threads)
		var wg sync.WaitGroup

		for _, h := range hostnames {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case sem <- struct{}{}:
			}

			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				defer func() { <-sem }()

				res := Result{Host: host}
				if ips, err := r.client.Lookup(host); err != nil {
					res.Err = err.Error()
				} else {
					res.IPs = ips
				}

				select {
				case out <- res:
				case <-ctx.Done():
				}
			}(h)
		}

		wg.Wait()
	}()

	return out
}
