// Package servicedetect identifies the service behind an open TCP port via
// praetorian-inc/fingerprintx — the modern replacement for upstream dddd's
// gonmap, so a service on a non-standard port (ssh on 2222) still routes right.
package servicedetect

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

type Endpoint struct {
	Host string
	Port int
}

// Result.Service is the fingerprintx protocol (ssh/http/mysql/...), empty when
// nothing matched.
type Result struct {
	Host    string
	Port    int
	Service string
	Version string
	TLS     bool
}

type Options struct {
	Threads        int
	TimeoutSeconds int
	// FastMode false (default) probes every plugin, not just the port's default
	// service — the whole point: catching services on odd ports.
	FastMode bool
}

func DefaultOptions() Options {
	return Options{Threads: 50, TimeoutSeconds: 5, FastMode: false}
}

type Detector struct {
	opts   Options
	config scan.Config
}

func New(opts Options) *Detector {
	if opts.Threads <= 0 {
		opts.Threads = 50
	}
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 5
	}
	return &Detector{
		opts: opts,
		config: scan.Config{
			FastMode:       opts.FastMode,
			DefaultTimeout: time.Duration(opts.TimeoutSeconds) * time.Second,
		},
	}
}

// Detect fingerprints each endpoint concurrently, one Result per endpoint that
// resolved to an IP. The channel closes when all finish or ctx is cancelled.
func (d *Detector) Detect(ctx context.Context, endpoints []Endpoint) <-chan Result {
	out := make(chan Result, 16)
	if ctx == nil {
		ctx = context.Background()
	}

	go func() {
		defer close(out)
		sem := make(chan struct{}, d.opts.Threads)
		var wg sync.WaitGroup

		for _, ep := range endpoints {
			addr, ok := resolveAddr(ep.Host)
			if !ok {
				continue
			}
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(ep Endpoint, addr netip.Addr) {
				defer wg.Done()
				defer func() { <-sem }()
				d.detectOne(ctx, ep, addr, out)
			}(ep, addr)
		}
		wg.Wait()
	}()

	return out
}

func (d *Detector) detectOne(ctx context.Context, ep Endpoint, addr netip.Addr, out chan<- Result) {
	target := plugins.Target{
		Address: netip.AddrPortFrom(addr, uint16(ep.Port)),
		Host:    ep.Host,
	}
	res := Result{Host: ep.Host, Port: ep.Port}
	// SimpleScanTarget takes no ctx; it bounds itself with DefaultTimeout.
	if svc, err := d.config.SimpleScanTarget(target); err == nil && svc != nil {
		res.Service = svc.Protocol
		res.Version = svc.Version
		res.TLS = svc.TLS
	}
	select {
	case out <- res:
	case <-ctx.Done():
	}
}

// resolveAddr turns an IP literal or hostname into a netip.Addr; fingerprintx
// needs an IP, so a hostname resolves to its first address.
func resolveAddr(host string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, true
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ips[0])
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
