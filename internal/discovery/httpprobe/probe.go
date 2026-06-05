// Package httpprobe wraps projectdiscovery/httpx/runner with a Go-idiomatic
// channel-based API.
//
// The original dddd used a callback that mutated package-level maps under
// a sync.Mutex. We surface a channel of strongly-typed Response records
// instead so the caller (workflow layer) owns state and concurrency.
//
// We project httpx's 50+-field Result down to the ~20 fields the rest of
// dddd-next actually consumes — narrowing here means upstream API churn
// in the wider Result struct rarely propagates further into our code.
package httpprobe

import (
	"context"
	"errors"
	"fmt"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"

	"dddd-next/pkg/fingerdsl"
)

// Response is dddd-next's narrowed view of an httpx scan result.
type Response struct {
	Input         string
	URL           string
	FinalURL      string
	Scheme        string
	Host          string
	Port          string
	Path          string
	StatusCode    int
	ContentLength int
	ContentType   string
	Title         string
	WebServer     string
	Body          string
	RawHeaders    string
	FavIconMMH3   string
	Technologies  []string
	A             []string
	CDN           bool
	Failed        bool
	Err           string
}

// Options configures the probe. Zero-value gives sensible defaults.
type Options struct {
	Targets         []string
	Threads         int    // default 50
	TimeoutSeconds  int    // default 10
	FollowRedirects bool   // default false
	TechDetect      bool   // default false
	Proxy           string // HTTP/SOCKS5 URL; empty disables
	Methods         string // default "GET"
	MaxBodyBytes    int    // default 2 MiB
}

// Probe drives a single httpx scan run.
type Probe struct {
	opts Options
}

// New builds a Probe with defaults applied.
func New(opts Options) *Probe {
	if opts.Threads == 0 {
		opts.Threads = 50
	}
	if opts.TimeoutSeconds == 0 {
		opts.TimeoutSeconds = 10
	}
	if opts.Methods == "" {
		opts.Methods = "GET"
	}
	if opts.MaxBodyBytes == 0 {
		opts.MaxBodyBytes = 2 << 20 // 2 MiB — enough for most title/banner regex hits
	}
	return &Probe{opts: opts}
}

// Run starts the scan and returns a channel of responses. The channel
// closes when the scan finishes or ctx is cancelled.
//
// Failed probes (no HTTP response) are dropped silently. Callers that
// want them can flip a future Options.IncludeFailed switch.
func (p *Probe) Run(ctx context.Context) (<-chan Response, error) {
	if len(p.opts.Targets) == 0 {
		return nil, errors.New("httpprobe: no targets")
	}

	out := make(chan Response, 128)

	runnerOpts := runner.Options{
		InputTargetHost:           goflags.StringSlice(p.opts.Targets),
		Methods:                   p.opts.Methods,
		Threads:                   p.opts.Threads,
		Timeout:                   p.opts.TimeoutSeconds,
		FollowRedirects:           p.opts.FollowRedirects,
		TechDetect:                p.opts.TechDetect,
		HTTPProxy:                 p.opts.Proxy,
		Silent:                    true,
		NoColor:                   true,
		MaxResponseBodySizeToRead: p.opts.MaxBodyBytes,
		MaxResponseBodySizeToSave: p.opts.MaxBodyBytes,
		// httpx fills Result.ResponseBody / RawHeaders only when this is set
		// (runner.go ~2174); without it, body= and header= fingerprints never hit.
		ResponseInStdout: true,
		OnResult: func(r runner.Result) {
			if r.Failed {
				return
			}
			select {
			case <-ctx.Done():
			case out <- toResponse(r):
			}
		},
	}

	r, err := runner.New(&runnerOpts)
	if err != nil {
		close(out)
		return nil, fmt.Errorf("httpprobe: create runner: %w", err)
	}

	go func() {
		defer close(out)
		defer r.Close()
		r.RunEnumeration()
	}()

	return out, nil
}

// toResponse maps httpx's verbose Result into our narrower type.
//
// Slices are copied so callers can't accidentally mutate runner-owned
// memory after the channel send.
func toResponse(r runner.Result) Response {
	resp := Response{
		Input:         r.Input,
		URL:           r.URL,
		FinalURL:      r.FinalURL,
		Scheme:        r.Scheme,
		Host:          r.Host,
		Port:          r.Port,
		Path:          r.Path,
		StatusCode:    r.StatusCode,
		ContentLength: r.ContentLength,
		ContentType:   r.ContentType,
		Title:         r.Title,
		WebServer:     r.WebServer,
		Body:          r.ResponseBody,
		RawHeaders:    r.RawHeaders,
		FavIconMMH3:   r.FavIconMMH3,
		Technologies:  append([]string(nil), r.Technologies...),
		A:             append([]string(nil), r.A...),
		CDN:           r.CDN,
		Failed:        r.Failed,
	}
	if r.Err != nil {
		resp.Err = r.Err.Error()
	}
	return resp
}

// ToFingerprintContext builds a fingerdsl.Context from a Response so the
// fingerprint engine can match against it directly. Field keys follow the
// conventions used in dddd's finger.yaml (all lower-case).
func ToFingerprintContext(r Response) fingerdsl.Context {
	return fingerdsl.Context{
		"body":         r.Body,
		"title":        r.Title,
		"header":       r.RawHeaders,
		"banner":       r.WebServer,
		"protocol":     r.Scheme,
		"icon_hash":    r.FavIconMMH3,
		"favicon_hash": r.FavIconMMH3,
	}
}
