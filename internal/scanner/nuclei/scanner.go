// Package nuclei wraps projectdiscovery/nuclei/v3 lib SDK with a
// channel-based, dddd-next-friendly API.
//
// The original dddd called into a forked exportrunner.ExportRunnerNew that
// exposed nuclei internals; we use the upstream public lib SDK instead. That
// constrains us to: NewNucleiEngineCtx → LoadAllTemplates → LoadTargets →
// ExecuteCallbackWithCtx → Close. Anything outside this contract has to be
// rebuilt on top of the SDK rather than reaching into private packages.
//
// Design notes:
//   - We project nuclei's output.ResultEvent onto types.Finding so callers
//     never import any nuclei package directly. Upstream field churn stops at
//     the toFinding boundary.
//   - The callback-based SDK is wrapped into a channel of findings, mirroring
//     how internal/discovery/httpprobe surfaces httpx results — same mental
//     model across the project.
//   - DisableUpdateCheck() + SetTemplatesDir pin nuclei to dddd-next's own
//     templates and skip the startup phone-home; `dddd update` owns updates.
package nuclei

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"dddd-next/internal/types"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	nucleiconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	pkgtypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Options configures a Scanner. Use DefaultOptions() for safe baseline values.
type Options struct {
	// TemplatesDir is the root directory containing nuclei YAML templates.
	// When empty, nuclei falls back to its built-in default location.
	TemplatesDir string

	// Templates is an explicit list of POC file paths. When set, nuclei loads
	// exactly these instead of walking TemplatesDir — the fingerprint→POC path.
	Templates []string

	// TemplateIDs filters templates by their `id:` field. This is the bridge
	// between dddd-next's fingerprint engine and targeted POC execution —
	// fingerprint hits → list of template IDs → only those templates run.
	TemplateIDs []string

	// Tags / ExcludeTags filter templates by tag membership.
	Tags        []string
	ExcludeTags []string

	// Severities is a CSV string accepted by nuclei (e.g. "high,critical").
	Severities        string
	ExcludeSeverities string

	// Concurrency tuning. Zero values fall back to library defaults.
	Concurrency     int // template concurrency (per host)
	HostConcurrency int // host concurrency (per template)

	// Proxy is a list of proxy URLs (e.g. ["http://127.0.0.1:7890"]).
	Proxy []string

	NoInteractsh     bool
	InteractshServer string
	InteractshToken  string

	// DisableUpdate stops nuclei from trying to upgrade templates on startup.
	// Default true — `dddd update` owns template lifecycle.
	DisableUpdate bool

	// Silent / Verbose / Debug control nuclei's internal log verbosity.
	// Default Silent=true so SDK callers don't get raw banners on stdout.
	Silent  bool
	Verbose bool
	Debug   bool

	// ResponseReadSize caps the bytes read from each response body.
	// Default 5 MiB matches nuclei CLI behavior.
	ResponseReadSize int
}

// DefaultOptions returns the recommended baseline for SDK consumers.
func DefaultOptions() Options {
	return Options{
		Concurrency:      25,
		HostConcurrency:  25,
		DisableUpdate:    true,
		Silent:           true,
		ResponseReadSize: 5 * 1024 * 1024,
	}
}

// Scanner runs nuclei templates against a set of targets and emits findings.
//
// One Scanner can be reused across multiple Scan calls but is NOT safe for
// concurrent Scan invocations. Use multiple Scanners for parallel scans.
type Scanner struct {
	opts   Options
	engine *nucleilib.NucleiEngine
}

// New constructs a Scanner. The provided ctx is bound to the underlying
// nuclei engine — canceling it tears down in-flight scans.
//
// Errors are wrapped with the "nuclei:" prefix for easy log grepping.
func New(ctx context.Context, opts Options) (*Scanner, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ensureIgnoreFile()
	// nuclei resolves templates from a process-global, not from our options;
	// pin it to ours so it won't fall back to a stray install and phone home.
	if opts.TemplatesDir != "" {
		nucleiconfig.DefaultConfig.SetTemplatesDir(opts.TemplatesDir)
	}
	sdkOpts := buildSDKOptions(opts)
	engine, err := nucleilib.NewNucleiEngineCtx(ctx, sdkOpts...)
	if err != nil {
		return nil, fmt.Errorf("nuclei: init engine: %w", err)
	}
	return &Scanner{opts: opts, engine: engine}, nil
}

// Scan executes nuclei against targets, sending each match to the returned
// channel. The channel is closed when the scan ends or ctx is canceled. Any
// fatal scan error is delivered on the returned errCh exactly once before
// errCh is closed.
//
// Caller must drain `findings` to completion (otherwise the producer
// goroutine leaks) and invoke Close() once finished with this Scanner.
func (s *Scanner) Scan(ctx context.Context, targets []string) (findings <-chan types.Finding, errCh <-chan error, err error) {
	if len(targets) == 0 {
		return nil, nil, errors.New("nuclei: no targets")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// LoadAllTemplates may take seconds — front-load it so the caller fails
	// fast on a misconfigured templates directory rather than seeing an
	// empty findings channel.
	if err := s.engine.LoadAllTemplates(); err != nil {
		return nil, nil, fmt.Errorf("nuclei: load templates: %w", err)
	}
	s.engine.LoadTargets(targets, false)

	out := make(chan types.Finding, 16)
	errs := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errs)

		callback := func(ev *output.ResultEvent) {
			if ev == nil {
				return
			}
			select {
			case out <- toFinding(ev):
			case <-ctx.Done():
			}
		}

		if execErr := s.engine.ExecuteCallbackWithCtx(ctx, callback); execErr != nil {
			errs <- fmt.Errorf("nuclei: execute: %w", execErr)
		}
	}()

	return out, errs, nil
}

// Close releases resources held by the underlying nuclei engine. Safe to call
// multiple times; nil-safe.
func (s *Scanner) Close() error {
	if s == nil || s.engine == nil {
		return nil
	}
	s.engine.Close()
	s.engine = nil
	return nil
}

// ensureIgnoreFile pre-creates ~/.config/nuclei/.nuclei-ignore so a fresh
// install doesn't log "Could not read nuclei-ignore file" on every run.
func ensureIgnoreFile() {
	dir, err := os.UserConfigDir()
	if err != nil {
		return
	}
	nucleiDir := filepath.Join(dir, "nuclei")
	if err := os.MkdirAll(nucleiDir, 0o755); err != nil {
		return
	}
	ignore := filepath.Join(nucleiDir, ".nuclei-ignore")
	// nuclei parses this as YAML with tags/files lists; a missing or comment-only
	// file makes it log "could not parse ... EOF". Rewrite unless it already has a
	// valid key (so we also fix a bad file an older build may have left behind).
	if data, err := os.ReadFile(ignore); err == nil {
		if strings.Contains(string(data), "tags:") || strings.Contains(string(data), "files:") {
			return
		}
	}
	_ = os.WriteFile(ignore, []byte("tags: []\nfiles: []\n"), 0o644)
}

// buildSDKOptions translates dddd-next Options into the SDK's functional
// options slice. Kept as a free function so it's trivially testable without
// initializing a real engine.
func buildSDKOptions(o Options) []nucleilib.NucleiSDKOptions {
	var opts []nucleilib.NucleiSDKOptions

	switch {
	case len(o.Templates) > 0:
		opts = append(opts, nucleilib.WithTemplatesOrWorkflows(nucleilib.TemplateSources{
			Templates: o.Templates,
		}))
	case o.TemplatesDir != "":
		opts = append(opts, nucleilib.WithTemplatesOrWorkflows(nucleilib.TemplateSources{
			Templates: []string{o.TemplatesDir},
		}))
	}

	filters := nucleilib.TemplateFilters{
		IDs:               o.TemplateIDs,
		Tags:              o.Tags,
		ExcludeTags:       o.ExcludeTags,
		Severity:          o.Severities,
		ExcludeSeverities: o.ExcludeSeverities,
	}
	if hasFilters(filters) {
		opts = append(opts, nucleilib.WithTemplateFilters(filters))
	}

	if o.Concurrency > 0 || o.HostConcurrency > 0 {
		opts = append(opts, nucleilib.WithConcurrency(nucleilib.Concurrency{
			TemplateConcurrency:           orDefault(o.Concurrency, 25),
			HostConcurrency:               orDefault(o.HostConcurrency, 25),
			HeadlessHostConcurrency:       10,
			HeadlessTemplateConcurrency:   10,
			JavascriptTemplateConcurrency: 10,
			TemplatePayloadConcurrency:    25,
			ProbeConcurrency:              50,
		}))
	}

	opts = append(opts, nucleilib.WithVerbosity(nucleilib.VerbosityOptions{
		Silent:  o.Silent,
		Verbose: o.Verbose,
		Debug:   o.Debug,
	}))

	if o.NoInteractsh || o.InteractshServer != "" || o.InteractshToken != "" {
		opts = append(opts, nucleilib.WithOptions(&pkgtypes.Options{
			NoInteractsh:    o.NoInteractsh,
			InteractshURL:   o.InteractshServer,
			InteractshToken: o.InteractshToken,
		}))
	}

	if o.DisableUpdate {
		// The startup update check phones home and aborts init on failure.
		opts = append(opts, nucleilib.DisableUpdateCheck())
	}

	if len(o.Proxy) > 0 {
		opts = append(opts, nucleilib.WithProxy(o.Proxy, false))
	}

	if o.ResponseReadSize > 0 {
		opts = append(opts, nucleilib.WithResponseReadSize(o.ResponseReadSize))
	}

	return opts
}

// hasFilters reports whether any TemplateFilters field is non-zero. Without
// this guard we'd register an empty filter, which nuclei treats as "match
// nothing" instead of "no filtering".
func hasFilters(f nucleilib.TemplateFilters) bool {
	return len(f.IDs) > 0 || len(f.Tags) > 0 || len(f.ExcludeTags) > 0 ||
		len(f.IncludeTags) > 0 || len(f.Authors) > 0 ||
		len(f.ExcludeIDs) > 0 || len(f.TemplateCondition) > 0 ||
		f.Severity != "" || f.ExcludeSeverities != "" ||
		f.ProtocolTypes != "" || f.ExcludeProtocolTypes != ""
}

func orDefault(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

// toFinding projects a nuclei ResultEvent onto a dddd-next types.Finding.
// Slices are defensively copied so downstream consumers cannot mutate
// nuclei's internal state via shared backing arrays.
func toFinding(ev *output.ResultEvent) types.Finding {
	var refs []string
	if ev.Info.Reference != nil {
		refs = sliceCopy(ev.Info.Reference.ToSlice())
	}
	return types.Finding{
		ID:           ev.TemplateID,
		Name:         ev.Info.Name,
		Severity:     mapSeverity(ev.Info.SeverityHolder.Severity.String()),
		Target:       pickTarget(ev),
		Template:     ev.Template,
		Description:  ev.Info.Description,
		References:   refs,
		Request:      ev.Request,
		Response:     ev.Response,
		Tags:         sliceCopy(ev.Info.Tags.ToSlice()),
		DiscoveredAt: ev.Timestamp,
	}
}

// pickTarget chooses the most specific identifier for where the match landed.
// Priority: full matched-at locator > URL > Host:Port > Host. A scanner
// consumer cares most about the exact spot, hence the ordering.
func pickTarget(ev *output.ResultEvent) string {
	if ev.Matched != "" {
		return ev.Matched
	}
	if ev.URL != "" {
		return ev.URL
	}
	if ev.Host != "" && ev.Port != "" {
		return ev.Host + ":" + ev.Port
	}
	return ev.Host
}

// mapSeverity normalizes nuclei severity strings to dddd-next types.Severity.
// Empty / unknown values fall back to SeverityInfo so the report writer never
// receives a tier it doesn't know how to sort.
func mapSeverity(s string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	}
	return types.SeverityInfo
}

// sliceCopy returns a defensive copy of the input slice. Returns nil for
// nil/empty inputs so JSON serialization stays clean (nil → omitted, []
// → "[]").
func sliceCopy(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}
