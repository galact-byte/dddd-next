// Package app wires the discovery and scanning modules into one scan pipeline
// driven by config.Config. It is the workflow layer the CLI calls.
//
// Stage flow (port scanning, weak-cred brute force and recon APIs land later):
//
//	targets -> classify -> [subdomain enum] -> DNS resolve -> HTTP probe
//	        -> fingerprint -> nuclei -> report
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"dddd-next/internal/audit"
	"dddd-next/internal/classifier"
	"dddd-next/internal/config"
	"dddd-next/internal/discovery/dnsx"
	"dddd-next/internal/discovery/httpprobe"
	"dddd-next/internal/discovery/subfinder"
	"dddd-next/internal/fingerprint"
	"dddd-next/internal/reporter"
	"dddd-next/internal/scanner/nuclei"
	"dddd-next/internal/types"
)

type Pipeline struct {
	cfg       config.Config
	configDir string
	finger    *fingerprint.Engine
	reporter  reporter.Reporter
	auditor   *audit.Auditor
}

// New loads the fingerprint database and sets up the reporter/auditor sinks.
// configDir is where finger.yaml and nuclei-templates live (next to the binary).
func New(cfg config.Config, configDir string) (*Pipeline, error) {
	fingerPath := filepath.Join(configDir, "fingers", "finger.yaml")
	eng, _, err := fingerprint.LoadYAML(fingerPath)
	if err != nil {
		return nil, fmt.Errorf("app: load fingerprints from %s: %w", fingerPath, err)
	}

	rep, err := buildReporter(cfg)
	if err != nil {
		return nil, err
	}

	aud := audit.Disabled()
	if cfg.AuditLog {
		a, aerr := audit.NewFile("audit.log")
		if aerr != nil {
			_ = rep.Close()
			return nil, fmt.Errorf("app: open audit log: %w", aerr)
		}
		aud = a
	}

	fmt.Printf("[*] fingerprints loaded: %d rules\n", eng.Size())
	return &Pipeline{cfg: cfg, configDir: configDir, finger: eng, reporter: rep, auditor: aud}, nil
}

func (p *Pipeline) Run(ctx context.Context) error {
	probeInputs, domains := p.parseTargets()

	if p.cfg.Subdomain && len(domains) > 0 {
		domains = p.enumerateSubdomains(ctx, domains)
	}
	if len(domains) > 0 {
		probeInputs = append(probeInputs, p.resolveDomains(ctx, domains)...)
	}

	probeInputs = dedup(probeInputs)
	if len(probeInputs) == 0 {
		fmt.Println("[!] no probeable targets after discovery")
		return nil
	}

	liveURLs := p.probeAndFingerprint(ctx, probeInputs)
	if len(liveURLs) > 0 {
		p.runNuclei(ctx, liveURLs)
	}
	return nil
}

func (p *Pipeline) Close() error {
	var errs []error
	if p.reporter != nil {
		if err := p.reporter.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.auditor != nil {
		if err := p.auditor.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// parseTargets classifies each -t value into a directly-probeable input or a
// bare domain that needs enumeration/resolution first. Input kinds that need
// the not-yet-built modules (CIDR/range -> port scan, search query -> recon
// API) are reported and skipped rather than silently dropped.
func (p *Pipeline) parseTargets() (probeInputs, domains []string) {
	for _, raw := range p.cfg.Targets {
		t, err := classifier.Parse(raw)
		if err != nil {
			fmt.Printf("[!] skip %q: %v\n", raw, err)
			continue
		}
		switch t.Type {
		case types.InputURL:
			probeInputs = append(probeInputs, t.URL)
		case types.InputIP, types.InputIPPort, types.InputDomainPort:
			probeInputs = append(probeInputs, hostPort(t))
		case types.InputDomain:
			domains = append(domains, t.Host)
		case types.InputCIDR, types.InputIPRange:
			fmt.Printf("[!] %q (%s): port scanning not implemented yet, skipped\n", raw, t.Type)
		case types.InputSearchQuery:
			fmt.Printf("[!] %q: recon API (Fofa/Hunter/Quake) not implemented yet, skipped\n", raw)
		default:
			fmt.Printf("[!] %q: unrecognized input, skipped\n", raw)
		}
	}
	return probeInputs, domains
}

func (p *Pipeline) enumerateSubdomains(ctx context.Context, domains []string) []string {
	fmt.Printf("[*] subdomain enumeration for %d domain(s)...\n", len(domains))
	opts := subfinder.DefaultOptions()
	opts.Domains = domains
	opts.Proxy = p.cfg.ProxyURL

	results, errCh, err := subfinder.New(opts).Run(ctx)
	if err != nil {
		fmt.Printf("[!] subfinder: %v\n", err)
		return domains
	}

	set := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		set[d] = struct{}{}
	}
	for r := range results {
		set[r.Host] = struct{}{}
	}
	for e := range errCh {
		if e != nil {
			fmt.Printf("[!] subfinder: %v\n", e)
		}
	}

	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	fmt.Printf("[*] subdomains: %d total\n", len(out))
	return out
}

// resolveDomains keeps only domains that resolve to at least one IP and records
// the host->IP mapping in the audit log. Dead names are dropped here so httpx
// does not waste connections on them.
func (p *Pipeline) resolveDomains(ctx context.Context, domains []string) []string {
	fmt.Printf("[*] resolving %d domain(s)...\n", len(domains))
	r, err := dnsx.New(dnsx.DefaultOptions())
	if err != nil {
		fmt.Printf("[!] dnsx: %v; passing domains through unresolved\n", err)
		return domains
	}

	var live []string
	for res := range r.ResolveMany(ctx, domains) {
		if res.Err != "" || len(res.IPs) == 0 {
			continue
		}
		live = append(live, res.Host)
		_ = p.auditor.LogInfo("resolve", map[string]any{"host": res.Host, "ips": res.IPs})
	}
	fmt.Printf("[*] resolved (live): %d\n", len(live))
	return live
}

func (p *Pipeline) probeAndFingerprint(ctx context.Context, inputs []string) []string {
	fmt.Printf("[*] HTTP probing %d target(s)...\n", len(inputs))
	probe := httpprobe.New(httpprobe.Options{
		Targets:    inputs,
		TechDetect: true,
		Proxy:      p.cfg.ProxyURL,
	})
	ch, err := probe.Run(ctx)
	if err != nil {
		fmt.Printf("[!] httpx: %v\n", err)
		return nil
	}

	var live []string
	hits := 0
	for resp := range ch {
		live = append(live, resp.URL)
		_ = p.auditor.LogResponse(resp.URL, "http-probe", map[string]any{
			"status": resp.StatusCode, "title": resp.Title,
		})
		for _, fp := range p.finger.Match(httpprobe.ToFingerprintContext(resp)) {
			fp.Target = resp.URL
			if werr := p.reporter.WriteFingerprint(resp.URL, fp); werr != nil {
				fmt.Printf("[!] report: %v\n", werr)
			}
			hits++
		}
	}
	fmt.Printf("[*] live web: %d, fingerprint hits: %d\n", len(live), hits)
	return live
}

func (p *Pipeline) runNuclei(ctx context.Context, urls []string) {
	tmplDir := filepath.Join(p.configDir, "nuclei-templates")
	if info, err := os.Stat(tmplDir); err != nil || !info.IsDir() {
		fmt.Printf("[!] nuclei templates not found at %s — run `dddd update` first; skipping vuln scan\n", tmplDir)
		return
	}

	fmt.Printf("[*] nuclei scanning %d target(s)...\n", len(urls))
	opts := nuclei.DefaultOptions()
	opts.TemplatesDir = tmplDir
	if p.cfg.ProxyURL != "" {
		opts.Proxy = []string{p.cfg.ProxyURL}
	}

	sc, err := nuclei.New(ctx, opts)
	if err != nil {
		fmt.Printf("[!] nuclei init: %v\n", err)
		return
	}
	defer sc.Close()

	findings, errCh, err := sc.Scan(ctx, urls)
	if err != nil {
		fmt.Printf("[!] nuclei scan: %v\n", err)
		return
	}

	n := 0
	for f := range findings {
		if werr := p.reporter.WriteFinding(f); werr != nil {
			fmt.Printf("[!] report: %v\n", werr)
		}
		_ = p.auditor.LogInfo("finding", map[string]any{
			"id": f.ID, "severity": string(f.Severity), "target": f.Target,
		})
		n++
	}
	for e := range errCh {
		if e != nil {
			fmt.Printf("[!] nuclei: %v\n", e)
		}
	}
	fmt.Printf("[*] findings: %d\n", n)
}

func buildReporter(cfg config.Config) (reporter.Reporter, error) {
	var sinks []reporter.Reporter
	switch cfg.OutputType {
	case "json":
		jr, err := reporter.NewJSONFile(cfg.Output)
		if err != nil {
			return nil, fmt.Errorf("app: json reporter: %w", err)
		}
		sinks = append(sinks, jr)
	default:
		tr, err := reporter.NewTextFile(cfg.Output)
		if err != nil {
			return nil, fmt.Errorf("app: text reporter: %w", err)
		}
		sinks = append(sinks, tr)
	}
	if cfg.HTMLOutput != "" {
		sinks = append(sinks, reporter.NewHTML(cfg.HTMLOutput))
	}
	return reporter.NewMulti(sinks...), nil
}

func hostPort(t types.Target) string {
	if t.Port > 0 {
		return fmt.Sprintf("%s:%d", t.Host, t.Port)
	}
	return t.Host
}

func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
