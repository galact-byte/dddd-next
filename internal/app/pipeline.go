// Package app wires the discovery and scanning modules into one scan pipeline
// driven by config.Config. It is the workflow layer the CLI calls.
//
// Stage flow:
//
//	targets -> classify -> [CIDR/range port scan | search-query recon]
//	        -> brute force -> [subdomain enum] -> DNS resolve -> HTTP probe
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
	"dddd-next/internal/discovery/portscan"
	"dddd-next/internal/discovery/subfinder"
	"dddd-next/internal/discovery/uncover"
	"dddd-next/internal/fingerprint"
	"dddd-next/internal/reporter"
	"dddd-next/internal/scanner/gopocs"
	"dddd-next/internal/scanner/nuclei"
	"dddd-next/internal/scanner/pocmap"
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
	probeInputs, domains, portscanSpecs, searchQueries := p.parseTargets()

	var openPorts []portscan.Result
	if len(portscanSpecs) > 0 {
		openPorts = append(openPorts, p.scanPorts(ctx, portscanSpecs)...)
	}
	if len(searchQueries) > 0 {
		openPorts = append(openPorts, p.recon(ctx, searchQueries)...)
	}
	if len(openPorts) > 0 {
		for _, r := range openPorts {
			probeInputs = append(probeInputs, fmt.Sprintf("%s:%d", r.Host, r.Port))
		}
		p.bruteForce(ctx, openPorts)
	}
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

	liveURLs, fpHits := p.probeAndFingerprint(ctx, probeInputs)
	if len(liveURLs) > 0 {
		p.runNuclei(ctx, liveURLs, fpHits)
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

// parseTargets classifies each -t value into a directly-probeable input, a bare
// domain that needs enumeration/resolution first, a CIDR/range that needs a
// port scan, or a search query that needs the recon engines.
func (p *Pipeline) parseTargets() (probeInputs, domains, portscanSpecs, searchQueries []string) {
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
			portscanSpecs = append(portscanSpecs, t.Raw)
		case types.InputSearchQuery:
			searchQueries = append(searchQueries, t.Raw)
		default:
			fmt.Printf("[!] %q: unrecognized input, skipped\n", raw)
		}
	}
	return probeInputs, domains, portscanSpecs, searchQueries
}

// scanPorts expands CIDR/IP-range specs into hosts and TCP-connect scans the
// common port set, returning open ports for both the HTTP probe and the brute
// forcer. Connect scanning is direct (no proxy) so it works on intranet targets.
func (p *Pipeline) scanPorts(ctx context.Context, specs []string) []portscan.Result {
	hosts, err := portscan.ExpandHosts(specs)
	if err != nil {
		fmt.Printf("[!] portscan: %v\n", err)
		return nil
	}
	fmt.Printf("[*] port scanning %d host(s) x %d ports...\n", len(hosts), len(portscan.DefaultPorts))

	sc := portscan.New(portscan.DefaultOptions())
	var open []portscan.Result
	for r := range sc.Scan(ctx, hosts) {
		open = append(open, r)
		_ = p.auditor.LogInfo("port-open", map[string]any{"host": r.Host, "port": r.Port})
	}
	fmt.Printf("[*] open ports: %d\n", len(open))
	return open
}

// bruteForce attempts weak credentials against the service ports the scanner
// found (ssh/mysql/postgresql/redis/ftp), writing each hit to the report. It
// runs independently of the web probe chain; non-service ports are ignored by
// the engine's routing.
func (p *Pipeline) bruteForce(ctx context.Context, openPorts []portscan.Result) {
	endpoints := make([]gopocs.Endpoint, 0, len(openPorts))
	for _, r := range openPorts {
		endpoints = append(endpoints, gopocs.Endpoint{Host: r.Host, Port: r.Port})
	}

	dictDir := filepath.Join(p.configDir, "dict")
	fmt.Printf("[*] weak-credential brute force on %d open port(s)...\n", len(endpoints))
	eng := gopocs.New(gopocs.DefaultOptions(dictDir))

	n := 0
	for f := range eng.Run(ctx, endpoints) {
		if werr := p.reporter.WriteFinding(f); werr != nil {
			fmt.Printf("[!] report: %v\n", werr)
		}
		_ = p.auditor.LogInfo("weak-cred", map[string]any{
			"id": f.ID, "target": f.Target, "desc": f.Description,
		})
		n++
	}
	fmt.Printf("[*] weak credentials: %d\n", n)
}

// recon resolves search-query targets through the uncover engines (fofa/hunter/
// quake) into open host:port assets, feeding the same downstream path as the
// port scanner. It needs internet egress and API keys (env vars); a missing-key
// error is reported per query, not fatal.
func (p *Pipeline) recon(ctx context.Context, queries []string) []portscan.Result {
	fmt.Printf("[*] recon: %d search query(ies) via fofa/hunter/quake...\n", len(queries))
	opts := uncover.DefaultOptions()
	opts.Proxy = p.cfg.ProxyURL
	src := uncover.New(opts)

	seen := make(map[string]struct{})
	var results []portscan.Result
	for _, q := range queries {
		assets, err := src.Query(ctx, q, 0)
		if err != nil {
			fmt.Printf("[!] recon %q: %v\n", q, err)
			continue
		}
		for _, a := range assets {
			host := a.Host
			if host == "" {
				host = a.IP
			}
			if host == "" || a.Port == 0 {
				continue
			}
			key := fmt.Sprintf("%s:%d", host, a.Port)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			results = append(results, portscan.Result{Host: host, Port: a.Port})
			_ = p.auditor.LogInfo("recon", map[string]any{"source": a.Source, "host": host, "port": a.Port, "url": a.URL})
		}
	}
	fmt.Printf("[*] recon assets: %d\n", len(results))
	return results
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

// probeAndFingerprint returns the live URLs plus a map of URL → matched product
// names, which the precise nuclei stage uses to pick each target's POCs.
func (p *Pipeline) probeAndFingerprint(ctx context.Context, inputs []string) ([]string, map[string][]string) {
	fmt.Printf("[*] HTTP probing %d target(s)...\n", len(inputs))
	probe := httpprobe.New(httpprobe.Options{
		Targets:    inputs,
		TechDetect: true,
		Proxy:      p.cfg.ProxyURL,
	})
	ch, err := probe.Run(ctx)
	if err != nil {
		fmt.Printf("[!] httpx: %v\n", err)
		return nil, nil
	}

	var live []string
	hits := make(map[string][]string)
	n := 0
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
			hits[resp.URL] = append(hits[resp.URL], fp.Name)
			n++
		}
	}
	fmt.Printf("[*] live web: %d, fingerprint hits: %d\n", len(live), n)
	return live, hits
}

// runNuclei scans the live URLs. Precise mode (default) loads only the POC
// files the fingerprint hits map to; full mode (-full) runs the whole
// nuclei-templates directory.
func (p *Pipeline) runNuclei(ctx context.Context, urls []string, fpHits map[string][]string) {
	opts := nuclei.DefaultOptions()
	if p.cfg.ProxyURL != "" {
		opts.Proxy = []string{p.cfg.ProxyURL}
	}

	if p.cfg.FullScan {
		tmplDir := filepath.Join(p.configDir, "nuclei-templates")
		if info, err := os.Stat(tmplDir); err != nil || !info.IsDir() {
			fmt.Printf("[!] nuclei templates not found at %s — run `dddd update` first; skipping vuln scan\n", tmplDir)
			return
		}
		opts.TemplatesDir = tmplDir
		fmt.Printf("[*] nuclei full scan: %d target(s) x all templates...\n", len(urls))
	} else {
		pocs := p.resolvePOCs(fpHits)
		if len(pocs) == 0 {
			fmt.Println("[*] nuclei precise: no fingerprint-matched POCs, skipping vuln scan")
			return
		}
		opts.Templates = pocs
		fmt.Printf("[*] nuclei precise scan: %d target(s) x %d matched POC(s)...\n", len(urls), len(pocs))
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

// resolvePOCs maps the fingerprint hits to the deduplicated set of POC files to
// run, via configs/pocs/mapping.yaml + legacy/. Returns nil (skip scan) when no
// product matched or the mapping can't be loaded.
func (p *Pipeline) resolvePOCs(fpHits map[string][]string) []string {
	if len(fpHits) == 0 {
		return nil
	}
	m, err := pocmap.Load(filepath.Join(p.configDir, "pocs", "mapping.yaml"))
	if err != nil {
		fmt.Printf("[!] pocmap: %v; skipping precise scan\n", err)
		return nil
	}
	pocDir := filepath.Join(p.configDir, "pocs", "legacy")
	resolved, stats := m.Resolve(fpHits, pocDir, !p.cfg.DisableGeneralPoc)
	fmt.Printf("[*] poc mapping: %d product hit(s) -> %d POC file(s) across %d target(s)\n",
		stats.MatchedNames, stats.UniquePOCs, stats.Targets)
	return pocmap.Union(resolved)
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
