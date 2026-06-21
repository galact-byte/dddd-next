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
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dddd-next/internal/audit"
	"dddd-next/internal/classifier"
	"dddd-next/internal/config"
	"dddd-next/internal/discovery/cdn"
	"dddd-next/internal/discovery/dirscan"
	"dddd-next/internal/discovery/dnsx"
	"dddd-next/internal/discovery/hostalive"
	"dddd-next/internal/discovery/httpprobe"
	"dddd-next/internal/discovery/hunter"
	"dddd-next/internal/discovery/portscan"
	"dddd-next/internal/discovery/servicedetect"
	"dddd-next/internal/discovery/subbrute"
	"dddd-next/internal/discovery/subfinder"
	"dddd-next/internal/discovery/synscan"
	"dddd-next/internal/discovery/uncover"
	"dddd-next/internal/fingerprint"
	"dddd-next/internal/reporter"
	"dddd-next/internal/scanner/gopocs"
	"dddd-next/internal/scanner/nuclei"
	"dddd-next/internal/scanner/pocmap"
	"dddd-next/internal/scanner/shiro"
	"dddd-next/internal/types"
	"dddd-next/pkg/fingerdsl"
)

type Pipeline struct {
	cfg       config.Config
	configDir string
	finger    *fingerprint.Engine
	reporter  reporter.Reporter
	auditor   *audit.Auditor

	// ipDomains maps an IP to the domains known to resolve to it, feeding the
	// vhost probe (re-request IP-based roots with each domain's Host header).
	ipDomains map[string][]string

	counts *countingReporter // tallies for the end-of-run summary

	// freshIdx maps a template basename (lowercased, no .yaml) to its path in
	// the updated nuclei-templates dir, so precise mode prefers the maintained
	// v3-compatible template over the frozen legacy/ copy. Built lazily once.
	freshIdx      map[string]string
	freshIdxBuilt bool
}

// New loads the fingerprint database and sets up the reporter/auditor sinks.
// configDir is where finger.yaml and nuclei-templates live (next to the binary).
func New(cfg config.Config, configDir string) (*Pipeline, error) {
	fingerPath := configuredPath(cfg.FingerConfigFilePath, filepath.Join(configDir, "fingers", "finger.yaml"))
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
		a, aerr := audit.NewFile(cfg.AuditLogFile)
		if aerr != nil {
			_ = rep.Close()
			return nil, fmt.Errorf("app: open audit log: %w", aerr)
		}
		aud = a
	}

	fmt.Printf("[32m[*][0m fingerprints loaded: %d rules\n", eng.Size())
	counter := newCountingReporter(rep)
	return &Pipeline{cfg: cfg, configDir: configDir, finger: eng, reporter: counter, auditor: aud, ipDomains: make(map[string][]string), counts: counter}, nil
}

func (p *Pipeline) Run(ctx context.Context) error {
	defer p.printSummary()

	probeInputs, directPorts, domains, portscanSpecs, searchQueries, fingerImports := p.parseTargets()

	if p.cfg.LowPerception {
		return p.runLowPerception(ctx, searchQueries)
	}

	openPorts := append([]portscan.Result(nil), directPorts...)
	if len(portscanSpecs) > 0 {
		openPorts = append(openPorts, p.scanPorts(ctx, portscanSpecs)...)
	}
	if len(searchQueries) > 0 {
		openPorts = append(openPorts, p.recon(ctx, searchQueries)...)
	}
	if len(openPorts) > 0 {
		services := p.detectServices(ctx, openPorts)
		probeInputs = append(probeInputs, webProbeInputs(openPorts, services)...)
		if shouldRunGoPocs(p.cfg) {
			p.bruteForce(ctx, openPorts, services)
		}
	}
	if p.cfg.Subdomain && len(domains) > 0 {
		domains = p.enumerateSubdomains(ctx, domains)
	}
	if len(domains) > 0 {
		domains = p.identifyCDN(ctx, domains)
	}
	if len(domains) > 0 {
		probeInputs = append(probeInputs, p.resolveDomains(ctx, domains)...)
	}

	probeInputs = dedup(probeInputs)
	if len(probeInputs) == 0 && len(fingerImports) == 0 {
		fmt.Println("[31m[!][0m no probeable targets after discovery")
		return nil
	}

	var liveURLs []string
	fpHits := make(map[string][]string)
	if len(probeInputs) > 0 {
		liveURLs, fpHits = p.probeAndFingerprint(ctx, probeInputs)
		if len(liveURLs) > 0 && !p.cfg.SkipDir {
			dirURLs, dirHits := p.dirProbe(ctx, stripPaths(liveURLs), fpHits)
			liveURLs = dedup(append(liveURLs, dirURLs...))
			for u, names := range dirHits {
				fpHits[u] = append(fpHits[u], names...)
			}
		}
		if len(liveURLs) > 0 && !p.cfg.NoHostBind {
			vhostURLs, vhostHits := p.vhostProbe(ctx, liveURLs)
			liveURLs = dedup(append(liveURLs, vhostURLs...))
			for u, names := range vhostHits {
				fpHits[u] = append(fpHits[u], names...)
			}
		}
	}

	// Re-imported fingerprints (fscan/dddd resume): feed POC selection directly,
	// no probing — the fingerprint was already known from the prior run.
	for target, names := range fingerImports {
		for _, n := range names {
			_ = p.reporter.WriteFingerprint(target, types.Fingerprint{Name: n, Target: target, Source: "import"})
		}
		fpHits[target] = append(fpHits[target], names...)
		liveURLs = append(liveURLs, target)
	}
	liveURLs = dedup(liveURLs)

	if len(liveURLs) > 0 && !p.cfg.NoPoc {
		p.runNuclei(ctx, liveURLs, fpHits)
		if shouldRunShiro(p.cfg) {
			p.shiroScan(ctx, liveURLs)
		}
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
func (p *Pipeline) parseTargets() (probeInputs []string, directPorts []portscan.Result, domains, portscanSpecs, searchQueries []string, fingerImports map[string][]string) {
	fingerImports = make(map[string][]string)
	for _, raw := range p.cfg.Targets {
		t, err := classifier.Parse(raw)
		if err != nil {
			fmt.Printf("[31m[!][0m skip %q: %v\n", raw, err)
			continue
		}
		switch t.Type {
		case types.InputURL:
			probeInputs = append(probeInputs, t.URL)
		case types.InputIPPort, types.InputDomainPort:
			directPorts = append(directPorts, portscan.Result{Host: t.Host, Port: t.Port})
		case types.InputDomain:
			domains = append(domains, t.Host)
		case types.InputIP, types.InputCIDR, types.InputIPRange:
			portscanSpecs = append(portscanSpecs, t.Raw)
		case types.InputSearchQuery:
			searchQueries = append(searchQueries, t.Raw)
		case types.InputFingerImport:
			if t.URL != "" {
				fingerImports[t.URL] = append(fingerImports[t.URL], t.Fingers...)
			}
		default:
			fmt.Printf("[31m[!][0m %q: unrecognized input, skipped\n", raw)
		}
	}
	return probeInputs, directPorts, domains, portscanSpecs, searchQueries, fingerImports
}

// scanPorts expands CIDR/IP-range specs into hosts, optionally pre-filters by
// liveness, then scans ports via TCP connect (default) or SYN (-st syn).
func (p *Pipeline) scanPorts(ctx context.Context, specs []string) []portscan.Result {
	hosts, err := portscan.ExpandHosts(specs)
	if err != nil {
		fmt.Printf("\x1b[31m[!]\x1b[0m portscan: %v\n", err)
		return nil
	}

	if !p.cfg.SkipHostDiscovery && (p.cfg.PingFirst || p.cfg.TCPPing) {
		hosts = p.hostDiscovery(ctx, hosts)
		if len(hosts) == 0 {
			return nil
		}
	}

	var open []portscan.Result
	if p.cfg.ScanType == "syn" {
		if results, ok := p.synScan(ctx, hosts); ok {
			open = results
		} else {
			fmt.Println("\x1b[31m[!]\x1b[0m SYN scan unavailable (needs npcap/admin); falling back to TCP connect")
			open = p.tcpScan(ctx, hosts)
		}
	} else {
		open = p.tcpScan(ctx, hosts)
	}

	open = p.filterByPortThreshold(open)
	for _, r := range open {
		_ = p.auditor.LogInfo("port-open", map[string]any{"host": r.Host, "port": r.Port})
	}
	fmt.Printf("\x1b[32m[*]\x1b[0m open ports: %d\n", len(open))
	return open
}

// tcpScan runs the dependency-free TCP connect scanner over the configured port
// set (curated default, -p override, minus -np exclusions).
func (p *Pipeline) tcpScan(ctx context.Context, hosts []string) []portscan.Result {
	opts := portscan.DefaultOptions()
	if p.cfg.TCPPortScanThreads > 0 {
		opts.Threads = p.cfg.TCPPortScanThreads
	}
	if p.cfg.PortScanTimeout > 0 {
		opts.TimeoutSeconds = p.cfg.PortScanTimeout
	}
	if p.cfg.Ports != "" {
		ports, perr := portscan.ParsePortSpec(p.cfg.Ports)
		if perr != nil {
			fmt.Printf("\x1b[31m[!]\x1b[0m %v\n", perr)
			return nil
		}
		opts.Ports = ports
	}
	if p.cfg.ExcludePorts != "" {
		excl, perr := portscan.ParsePortSpec(p.cfg.ExcludePorts)
		if perr != nil {
			fmt.Printf("\x1b[31m[!]\x1b[0m exclude ports: %v\n", perr)
		} else {
			opts.Ports = excludeFrom(opts.Ports, excl)
		}
	}

	fmt.Printf("\x1b[32m[*]\x1b[0m TCP port scanning %d host(s) x %d ports...\n", len(hosts), len(opts.Ports))
	sc := portscan.New(opts)
	var open []portscan.Result
	for r := range sc.Scan(ctx, hosts) {
		fmt.Printf("\x1b[32m  [+]\x1b[0m %s:%d\n", r.Host, r.Port)
		open = append(open, r)
	}
	return open
}

// hostDiscovery pre-filters hosts by ICMP (-ping) and/or TCP connect (-tp); a
// host is kept if either probe answers.
func (p *Pipeline) hostDiscovery(ctx context.Context, hosts []string) []string {
	before := len(hosts)
	aliveSet := make(map[string]struct{})

	if p.cfg.PingFirst && !p.cfg.NoICMPPing {
		for _, h := range hostalive.CheckLive(ctx, hosts, false) {
			aliveSet[h] = struct{}{}
		}
		fmt.Printf("\x1b[32m[*]\x1b[0m ICMP liveness: %d/%d responded\n", len(aliveSet), before)
	}

	if p.cfg.TCPPing {
		var pending []string
		if p.cfg.PingFirst {
			for _, h := range hosts {
				if _, ok := aliveSet[h]; !ok {
					pending = append(pending, h)
				}
			}
		} else {
			pending = hosts
		}
		added := hostalive.CheckLiveTCP(ctx, pending, nil, p.cfg.PortScanTimeout)
		for _, h := range added {
			aliveSet[h] = struct{}{}
		}
		fmt.Printf("\x1b[32m[*]\x1b[0m TCP liveness: +%d host(s)\n", len(added))
	}

	alive := make([]string, 0, len(aliveSet))
	for _, h := range hosts {
		if _, ok := aliveSet[h]; ok {
			alive = append(alive, h)
			delete(aliveSet, h)
		}
	}
	fmt.Printf("\x1b[32m[*]\x1b[0m host discovery: %d/%d alive\n", len(alive), before)
	return alive
}

// synScan runs a naabu SYN scan; ok is false when raw sockets are unavailable
// (no npcap/privilege), signalling the caller to fall back to TCP connect.
func (p *Pipeline) synScan(ctx context.Context, hosts []string) ([]portscan.Result, bool) {
	fmt.Printf("\x1b[36m[SYN]\x1b[0m scanning %d host(s)...\n", len(hosts))
	opts := synscan.DefaultOptions()
	opts.Rate = p.cfg.SYNScanRate
	results, err := synscan.Scan(ctx, hosts, p.synPortSpec(), opts)
	if err != nil {
		fmt.Printf("\x1b[31m[!]\x1b[0m synscan: %v\n", err)
		return nil, false
	}
	open := make([]portscan.Result, 0, len(results))
	for _, r := range results {
		fmt.Printf("\x1b[36m  [+]\x1b[0m %s:%d\n", r.Host, r.Port)
		open = append(open, portscan.Result{Host: r.Host, Port: r.Port})
	}
	return open, true
}

// synPortSpec renders the naabu port string: -p when set (all/full -> full
// range), else the curated default set. naabu rejects the "top1000" alias.
func (p *Pipeline) synPortSpec() string {
	spec := strings.TrimSpace(p.cfg.Ports)
	if spec == "" {
		parts := make([]string, len(portscan.DefaultPorts))
		for idx, port := range portscan.DefaultPorts {
			parts[idx] = strconv.Itoa(port)
		}
		return strings.Join(parts, ",")
	}
	if strings.EqualFold(spec, "all") || strings.EqualFold(spec, "full") {
		return "1-65535"
	}
	return spec
}

// bruteForce attempts weak credentials against the service ports the scanner
// found (ssh/mysql/postgresql/redis/ftp), writing each hit to the report. It
// runs independently of the web probe chain; non-service ports are ignored by
// the engine's routing.
func (p *Pipeline) bruteForce(ctx context.Context, openPorts []portscan.Result, services map[string]string) {
	endpoints := make([]gopocs.Endpoint, 0, len(openPorts))
	for _, r := range openPorts {
		ep := gopocs.Endpoint{Host: r.Host, Port: r.Port}
		if svc := services[fmt.Sprintf("%s:%d", r.Host, r.Port)]; svc != "" {
			ep.Service = svc
		}
		endpoints = append(endpoints, ep)
	}

	dictDir := filepath.Join(p.configDir, "dict")
	fmt.Printf("[32m[*][0m weak-credential brute force on %d open port(s)...\n", len(endpoints))
	opts := buildGoPocOptions(p.cfg, dictDir)
	eng := gopocs.New(opts)

	n := 0
	for f := range eng.Run(ctx, endpoints) {
		fmt.Println(findingLine(f))
		if werr := p.reporter.WriteFinding(f); werr != nil {
			fmt.Printf("[31m[!][0m report: %v\n", werr)
		}
		_ = p.auditor.LogInfo("weak-cred", map[string]any{
			"id": f.ID, "target": f.Target, "desc": f.Description,
		})
		n++
	}
	fmt.Printf("[32m[*][0m weak credentials: %d\n", n)
}

// detectServices fingerprints each open port so brute forcing routes by the
// real service, not just the port number. Returns host:port → service name.
func (p *Pipeline) detectServices(ctx context.Context, openPorts []portscan.Result) map[string]string {
	eps := make([]servicedetect.Endpoint, 0, len(openPorts))
	for _, r := range openPorts {
		eps = append(eps, servicedetect.Endpoint{Host: r.Host, Port: r.Port})
	}
	fmt.Printf("[32m[*][0m fingerprinting %d open port(s)...\n", len(eps))

	svcOpts := servicedetect.DefaultOptions()
	svcOpts.Threads = p.cfg.ServiceDetectThreads
	svcOpts.TimeoutSeconds = p.cfg.ServiceDetectTimeout
	det := servicedetect.New(svcOpts)
	out := make(map[string]string)
	for res := range det.Detect(ctx, eps) {
		if res.Service == "" {
			continue
		}
		out[fmt.Sprintf("%s:%d", res.Host, res.Port)] = res.Service
		fmt.Printf("  %s://%s:%d\n", res.Service, res.Host, res.Port)
		_ = p.auditor.LogInfo("service", map[string]any{
			"host": res.Host, "port": res.Port, "service": res.Service, "version": res.Version,
		})
	}
	fmt.Printf("[32m[*][0m services identified: %d\n", len(out))
	return out
}

// recon resolves search-query targets through the uncover engines (fofa/hunter/
// quake) into open host:port assets, feeding the same downstream path as the
// port scanner. It needs internet egress and API keys (env vars); a missing-key
// error is reported per query, not fatal.
func (p *Pipeline) recon(ctx context.Context, queries []string) []portscan.Result {
	fmt.Printf("[32m[*][0m recon: %d search query(ies) via fofa/hunter/quake...\n", len(queries))
	opts := uncover.DefaultOptions()
	opts.Proxy = p.cfg.ProxyURL
	if len(p.cfg.ReconAgents) > 0 {
		opts.Agents = append([]string(nil), p.cfg.ReconAgents...)
	}
	if p.cfg.ReconLimit > 0 {
		opts.Limit = p.cfg.ReconLimit
	}
	src := uncover.New(opts)

	seen := make(map[string]struct{})
	var results []portscan.Result
	for _, q := range queries {
		assets, err := src.Query(ctx, q, p.cfg.ReconLimit)
		if err != nil {
			fmt.Printf("[31m[!][0m recon %q: %v\n", q, err)
			continue
		}
		for _, a := range assets {
			if a.IP != "" && !p.cfg.AllowLocalAreaDomain && isPrivateIP(a.IP) {
				continue
			}
			host := a.Host
			if p.cfg.OnlyIPPort && a.IP != "" {
				host = a.IP
			}
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
	fmt.Printf("[32m[*][0m recon assets: %d\n", len(results))
	return results
}

func (p *Pipeline) enumerateSubdomains(ctx context.Context, domains []string) []string {
	fmt.Printf("[32m[*][0m subdomain enumeration for %d domain(s)...\n", len(domains))

	set := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		set[d] = struct{}{}
	}

	// Active brute first — it catches subdomains absent from passive sources.
	if !p.cfg.NoSubBrute {
		for _, h := range p.subdomainBrute(ctx, domains) {
			set[h] = struct{}{}
		}
	}

	if shouldRunPassiveSubfinder(p.cfg) {
		opts := subfinder.DefaultOptions()
		opts.Domains = domains
		opts.Proxy = p.cfg.ProxyURL
		results, errCh, err := subfinder.New(opts).Run(ctx)
		if err != nil {
			fmt.Printf("[31m[!][0m subfinder: %v\n", err) // keep brute results; don't abort enum
		} else {
			for r := range results {
				set[r.Host] = struct{}{}
			}
			for e := range errCh {
				if e != nil {
					fmt.Printf("[31m[!][0m subfinder: %v\n", e)
				}
			}
		}
	}

	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	fmt.Printf("[32m[*][0m subdomains: %d total\n", len(out))
	return out
}

// subdomainBrute resolves "<word>.<domain>" candidates and keeps those that
// answer. Wildcard-DNS domains (a sentinel label still resolves) are skipped,
// else every word "resolves" and floods the scan with non-existent hosts.
func (p *Pipeline) subdomainBrute(ctx context.Context, domains []string) []string {
	words, err := subbrute.LoadWordlist(configuredPath(p.cfg.SubdomainWordListFile, filepath.Join(p.configDir, "dict", "subdomains.txt")))
	if err != nil {
		fmt.Printf("[31m[!][0m subbrute: %v; skipping brute-force\n", err)
		return nil
	}

	dnsOpts := dnsx.DefaultOptions()
	if p.cfg.SubdomainBruteThreads > 0 {
		dnsOpts.Threads = p.cfg.SubdomainBruteThreads
	}
	r, err := dnsx.New(dnsOpts)
	if err != nil {
		fmt.Printf("[31m[!][0m subbrute dnsx: %v; skipping brute-force\n", err)
		return nil
	}

	var bruteable []string
	for _, d := range domains {
		if ips, _ := r.Resolve("zzqx9k7wildcardprobe." + d); len(ips) > 0 {
			fmt.Printf("[32m[*][0m subbrute: %s has wildcard DNS, skipping brute-force\n", d)
			continue
		}
		bruteable = append(bruteable, d)
	}
	if len(bruteable) == 0 {
		return nil
	}

	candidates := subbrute.Candidates(bruteable, words)
	fmt.Printf("[32m[*][0m subbrute: resolving %d candidate(s) across %d domain(s)...\n", len(candidates), len(bruteable))

	var found []string
	for res := range r.ResolveMany(ctx, candidates) {
		if res.Err == "" && len(res.IPs) > 0 {
			found = append(found, res.Host)
		}
	}
	fmt.Printf("[32m[*][0m subbrute: %d subdomain(s) resolved\n", len(found))
	return found
}

// identifyCDN flags domains behind a CDN/WAF so the operator knows the resolved
// IP is an edge, not the origin. Flagged domains are still probed by default
// (probing through a CDN reaches the app); -skip-cdn excludes them.
func (p *Pipeline) identifyCDN(ctx context.Context, domains []string) []string {
	fmt.Printf("[32m[*][0m CDN identification on %d domain(s)...\n", len(domains))

	results := make([]cdn.Result, len(domains))
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	for i, d := range domains {
		select {
		case <-ctx.Done():
			wg.Wait()
			return domains // cancelled: don't drop anything
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(i int, d string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = cdn.Check(d)
		}(i, d)
	}
	wg.Wait()

	keep := make([]string, 0, len(domains))
	flagged := 0
	for i, d := range domains {
		if results[i].IsCDN {
			flagged++
			_ = p.auditor.LogInfo("cdn", map[string]any{"domain": d, "provider": results[i].Provider})
			_ = p.reporter.WriteFingerprint(d, types.Fingerprint{
				Name: "CDN: " + results[i].Provider, Target: d, Source: "cdn", Confidence: 80,
			})
			if shouldDropCDN(p.cfg) {
				continue
			}
		}
		keep = append(keep, d)
	}
	if shouldDropCDN(p.cfg) {
		fmt.Printf("[32m[*][0m CDN: %d flagged and dropped (-skip-cdn), %d kept\n", flagged, len(keep))
	} else {
		fmt.Printf("[32m[*][0m CDN: %d flagged (still probed; -skip-cdn to exclude)\n", flagged)
	}
	return keep
}

// resolveDomains keeps only domains that resolve to at least one IP and records
// the host->IP mapping in the audit log. Dead names are dropped here so httpx
// does not waste connections on them.
func (p *Pipeline) resolveDomains(ctx context.Context, domains []string) []string {
	fmt.Printf("[32m[*][0m resolving %d domain(s)...\n", len(domains))
	r, err := dnsx.New(dnsx.DefaultOptions())
	if err != nil {
		fmt.Printf("[31m[!][0m dnsx: %v; passing domains through unresolved\n", err)
		return domains
	}

	var live []string
	for res := range r.ResolveMany(ctx, domains) {
		if res.Err != "" || len(res.IPs) == 0 {
			continue
		}
		live = append(live, res.Host)
		p.recordHostIPs(res.Host, res.IPs)
		_ = p.auditor.LogInfo("resolve", map[string]any{"host": res.Host, "ips": res.IPs})
	}
	fmt.Printf("[32m[*][0m resolved (live): %d\n", len(live))
	return live
}

// probeAndFingerprint returns the live URLs plus a map of URL → matched product
// names, which the precise nuclei stage uses to pick each target's POCs.
func (p *Pipeline) probeAndFingerprint(ctx context.Context, inputs []string) ([]string, map[string][]string) {
	fmt.Printf("[32m[*][0m HTTP probing %d target(s)...\n", len(inputs))
	probe := httpprobe.New(buildHTTPProbeOptions(p.cfg, inputs, nil))
	ch, err := probe.Run(ctx)
	if err != nil {
		fmt.Printf("[31m[!][0m httpx: %v\n", err)
		return nil, nil
	}

	var live []string
	hits := make(map[string][]string)
	active, passive := 0, 0
	var redirectTargets []string
	seenRedirectTargets := make(map[string]struct{})
	handleResponse := func(resp httpprobe.Response, collectRedirects bool) {
		live = append(live, resp.URL)
		p.recordHostIPs(resp.Host, resp.A)
		_ = p.auditor.LogResponse(resp.URL, "http-probe", map[string]any{
			"status": resp.StatusCode, "title": resp.Title,
		})
		for _, fp := range p.finger.Match(httpprobe.ToFingerprintContext(resp)) {
			fp.Target = resp.URL
			if werr := p.reporter.WriteFingerprint(resp.URL, fp); werr != nil {
				fmt.Printf("[31m[!][0m report: %v\n", werr)
			}
			hits[resp.URL] = append(hits[resp.URL], fp.Name)
			active++
		}
		// Passive fingerprints: httpx already ran wappalyzer (TechDetect) on the
		// response we fetched. Surface those technologies and feed them to POC
		// selection too — they catch products the active DSL rules miss.
		for _, tech := range resp.Technologies {
			if tech == "" {
				continue
			}
			fp := types.Fingerprint{Name: tech, Target: resp.URL, Source: "wappalyzer", Confidence: 75}
			if werr := p.reporter.WriteFingerprint(resp.URL, fp); werr != nil {
				fmt.Printf("[31m[!][0m report: %v\n", werr)
			}
			hits[resp.URL] = append(hits[resp.URL], tech)
			passive++
		}
		if names := dedup(hits[resp.URL]); len(names) > 0 {
			fmt.Printf("  %s \x1b[36m[%s]\x1b[0m\n", resp.URL, strings.Join(names, ","))
		} else {
			fmt.Printf("  %s\n", resp.URL)
		}
		if !collectRedirects {
			return
		}
		next := sameOriginRedirectTarget(resp)
		if next == "" {
			return
		}
		if _, ok := seenRedirectTargets[next]; ok {
			return
		}
		seenRedirectTargets[next] = struct{}{}
		redirectTargets = append(redirectTargets, next)
	}
	for resp := range ch {
		handleResponse(resp, true)
	}
	if len(redirectTargets) > 0 {
		seenLive := make(map[string]struct{}, len(live))
		for _, u := range live {
			seenLive[u] = struct{}{}
		}
		var targets []string
		for _, u := range redirectTargets {
			if _, ok := seenLive[u]; ok {
				continue
			}
			targets = append(targets, u)
		}
		if len(targets) > 0 {
			fmt.Printf("[32m[*][0m HTTP redirect follow-up probing %d target(s)...\n", len(targets))
			redirectProbe := httpprobe.New(buildHTTPProbeOptions(p.cfg, targets, nil))
			redirectCh, redirectErr := redirectProbe.Run(ctx)
			if redirectErr != nil {
				fmt.Printf("[31m[!][0m httpx redirect follow-up: %v\n", redirectErr)
			} else {
				for resp := range redirectCh {
					handleResponse(resp, false)
				}
			}
		}
	}
	fmt.Printf("[32m[*][0m live web: %d, fingerprint hits: %d active + %d passive(tech)\n", len(live), active, passive)
	return live, hits
}

func sameOriginRedirectTarget(resp httpprobe.Response) string {
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return ""
	}
	loc := responseHeaderValue(resp.RawHeaders, "Location")
	if loc == "" {
		return ""
	}
	base, err := url.Parse(resp.URL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ""
	}
	if base.Path == "" {
		base.Path = "/"
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	next := base.ResolveReference(ref)
	if next.Scheme != base.Scheme || !strings.EqualFold(next.Host, base.Host) {
		return ""
	}
	if next.String() == resp.URL {
		return ""
	}
	return next.String()
}

func responseHeaderValue(rawHeaders, name string) string {
	for _, line := range strings.Split(strings.ReplaceAll(rawHeaders, "\r\n", "\n"), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), name) {
			continue
		}
		return strings.TrimSpace(value)
	}
	return ""
}

// dirProbe requests well-known product paths (/nacos/, /druid/, ...) on each
// live root and fingerprints the responses, catching products on a sub-path the
// homepage probe missed. Returns matched path URLs and their hits for nuclei.
func (p *Pipeline) dirProbe(ctx context.Context, baseURLs []string, known map[string][]string) ([]string, map[string][]string) {
	// A product path counts only if it reveals a NEW product; the root's own
	// generic stack (Apache/PHP/...) re-matching every path is a false positive.
	knownByRoot := make(map[string]map[string]struct{})
	for u, names := range known {
		root := rootURL(u)
		if knownByRoot[root] == nil {
			knownByRoot[root] = make(map[string]struct{})
		}
		for _, n := range names {
			knownByRoot[root][n] = struct{}{}
		}
	}

	db, err := dirscan.Load(configuredPath(p.cfg.DirSearchYaml, filepath.Join(p.configDir, "dir.yaml")))
	if err != nil {
		fmt.Printf("[31m[!][0m dirscan: %v; skipping product-path probe\n", err)
		return nil, nil
	}
	paths := db.Paths()
	if len(paths) == 0 {
		return nil, nil
	}
	fmt.Printf("[32m[*][0m product-path probe: %d path(s) across %d root(s)...\n", len(paths), len(baseURLs))

	probe := httpprobe.New(httpprobe.Options{
		Targets:         baseURLs,
		RequestPaths:    paths,
		TechDetect:      true,
		FollowRedirects: true,
		Proxy:           p.cfg.ProxyURL,
		// Modest concurrency: hammering one root with many paths can overwhelm a
		// fragile target into dropping connections, which read as false negatives.
		Threads: 15,
	})
	ch, err := probe.Run(ctx)
	if err != nil {
		fmt.Printf("[31m[!][0m dirscan httpx: %v\n", err)
		return nil, nil
	}

	var urls []string
	hits := make(map[string][]string)
	for resp := range ch {
		if !shouldFingerprintDirProbeResponse(resp) {
			continue
		}
		var matched bool
		root := rootURL(resp.URL)
		for _, fp := range p.finger.Match(httpprobe.ToFingerprintContext(resp)) {
			if _, seen := knownByRoot[root][fp.Name]; seen {
				continue
			}
			fp.Target = resp.URL
			if werr := p.reporter.WriteFingerprint(resp.URL, fp); werr != nil {
				fmt.Printf("[31m[!][0m report: %v\n", werr)
			}
			hits[resp.URL] = append(hits[resp.URL], fp.Name)
			matched = true
		}
		if matched {
			urls = append(urls, resp.URL)
			fmt.Printf("  %s \x1b[36m[%s]\x1b[0m\n", resp.URL, strings.Join(dedup(hits[resp.URL]), ","))
		}
	}
	fmt.Printf("[32m[*][0m product-path probe: %d path(s) matched a fingerprint\n", len(urls))
	return urls, hits
}

func shouldFingerprintDirProbeResponse(resp httpprobe.Response) bool {
	return resp.StatusCode != 404
}

// shiroScan brute-forces the Shiro rememberMe key on each live web root. The
// per-target key loop is sequential; only the targets run in parallel, so a
// vulnerable host isn't hit by the whole key list at once.
func (p *Pipeline) shiroScan(ctx context.Context, urls []string) {
	urls = shiroTargets(urls)
	if len(urls) == 0 {
		return
	}
	keys, err := shiro.LoadKeys(filepath.Join(p.configDir, "dict", "shirokeys.txt"))
	if err != nil {
		fmt.Printf("[31m[!][0m shiro: %v; skipping shiro check\n", err)
		return
	}
	sc := shiro.New(keys, 10*time.Second, p.cfg.ProxyURL)
	fmt.Printf("[32m[*][0m shiro key check on %d web root(s) (%d keys)...\n", len(urls), len(keys))

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	hits := 0
	for _, u := range urls {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			f, err := sc.Scan(ctx, u)
			if err != nil || f == nil {
				return
			}
			fmt.Println(findingLine(*f))
			if f.Description != "" {
				fmt.Printf("      \x1b[2m%s\x1b[0m\n", f.Description) // surface the cracked key/mode
			}
			if werr := p.reporter.WriteFinding(*f); werr != nil {
				fmt.Printf("[31m[!][0m report: %v\n", werr)
			}
			_ = p.auditor.LogInfo("finding", map[string]any{"id": f.ID, "severity": string(f.Severity), "target": f.Target})
			mu.Lock()
			hits++
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	fmt.Printf("[32m[*][0m shiro: %d weak key(s) found\n", hits)
}

func shiroTargets(urls []string) []string {
	normalized := make([]string, 0, len(urls))
	hasRoot := make(map[string]bool)
	for _, raw := range urls {
		target, root, isRoot := normalizeShiroTarget(raw)
		if target == "" {
			continue
		}
		normalized = append(normalized, target)
		if isRoot {
			hasRoot[root] = true
		}
	}

	seen := make(map[string]struct{}, len(normalized))
	out := make([]string, 0, len(normalized))
	for _, target := range normalized {
		_, root, _ := normalizeShiroTarget(target)
		if hasRoot[root] {
			target = root
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}

func normalizeShiroTarget(raw string) (target, root string, isRoot bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", false
	}
	root = u.Scheme + "://" + u.Host
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = stripPathParams(u.Path)
	if u.Path == "" || u.Path == "/" {
		return root, root, true
	}
	return u.String(), root, false
}

func stripPathParams(path string) string {
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if idx := strings.IndexByte(part, ';'); idx >= 0 {
			parts[i] = part[:idx]
		}
	}
	return strings.Join(parts, "/")
}

// runNuclei scans the live URLs. Precise mode (default) loads only the POC
// files the fingerprint hits map to; full mode (-full) runs the whole
// nuclei-templates directory.
func (p *Pipeline) runNuclei(ctx context.Context, urls []string, fpHits map[string][]string) {
	opts := buildNucleiOptions(p.cfg)

	if p.cfg.FullScan {
		tmplDir := p.nucleiTemplateDir()
		if info, err := os.Stat(tmplDir); err != nil || !info.IsDir() {
			fmt.Printf("[31m[!][0m nuclei templates not found at %s — run `dddd update` first; skipping vuln scan\n", tmplDir)
			return
		}
		opts.TemplatesDir = tmplDir
		fmt.Printf("[32m[*][0m nuclei full scan: %d target(s) x all templates...\n", len(urls))
	} else if strings.TrimSpace(p.cfg.PocName) != "" {
		pocs := p.resolvePOCsByQuery(p.cfg.PocName)
		targets := directPOCTargets(urls)
		if len(pocs) == 0 || len(targets) == 0 {
			fmt.Println("[32m[*][0m nuclei fuzzy POC: no matched POC or target, skipping vuln scan")
			return
		}
		opts.Templates = pocs
		fmt.Printf("[32m[*][0m nuclei fuzzy POC scan: %d target(s) x %d POC(s)...\n", len(targets), len(pocs))
		p.runNucleiBatch(ctx, opts, targets)
		return
	} else {
		targetPOCs := p.resolvePOCTargets(fpHits)
		if len(targetPOCs) == 0 {
			fmt.Println("[32m[*][0m nuclei precise: no fingerprint-matched POCs, skipping vuln scan")
			return
		}
		p.runPreciseNuclei(ctx, opts, targetPOCs)
		return
	}

	p.runNucleiBatch(ctx, opts, urls)
}

func (p *Pipeline) runPreciseNuclei(ctx context.Context, baseOpts nuclei.Options, targetPOCs map[string][]string) {
	groups := groupTargetsByTemplates(targetPOCs)
	fmt.Printf("[32m[*][0m nuclei precise scan: %d target group(s) across %d target(s)...\n", len(groups), len(targetPOCs))
	for _, group := range groups {
		opts := baseOpts
		opts.Templates = group.templates
		fmt.Printf("[32m[*][0m nuclei precise group: %d target(s) x %d POC(s)...\n", len(group.targets), len(group.templates))
		p.runNucleiBatch(ctx, opts, group.targets)
	}
}

func (p *Pipeline) runNucleiBatch(ctx context.Context, opts nuclei.Options, urls []string) int {
	sc, err := nuclei.New(ctx, opts)
	if err != nil {
		fmt.Printf("[31m[!][0m nuclei init: %v\n", err)
		return 0
	}
	defer sc.Close()

	findings, errCh, err := sc.Scan(ctx, urls)
	if err != nil {
		fmt.Printf("[31m[!][0m nuclei scan: %v\n", err)
		return 0
	}

	n := 0
	for f := range findings {
		if p.counts.SeenFinding(f) {
			continue
		}
		fmt.Println(findingLine(f))
		if werr := p.reporter.WriteFinding(f); werr != nil {
			fmt.Printf("[31m[!][0m report: %v\n", werr)
		}
		_ = p.auditor.LogInfo("finding", map[string]any{
			"id": f.ID, "severity": string(f.Severity), "target": f.Target,
		})
		n++
	}
	for e := range errCh {
		if e != nil {
			fmt.Printf("[31m[!][0m nuclei: %v\n", e)
		}
	}
	fmt.Printf("[32m[*][0m findings: %d\n", n)
	return n
}

// resolvePOCs maps the fingerprint hits to the deduplicated set of POC files to
// run. Each mapped POC name resolves to the maintained nuclei-templates copy
// first (works on nuclei v3), falling back to the frozen legacy/ file only when
// upstream doesn't carry it. This is why `dddd update` benefits precise mode:
// legacy templates with v2-deprecated syntax (e.g. req-condition) silently fail
// to load on v3.8, so we prefer their upstream-maintained replacements.
// Returns nil (skip scan) when no product matched or the mapping can't load.
func (p *Pipeline) resolvePOCs(fpHits map[string][]string) []string {
	return pocmap.Union(p.resolvePOCTargets(fpHits))
}

func (p *Pipeline) resolvePOCTargets(fpHits map[string][]string) map[string][]string {
	if len(fpHits) == 0 {
		return nil
	}
	m, err := pocmap.Load(p.workflowYamlPath())
	if err != nil {
		fmt.Printf("[31m[!][0m pocmap: %v; skipping precise scan\n", err)
		return nil
	}
	namesByTarget, stats := m.ResolveNamesByTarget(fpHits, !p.cfg.DisableGeneralPoc)
	namesByTarget = filterTargetPOCNamesByQuery(namesByTarget, p.cfg.PocName)
	if len(namesByTarget) == 0 {
		return nil
	}

	idx := p.freshTemplateIndex()
	legacyDir := p.legacyPOCDir()
	resolved := make(map[string][]string, len(namesByTarget))
	pathCache := make(map[string]string)
	uniquePaths := make(map[string]struct{})
	var fresh, legacy, missing int

	resolvePath := func(name string) string {
		if path, ok := pathCache[name]; ok {
			return path
		}
		path := ""
		if p, ok := idx[strings.ToLower(name)]; ok {
			path = p
			fresh++
		} else {
			lp := filepath.Join(legacyDir, name+".yaml")
			if info, statErr := os.Stat(lp); statErr == nil && !info.IsDir() {
				path = lp
				legacy++
			}
		}
		if path == "" {
			missing++
		}
		pathCache[name] = path
		return path
	}

	for target, names := range namesByTarget {
		seen := make(map[string]struct{}, len(names))
		for _, name := range names {
			path := resolvePath(name)
			if path == "" {
				continue
			}
			if _, dup := seen[path]; dup {
				continue
			}
			seen[path] = struct{}{}
			resolved[target] = append(resolved[target], path)
			uniquePaths[path] = struct{}{}
		}
		if len(resolved[target]) == 0 {
			delete(resolved, target)
			continue
		}
	}
	resolved = deduplicateSessionRedirectPOCTargets(resolved)
	if len(resolved) == 0 {
		return nil
	}

	fmt.Printf("[32m[*][0m poc mapping: %d product hit(s) -> %d target(s) / %d unique POC(s) [%d updated, %d legacy, %d unavailable]\n",
		stats.MatchedNames, len(resolved), len(uniquePaths), fresh, legacy, missing)
	return resolved
}

func deduplicateSessionRedirectPOCTargets(targetPOCs map[string][]string) map[string][]string {
	if len(targetPOCs) == 0 {
		return targetPOCs
	}
	out := make(map[string][]string, len(targetPOCs))
	sessionChildren := make(map[string]string)
	for target, templates := range targetPOCs {
		normalized, root, hadPathParams := normalizeSessionPOCTarget(target)
		mergePOCTemplates(out, normalized, templates)
		if hadPathParams && normalized != "" && root != "" && normalized != root {
			sessionChildren[normalized] = root
		}
	}
	for child, root := range sessionChildren {
		if containsAllTemplates(out[root], out[child]) {
			delete(out, child)
		}
	}
	for target := range out {
		sort.Strings(out[target])
	}
	return out
}

func normalizeSessionPOCTarget(raw string) (target, root string, hadPathParams bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw, "", false
	}
	root = u.Scheme + "://" + u.Host
	hadPathParams = strings.Contains(u.Path, ";")
	if !hadPathParams {
		return raw, root, false
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = stripPathParams(u.Path)
	return u.String(), root, true
}

func mergePOCTemplates(dst map[string][]string, target string, templates []string) {
	if target == "" || len(templates) == 0 {
		return
	}
	seen := make(map[string]struct{}, len(dst[target])+len(templates))
	for _, existing := range dst[target] {
		seen[existing] = struct{}{}
	}
	for _, tmpl := range templates {
		if tmpl == "" {
			continue
		}
		if _, ok := seen[tmpl]; ok {
			continue
		}
		seen[tmpl] = struct{}{}
		dst[target] = append(dst[target], tmpl)
	}
}

func containsAllTemplates(haystack, needles []string) bool {
	if len(needles) == 0 {
		return true
	}
	if len(haystack) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(haystack))
	for _, tmpl := range haystack {
		seen[tmpl] = struct{}{}
	}
	for _, tmpl := range needles {
		if _, ok := seen[tmpl]; !ok {
			return false
		}
	}
	return true
}

func (p *Pipeline) resolvePOCsByQuery(query string) []string {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil
	}

	type candidate struct {
		base string
		path string
	}
	var candidates []candidate
	seenBases := make(map[string]struct{})

	for base, path := range p.freshTemplateIndex() {
		if !strings.Contains(base, query) {
			continue
		}
		candidates = append(candidates, candidate{base: base, path: path})
		seenBases[base] = struct{}{}
	}

	legacyDir := p.legacyPOCDir()
	_ = filepath.WalkDir(legacyDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}
		base := strings.ToLower(strings.TrimSuffix(d.Name(), ".yaml"))
		if !strings.Contains(base, query) {
			return nil
		}
		if _, ok := seenBases[base]; ok {
			return nil
		}
		candidates = append(candidates, candidate{base: base, path: path})
		seenBases[base] = struct{}{}
		return nil
	})

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].base < candidates[j].base
	})
	out := make([]string, len(candidates))
	for i, c := range candidates {
		out[i] = c.path
	}
	return out
}

func directPOCTargets(urls []string) []string {
	return dedup(stripPaths(urls))
}

type preciseNucleiGroup struct {
	targets   []string
	templates []string
}

func groupTargetsByTemplates(targetPOCs map[string][]string) []preciseNucleiGroup {
	byKey := make(map[string]*preciseNucleiGroup)
	for target, templates := range targetPOCs {
		if target == "" || len(templates) == 0 {
			continue
		}
		copied := append([]string(nil), templates...)
		sort.Strings(copied)
		key := strings.Join(copied, "\x00")
		group := byKey[key]
		if group == nil {
			group = &preciseNucleiGroup{templates: copied}
			byKey[key] = group
		}
		group.targets = append(group.targets, target)
	}

	out := make([]preciseNucleiGroup, 0, len(byKey))
	for _, group := range byKey {
		sort.Strings(group.targets)
		out = append(out, *group)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Join(out[i].templates, "\x00") < strings.Join(out[j].templates, "\x00")
	})
	return out
}

func filterTargetPOCNamesByQuery(targetNames map[string][]string, query string) map[string][]string {
	query = strings.TrimSpace(query)
	if query == "" {
		return targetNames
	}
	out := make(map[string][]string, len(targetNames))
	for target, names := range targetNames {
		filtered := filterPOCNamesByQuery(names, query)
		if len(filtered) == 0 {
			continue
		}
		out[target] = filtered
	}
	return out
}

// freshTemplateIndex lazily builds a basename->path index of the updated
// nuclei-templates dir (the one `dddd update` maintains). Returns an empty map
// when that dir is absent, so precise mode degrades to legacy-only. Built once
// and cached; the walk only stats directory entries, not file contents.
func (p *Pipeline) freshTemplateIndex() map[string]string {
	if p.freshIdxBuilt {
		return p.freshIdx
	}
	p.freshIdxBuilt = true
	idx := make(map[string]string)
	p.freshIdx = idx

	dir := p.nucleiTemplateDir()
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return idx
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yaml") {
			return nil
		}
		base := strings.ToLower(strings.TrimSuffix(name, ".yaml"))
		if _, exists := idx[base]; !exists { // first match wins; http/ is walked early
			idx[base] = path
		}
		return nil
	})
	return idx
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

func stripPaths(urls []string) []string {
	out := make([]string, 0, len(urls))
	seen := make(map[string]struct{})
	for _, u := range urls {
		i := strings.Index(u, "://")
		if i < 0 {
			continue
		}
		hostStart := i + 3
		if j := strings.IndexByte(u[hostStart:], '/'); j >= 0 {
			u = u[:hostStart+j]
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}

func mergeHitsToRoots(hits map[string][]string) map[string][]string {
	rooted := make(map[string][]string)
	for url, names := range hits {
		roots := stripPaths([]string{url})
		if len(roots) == 0 {
			continue
		}
		root := roots[0]
		rooted[root] = append(rooted[root], names...)
	}
	for k, v := range rooted {
		rooted[k] = dedup(v)
	}
	return rooted
}

var httpProbePorts = map[int]struct{}{
	80: {}, 81: {}, 88: {}, 443: {}, 300: {}, 1080: {}, 3000: {},
	4443: {}, 4567: {}, 5000: {}, 5100: {}, 5800: {}, 5985: {}, 5986: {},
	7001: {}, 7070: {}, 7443: {}, 7777: {}, 8000: {}, 8001: {},
	8008: {}, 8043: {}, 8080: {}, 8081: {}, 8088: {}, 8089: {}, 8090: {},
	8180: {}, 8443: {}, 8448: {}, 8888: {}, 9000: {}, 9001: {}, 9043: {},
	8848: {}, 9060: {}, 9080: {}, 9090: {}, 9200: {}, 9443: {}, 9999: {}, 10000: {},
	18080: {},
}

func shouldHTTPProbe(port int, key string, services map[string]string) bool {
	if svc := services[key]; svc != "" {
		switch svc {
		case "http", "https", "http-alt", "ssl", "unknown":
			return true
		case "ssh", "ftp", "smtp", "mysql", "mssql", "oracle", "redis",
			"mongodb", "smb", "rdp", "telnet", "netbios", "rpc", "adb",
			"memcached", "jdwp", "postgresql":
			return false
		}
	}
	_, ok := httpProbePorts[port]
	return ok
}

func webProbeInputs(openPorts []portscan.Result, services map[string]string) []string {
	var out []string
	for _, r := range openPorts {
		key := fmt.Sprintf("%s:%d", r.Host, r.Port)
		if shouldHTTPProbe(r.Port, key, services) {
			out = append(out, key)
		}
	}
	return out
}

func (p *Pipeline) filterByPortThreshold(results []portscan.Result) []portscan.Result {
	if p.cfg.PortsThreshold <= 0 {
		return results
	}
	counts := make(map[string]int)
	for _, r := range results {
		counts[r.Host]++
	}
	var out []portscan.Result
	for _, r := range results {
		if counts[r.Host] > p.cfg.PortsThreshold {
			continue
		}
		out = append(out, r)
	}
	return out
}

func excludeFrom(ports, exclude []int) []int {
	exm := make(map[int]struct{}, len(exclude))
	for _, p := range exclude {
		exm[p] = struct{}{}
	}
	var out []int
	for _, p := range ports {
		if _, ok := exm[p]; !ok {
			out = append(out, p)
		}
	}
	return out
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

// vhostProbe re-requests IP-based live roots with each domain known to resolve
// to that IP (Host = domain), surfacing virtual hosts that answer only by name —
// notably on non-standard ports a bare-IP probe can't attribute.
func (p *Pipeline) vhostProbe(ctx context.Context, liveURLs []string) ([]string, map[string][]string) {
	if len(p.ipDomains) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var targets []string
	for _, u := range liveURLs {
		scheme, host, port := splitURL(u)
		if host == "" || net.ParseIP(host) == nil {
			continue
		}
		for _, d := range p.ipDomains[host] {
			vu := scheme + "://" + d
			if port != "" {
				vu += ":" + port
			}
			if _, ok := seen[vu]; ok {
				continue
			}
			seen[vu] = struct{}{}
			targets = append(targets, vu)
		}
	}
	if len(targets) == 0 {
		return nil, nil
	}
	fmt.Printf("\x1b[32m[*]\x1b[0m vhost probe: %d domain-bound candidate(s)...\n", len(targets))

	probe := httpprobe.New(httpprobe.Options{
		Targets:         targets,
		TechDetect:      true,
		FollowRedirects: true,
		Proxy:           p.cfg.ProxyURL,
		Threads:         50,
	})
	ch, err := probe.Run(ctx)
	if err != nil {
		fmt.Printf("\x1b[31m[!]\x1b[0m vhost httpx: %v\n", err)
		return nil, nil
	}

	var urls []string
	hits := make(map[string][]string)
	for resp := range ch {
		urls = append(urls, resp.URL)
		_ = p.auditor.LogInfo("vhost", map[string]any{"url": resp.URL, "status": resp.StatusCode, "title": resp.Title})
		for _, fp := range p.finger.Match(httpprobe.ToFingerprintContext(resp)) {
			fp.Target = resp.URL
			if werr := p.reporter.WriteFingerprint(resp.URL, fp); werr != nil {
				fmt.Printf("\x1b[31m[!]\x1b[0m report: %v\n", werr)
			}
			hits[resp.URL] = append(hits[resp.URL], fp.Name)
		}
		for _, tech := range resp.Technologies {
			if tech == "" {
				continue
			}
			fp := types.Fingerprint{Name: tech, Target: resp.URL, Source: "wappalyzer", Confidence: 75}
			if werr := p.reporter.WriteFingerprint(resp.URL, fp); werr != nil {
				fmt.Printf("\x1b[31m[!]\x1b[0m report: %v\n", werr)
			}
			hits[resp.URL] = append(hits[resp.URL], tech)
		}
	}
	fmt.Printf("\x1b[32m[*]\x1b[0m vhost probe: %d live domain-bound root(s)\n", len(urls))
	return urls, hits
}

// recordHostIPs maps each resolved IP back to a hostname (IP-literal hosts are
// skipped) so vhostProbe can re-request IP roots by domain.
func (p *Pipeline) recordHostIPs(host string, ips []string) {
	if host == "" || net.ParseIP(host) != nil {
		return
	}
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		p.ipDomains[ip] = appendUnique(p.ipDomains[ip], host)
	}
}

func splitURL(raw string) (scheme, host, port string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", ""
	}
	return u.Scheme, u.Hostname(), u.Port()
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func rootURL(raw string) string {
	roots := stripPaths([]string{raw})
	if len(roots) == 0 {
		return raw
	}
	return roots[0]
}

// runLowPerception pulls assets from Hunter and fingerprints each web asset from
// the banner Hunter returns — no packet reaches the target. Web roots go to
// nuclei, non-web services to gopocs (the exploit phase itself still sends).
func (p *Pipeline) runLowPerception(ctx context.Context, queries []string) error {
	if len(queries) == 0 {
		fmt.Println("\x1b[31m[!]\x1b[0m low-perception (-lpm) needs a Hunter query as -t, e.g. -t 'app=\"seeyon\"'")
		return nil
	}

	client, err := hunter.New(hunter.Options{
		APIKey:   os.Getenv("HUNTER_API_KEY"),
		PageSize: p.cfg.HunterPageSize,
		MaxPages: p.cfg.HunterMaxPages,
		Proxy:    p.cfg.ProxyURL,
	})
	if err != nil {
		return fmt.Errorf("app: low-perception: %w", err)
	}

	var liveURLs []string
	fpHits := make(map[string][]string)
	var openPorts []portscan.Result
	services := make(map[string]string)

	for _, q := range queries {
		fmt.Printf("\x1b[32m[*]\x1b[0m hunter low-perception query: %s\n", q)
		assets, qerr := client.Search(ctx, q)
		if qerr != nil {
			fmt.Printf("\x1b[31m[!]\x1b[0m hunter: %v\n", qerr)
			continue
		}
		for _, a := range assets {
			if a.IsWeb {
				rootURL := fmt.Sprintf("%s://%s:%d", webScheme(a.Protocol), a.IP, a.Port)
				b := hunter.ParseBanner(a.Banner)
				fctx := fingerdsl.Context{
					"body":     b.Body,
					"header":   b.Header,
					"title":    a.Title,
					"banner":   b.Server,
					"protocol": webScheme(a.Protocol),
				}
				for _, fp := range p.finger.Match(fctx) {
					fp.Target = rootURL
					if werr := p.reporter.WriteFingerprint(rootURL, fp); werr != nil {
						fmt.Printf("\x1b[31m[!]\x1b[0m report: %v\n", werr)
					}
					fpHits[rootURL] = append(fpHits[rootURL], fp.Name)
				}
				liveURLs = append(liveURLs, rootURL)
				_ = p.auditor.LogInfo("hunter-web", map[string]any{"url": rootURL, "title": a.Title})
			} else {
				openPorts = append(openPorts, portscan.Result{Host: a.IP, Port: a.Port})
				if a.Protocol != "" {
					services[fmt.Sprintf("%s:%d", a.IP, a.Port)] = a.Protocol
				}
				_ = p.auditor.LogInfo("hunter-service", map[string]any{"host": a.IP, "port": a.Port, "protocol": a.Protocol})
			}
		}
	}

	liveURLs = dedup(liveURLs)
	fmt.Printf("\x1b[32m[*]\x1b[0m low-perception: %d web root(s), %d service(s) — no packet sent to targets\n", len(liveURLs), len(openPorts))

	if len(openPorts) > 0 && shouldRunGoPocs(p.cfg) {
		p.bruteForce(ctx, openPorts, services)
	}
	if len(liveURLs) > 0 && !p.cfg.NoPoc {
		p.runNuclei(ctx, liveURLs, fpHits)
		if shouldRunShiro(p.cfg) {
			p.shiroScan(ctx, liveURLs)
		}
	}
	return nil
}

func webScheme(proto string) string {
	if strings.EqualFold(proto, "https") {
		return "https"
	}
	return "http"
}

func configuredPath(custom, fallback string) string {
	if strings.TrimSpace(custom) != "" {
		return custom
	}
	return fallback
}

func (p *Pipeline) nucleiTemplateDir() string {
	return configuredPath(p.cfg.NucleiTemplateDir, filepath.Join(p.configDir, "nuclei-templates"))
}

func (p *Pipeline) workflowYamlPath() string {
	return configuredPath(p.cfg.WorkflowYamlPath, filepath.Join(p.configDir, "pocs", "mapping.yaml"))
}

func (p *Pipeline) legacyPOCDir() string {
	if strings.TrimSpace(p.cfg.NucleiTemplateDir) != "" {
		return p.cfg.NucleiTemplateDir
	}
	return filepath.Join(p.configDir, "pocs", "legacy")
}
