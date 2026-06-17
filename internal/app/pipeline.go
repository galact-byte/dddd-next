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
	"net"
	"net/url"
	"os"
	"path/filepath"
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
		a, aerr := audit.NewFile(cfg.AuditLogFile)
		if aerr != nil {
			_ = rep.Close()
			return nil, fmt.Errorf("app: open audit log: %w", aerr)
		}
		aud = a
	}

	fmt.Printf("[32m[*][0m fingerprints loaded: %d rules\n", eng.Size())
	return &Pipeline{cfg: cfg, configDir: configDir, finger: eng, reporter: rep, auditor: aud, ipDomains: make(map[string][]string)}, nil
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
		services := p.detectServices(ctx, openPorts)
		for _, r := range openPorts {
			probeInputs = append(probeInputs, fmt.Sprintf("%s:%d", r.Host, r.Port))
		}
		if !p.cfg.NoBrute {
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
	if len(probeInputs) == 0 {
		fmt.Println("[31m[!][0m no probeable targets after discovery")
		return nil
	}

	liveURLs, fpHits := p.probeAndFingerprint(ctx, probeInputs)
	if len(liveURLs) > 0 && !p.cfg.SkipDir {
		dirURLs, dirHits := p.dirProbe(ctx, stripPaths(liveURLs))
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
	if len(liveURLs) > 0 {
		if !p.cfg.NoPoc {
			p.runNuclei(ctx, liveURLs, fpHits)
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
func (p *Pipeline) parseTargets() (probeInputs, domains, portscanSpecs, searchQueries []string) {
	for _, raw := range p.cfg.Targets {
		t, err := classifier.Parse(raw)
		if err != nil {
			fmt.Printf("[31m[!][0m skip %q: %v\n", raw, err)
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
			fmt.Printf("[31m[!][0m %q: unrecognized input, skipped\n", raw)
		}
	}
	return probeInputs, domains, portscanSpecs, searchQueries
}

// scanPorts expands CIDR/IP-range specs into hosts, optionally pre-filters by
// liveness, then scans ports via TCP connect (default) or SYN (-st syn).
func (p *Pipeline) scanPorts(ctx context.Context, specs []string) []portscan.Result {
	hosts, err := portscan.ExpandHosts(specs)
	if err != nil {
		fmt.Printf("\x1b[31m[!]\x1b[0m portscan: %v\n", err)
		return nil
	}

	if p.cfg.PingFirst || p.cfg.TCPPing {
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
		open = append(open, r)
	}
	return open
}

// hostDiscovery pre-filters hosts by ICMP (-ping) and/or TCP connect (-tp); a
// host is kept if either probe answers.
func (p *Pipeline) hostDiscovery(ctx context.Context, hosts []string) []string {
	before := len(hosts)
	aliveSet := make(map[string]struct{})

	if p.cfg.PingFirst {
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
	opts := gopocs.DefaultOptions(dictDir)
	opts.CustomCreds = p.cfg.CustomCreds
	eng := gopocs.New(opts)

	n := 0
	for f := range eng.Run(ctx, endpoints) {
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
	src := uncover.New(opts)

	seen := make(map[string]struct{})
	var results []portscan.Result
	for _, q := range queries {
		assets, err := src.Query(ctx, q, 0)
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
	words, err := subbrute.LoadWordlist(filepath.Join(p.configDir, "dict", "subdomains.txt"))
	if err != nil {
		fmt.Printf("[31m[!][0m subbrute: %v; skipping brute-force\n", err)
		return nil
	}

	r, err := dnsx.New(dnsx.DefaultOptions())
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
			if p.cfg.SkipCDN {
				continue
			}
		}
		keep = append(keep, d)
	}
	if p.cfg.SkipCDN {
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
	probe := httpprobe.New(httpprobe.Options{
		Targets:    inputs,
		TechDetect: true,
		Proxy:      p.cfg.ProxyURL,
	})
	ch, err := probe.Run(ctx)
	if err != nil {
		fmt.Printf("[31m[!][0m httpx: %v\n", err)
		return nil, nil
	}

	var live []string
	hits := make(map[string][]string)
	active, passive := 0, 0
	for resp := range ch {
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
	}
	fmt.Printf("[32m[*][0m live web: %d, fingerprint hits: %d active + %d passive(tech)\n", len(live), active, passive)
	return live, hits
}

// dirProbe requests well-known product paths (/nacos/, /druid/, ...) on each
// live root and fingerprints the responses, catching products on a sub-path the
// homepage probe missed. Returns matched path URLs and their hits for nuclei.
func (p *Pipeline) dirProbe(ctx context.Context, baseURLs []string) ([]string, map[string][]string) {
	db, err := dirscan.Load(filepath.Join(p.configDir, "dir.yaml"))
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
		Targets:      baseURLs,
		RequestPaths: paths,
		TechDetect:   true,
		Proxy:        p.cfg.ProxyURL,
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
		var matched bool
		for _, fp := range p.finger.Match(httpprobe.ToFingerprintContext(resp)) {
			fp.Target = resp.URL
			if werr := p.reporter.WriteFingerprint(resp.URL, fp); werr != nil {
				fmt.Printf("[31m[!][0m report: %v\n", werr)
			}
			hits[resp.URL] = append(hits[resp.URL], fp.Name)
			matched = true
		}
		if matched {
			urls = append(urls, resp.URL)
		}
	}
	fmt.Printf("[32m[*][0m product-path probe: %d path(s) matched a fingerprint\n", len(urls))
	return urls, hits
}

// shiroScan brute-forces the Shiro rememberMe key on each live web root. The
// per-target key loop is sequential; only the targets run in parallel, so a
// vulnerable host isn't hit by the whole key list at once.
func (p *Pipeline) shiroScan(ctx context.Context, urls []string) {
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

// runNuclei scans the live URLs. Precise mode (default) loads only the POC
// files the fingerprint hits map to; full mode (-full) runs the whole
// nuclei-templates directory.
func (p *Pipeline) runNuclei(ctx context.Context, urls []string, fpHits map[string][]string) {
	opts := nuclei.DefaultOptions()
	if p.cfg.ProxyURL != "" {
		opts.Proxy = []string{p.cfg.ProxyURL}
	}
	if len(p.cfg.Severity) > 0 {
		opts.Severities = strings.Join(p.cfg.Severity, ",")
	}
	if len(p.cfg.ExcludeSeverity) > 0 {
		opts.ExcludeSeverities = strings.Join(p.cfg.ExcludeSeverity, ",")
	}
	if len(p.cfg.Tags) > 0 {
		opts.Tags = p.cfg.Tags
	}
	if len(p.cfg.ExcludeTags) > 0 {
		opts.ExcludeTags = p.cfg.ExcludeTags
	}

	if p.cfg.FullScan {
		tmplDir := filepath.Join(p.configDir, "nuclei-templates")
		if info, err := os.Stat(tmplDir); err != nil || !info.IsDir() {
			fmt.Printf("[31m[!][0m nuclei templates not found at %s — run `dddd update` first; skipping vuln scan\n", tmplDir)
			return
		}
		opts.TemplatesDir = tmplDir
		fmt.Printf("[32m[*][0m nuclei full scan: %d target(s) x all templates...\n", len(urls))
	} else {
		pocs := p.resolvePOCs(fpHits)
		if len(pocs) == 0 {
			fmt.Println("[32m[*][0m nuclei precise: no fingerprint-matched POCs, skipping vuln scan")
			return
		}
		opts.Templates = pocs
		fmt.Printf("[32m[*][0m nuclei precise scan: %d target(s) x %d matched POC(s)...\n", len(urls), len(pocs))
	}

	sc, err := nuclei.New(ctx, opts)
	if err != nil {
		fmt.Printf("[31m[!][0m nuclei init: %v\n", err)
		return
	}
	defer sc.Close()

	findings, errCh, err := sc.Scan(ctx, urls)
	if err != nil {
		fmt.Printf("[31m[!][0m nuclei scan: %v\n", err)
		return
	}

	n := 0
	for f := range findings {
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
		fmt.Printf("[31m[!][0m pocmap: %v; skipping precise scan\n", err)
		return nil
	}
	pocDir := filepath.Join(p.configDir, "pocs", "legacy")
	resolved, stats := m.Resolve(fpHits, pocDir, !p.cfg.DisableGeneralPoc)
	fmt.Printf("[32m[*][0m poc mapping: %d product hit(s) -> %d POC file(s) across %d target(s)\n",
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
	9060: {}, 9080: {}, 9090: {}, 9200: {}, 9443: {}, 9999: {}, 10000: {},
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
		Targets:    targets,
		TechDetect: true,
		Proxy:      p.cfg.ProxyURL,
		Threads:    50,
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
