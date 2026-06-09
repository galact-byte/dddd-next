// Package gopocs brute-forces weak credentials against common services.
//
// It follows internal/scanner/nuclei's shape — a channel of types.Finding with
// no third-party types leaking to callers — rather than the abstract Scanner
// interface sketched in docs/ARCHITECTURE.md, which the codebase has outgrown.
// Each Cracker wraps a mature client library so we reuse the projectdiscovery
// dependency tree instead of hand-rolling protocol handshakes.
package gopocs

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"dddd-next/internal/types"
)

// Credential is one username/password guess. Password-only dicts (redis) leave
// User empty.
type Credential struct {
	User string
	Pass string
}

// Cracker attempts credentials against one service instance.
type Cracker interface {
	Service() string
	// Try reports whether cred authenticates. (false, nil) is a clean auth
	// rejection — try the next credential. A non-nil error is a connect/
	// protocol failure — abandon this endpoint, the rest will fail too.
	Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error)
}

// ProbeFunc is a credential-less service check (e.g. MS17-010): it returns a
// Finding when the host is vulnerable, nil when not.
type ProbeFunc func(ctx context.Context, host string, port int, timeout time.Duration) (*types.Finding, error)

// defaultServicePorts routes a default port to the service whose dict/cracker
// handles it. Only ports listed here are brute-forced; everything else is left
// to the HTTP probe. Copied into each Engine so callers/tests can override.
var defaultServicePorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	139:   "netbios",
	445:   "smb",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5555:  "adb",
	6379:  "redis",
	11211: "memcached",
	27017: "mongodb",
}

// Endpoint is an open host:port discovered by the port scanner. Service, when
// set by the fingerprinter, routes the cracker directly; empty falls back to
// the port→service map.
type Endpoint struct {
	Host    string
	Port    int
	Service string
}

type Options struct {
	DictDir       string
	Threads       int // concurrent endpoints (NOT concurrent guesses per host)
	TimeoutSecond int
	StopOnFirst   bool // stop a service after its first valid credential
}

func DefaultOptions(dictDir string) Options {
	return Options{DictDir: dictDir, Threads: 50, TimeoutSecond: 5, StopOnFirst: true}
}

type Engine struct {
	opts         Options
	crackers     map[string]Cracker
	probes       map[string]ProbeFunc
	servicePorts map[int]string
}

func New(opts Options) *Engine {
	if opts.Threads <= 0 {
		opts.Threads = 50
	}
	if opts.TimeoutSecond <= 0 {
		opts.TimeoutSecond = 5
	}
	return &Engine{
		opts: opts,
		crackers: map[string]Cracker{
			"ssh":        sshCracker{},
			"mysql":      mysqlCracker{},
			"postgresql": postgresCracker{},
			"redis":      redisCracker{},
			"ftp":        ftpCracker{},
			"mssql":      mssqlCracker{},
			"oracle":     oracleCracker{},
			"mongodb":    mongodbCracker{},
			"smb":        smbCracker{},
			"rdp":        rdpCracker{},
			"telnet":     telnetCracker{},
		},
		probes: map[string]ProbeFunc{
			"smb":       probeMS17010,
			"memcached": probeMemcached,
			"adb":       probeADB,
			"jdwp":      probeJDWP,
			"telnet":    probeTelnet,
			"netbios":   probeNetBIOS,
		},
		servicePorts: defaultServicePorts,
	}
}

// Run routes each endpoint to its service cracker, brute forces with the
// matching dict, and emits a Finding per cracked service. The channel closes
// when all endpoints finish or ctx is cancelled.
//
// Concurrency is per-endpoint (Threads): guesses within one endpoint run
// sequentially so a single host isn't hammered in parallel.
func (e *Engine) Run(ctx context.Context, endpoints []Endpoint) <-chan types.Finding {
	out := make(chan types.Finding, 16)
	if ctx == nil {
		ctx = context.Background()
	}

	go func() {
		defer close(out)

		jobs := e.routableJobs(endpoints)
		if len(jobs) == 0 {
			return
		}
		dicts := e.loadDicts(jobs)
		timeout := time.Duration(e.opts.TimeoutSecond) * time.Second

		sem := make(chan struct{}, e.opts.Threads)
		var wg sync.WaitGroup

		for _, j := range jobs {
			creds := dicts[j.service]
			_, hasProbe := e.probes[j.service]
			if len(creds) == 0 && !hasProbe {
				continue
			}

			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case sem <- struct{}{}:
			}

			wg.Add(1)
			go func(j job, creds []Credential) {
				defer wg.Done()
				defer func() { <-sem }()
				e.handleEndpoint(ctx, j, creds, timeout, out)
			}(j, creds)
		}
		wg.Wait()
	}()

	return out
}

type job struct {
	ep      Endpoint
	service string
}

func (e *Engine) routableJobs(endpoints []Endpoint) []job {
	var jobs []job
	for _, ep := range endpoints {
		svc := ep.Service
		if svc == "" {
			svc = e.servicePorts[ep.Port] // fall back to the port→service map
		}
		_, hasCracker := e.crackers[svc]
		_, hasProbe := e.probes[svc]
		if !hasCracker && !hasProbe {
			continue
		}
		jobs = append(jobs, job{ep: ep, service: svc})
	}
	return jobs
}

// loadDicts reads each needed service dict once. A missing/unreadable dict is
// logged and its jobs are skipped (omitted from the returned map).
func (e *Engine) loadDicts(jobs []job) map[string][]Credential {
	need := make(map[string]struct{})
	for _, j := range jobs {
		need[j.service] = struct{}{}
	}

	dicts := make(map[string][]Credential, len(need))
	for svc := range need {
		path := filepath.Join(e.opts.DictDir, svc+".txt")
		creds, err := ParseDict(path)
		if err != nil {
			fmt.Printf("[!] gopocs: %s dict: %v\n", svc, err)
			continue
		}
		dicts[svc] = creds
	}
	return dicts
}

// handleEndpoint runs the service's credential-less probe (if any), then brute
// forces with the dict (if the service has a cracker and credentials).
func (e *Engine) handleEndpoint(ctx context.Context, j job, creds []Credential, timeout time.Duration, out chan<- types.Finding) {
	if probe, ok := e.probes[j.service]; ok {
		if f, perr := probe(ctx, j.ep.Host, j.ep.Port, timeout); perr == nil && f != nil {
			select {
			case out <- *f:
			case <-ctx.Done():
				return
			}
		}
	}
	if _, ok := e.crackers[j.service]; ok && len(creds) > 0 {
		e.bruteEndpoint(ctx, j, creds, timeout, out)
	}
}

func (e *Engine) bruteEndpoint(ctx context.Context, j job, creds []Credential, timeout time.Duration, out chan<- types.Finding) {
	cr := e.crackers[j.service]
	for _, cred := range creds {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ok, err := cr.Try(ctx, j.ep.Host, j.ep.Port, cred, timeout)
		if err != nil {
			return
		}
		if !ok {
			continue
		}

		select {
		case out <- e.toFinding(j, cred):
		case <-ctx.Done():
			return
		}
		if e.opts.StopOnFirst {
			return
		}
	}
}

func (e *Engine) toFinding(j job, cred Credential) types.Finding {
	login := cred.Pass
	if cred.User != "" {
		login = cred.User + ":" + cred.Pass
	}
	return types.Finding{
		ID:           "weak-credential-" + j.service,
		Name:         "Weak Credential (" + j.service + ")",
		Severity:     types.SeverityHigh,
		Target:       net.JoinHostPort(j.ep.Host, strconv.Itoa(j.ep.Port)),
		Description:  fmt.Sprintf("%s accepts weak credential %q", j.service, login),
		Tags:         []string{"weak-cred", j.service},
		DiscoveredAt: time.Now(),
	}
}

// ParseDict reads a credential dictionary. Lines containing " : " split into
// user/pass; bare lines are password-only (empty user, e.g. redis). Blank
// lines and # comments are skipped.
func ParseDict(path string) ([]Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("gopocs: open dict %s: %w", path, err)
	}
	defer f.Close()

	var creds []Credential
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if user, pass, ok := splitCred(line); ok {
			creds = append(creds, Credential{User: user, Pass: pass})
		} else {
			creds = append(creds, Credential{Pass: line})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("gopocs: read dict %s: %w", path, err)
	}
	return creds, nil
}

func splitCred(line string) (user, pass string, ok bool) {
	if i := strings.Index(line, " : "); i >= 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+3:]), true
	}
	return "", "", false
}
