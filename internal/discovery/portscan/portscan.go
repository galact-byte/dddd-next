// Package portscan provides a dependency-free TCP connect scanner.
//
// dddd-next deliberately avoids naabu/libpcap here: connect scanning needs no
// raw sockets or npcap, so it runs unprivileged on Windows and inside the
// intranets dddd targets. It mirrors internal/discovery/dnsx's bounded
// worker-pool shape (sem channel + WaitGroup) for a consistent feel.
package portscan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultPorts is a curated set of common service ports: web stacks plus the
// services dddd-next ships weak-credential dictionaries for (ftp/ssh/mysql/
// mssql/oracle/postgresql/redis/rdp/smb/mongodb), so a hit here feeds both the
// HTTP probe and the later brute-force stage.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443,
	445, 465, 587, 636, 873, 993, 995, 1080, 1433, 1521, 1883, 2049, 2181,
	2375, 3306, 3389, 4848, 5000, 5432, 5555, 5601, 5900, 5984, 6379, 6443, 7001,
	7002, 8000, 8001, 8008, 8009, 8069, 8080, 8081, 8088, 8089, 8090, 8161,
	8443, 8500, 8888, 9000, 9001, 9042, 9090, 9092, 9200, 9300, 10250, 11211,
	15672, 27017, 27018, 50070,
}

// maxExpand caps host expansion so a stray large CIDR (e.g. /8) can't exhaust
// memory before the scan even starts.
const maxExpand = 1 << 20

// ParsePortSpec turns a CLI port spec into a port list: a comma-separated mix
// of single ports and a-b ranges ("80,443,8000-8100"), or "all"/"full" for
// 1-65535. Empty returns nil (caller uses DefaultPorts); out-of-range or
// reversed ranges are rejected.
func ParsePortSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	switch strings.ToLower(spec) {
	case "all", "full":
		ports := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}

	var ports []int
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(tok, "-")
		if !isRange {
			p, err := strconv.Atoi(tok)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("portscan: invalid port %q", tok)
			}
			ports = append(ports, p)
			continue
		}
		start, err1 := strconv.Atoi(strings.TrimSpace(lo))
		end, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
			return nil, fmt.Errorf("portscan: invalid port range %q", tok)
		}
		for p := start; p <= end; p++ {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("portscan: port spec %q yielded no ports", spec)
	}
	return dedupSortPorts(ports), nil
}

// Result is one open port found on a host.
type Result struct {
	Host string
	Port int
}

// Options configures a Scanner; zero values fall back to safe defaults.
type Options struct {
	Ports          []int
	TimeoutSeconds int
	Threads        int
}

func DefaultOptions() Options {
	return Options{Ports: DefaultPorts, TimeoutSeconds: 3, Threads: 500}
}

type Scanner struct {
	ports   []int
	timeout time.Duration
	threads int
}

// New normalizes Options (dedupes/sorts ports, applies defaults) and returns a
// ready Scanner. It performs no network I/O.
func New(opts Options) *Scanner {
	ports := dedupSortPorts(opts.Ports)
	if len(ports) == 0 {
		ports = dedupSortPorts(DefaultPorts)
	}
	timeout := time.Duration(opts.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	threads := opts.Threads
	if threads <= 0 {
		threads = 500
	}
	return &Scanner{ports: ports, timeout: timeout, threads: threads}
}

// Scan probes every host×port pair and emits one Result per OPEN port. The
// channel closes when the sweep finishes or ctx is cancelled.
func (s *Scanner) Scan(ctx context.Context, hosts []string) <-chan Result {
	out := make(chan Result, 64)
	if ctx == nil {
		ctx = context.Background()
	}

	go func() {
		defer close(out)

		sem := make(chan struct{}, s.threads)
		var wg sync.WaitGroup

		for _, h := range hosts {
			for _, p := range s.ports {
				select {
				case <-ctx.Done():
					wg.Wait()
					return
				case sem <- struct{}{}:
				}

				wg.Add(1)
				go func(host string, port int) {
					defer wg.Done()
					defer func() { <-sem }()

					if dialOpen(ctx, host, port, s.timeout) {
						select {
						case out <- Result{Host: host, Port: port}:
						case <-ctx.Done():
						}
					}
				}(h, p)
			}
		}

		wg.Wait()
	}()

	return out
}

func dialOpen(ctx context.Context, host string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ExpandHosts turns IP / CIDR / IP-range specs into a deduplicated list of IPv4
// literals. IPv6 and malformed specs return an error rather than being skipped
// silently, so the caller can surface bad input instead of scanning nothing.
func ExpandHosts(specs []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string

	add := func(ip string) error {
		if _, ok := seen[ip]; ok {
			return nil
		}
		if len(seen) >= maxExpand {
			return fmt.Errorf("portscan: host expansion exceeds %d addresses; narrow the range", maxExpand)
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
		return nil
	}

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		switch {
		case spec == "":
			continue
		case strings.Contains(spec, "/"):
			if err := expandCIDR(spec, add); err != nil {
				return nil, err
			}
		case strings.Contains(spec, "-"):
			if err := expandRange(spec, add); err != nil {
				return nil, err
			}
		default:
			ip := net.ParseIP(spec)
			if ip == nil || ip.To4() == nil {
				return nil, fmt.Errorf("portscan: %q is not an IPv4 address", spec)
			}
			if err := add(ip.To4().String()); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func expandCIDR(spec string, add func(string) error) error {
	_, ipnet, err := net.ParseCIDR(spec)
	if err != nil {
		return fmt.Errorf("portscan: parse CIDR %q: %w", spec, err)
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("portscan: %q is not IPv4 (IPv6 ranges unsupported)", spec)
	}
	start := binary.BigEndian.Uint32(ip4)
	mask := binary.BigEndian.Uint32(ipnet.Mask)
	end := start | ^mask
	for n := start; ; n++ {
		if err := add(u32ToIP(n)); err != nil {
			return err
		}
		if n == end {
			break
		}
	}
	return nil
}

func expandRange(spec string, add func(string) error) error {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("portscan: bad IP range %q", spec)
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))
	if startIP == nil || endIP == nil || startIP.To4() == nil || endIP.To4() == nil {
		return fmt.Errorf("portscan: %q is not a valid IPv4 range", spec)
	}
	start := binary.BigEndian.Uint32(startIP.To4())
	end := binary.BigEndian.Uint32(endIP.To4())
	if start > end {
		return fmt.Errorf("portscan: range start > end in %q", spec)
	}
	for n := start; ; n++ {
		if err := add(u32ToIP(n)); err != nil {
			return err
		}
		if n == end {
			break
		}
	}
	return nil
}

func u32ToIP(n uint32) string {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).String()
}

func dedupSortPorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	var out []int
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
