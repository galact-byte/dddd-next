// Package hostalive checks host liveness by ICMP echo, an opt-in pre-filter for
// large port-scan ranges. Off by default: hardened hosts often drop ICMP while
// exposing open ports, so filtering by it would silently miss them. Tries a raw
// ICMP socket first, then falls back to the system ping command (no privilege).
package hostalive

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

var DefaultTCPPingPorts = []int{80, 443, 22, 3389, 445}

// CheckLiveTCP returns hosts with at least one of ports open — a TCP liveness
// pre-filter for networks that drop ICMP but still answer TCP.
func CheckLiveTCP(ctx context.Context, hosts []string, ports []int, timeoutSeconds int) []string {
	if len(hosts) == 0 {
		return nil
	}
	if len(ports) == 0 {
		ports = DefaultTCPPingPorts
	}
	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	const maxConcurrent = 256
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex
	aliveSet := make(map[string]struct{})

loop:
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			break loop
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if tcpOpen(ctx, host, port, timeout) {
					mu.Lock()
					aliveSet[host] = struct{}{}
					mu.Unlock()
					return
				}
			}
		}(host)
	}
	wg.Wait()

	alive := make([]string, 0, len(aliveSet))
	for _, host := range hosts { // preserve input order, drop duplicates
		if _, ok := aliveSet[host]; ok {
			alive = append(alive, host)
			delete(aliveSet, host)
		}
	}
	return alive
}

func tcpOpen(ctx context.Context, host string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// CheckLive returns the subset of hosts that answer ICMP. forcePing skips the
// raw-socket attempt and goes straight to the system ping command (useful when
// raw ICMP is known to be blocked or unwanted).
func CheckLive(ctx context.Context, hosts []string, forcePing bool) []string {
	if len(hosts) == 0 {
		return nil
	}
	if !forcePing {
		if alive, ok := icmpEcho(ctx, hosts); ok {
			return alive
		}
	}
	return pingCommand(ctx, hosts)
}

// icmpEcho sends one echo request per host over a shared raw socket. ok is
// false when the raw socket can't be opened (no privilege) — the caller then
// falls back to the ping command.
func icmpEcho(ctx context.Context, hosts []string) (alive []string, ok bool) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, false
	}
	defer conn.Close()

	want := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		want[h] = struct{}{}
	}

	var mu sync.Mutex
	seen := make(map[string]struct{})
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n == 0 || peer == nil {
				continue
			}
			ip := peer.String()
			mu.Lock()
			if _, isTarget := want[ip]; isTarget {
				seen[ip] = struct{}{}
			}
			mu.Unlock()
		}
	}()

	for _, host := range hosts {
		dst, err := net.ResolveIPAddr("ip", host)
		if err != nil {
			continue
		}
		_, _ = conn.WriteTo(makeEchoRequest(host), dst)
	}

	// Longer windows answer fewer false negatives on large sweeps.
	wait := 3 * time.Second
	if len(hosts) > 256 {
		wait = 6 * time.Second
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	case <-done:
	}
	_ = conn.Close()

	mu.Lock()
	defer mu.Unlock()
	for ip := range seen {
		alive = append(alive, ip)
	}
	return alive, true
}

// pingCommand shells out to the platform ping, one process per host (capped),
// treating a "ttl=" line in the output as proof of a reply. Exit codes are
// unreliable on Windows (a router's "unreachable" can still exit 0), so we
// match the reply text instead.
func pingCommand(ctx context.Context, hosts []string) []string {
	const maxConcurrent = 50
	limiter := make(chan struct{}, maxConcurrent)
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		alive []string
	)
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			wg.Wait()
			return alive
		case limiter <- struct{}{}:
		}
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			defer func() { <-limiter }()
			if pingOnce(ctx, host) {
				mu.Lock()
				alive = append(alive, host)
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()
	return alive
}

func pingOnce(ctx context.Context, host string) bool {
	var args []string
	switch runtime.GOOS {
	case "windows":
		args = []string{"-n", "1", "-w", "1000", host} // -w is milliseconds on Windows
	case "darwin":
		args = []string{"-c", "1", "-W", "1000", host} // -W is milliseconds on macOS
	default:
		args = []string{"-c", "1", "-W", "1", host} // -W is seconds on Linux
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, pingBinary(), args...)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return false
	}
	return strings.Contains(strings.ToLower(out.String()), "ttl=")
}

// pingBinary resolves the ping executable. On Windows it returns the absolute
// System32 path rather than trusting PATH order: a stray ping.py or a planted
// ping.exe earlier in PATH would otherwise be run instead of the real one.
func pingBinary() string {
	if runtime.GOOS == "windows" {
		if root := os.Getenv("SystemRoot"); root != "" {
			return filepath.Join(root, "System32", "ping.exe")
		}
		return "ping.exe"
	}
	return "ping"
}

// makeEchoRequest builds an ICMP type-8 echo request with a correct checksum.
func makeEchoRequest(host string) []byte {
	msg := make([]byte, 40)
	msg[0] = 8 // type: echo request
	id0, id1 := identifier(host)
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = sequence(1)
	check := checksum(msg)
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 0xff)
	return msg
}

func checksum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}

func sequence(v int16) (byte, byte) { return byte(v >> 8), byte(v & 0xff) }

func identifier(host string) (byte, byte) {
	if len(host) < 2 {
		return 0, 0
	}
	return host[0], host[1]
}
