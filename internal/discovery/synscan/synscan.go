package synscan

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

type Result struct {
	Host string
	Port int
}

type Options struct {
	Rate  int
	Ports string
}

func DefaultOptions() Options {
	return Options{Rate: 10000}
}

func Scan(ctx context.Context, targets []string, ports string, opts Options) ([]Result, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	tmp, err := os.CreateTemp("", "dddd-synscan-*.json")
	if err != nil {
		return nil, fmt.Errorf("synscan: temp file: %w", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	runOpts := &runner.Options{
		Host:          goflags.StringSlice(targets),
		Ports:         ports,
		ScanType:      "s",
		Rate:          opts.Rate,
		Output:        tmp.Name(),
		JSON:          true,
		Silent:        true,
		DisableStdout: true,
		Ping:          false,
		Verify:        false,
		Debug:         false,
		Retries:       1,
		Timeout:       runner.DefaultPortTimeoutSynScan,
		Threads:       50,
	}

	r, err := runner.NewRunner(runOpts)
	if err != nil {
		return nil, fmt.Errorf("synscan: %w", err)
	}
	defer r.Close()

	if err := r.RunEnumeration(ctx); err != nil {
		return nil, fmt.Errorf("synscan: %w", err)
	}

	return parseJSONOutput(tmp.Name())
}

func parseJSONOutput(path string) ([]Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []Result
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		host, port, ok := parseJSONLine(line)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s:%d", host, port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, Result{Host: host, Port: port})
	}
	return results, sc.Err()
}

func parseJSONLine(line string) (host string, port int, ok bool) {
	// naabu JSON: {"host":"1.1.1.1","ip":"1.1.1.1","port":80,"protocol":"tcp",...}
	ip := extractJSONField(line, `"ip":"`, `"`)
	if ip == "" {
		ip = extractJSONField(line, `"host":"`, `"`)
	}
	if ip == "" {
		return "", 0, false
	}
	portStr := extractJSONField(line, `"port":`, `,`)
	if portStr == "" {
		portStr = extractJSONField(line, `"port":`, `}`)
	}
	p, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil || p == 0 {
		return "", 0, false
	}
	return ip, p, true
}

func extractJSONField(s, prefix, suffix string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	start := i + len(prefix)
	rest := s[start:]
	j := strings.Index(rest, suffix)
	if j < 0 {
		return rest
	}
	return rest[:j]
}
