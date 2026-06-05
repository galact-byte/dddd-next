// Package config holds runtime configuration loaded from CLI flags and
// (later) YAML files. Right now we deliberately use only the standard
// library so the foundational modules can compile without pulling in
// cobra / viper / koanf — those land once the CLI surface stabilises.
package config

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Config is the resolved configuration for a single run.
//
// Only fields the foundational pipeline already needs live here. Modules
// added later (scanner, reporter, updater) extend this struct via PRs —
// keep it small so missing wiring stays obvious.
type Config struct {
	Targets     []string
	TargetsFile string

	Output     string
	OutputType string
	HTMLOutput string
	AuditLog   bool

	Subdomain bool
	ProxyURL  string

	LogLevel string

	Subcommand string
}

// Defaults returns a Config with sane non-zero defaults applied.
func Defaults() Config {
	return Config{
		Output:     "result.txt",
		OutputType: "text",
		HTMLOutput: "",
		LogLevel:   "info",
	}
}

// ParseArgs builds a Config from os.Args-style input. It accepts the program
// name as args[0] (matching os.Args layout) and parses the rest.
//
// Errors come back wrapped so callers can decide whether to log-and-exit
// or surface them in tests.
func ParseArgs(args []string) (Config, error) {
	if len(args) == 0 {
		return Config{}, errors.New("config: args is empty (missing program name)")
	}

	cfg := Defaults()

	if len(args) > 1 {
		switch args[1] {
		case "update":
			cfg.Subcommand = "update"
			return cfg, nil
		case "version", "-v", "--version":
			cfg.Subcommand = "version"
			return cfg, nil
		}
	}

	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var targets stringList
	fs.Var(&targets, "t", "target (repeatable): IP / CIDR / Range / URL / Domain / search query")
	fs.StringVar(&cfg.TargetsFile, "tf", "", "file containing targets, one per line")

	fs.StringVar(&cfg.Output, "o", cfg.Output, "result output file")
	fs.StringVar(&cfg.OutputType, "ot", cfg.OutputType, "output format: text | json")
	fs.StringVar(&cfg.HTMLOutput, "ho", cfg.HTMLOutput, "HTML report file (empty disables)")
	fs.BoolVar(&cfg.AuditLog, "a", cfg.AuditLog, "enable audit log (audit.log)")

	fs.BoolVar(&cfg.Subdomain, "sd", cfg.Subdomain, "enumerate subdomains for domain targets")
	fs.StringVar(&cfg.ProxyURL, "proxy", cfg.ProxyURL, "HTTP/SOCKS5 proxy URL for outgoing requests")

	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug | info | warn | error")

	if err := fs.Parse(args[1:]); err != nil {
		return cfg, fmt.Errorf("config: parse flags: %w", err)
	}

	cfg.Targets = append(cfg.Targets, targets...)

	if cfg.TargetsFile != "" {
		fileTargets, err := readLines(cfg.TargetsFile)
		if err != nil {
			return cfg, fmt.Errorf("config: read targets file: %w", err)
		}
		cfg.Targets = append(cfg.Targets, fileTargets...)
	}

	return cfg, nil
}

// Validate checks the resolved Config is internally consistent.
func (c Config) Validate() error {
	if c.Subcommand != "" {
		return nil
	}
	if len(c.Targets) == 0 {
		return errors.New("config: no targets supplied (-t or -tf required)")
	}
	switch c.OutputType {
	case "text", "json":
	default:
		return fmt.Errorf("config: invalid output type %q (want text|json)", c.OutputType)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: invalid log level %q", c.LogLevel)
	}
	return nil
}

// stringList lets a flag accept multiple values via repetition.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

// LoadDotEnv reads KEY=VALUE lines from a .env file and exports any key not
// already set in the environment, so an explicit shell `export` always wins.
// A missing file is not an error: .env is optional and only carries local
// secrets (recon API keys) that must never be committed.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		_ = os.Setenv(key, val)
	}
	return scanner.Err()
}
