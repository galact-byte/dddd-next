// Package main is the dddd-next CLI entry point.
//
//	dddd -t <target> [flags]   scan mode (default)
//	dddd update                pull latest nuclei-templates and POC sources
//	dddd version               print version
//	dddd help                  usage
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"dddd-next/internal/app"
	"dddd-next/internal/config"
	"dddd-next/internal/updater"
)

const appName = "dddd-next"

var appVersion = "0.1.42-dev"

func main() {
	loadDotEnv()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Print(versionLine())
			return
		case "help", "-h", "--help":
			printHelp()
			return
		case "update":
			os.Exit(runUpdate(os.Args[2:]))
		}
	}
	os.Exit(runScan(os.Args))
}

func versionLine() string {
	return fmt.Sprintf("%s %s\n", appName, appVersion)
}

func runScan(args []string) int {
	cfg, err := config.ParseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Run `dddd help` for usage.")
		return 2
	}
	if cfg.ProxyTest {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := config.TestProxy(ctx, cfg.ProxyURL, cfg.ProxyTestURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Printf("[*] proxy test ok: %s via %s\n", cfg.ProxyTestURL, config.RedactURLCredentials(cfg.ProxyURL))
	}

	printBanner()

	outDir := setupOutputDir()
	cfg = prepareOutputPaths(cfg, outDir)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	pipeline, err := app.New(cfg, resolveConfigDir())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer pipeline.Close()

	fmt.Printf("\x1b[32m[*]\x1b[0m %d target(s)  ·  %s  ·  output -> %s\n", len(cfg.Targets), scanModeLabel(cfg), outDir)
	if err := pipeline.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("[*] done. results -> %s\n", outDir)
	return 0
}

func setupOutputDir() string {
	ts := time.Now().Format("2006-01-02_150405")
	return createOutputDir("output", ts)
}

func createOutputDir(base, stamp string) string {
	_ = os.MkdirAll(base, 0755)
	for i := 1; ; i++ {
		name := stamp
		if i > 1 {
			name = fmt.Sprintf("%s-%d", stamp, i)
		}
		dir := filepath.Join(base, name)
		err := os.Mkdir(dir, 0755)
		if err == nil {
			return dir
		}
		if os.IsExist(err) {
			continue
		}
		_ = os.MkdirAll(dir, 0755)
		return dir
	}
}

func prepareOutputPaths(cfg config.Config, outDir string) config.Config {
	if cfg.Output != "" {
		cfg.Output = filepath.Join(outDir, cfg.Output)
	}
	if cfg.HTMLOutput != "" {
		cfg.HTMLOutput = filepath.Join(outDir, cfg.HTMLOutput)
	}
	if cfg.AuditLog {
		cfg.AuditLogFile = filepath.Join(outDir, cfg.AuditLogFile)
	}
	return cfg
}

func printBanner() {
	c := "\x1b[36m"
	b := "\x1b[1m"
	d := "\x1b[2m"
	x := "\x1b[0m"
	fmt.Println()
	fmt.Printf("%s     _       _       _       _%s\n", c, x)
	fmt.Printf("%s  __| |   __| |   __| |   __| |%s   %sdddd-next%s\n", c, x, b, x)
	fmt.Printf("%s / _` |  / _` |  / _` |  / _` |%s   %sautomated asset recon + vuln scan%s\n", c, x, d, x)
	fmt.Printf("%s \\__,_|  \\__,_|  \\__,_|  \\__,_|%s   %s%s%s\n", c, x, d, appVersion, x)
	fmt.Println()
}

func scanModeLabel(cfg config.Config) string {
	switch {
	case cfg.LowPerception:
		return "low-perception"
	case cfg.FullScan:
		return "full-nuclei"
	case cfg.NoPoc:
		return "recon-only"
	default:
		return "precise-poc"
	}
}

func printHelp() {
	fmt.Printf(`%s %s — automated asset surveying and vulnerability scanning.

Usage:
  dddd -t <target> [flags]              scan mode
  dddd <subcommand>

Scan flags:
  -t <target>     target (repeatable): IP / CIDR / Range / IP:Port / Domain / URL / search query
  -tf <file>      targets file, one per line (accepts fscan "ip:port open" and dddd "[FP] ..." lines)
  -o <file>       result output file (default result.txt)
  -ot <text|json> output format (default text)
  -ho <file>      HTML report file (empty disables)
  -a              enable audit log (audit.log)
  -alf <file>     audit log filename (default audit.log)

  -sd             enumerate subdomains for domain targets
  -nsb            skip active subdomain brute-force
  -ns             skip passive subdomain enumeration (subfinder)
  -proxy <url>    HTTP/SOCKS5 proxy for outgoing requests

  -st <tcp|syn>   scan type: tcp (connect, default) | syn (requires npcap/admin)
  -sst <n>        SYN scan packet rate (default 10000)
  -p <ports>      port spec: "80,443,8000-8100" or "all" (default: curated)
  -np <ports>     exclude specific ports (comma-separated)
  -pmc <n>        max open ports per IP before dropping as firewalled (default 300)
  -ping           ICMP-ping first, only scan responding hosts
  -tp             TCP-connect liveness probe (use with or instead of -ping)
  -skip-cdn       exclude CDN/WAF-fronted domains
  -ac             allow scanning CDN assets (overrides -skip-cdn)
  -no-dir         skip product-path probing (/nacos/, /druid/, ...)
  -nhb            disable domain-bound (vhost) asset probing
  -oip            pull recon assets as IP:Port instead of Domain:Port
  -ld             keep recon assets that resolve to LAN/private IPs
  -lpm            Hunter low-perception: fingerprint from Hunter's banner, no probe
  -limit <n>      max assets per recon query (fofa/hunter/quake; 0 = 100)

  -full           run all nuclei templates instead of fingerprint-matched POCs
  -no-general     skip the product-independent General-Poc set (precise mode)
  -severity <s>   nuclei severity filter (repeatable: critical,high,medium,low,info)
  -exclude-severity <s>  exclude nuclei severities (repeatable)
  -tags <t>       nuclei template tags to include (repeatable)
  -exclude-tags <t>  nuclei template tags to exclude (repeatable)
  -poc <name>     fuzzy-match POC template by name/id substring

  -no-brute       skip weak-credential brute-force (gopocs)
  -no-poc         skip all POC/exploit checks (nuclei + shiro)
  -ngp            skip gopocs weak-cred/crack checks only (nuclei+shiro still run)
  -ni             disable interactsh OOB server
  -iserver <url>  custom interactsh server URL
  -itoken <t>     interactsh auth token

  -up <user:pass> custom credential (repeatable)
  -upf <file>     custom credential file (user:pass per line)

  -tst <n>        TCP port scan threads (default 1000)
  -pst <n>        TCP port scan timeout seconds (default 6)
  -tc <n>         service detection threads (default 500)
  -nto <n>        service detection timeout seconds (default 5)
  -sbt <n>        subdomain brute-force threads (default 150)
  -wt <n>         Web probe threads (default 200)
  -wto <n>        Web probe timeout seconds (default 10)
  -gpt <n>        GoPoC threads (default 50)

  -pt             test proxy before use
  -ptu <url>      proxy test URL (default https://www.baidu.com)
  -log-level      debug | info | warn | error (default info)

Subcommands:
  update          Pull the latest nuclei-templates and POC sources via git
  version         Show version info
  help            Show this help

Proxy:
  git and scanners inherit HTTP_PROXY / HTTPS_PROXY from the environment.
  Windows CMD:        set HTTPS_PROXY=http://127.0.0.1:7890
  Windows PowerShell: $env:HTTPS_PROXY="http://127.0.0.1:7890"

Recon (search-query targets):
  Queries like -t 'app="seeyon"' hit fofa/hunter/quake. Put API keys in a
  .env file next to the binary (copy .env.example): FOFA_EMAIL + FOFA_KEY,
  HUNTER_API_KEY, QUAKE_TOKEN. Free FOFA accounts have no API quota.

Configs:
  Release binaries include baseline configs. If no configs/ exists next to the
  binary or in the working directory, dddd-next writes them to
  ~/Downloads/dddd-next/configs and uses that directory. Put configs/ next to
  the binary to override or customize them.

Vulnerability scan (nuclei):
  Default precise mode runs only the POCs a target's fingerprints map to
  (configs/pocs/mapping.yaml) plus a general POC set — not all 13000+ templates.
  -full scans every template; -no-general drops the general set.

Inspired by SleepingBag945/dddd (MIT License).
`, appName, appVersion)
}

func runUpdate(args []string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := updater.IsAvailable(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Install git from https://git-scm.com/ and ensure it is on PATH.")
		return 2
	}

	cfgDir := resolveConfigDir()
	sources := updater.DefaultSources(cfgDir)

	fmt.Printf("dddd-next update — %d source(s) -> %s\n", len(sources), cfgDir)
	fmt.Println("(set HTTPS_PROXY if behind a restricted network)")
	fmt.Println()

	u := updater.New(sources)
	results := u.Update(ctx)

	fmt.Println()
	fmt.Print(updater.Summary(results))

	for _, r := range results {
		if r.Action == updater.ActionFailed {
			return 1
		}
	}
	return 0
}

// loadDotEnv pulls local secrets (recon API keys) from a .env file next to the
// working dir or the binary into the environment, where uncover reads them.
// Both lookups are best-effort: .env is optional and gitignored.
func loadDotEnv() {
	_ = config.LoadDotEnv(".env")
	if exe, err := os.Executable(); err == nil {
		_ = config.LoadDotEnv(filepath.Join(filepath.Dir(exe), ".env"))
	}
}
