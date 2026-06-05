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

	"dddd-next/internal/app"
	"dddd-next/internal/config"
	"dddd-next/internal/updater"
)

const (
	appName    = "dddd-next"
	appVersion = "0.1.12-dev"
)

func main() {
	loadDotEnv()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Printf("%s %s\n", appName, appVersion)
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	pipeline, err := app.New(cfg, resolveConfigDir())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer pipeline.Close()

	fmt.Printf("%s %s — scanning %d target(s)\n", appName, appVersion, len(cfg.Targets))
	if err := pipeline.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("[*] done. results -> %s\n", cfg.Output)
	return 0
}

func printHelp() {
	fmt.Printf(`%s %s — automated asset surveying and vulnerability scanning.

Usage:
  dddd -t <target> [flags]              scan mode
  dddd <subcommand>

Scan flags:
  -t <target>     target (repeatable): IP / CIDR / Range / IP:Port / Domain / URL / search query
  -tf <file>      targets file, one per line
  -o <file>       result output file (default result.txt)
  -ot <text|json> output format (default text)
  -ho <file>      HTML report file (empty disables)
  -a              enable audit log (audit.log)
  -sd             enumerate subdomains for domain targets
  -proxy <url>    HTTP/SOCKS5 proxy for outgoing requests
  -full           run all nuclei templates instead of fingerprint-matched POCs
  -no-general     skip the product-independent General-Poc set (precise mode)
  -log-level      debug | info | warn | error

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

// resolveConfigDir picks `configs/` next to the binary, falling back to
// `./configs` relative to the current working directory.
func resolveConfigDir() string {
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "configs")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return "configs"
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
