// Package main is the dddd-next CLI entry point.
//
// Subcommands implemented so far:
//
//	dddd update     pull latest nuclei-templates and other POC sources
//	dddd version    print version
//	dddd help       short usage
//
// Scan mode (the default `-t <target>` invocation) is wired up in a later
// commit once the discovery / scanner modules land.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"dddd-next/internal/updater"
)

const (
	appName    = "dddd-next"
	appVersion = "0.1.2-dev"
)

func main() {
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

	fmt.Printf("%s %s — scan mode is not wired up yet.\n", appName, appVersion)
	fmt.Println("Available subcommands: update, version, help")
	fmt.Println("Run `dddd help` for details.")
}

func printHelp() {
	fmt.Printf(`%s %s — automated asset surveying and vulnerability scanning.

Usage:
  dddd <subcommand> [flags]
  dddd -t <target> [flags]              (scan mode — coming soon)

Subcommands:
  update          Pull the latest nuclei-templates and POC sources via git
  version         Show version info
  help            Show this help

Proxy:
  git inherits HTTP_PROXY / HTTPS_PROXY from the environment.
  Windows CMD:        set HTTPS_PROXY=http://127.0.0.1:7890
  Windows PowerShell: $env:HTTPS_PROXY="http://127.0.0.1:7890"
  Linux / macOS:      export HTTPS_PROXY=http://127.0.0.1:7890

Project: https://github.com/galact-byte (private, local-only for now)
Inspired by SleepingBag945/dddd (MIT License).
`, appName, appVersion)
}

func runUpdate(args []string) int {
	// Catch Ctrl-C so a clone-in-progress can be interrupted cleanly.
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
