package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"dddd-next/internal/updater"
)

func parseUpgradeArgs(args []string) (bool, error) {
	fs := flag.NewFlagSet("dddd upgrade", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var check bool
	fs.BoolVar(&check, "check", false, "check for a newer executable without downloading it")
	if err := fs.Parse(args); err != nil {
		return false, err
	}
	if fs.NArg() != 0 {
		return false, fmt.Errorf("unexpected upgrade argument: %s", fs.Arg(0))
	}
	return check, nil
}

func runBinaryUpdate(args []string) int {
	checkOnly, err := parseUpgradeArgs(args)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, err)
		}
		fmt.Fprintln(os.Stderr, "Usage: dddd upgrade [--check]")
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	timeout := 10 * time.Minute
	if checkOnly {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u := updater.NewBinaryUpdater(appVersion)
	fmt.Printf("[updater] checking dddd-next releases (current: %s)\n", appVersion)
	var result updater.BinaryRelease
	if checkOnly {
		result, err = u.Check(ctx)
	} else {
		result, err = u.Update(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Releases: https://github.com/galact-byte/dddd-next/releases/latest")
		return 1
	}
	switch {
	case result.Updated:
		fmt.Printf("[updater] updated %s -> %s; the new version is ready for the next run.\n", appVersion, result.Version)
	case result.Available:
		fmt.Printf("[updater] update available: %s -> %s; run `dddd upgrade` to install.\n", appVersion, result.Version)
	default:
		fmt.Printf("[updater] no newer stable release (current: %s, latest: %s).\n", appVersion, result.Version)
	}
	return 0
}
