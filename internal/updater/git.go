package updater

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// GitRunner abstracts shelling out to git so tests can fake it.
type GitRunner interface {
	Run(ctx context.Context, dir string, args ...string) ([]byte, error)
	Version(ctx context.Context) (string, error)
}

// execRunner is the production runner backed by `os/exec`.
type execRunner struct{}

func newExecRunner() GitRunner { return execRunner{} }

func (execRunner) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("git %s: %w (stderr: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (e execRunner) Version(ctx context.Context) (string, error) {
	out, err := e.Run(ctx, "", "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// IsAvailable checks whether the system has a usable `git` on PATH.
// Use this at startup to fail fast with a helpful message rather than
// midway through a clone.
func IsAvailable(ctx context.Context) error {
	_, err := newExecRunner().Version(ctx)
	if err != nil {
		return fmt.Errorf("updater: git not available on PATH: %w", err)
	}
	return nil
}
