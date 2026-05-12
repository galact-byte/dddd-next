// Package updater pulls remote POC and rule sources via the system `git`
// command. Using exec rather than a Go-native git library keeps the binary
// small and matches the typical user expectation of "I have git installed".
//
// The package is deliberately decoupled from any specific source — call
// New() with whatever Source list makes sense for your deployment. The
// canonical set (nuclei-templates) is available through DefaultSources.
package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Source describes one remote repository that holds POCs, fingerprints,
// or other update-able assets.
type Source struct {
	Name   string // friendly id used in logs
	URL    string // git clone URL
	Dir    string // local target directory
	Branch string // optional explicit branch; empty = default
	Depth  int    // optional shallow clone depth; 0 = full clone
}

// Action enumerates what updateOne actually did.
type Action string

const (
	ActionCloned   Action = "cloned"
	ActionUpdated  Action = "updated"
	ActionNoChange Action = "no-change"
	ActionFailed   Action = "failed"
)

// Result captures the outcome of updating a single Source.
type Result struct {
	Source   Source
	Action   Action
	HeadSHA  string
	Duration time.Duration
	Err      error
}

// Updater coordinates updates for an ordered list of sources.
type Updater struct {
	sources  []Source
	runner   GitRunner
	progress io.Writer
}

// New creates an Updater with the default exec-based git runner.
func New(sources []Source) *Updater {
	return &Updater{
		sources:  sources,
		runner:   newExecRunner(),
		progress: os.Stderr,
	}
}

// WithRunner swaps the GitRunner — intended for tests.
func (u *Updater) WithRunner(r GitRunner) *Updater {
	u.runner = r
	return u
}

// WithProgress redirects progress messages (defaults to stderr).
func (u *Updater) WithProgress(w io.Writer) *Updater {
	u.progress = w
	return u
}

// Update runs every Source sequentially. A single failure does not abort
// the remaining sources — the per-source outcome is in Result.Err.
//
// Returns a fan-in summary: the slice mirrors u.sources order.
func (u *Updater) Update(ctx context.Context) []Result {
	results := make([]Result, 0, len(u.sources))
	for _, src := range u.sources {
		results = append(results, u.updateOne(ctx, src))
		if ctx.Err() != nil {
			break
		}
	}
	return results
}

func (u *Updater) updateOne(ctx context.Context, src Source) Result {
	start := time.Now()
	r := Result{Source: src}

	if src.URL == "" || src.Dir == "" {
		r.Action = ActionFailed
		r.Err = errors.New("updater: source URL and Dir are required")
		r.Duration = time.Since(start)
		return r
	}

	if isGitRepo(src.Dir) {
		fmt.Fprintf(u.progress, "[updater] pulling %s (%s)\n", src.Name, src.Dir)
		oldSHAOut, _ := u.runner.Run(ctx, src.Dir, "rev-parse", "HEAD")
		oldSHA := strings.TrimSpace(string(oldSHAOut))

		if _, err := u.runner.Run(ctx, src.Dir, "pull", "--ff-only"); err != nil {
			r.Action = ActionFailed
			r.Err = fmt.Errorf("pull %s: %w", src.Name, err)
			r.Duration = time.Since(start)
			return r
		}

		newSHAOut, _ := u.runner.Run(ctx, src.Dir, "rev-parse", "HEAD")
		r.HeadSHA = strings.TrimSpace(string(newSHAOut))
		if oldSHA == r.HeadSHA {
			r.Action = ActionNoChange
		} else {
			r.Action = ActionUpdated
		}
		r.Duration = time.Since(start)
		return r
	}

	parent := filepath.Dir(src.Dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		r.Action = ActionFailed
		r.Err = fmt.Errorf("mkdir %s: %w", parent, err)
		r.Duration = time.Since(start)
		return r
	}

	args := []string{"clone"}
	if src.Depth > 0 {
		args = append(args, "--depth", strconv.Itoa(src.Depth))
	}
	if src.Branch != "" {
		args = append(args, "--branch", src.Branch)
	}
	args = append(args, src.URL, src.Dir)

	fmt.Fprintf(u.progress, "[updater] cloning %s -> %s\n", src.Name, src.Dir)
	if _, err := u.runner.Run(ctx, "", args...); err != nil {
		r.Action = ActionFailed
		r.Err = err
		r.Duration = time.Since(start)
		return r
	}

	shaOut, _ := u.runner.Run(ctx, src.Dir, "rev-parse", "HEAD")
	r.HeadSHA = strings.TrimSpace(string(shaOut))
	r.Action = ActionCloned
	r.Duration = time.Since(start)
	return r
}

// isGitRepo returns true when dir contains a .git entry. We accept both
// a directory (normal clone) and a file (worktree marker), so a worktree
// of the templates repo would also be recognised.
func isGitRepo(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil && (info.IsDir() || info.Mode().IsRegular())
}

// DefaultSources returns the canonical update set: nuclei templates.
// Callers may merge in additional Source entries from user config.
func DefaultSources(baseDir string) []Source {
	return []Source{
		{
			Name:  "nuclei-templates",
			URL:   "https://github.com/projectdiscovery/nuclei-templates.git",
			Dir:   filepath.Join(baseDir, "nuclei-templates"),
			Depth: 1, // shallow keeps the on-disk footprint manageable
		},
	}
}

// Summary returns a human-readable digest of the results, suitable for
// stdout after `dddd update` completes.
func Summary(results []Result) string {
	var b strings.Builder
	var failed int
	for _, r := range results {
		switch r.Action {
		case ActionFailed:
			failed++
			fmt.Fprintf(&b, "  [FAIL]   %s — %v (%s)\n", r.Source.Name, r.Err, r.Duration.Round(time.Millisecond))
		default:
			sha := r.HeadSHA
			if len(sha) > 8 {
				sha = sha[:8]
			}
			fmt.Fprintf(&b, "  [%-8s] %s @ %s (%s)\n", r.Action, r.Source.Name, sha, r.Duration.Round(time.Millisecond))
		}
	}
	if failed > 0 {
		fmt.Fprintf(&b, "\n%d source(s) failed.\n", failed)
	}
	return b.String()
}
