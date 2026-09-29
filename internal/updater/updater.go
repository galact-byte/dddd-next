// Package updater pulls remote POC and rule sources via the system `git`
// command. Using exec rather than a Go-native git library keeps the binary
// small and matches the typical user expectation of "I have git installed".
//
// The package is deliberately decoupled from any specific source — call
// New() with whatever Source list makes sense for your deployment. The
// canonical set (nuclei-templates) is available through DefaultSources.
package updater

import (
	"bytes"
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
	Source      Source
	Action      Action
	HeadSHA     string
	PreviousSHA string
	Duration    time.Duration
	Err         error
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
		fmt.Fprintf(u.progress, "[updater] updating %s (%s)\n", src.Name, src.Dir)
		oldSHAOut, _ := u.runner.Run(ctx, src.Dir, "rev-parse", "HEAD")
		oldSHA := strings.TrimSpace(string(oldSHAOut))
		r.PreviousSHA = oldSHA

		var err error
		if src.Depth > 0 {
			err = u.syncShallow(ctx, src)
		} else {
			_, err = u.runWithProgress(ctx, src.Dir, "pull", "--ff-only", "--progress")
		}
		if err != nil {
			r.Action = ActionFailed
			r.Err = fmt.Errorf("update %s: %w", src.Name, err)
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

	args := []string{"clone", "--progress"}
	if src.Depth > 0 {
		args = append(args, "--depth", strconv.Itoa(src.Depth), "--no-tags")
	}
	if src.Branch != "" {
		args = append(args, "--branch", src.Branch)
	}
	args = append(args, src.URL, src.Dir)

	fmt.Fprintf(u.progress, "[updater] cloning %s -> %s\n", src.Name, src.Dir)
	if _, err := u.runWithProgress(ctx, "", args...); err != nil {
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

// syncShallow moves a shallow clone to the remote tip without `git pull`.
// A shallow pull follows merge parents back past the shallow boundary and
// auto-follows every tag it reaches, which turns a depth-1 checkout into a
// near-full clone. Fetching the tip again with --depth keeps it shallow.
func (u *Updater) syncShallow(ctx context.Context, src Source) error {
	status, err := u.runner.Run(ctx, src.Dir, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(status)) != 0 {
		return fmt.Errorf("local changes to tracked files in %s; commit, stash or discard them before updating", src.Dir)
	}
	branch := src.Branch
	if branch == "" {
		upstream, err := u.runner.Run(ctx, src.Dir, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
		name := strings.TrimSpace(string(upstream))
		if err != nil || !strings.HasPrefix(name, "origin/") {
			return fmt.Errorf("cannot determine the origin branch tracked by %s; check out the template branch", src.Dir)
		}
		branch = strings.TrimPrefix(name, "origin/")
	}
	tracking := "refs/remotes/origin/" + branch
	ahead, err := u.runner.Run(ctx, src.Dir, "rev-list", "--count", tracking+"..HEAD")
	if err != nil {
		return err
	}
	if n := strings.TrimSpace(string(ahead)); n != "0" {
		return fmt.Errorf("%s local commit(s) in %s would be discarded; move them elsewhere before updating", n, src.Dir)
	}
	quiet := "-q" // older git: hides ref lines but also local receive progress
	if gitAtLeast(ctx, u.runner, 2, 41) {
		quiet = "--porcelain" // ref lines go to stdout; all progress stays on stderr
	}
	if _, err := u.runWithProgress(ctx, src.Dir, "fetch", quiet, "--progress", "--no-tags",
		"--depth", strconv.Itoa(src.Depth), "origin", "+refs/heads/"+branch+":"+tracking); err != nil {
		return err
	}
	_, err = u.runner.Run(ctx, src.Dir, "reset", "-q", "--hard", tracking)
	return err
}

// gitAtLeast parses `git version X.Y...`; unknown formats count as older.
func gitAtLeast(ctx context.Context, runner GitRunner, major, minor int) bool {
	version, err := runner.Version(ctx)
	if err != nil {
		return false
	}
	parts := strings.SplitN(strings.TrimPrefix(version, "git version "), ".", 3)
	if len(parts) < 2 {
		return false
	}
	gotMajor, err1 := strconv.Atoi(parts[0])
	gotMinor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return gotMajor > major || gotMajor == major && gotMinor >= minor
}

// Custom runners can opt into streaming without changing the GitRunner contract.
func (u *Updater) runWithProgress(ctx context.Context, dir string, args ...string) ([]byte, error) {
	if runner, ok := u.runner.(interface {
		RunWithProgress(context.Context, string, io.Writer, ...string) ([]byte, error)
	}); ok {
		return runner.RunWithProgress(ctx, dir, u.progress, args...)
	}
	return u.runner.Run(ctx, dir, args...)
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
			if r.Action == ActionUpdated && r.PreviousSHA != "" {
				previous := r.PreviousSHA
				if len(previous) > 8 {
					previous = previous[:8]
				}
				sha = previous + " -> " + sha
			}
			fmt.Fprintf(&b, "  [%-8s] %s @ %s (%s)\n", r.Action, r.Source.Name, sha, r.Duration.Round(time.Millisecond))
		}
	}
	if failed > 0 {
		fmt.Fprintf(&b, "\n%d source(s) failed.\n", failed)
	}
	return b.String()
}
