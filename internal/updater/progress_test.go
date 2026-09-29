package updater

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdateShowsGitProgress(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("LC_ALL", "C")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remote := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = remote
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init")
	commit := func(contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(remote, "template.yaml"), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		git("add", "template.yaml")
		git("-c", "user.name=Updater Test", "-c", "user.email=updater@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "test templates")
	}
	commit("id: first\n")
	remotePath := filepath.ToSlash(remote)
	if !strings.HasPrefix(remotePath, "/") {
		remotePath = "/" + remotePath
	}
	remoteURL := (&url.URL{Scheme: "file", Path: remotePath}).String()
	target := filepath.Join(t.TempDir(), "templates with spaces")
	var progress bytes.Buffer
	u := New([]Source{{Name: "templates", URL: remoteURL, Dir: target, Depth: 1}}).WithProgress(&progress)
	check := func(want Action) {
		t.Helper()
		progress.Reset()
		results := u.Update(ctx)
		if len(results) != 1 || results[0].Action != want || results[0].Err != nil {
			t.Fatalf("update = %+v", results)
		}
		if want != ActionNoChange {
			stage := "Receiving objects:"
			if want == ActionUpdated {
				stage = "Counting objects:"
			}
			for _, text := range []string{stage, "100%"} {
				if !strings.Contains(progress.String(), text) {
					t.Errorf("progress missing %q:\n%s", text, progress.String())
				}
			}
		}
		if strings.Contains(progress.String(), results[0].HeadSHA) {
			t.Errorf("internal rev-parse output leaked into progress: %s", progress.String())
		}
		t.Logf("%s progress:\n%s", want, progress.String())
	}
	check(ActionCloned)
	commit("id: second\n")
	check(ActionUpdated)
	check(ActionNoChange)
}

func TestUpdateStreamsBeforeExitAndPreservesFailure(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("LC_ALL", "C")
	t.Setenv("NO_PROXY", "127.0.0.1")
	for _, cancelled := range []bool{false, true} {
		name := "http failure"
		if cancelled {
			name = "cancellation"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			progress := &cloneProgress{started: make(chan struct{})}
			streamed := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-progress.started:
					select {
					case <-streamed:
					default:
						close(streamed)
					}
					if cancelled {
						cancel()
					}
					http.Error(w, "template server unavailable", http.StatusServiceUnavailable)
				case <-r.Context().Done():
				}
			}))
			defer server.Close()
			results := New([]Source{{Name: "templates", URL: server.URL + "/templates.git", Dir: filepath.Join(t.TempDir(), "templates")}}).
				WithProgress(progress).Update(ctx)
			if len(results) != 1 || results[0].Action != ActionFailed || results[0].Err == nil {
				t.Fatalf("update = %+v", results)
			}
			select {
			case <-streamed:
			default:
				t.Fatal("Git progress was not delivered while the HTTP request was pending")
			}
			if cancelled {
				if ctx.Err() != context.Canceled {
					t.Fatalf("context error = %v, want canceled", ctx.Err())
				}
			} else {
				for _, text := range []string{"fatal:", "503"} {
					if !strings.Contains(results[0].Err.Error(), text) || !strings.Contains(progress.String(), text) {
						t.Errorf("missing %q in error or progress: %v\n%s", text, results[0].Err, progress.String())
					}
				}
			}
		})
	}
}

type cloneProgress struct {
	bytes.Buffer
	started chan struct{}
}

func (p *cloneProgress) Write(data []byte) (int, error) {
	n, err := p.Buffer.Write(data)
	if strings.Contains(p.String(), "Cloning into") {
		select {
		case <-p.started:
		default:
			close(p.started)
		}
	}
	return n, err
}

// A shallow `git pull` follows merge parents back into old history and
// auto-follows every tag it reaches; nuclei-templates turned a depth-1
// clone into a ~700 MiB full fetch this way.
func TestShallowUpdateStaysShallowWithoutTags(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("LC_ALL", "C")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remote := t.TempDir()
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-c", "user.name=Updater Test", "-c", "user.email=updater@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(remote, name), []byte(name+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		git(remote, "add", name)
		git(remote, "commit", "-m", name)
	}
	git(remote, "init", "-b", "main")
	for i := 0; i < 5; i++ {
		commit(fmt.Sprintf("old-%d.yaml", i))
		git(remote, "tag", fmt.Sprintf("v%d", i))
	}
	git(remote, "checkout", "-b", "side", "HEAD~3")
	commit("side.yaml")
	git(remote, "checkout", "main")

	remotePath := filepath.ToSlash(remote)
	if !strings.HasPrefix(remotePath, "/") {
		remotePath = "/" + remotePath
	}
	target := filepath.Join(t.TempDir(), "templates")
	var progress bytes.Buffer
	u := New([]Source{{Name: "templates", URL: (&url.URL{Scheme: "file", Path: remotePath}).String(), Dir: target, Depth: 1}}).WithProgress(&progress)
	if r := u.Update(ctx); r[0].Err != nil || r[0].Action != ActionCloned {
		t.Fatalf("clone = %+v", r)
	}

	git(remote, "merge", "--no-ff", "side", "-m", "merge side")
	commit("new.yaml")
	git(remote, "tag", "v-new")
	if err := os.WriteFile(filepath.Join(target, "custom.yaml"), []byte("keep me\n"), 0600); err != nil {
		t.Fatal(err)
	}
	progress.Reset()
	r := u.Update(ctx)
	if r[0].Err != nil || r[0].Action != ActionUpdated {
		t.Fatalf("update = %+v\n%s", r, progress.String())
	}
	if n := git(target, "rev-list", "--count", "HEAD"); n != "1" {
		t.Errorf("history grew to %s commits; update must stay shallow", n)
	}
	if tags := git(target, "tag"); tags != "" {
		t.Errorf("tags were fetched: %q", tags)
	}
	for _, name := range []string{"side.yaml", "new.yaml", "custom.yaml"} {
		if _, err := os.Stat(filepath.Join(target, name)); err != nil {
			t.Errorf("%s missing after update: %v", name, err)
		}
	}
	for _, noise := range []string{"[new tag]", "From ", "->"} {
		if strings.Contains(progress.String(), noise) {
			t.Errorf("ref update noise %q in progress:\n%s", noise, progress.String())
		}
	}
}

func TestShallowUpdateRefusesLocalChanges(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("LC_ALL", "C")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remote := t.TempDir()
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-c", "user.name=Updater Test", "-c", "user.email=updater@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git(remote, "init", "-b", "main")
	write := func(dir, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(remote, "one\n")
	git(remote, "add", "a.yaml")
	git(remote, "commit", "-m", "one")
	remotePath := filepath.ToSlash(remote)
	if !strings.HasPrefix(remotePath, "/") {
		remotePath = "/" + remotePath
	}
	target := filepath.Join(t.TempDir(), "templates")
	u := New([]Source{{Name: "templates", URL: (&url.URL{Scheme: "file", Path: remotePath}).String(), Dir: target, Depth: 1}}).WithProgress(io.Discard)
	if r := u.Update(ctx); r[0].Err != nil {
		t.Fatalf("clone = %+v", r)
	}
	write(remote, "two\n")
	git(remote, "commit", "-am", "two")

	write(target, "edited locally\n")
	r := u.Update(ctx)
	if r[0].Action != ActionFailed || r[0].Err == nil || !strings.Contains(r[0].Err.Error(), "local changes") {
		t.Fatalf("dirty update = %+v", r)
	}
	if data, _ := os.ReadFile(filepath.Join(target, "a.yaml")); string(data) != "edited locally\n" {
		t.Fatalf("local edit was overwritten: %q", data)
	}

	git(target, "checkout", "--", "a.yaml")
	git(target, "commit", "--allow-empty", "-m", "local commit")
	r = u.Update(ctx)
	if r[0].Action != ActionFailed || r[0].Err == nil || !strings.Contains(r[0].Err.Error(), "local commit") {
		t.Fatalf("update with local commit = %+v", r)
	}
}
