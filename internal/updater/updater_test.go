package updater

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner is a recording GitRunner used to assert the exec call shape.
type fakeRunner struct {
	calls    []fakeCall
	responses map[string][]byte // key: joined args -> stdout
	errOn    map[string]error  // key: joined args -> err
}

type fakeCall struct {
	dir  string
	args []string
}

func newFake() *fakeRunner {
	return &fakeRunner{
		responses: map[string][]byte{},
		errOn:     map[string]error{},
	}
}

func (f *fakeRunner) Run(_ context.Context, dir string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, fakeCall{dir: dir, args: append([]string(nil), args...)})
	key := strings.Join(args, " ")
	if err, ok := f.errOn[key]; ok {
		return nil, err
	}
	if out, ok := f.responses[key]; ok {
		return out, nil
	}
	return nil, nil
}

func (f *fakeRunner) Version(_ context.Context) (string, error) {
	return "git version fake-1.0", nil
}

func TestCloneNewSource(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "templates")

	f := newFake()
	f.responses["rev-parse HEAD"] = []byte("abc1234\n")

	u := New([]Source{{Name: "t", URL: "https://example.com/x.git", Dir: target, Depth: 1}}).
		WithRunner(f).
		WithProgress(new(bytes.Buffer))

	res := u.Update(context.Background())
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if res[0].Action != ActionCloned {
		t.Errorf("Action = %s, want cloned", res[0].Action)
	}
	if res[0].HeadSHA != "abc1234" {
		t.Errorf("HeadSHA = %q", res[0].HeadSHA)
	}
	if res[0].Err != nil {
		t.Errorf("unexpected err: %v", res[0].Err)
	}

	// 2 calls expected: clone + rev-parse
	if len(f.calls) != 2 {
		t.Fatalf("calls = %d, want 2 (%+v)", len(f.calls), f.calls)
	}
	cloneCall := f.calls[0]
	if cloneCall.args[0] != "clone" {
		t.Errorf("first arg = %q, want clone", cloneCall.args[0])
	}
	joined := strings.Join(cloneCall.args, " ")
	if !strings.Contains(joined, "--depth 1") {
		t.Errorf("shallow flag missing: %s", joined)
	}
}

func TestPullExistingRepo(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "existing")
	if err := os.MkdirAll(filepath.Join(target, ".git"), 0o755); err != nil {
		t.Fatalf("setup .git: %v", err)
	}

	f := newFake()
	// First rev-parse before pull, second one after — different SHAs => updated.
	f.responses["rev-parse HEAD"] = []byte("first1\n")

	u := New([]Source{{Name: "t", URL: "https://x.git", Dir: target}}).
		WithRunner(f).
		WithProgress(new(bytes.Buffer))

	// override response on the second rev-parse call by using a stateful runner
	calls := 0
	statefulRunner := runnerFunc(func(ctx context.Context, dir string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "rev-parse HEAD":
			calls++
			if calls == 1 {
				return []byte("old111\n"), nil
			}
			return []byte("new222\n"), nil
		case "pull --ff-only":
			return []byte("ok"), nil
		}
		return nil, nil
	})
	u.WithRunner(statefulRunner)

	res := u.Update(context.Background())
	if res[0].Action != ActionUpdated {
		t.Errorf("Action = %s, want updated", res[0].Action)
	}
	if res[0].HeadSHA != "new222" {
		t.Errorf("HeadSHA = %q", res[0].HeadSHA)
	}
}

func TestNoChangeWhenSHASame(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "same")
	os.MkdirAll(filepath.Join(target, ".git"), 0o755)

	stateful := runnerFunc(func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "rev-parse HEAD" {
			return []byte("aaa111\n"), nil
		}
		return nil, nil
	})
	u := New([]Source{{Name: "t", URL: "https://x.git", Dir: target}}).
		WithRunner(stateful).
		WithProgress(new(bytes.Buffer))

	res := u.Update(context.Background())
	if res[0].Action != ActionNoChange {
		t.Errorf("Action = %s, want no-change", res[0].Action)
	}
}

func TestFailureIsolated(t *testing.T) {
	dir := t.TempDir()
	target1 := filepath.Join(dir, "good")
	target2 := filepath.Join(dir, "bad")

	stateful := runnerFunc(func(ctx context.Context, d string, args ...string) ([]byte, error) {
		// clone is invoked with cmd.Dir = "" — we identify the bad source
		// by inspecting args (URL/target appear there) rather than d.
		joined := strings.Join(args, " ")
		if args[0] == "clone" && strings.Contains(joined, target2) {
			return nil, errors.New("network unreachable")
		}
		if joined == "rev-parse HEAD" {
			return []byte("good11\n"), nil
		}
		return nil, nil
	})

	u := New([]Source{
		{Name: "good", URL: "https://x.git", Dir: target1},
		{Name: "bad", URL: "https://y.git", Dir: target2},
	}).WithRunner(stateful).WithProgress(new(bytes.Buffer))

	results := u.Update(context.Background())
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	if results[1].Action != ActionFailed {
		t.Errorf("second action = %s, want failed", results[1].Action)
	}
	if results[1].Err == nil {
		t.Error("expected err on bad source")
	}
}

func TestInvalidSource(t *testing.T) {
	u := New([]Source{{Name: "empty"}}).WithRunner(newFake()).WithProgress(new(bytes.Buffer))
	res := u.Update(context.Background())
	if res[0].Action != ActionFailed {
		t.Errorf("Action = %s, want failed", res[0].Action)
	}
}

func TestDefaultSources(t *testing.T) {
	got := DefaultSources("/tmp/configs")
	if len(got) != 1 {
		t.Fatalf("want 1 source, got %d", len(got))
	}
	if got[0].Name != "nuclei-templates" {
		t.Errorf("name = %s", got[0].Name)
	}
	if !strings.HasSuffix(got[0].Dir, "nuclei-templates") {
		t.Errorf("dir = %s", got[0].Dir)
	}
	if got[0].Depth != 1 {
		t.Errorf("depth = %d, want 1", got[0].Depth)
	}
}

func TestSummary(t *testing.T) {
	results := []Result{
		{Source: Source{Name: "a"}, Action: ActionCloned, HeadSHA: "abcdef1234567890"},
		{Source: Source{Name: "b"}, Action: ActionFailed, Err: errors.New("boom")},
	}
	s := Summary(results)
	for _, want := range []string{"cloned", "a", "abcdef12", "FAIL", "b", "boom", "1 source(s) failed"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
}

// runnerFunc adapts a closure into a GitRunner — handy for stateful fakes.
type runnerFunc func(ctx context.Context, dir string, args ...string) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return f(ctx, dir, args...)
}
func (runnerFunc) Version(_ context.Context) (string, error) { return "fake", nil }
