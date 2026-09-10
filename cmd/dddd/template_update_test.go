package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"dddd-next/internal/config"
)

func TestUpdateFlagsRejectUnknownAndAcceptTemplateDirectory(t *testing.T) {
	for _, args := range [][]string{{"-nt", "custom templates"}, {"-nuclei-template", "custom templates"}} {
		got, err := parseUpdateArgs(args)
		if err != nil || got != "custom templates" {
			t.Fatalf("got %q, %v", got, err)
		}
	}
	for _, args := range [][]string{{"-unknown"}, {"-nt"}, {"unexpected"}, {"-nt", " "}} {
		if _, err := parseUpdateArgs(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestUpdateRemembersDirectoryOnlyAfterSuccess(t *testing.T) {
	state := filepath.Join(t.TempDir(), "templates.json")
	baseline := t.TempDir()
	custom := filepath.Join(t.TempDir(), "custom templates")
	runner := &templateGit{}
	if err := updateTemplates(context.Background(), custom, baseline, state, runner); err != nil {
		t.Fatal(err)
	}
	if got, err := loadTemplateDir(state); err != nil || got != custom {
		t.Fatalf("saved = %q, %v", got, err)
	}
	runner.dirs = nil
	if err := updateTemplates(context.Background(), "", t.TempDir(), state, runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.dirs) == 0 || runner.dirs[0] != custom {
		t.Fatalf("subsequent update used %v", runner.dirs)
	}
	runner.fail = true
	if err := updateTemplates(context.Background(), filepath.Join(t.TempDir(), "failed"), baseline, state, runner); err == nil {
		t.Fatal("expected update failure")
	}
	if got, err := loadTemplateDir(state); err != nil || got != custom {
		t.Fatalf("failed update changed settings: %q, %v", got, err)
	}
	runner.fail = false
	replacement := filepath.Join(t.TempDir(), "replacement")
	if err := updateTemplates(context.Background(), replacement, baseline, state, runner); err != nil {
		t.Fatal(err)
	}
	if got, err := loadTemplateDir(state); err != nil || got != replacement {
		t.Fatalf("replacement = %q, %v", got, err)
	}
}

func TestUpdateDefaultAndRelativeDirectory(t *testing.T) {
	state := filepath.Join(t.TempDir(), "templates.json")
	baseline := t.TempDir()
	runner := &templateGit{}
	if err := updateTemplates(context.Background(), "", baseline, state, runner); err != nil {
		t.Fatal(err)
	}
	if runner.dirs[0] != filepath.Join(baseline, "nuclei-templates") {
		t.Fatalf("default = %v", runner.dirs)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("default should not persist: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "relative templates")
	relative, err := filepath.Rel(cwd, target)
	if err != nil {
		t.Skip("temp directory is on another drive")
	}
	if err := updateTemplates(context.Background(), relative, baseline, state, runner); err != nil {
		t.Fatal(err)
	}
	if got, err := loadTemplateDir(state); err != nil || got != target {
		t.Fatalf("relative saved = %q, %v", got, err)
	}
}

func TestScanLoadsSavedDirectoryAndExplicitOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("APPDATA", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HOME", home)
	path, err := templateSettingsPath()
	if err != nil {
		t.Fatal(err)
	}
	saved := t.TempDir()
	if err := saveTemplateDir(path, saved); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	if err := applyTemplateSettings(&cfg); err != nil || cfg.SavedNucleiTemplateDir != saved {
		t.Fatalf("scan settings = %q, %v", cfg.SavedNucleiTemplateDir, err)
	}
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg = config.Defaults()
	if err := applyTemplateSettings(&cfg); err == nil {
		t.Fatal("corrupt settings should be reported")
	}
	cfg.NucleiTemplateDir = "explicit"
	if err := applyTemplateSettings(&cfg); err != nil || cfg.NucleiTemplateDir != "explicit" {
		t.Fatalf("explicit override: %v", err)
	}
	cfg = config.Defaults()
	cfg.NoPoc = true
	if err := applyTemplateSettings(&cfg); err != nil {
		t.Fatalf("recon-only should not require template settings: %v", err)
	}
}

func TestUpdateReportsSettingsWriteFailure(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := updateTemplates(context.Background(), t.TempDir(), t.TempDir(), filepath.Join(parent, "templates.json"), &templateGit{}); err == nil {
		t.Fatal("expected settings write error")
	}
}

type templateGit struct {
	fail bool
	dirs []string
}

func (g *templateGit) Version(context.Context) (string, error) { return "git test", nil }
func (g *templateGit) Run(_ context.Context, dir string, args ...string) ([]byte, error) {
	if g.fail {
		return nil, errors.New("simulated git failure")
	}
	if args[0] == "clone" {
		dir = args[len(args)-1]
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0755); err != nil {
			return nil, err
		}
	}
	g.dirs = append(g.dirs, dir)
	return []byte("abc123"), nil
}

func TestRememberedTemplateDirectory(t *testing.T) {
	state := filepath.Join(t.TempDir(), "settings", "templates.json")
	if got, err := loadTemplateDir(state); err != nil || got != "" {
		t.Fatalf("missing settings: %q, %v", got, err)
	}
	dir := t.TempDir()
	if err := saveTemplateDir(state, dir); err != nil {
		t.Fatal(err)
	}
	if got, err := loadTemplateDir(state); err != nil || got != dir {
		t.Fatalf("saved settings: %q, %v", got, err)
	}
	if err := os.WriteFile(state, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTemplateDir(state); err == nil {
		t.Fatal("accepted corrupt settings")
	}
}
