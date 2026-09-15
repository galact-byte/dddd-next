package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeRejectsScanAndTemplateArgumentsBeforeDoingWork(t *testing.T) {
	for _, args := range [][]string{{"-t", "example.com"}, {"--check", "-nt", "templates"}, {"unexpected"}, {"--check", "unexpected"}} {
		code, stderr := updateCLIError(t, append([]string{"dddd", "upgrade"}, args...))
		if code != 2 || !strings.Contains(stderr, "Usage: dddd upgrade [--check]") {
			t.Fatalf("args = %v, exit code = %d, stderr = %q", args, code, stderr)
		}
	}
}

func TestUpgradeCheckOption(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		check bool
	}{{nil, false}, {[]string{"--check"}, true}, {[]string{"-check"}, true}, {[]string{"--check=false"}, false}} {
		check, err := parseUpgradeArgs(tc.args)
		if err != nil || check != tc.check {
			t.Fatalf("args = %v, check = %v, err = %v", tc.args, check, err)
		}
	}
}

func TestTemplateUpdateKeepsArgumentValidation(t *testing.T) {
	code, stderr := updateCLIError(t, []string{"dddd", "update", "-nt"})
	if code != 2 || !strings.Contains(stderr, "Usage: dddd update [-nt <template-directory>]") {
		t.Fatalf("exit code = %d, stderr = %q; want template update usage error", code, stderr)
	}
}

func TestUpgradeHelpDoesNotAccessNetwork(t *testing.T) {
	code, stderr := updateCLIError(t, []string{"dddd", "upgrade", "--help"})
	if code != 0 || !strings.Contains(stderr, "Usage: dddd upgrade [--check]") {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
}

func updateCLIError(t *testing.T, args []string) (int, string) {
	t.Helper()
	file, err := os.Create(filepath.Join(t.TempDir(), "stderr.txt"))
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = file
	defer func() {
		os.Stderr = previous
		file.Close()
	}()
	code := runCLI(args)
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, string(data)
}
