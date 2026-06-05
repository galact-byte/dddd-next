package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseArgsTargets(t *testing.T) {
	cfg, err := ParseArgs([]string{"dddd-next", "-t", "192.168.1.1", "-t", "example.com"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if len(cfg.Targets) != 2 {
		t.Fatalf("Targets len = %d, want 2 (%v)", len(cfg.Targets), cfg.Targets)
	}
	if cfg.Targets[0] != "192.168.1.1" || cfg.Targets[1] != "example.com" {
		t.Errorf("Targets = %v", cfg.Targets)
	}
}

func TestParseArgsDefaults(t *testing.T) {
	cfg, err := ParseArgs([]string{"dddd-next", "-t", "x"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if cfg.Output != "result.txt" {
		t.Errorf("Output default = %q", cfg.Output)
	}
	if cfg.OutputType != "text" {
		t.Errorf("OutputType default = %q", cfg.OutputType)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel default = %q", cfg.LogLevel)
	}
}

func TestParseArgsTargetsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	content := "1.1.1.1\nexample.com\n\n# comment\n2.2.2.2\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	cfg, err := ParseArgs([]string{"dddd-next", "-tf", path})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if len(cfg.Targets) != 3 {
		t.Errorf("Targets = %v", cfg.Targets)
	}
}

func TestSubcommand(t *testing.T) {
	for _, sub := range []string{"update", "version"} {
		t.Run(sub, func(t *testing.T) {
			cfg, err := ParseArgs([]string{"dddd-next", sub})
			if err != nil {
				t.Fatalf("ParseArgs: %v", err)
			}
			if cfg.Subcommand != sub {
				t.Errorf("Subcommand = %q, want %q", cfg.Subcommand, sub)
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("subcommands should skip validation: %v", err)
			}
		})
	}
}

func TestValidateNoTargets(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err == nil {
		t.Error("expected validation error for empty targets")
	}
}

func TestValidateBadOutputType(t *testing.T) {
	cfg := Defaults()
	cfg.Targets = []string{"x"}
	cfg.OutputType = "xml"
	if err := cfg.Validate(); err == nil {
		t.Error("expected validation error for xml output type")
	}
}

func TestValidateBadLogLevel(t *testing.T) {
	cfg := Defaults()
	cfg.Targets = []string{"x"}
	cfg.LogLevel = "trace"
	if err := cfg.Validate(); err == nil {
		t.Error("expected validation error for invalid log level")
	}
}

func TestLoadDotEnvParses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "# comment\n\nDDDD_DOTENV_A=hello\nDDDD_DOTENV_B=\"quoted value\"\nDDDD_DOTENV_C =  spaced \n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, k := range []string{"DDDD_DOTENV_A", "DDDD_DOTENV_B", "DDDD_DOTENV_C"} {
		os.Unsetenv(k)
		defer os.Unsetenv(k)
	}
	if err := LoadDotEnv(path); err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	if v := os.Getenv("DDDD_DOTENV_A"); v != "hello" {
		t.Errorf("A = %q, want hello", v)
	}
	if v := os.Getenv("DDDD_DOTENV_B"); v != "quoted value" {
		t.Errorf("B = %q, want 'quoted value'", v)
	}
	if v := os.Getenv("DDDD_DOTENV_C"); v != "spaced" {
		t.Errorf("C = %q, want spaced", v)
	}
}

func TestLoadDotEnvEnvWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("DDDD_DOTENV_WIN=fromfile\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("DDDD_DOTENV_WIN", "fromenv")
	if err := LoadDotEnv(path); err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	if v := os.Getenv("DDDD_DOTENV_WIN"); v != "fromenv" {
		t.Errorf("explicit env must win: got %q, want fromenv", v)
	}
}

func TestLoadDotEnvMissingFileOK(t *testing.T) {
	if err := LoadDotEnv(filepath.Join(t.TempDir(), "nope.env")); err != nil {
		t.Errorf("missing file should be a no-op, got %v", err)
	}
}
