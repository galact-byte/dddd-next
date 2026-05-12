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
