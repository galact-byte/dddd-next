package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseArgsTargetFileWindowsText(t *testing.T) {
	t.Chdir(t.TempDir())
	path := "目标 列表.txt"
	content := "\ufeff192.0.2.1\r\n\r\n # comment\r\n  example.com  \r\n192.0.2.2:8080 open\r\n[FP] http://192.0.2.3 | Nacos | confidence=90\r\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "example.com", "192.0.2.2:8080 open", "[FP] http://192.0.2.3 | Nacos | confidence=90"}
	for _, flag := range []string{"-t", "-target"} {
		t.Run(flag, func(t *testing.T) {
			cfg, err := ParseArgs([]string{"dddd", flag, path})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.Targets, want) {
				t.Fatalf("Targets = %q, want %q", cfg.Targets, want)
			}
		})
	}
}

func TestParseArgsMixedTargetsAndFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	for name, content := range map[string]string{
		"targets":     "example.com\n192.0.2.1\n",
		"more.txt":    "192.0.2.2\n",
		"example.com": "must-not-load-nested-files\n",
	} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	direct := []string{"https://example.test/a,b?q=1", "192.0.2.0/24", "192.0.2.5-192.0.2.9", "[::1]:80", `app="a/b" && title="x,y"`, "missing.test"}
	args := []string{"dddd", "-t", "targets"}
	for _, target := range direct {
		args = append(args, "-t", target)
	}
	args = append(args, "-t", "more.txt")
	cfg, err := ParseArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{"example.com", "192.0.2.1"}, direct...)
	want = append(want, "192.0.2.2")
	if !reflect.DeepEqual(cfg.Targets, want) {
		t.Fatalf("Targets = %q, want %q", cfg.Targets, want)
	}
}

func TestParseArgsTargetFileFailures(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("directory", 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"empty.txt": "# no targets\r\n\r\n", "oversized.txt": strings.Repeat("x", 70*1024)} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, flag := range []string{"-t", "-target"} {
		for _, path := range []string{"directory", "empty.txt", "oversized.txt"} {
			t.Run(flag+"/"+path, func(t *testing.T) {
				cfg, err := ParseArgs([]string{"dddd", flag, path})
				if err == nil {
					err = cfg.Validate()
				}
				if err == nil {
					t.Fatalf("invalid file input was accepted: %q", cfg.Targets)
				}
			})
		}
	}
}

func TestParseArgsRejectsRemovedTargetFileFlag(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("targets.txt", []byte("192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := ParseArgs([]string{"dddd", "-tf", "targets.txt"})
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined: -tf") {
		t.Fatalf("removed -tf flag must be rejected, got %v", err)
	}
}

func TestParseArgsLegacyTargetFile(t *testing.T) {
	t.Chdir(t.TempDir())
	want := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}
	if err := os.WriteFile("1.txt", []byte("192.0.2.1\r\n192.0.2.2\r\n192.0.2.3\r\n192.0.2.4\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs("1.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"-t", "-target"} {
		for _, path := range []string{"1.txt", absolute} {
			t.Run(flag+"/"+path, func(t *testing.T) {
				cfg, err := ParseArgs([]string{"dddd", flag, path, "-p", "1-65535"})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(cfg.Targets, want) {
					t.Fatalf("Targets = %q, want four IPs %q (file name must not reach DNS)", cfg.Targets, want)
				}
				if cfg.Ports != "1-65535" {
					t.Fatalf("Ports = %q", cfg.Ports)
				}
			})
		}
	}
}
