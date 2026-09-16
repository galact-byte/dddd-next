package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestHelpListsEffectiveOptionsAndAliases(t *testing.T) {
	for _, args := range [][]string{
		{"dddd", "help"}, {"dddd", "-h"}, {"dddd", "--help"},
		{"dddd", "-t", "missing-target-file.txt", "--help"},
	} {
		code, stdout, stderr := captureHelpCLI(t, args)
		if code != 0 || stderr != "" {
			t.Fatalf("args = %v, code = %d, stderr = %q", args, code, stderr)
		}
		for _, group := range []string{
			"-t, -target", "-o, -output", "-ot, -output-type", "-ho, -html-output",
			"-a", "-alf, -audit-log-filename", "-sd, -subdomain",
			"-nsb, -no-subdomain-brute", "-ns, -no-subfinder", "-proxy",
			"-st, -scan-type", "-sst, -syn-scan-threads", "-p, -port", "-np, -no-port",
			"-pmc, -ports-max-count", "-ping", "-tp, -tcp-ping", "-Pn", "-nip, -no-icmp-ping",
			"-skip-cdn", "-ac, -allow-cdn", "-no-dir, -nd", "-nhb, -no-host-bind",
			"-oip", "-ld, -local-domain", "-lpm, -low-perception-mode",
			"-limit, -fmc, -fofa-max-count, -qmc, -quake-max-count",
			"-fofa", "-hunter", "-quake", "-hps, -hunter-page-size", "-hmpc, -hunter-max-page-count",
			"-nt, -nuclei-template", "-fy, -finger-yaml", "-wy, -workflow-yaml",
			"-dy, -dir-yaml", "-swl, -subdomain-word-list",
			"-full", "-no-general, -dgp, -disable-general-poc", "-severity, -s", "-exclude-severity",
			"-tags", "-exclude-tags, -et", "-poc, -poc-name",
			"-no-brute, -nb", "-no-poc, -npoc", "-ngp, -no-golang-poc", "-ni, -no-interactsh",
			"-iserver, -interactsh-server", "-itoken, -interactsh-token",
			"-up, -username-password", "-upf, -username-password-file",
			"-tst, -tcp-scan-threads", "-pst, -port-scan-timeout", "-tc, -nmap-threads",
			"-nto, -nmap-timeout", "-sbt, -subdomain-brute-threads", "-wt, -web-threads",
			"-wto, -web-timeout", "-gpt, -golang-poc-threads", "-pt, -proxy-test", "-ptu, -proxy-test-url",
		} {
			if !regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(group) + `(?:\s|$)`).MatchString(stdout) {
				t.Errorf("args = %v: missing option group %q", args, group)
			}
		}
		for _, hidden := range []string{"mp", "masscan-path", "acf", "api-config-file", "log-level"} {
			if regexp.MustCompile(`(?:^|\s)-` + hidden + `(?:\s|,|$)`).MatchString(stdout) {
				t.Errorf("help advertises ignored option -%s", hidden)
			}
		}
	}
}

func TestTemplateUpdateHelpDoesNotStartUpdate(t *testing.T) {
	for _, option := range []string{"-h", "--help"} {
		code, stderr := updateCLIError(t, []string{"dddd", "update", option})
		if code != 0 || !strings.Contains(stderr, "Usage: dddd update [-nt <template-directory>]") || !strings.Contains(stderr, "-nuclei-template") {
			t.Fatalf("code = %d, stderr = %q", code, stderr)
		}
	}
}

func captureHelpCLI(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	file, err := os.Create(filepath.Join(t.TempDir(), "stdout.txt"))
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = file
	defer func() {
		os.Stdout = previous
		file.Close()
	}()
	code, stderr := updateCLIError(t, args)
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, string(data), stderr
}

func TestScanWarnsForIgnoredOptions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		value    string
		guidance string
	}{
		{"mp", "private-masscan-path", "内置 SYN"},
		{"masscan-path", "private-masscan-path", "内置 SYN"},
		{"acf", "private-api-path", ".env"},
		{"api-config-file", "private-api-path", ".env"},
		{"log-level", "debug", "日志级别"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No target: stop at validation, before any scan or config writes.
			code, stderr := updateCLIError(t, []string{"dddd", "--" + tc.name + "=" + tc.value})
			if code != 2 || !strings.Contains(stderr, "no targets supplied") {
				t.Fatalf("code = %d, stderr = %q", code, stderr)
			}
			if !strings.Contains(stderr, "[warn]") || !strings.Contains(stderr, "-"+tc.name+" 已忽略") || !strings.Contains(stderr, tc.guidance) {
				t.Errorf("missing ignored-option guidance: %q", stderr)
			}
			if strings.Contains(stderr, tc.value) {
				t.Errorf("warning echoes option value: %q", stderr)
			}
		})
	}
}

func TestScanDoesNotWarnForDefaultsOrEffectiveAliases(t *testing.T) {
	for _, args := range [][]string{
		{"dddd"},
		{"dddd", "-Pn", "-nip", "-nb", "-fy", "custom.yaml", "-fofa", "-hps", "10"},
	} {
		code, stderr := updateCLIError(t, args)
		if code != 2 || !strings.Contains(stderr, "no targets supplied") || strings.Contains(stderr, "[warn]") {
			t.Fatalf("args = %v, code = %d, stderr = %q", args, code, stderr)
		}
	}
}
