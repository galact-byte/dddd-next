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
	if cfg.HTMLOutput != "report.html" {
		t.Errorf("HTMLOutput default = %q", cfg.HTMLOutput)
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

func TestParseArgsNewFlags(t *testing.T) {
	cfg, err := ParseArgs([]string{"dddd", "-t", "1.1.1.1", "-severity", "critical", "-severity", "high", "-tags", "rce", "-exclude-tags", "dos", "-up", "admin:admin", "-no-brute", "-no-poc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Severity) != 2 || cfg.Severity[0] != "critical" || cfg.Severity[1] != "high" {
		t.Errorf("Severity = %v, want [critical high]", cfg.Severity)
	}
	if len(cfg.Tags) != 1 || cfg.Tags[0] != "rce" {
		t.Errorf("Tags = %v, want [rce]", cfg.Tags)
	}
	if len(cfg.ExcludeTags) != 1 || cfg.ExcludeTags[0] != "dos" {
		t.Errorf("ExcludeTags = %v, want [dos]", cfg.ExcludeTags)
	}
	if len(cfg.CustomCreds) != 1 || cfg.CustomCreds[0] != "admin:admin" {
		t.Errorf("CustomCreds = %v, want [admin:admin]", cfg.CustomCreds)
	}
	if !cfg.NoBrute {
		t.Error("NoBrute = false, want true")
	}
	if !cfg.NoPoc {
		t.Error("NoPoc = false, want true")
	}
}

func TestParseArgsLegacyAliases(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"dddd", "-t", "1.1.1.1",
		"-npoc", "-nb", "-dgp", "-nd",
		"-s", "critical,high",
		"-et", "dos,xss",
		"-poc-name", "29441",
		"-no-golang-poc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NoPoc || !cfg.NoBrute || !cfg.DisableGeneralPoc || !cfg.SkipDir || !cfg.NoGoPoc {
		t.Fatalf("legacy bool aliases not applied: %+v", cfg)
	}
	if len(cfg.Severity) != 1 || cfg.Severity[0] != "critical,high" {
		t.Fatalf("Severity = %v, want [critical,high]", cfg.Severity)
	}
	if len(cfg.ExcludeTags) != 1 || cfg.ExcludeTags[0] != "dos,xss" {
		t.Fatalf("ExcludeTags = %v, want [dos,xss]", cfg.ExcludeTags)
	}
	if cfg.PocName != "29441" {
		t.Fatalf("PocName = %q, want 29441", cfg.PocName)
	}
}

func TestParseArgsOriginalCompatibilityFlags(t *testing.T) {
	dir := t.TempDir()
	credsFile := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(credsFile, []byte("admin:admin\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseArgs([]string{
		"dddd",
		"-target", "1.1.1.1",
		"-port", "80,443",
		"-no-port", "22",
		"-ports-max-count", "9",
		"-scan-type", "tcp",
		"-tcp-scan-threads", "11",
		"-syn-scan-threads", "12",
		"-port-scan-timeout", "7",
		"-tcp-ping",
		"-Pn",
		"-no-icmp-ping",
		"-subdomain",
		"-no-subdomain-brute",
		"-no-subfinder",
		"-subdomain-brute-threads", "13",
		"-local-domain",
		"-allow-cdn",
		"-no-host-bind",
		"-web-threads", "14",
		"-web-timeout", "15",
		"-proxy-test",
		"-proxy-test-url", "http://proxy.test",
		"-output", "out.txt",
		"-output-type", "json",
		"-html-output", "report.html",
		"-disable-general-poc",
		"-exclude-tags", "dos,xss",
		"-severity", "critical,high",
		"-no-interactsh",
		"-interactsh-server", "http://is.example",
		"-interactsh-token", "tok",
		"-api-config-file", "api.yaml",
		"-nuclei-template", "custom-pocs",
		"-workflow-yaml", "workflow.yaml",
		"-finger-yaml", "finger.yaml",
		"-dir-yaml", "dir.yaml",
		"-subdomain-word-list", "subs.txt",
		"-username-password", "root:toor",
		"-username-password-file", credsFile,
		"-audit-log-filename", "audit2.log",
		"-fofa",
		"-fofa-max-count", "25",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Targets) != 1 || cfg.Targets[0] != "1.1.1.1" {
		t.Fatalf("Targets = %v, want [1.1.1.1]", cfg.Targets)
	}
	if cfg.Ports != "80,443" || cfg.ExcludePorts != "22" || cfg.PortsThreshold != 9 {
		t.Fatalf("port flags not applied: %+v", cfg)
	}
	if cfg.ScanType != "tcp" || cfg.TCPPortScanThreads != 11 || cfg.SYNScanRate != 12 || cfg.PortScanTimeout != 7 {
		t.Fatalf("scan tuning flags not applied: %+v", cfg)
	}
	if !cfg.TCPPing || !cfg.SkipHostDiscovery || !cfg.NoICMPPing {
		t.Fatalf("host discovery flags not applied: %+v", cfg)
	}
	if !cfg.Subdomain || !cfg.NoSubBrute || !cfg.NoPassiveSubfinder || cfg.SubdomainBruteThreads != 13 {
		t.Fatalf("subdomain flags not applied: %+v", cfg)
	}
	if !cfg.AllowLocalAreaDomain || !cfg.AllowCDN || !cfg.NoHostBind {
		t.Fatalf("asset control flags not applied: %+v", cfg)
	}
	if cfg.WebThreads != 14 || cfg.WebTimeout != 15 {
		t.Fatalf("web tuning flags not applied: %+v", cfg)
	}
	if !cfg.ProxyTest || cfg.ProxyTestURL != "http://proxy.test" {
		t.Fatalf("proxy test flags not applied: %+v", cfg)
	}
	if cfg.Output != "out.txt" || cfg.OutputType != "json" || cfg.HTMLOutput != "report.html" {
		t.Fatalf("output flags not applied: %+v", cfg)
	}
	if !cfg.DisableGeneralPoc || len(cfg.ExcludeTags) != 1 || cfg.ExcludeTags[0] != "dos,xss" || len(cfg.Severity) != 1 || cfg.Severity[0] != "critical,high" {
		t.Fatalf("poc filter flags not applied: %+v", cfg)
	}
	if !cfg.NoInteractsh || cfg.InteractshServer != "http://is.example" || cfg.InteractshToken != "tok" {
		t.Fatalf("interactsh flags not applied: %+v", cfg)
	}
	if cfg.APIConfigFilePath != "api.yaml" || cfg.NucleiTemplateDir != "custom-pocs" || cfg.WorkflowYamlPath != "workflow.yaml" || cfg.FingerConfigFilePath != "finger.yaml" || cfg.DirSearchYaml != "dir.yaml" || cfg.SubdomainWordListFile != "subs.txt" {
		t.Fatalf("config path flags not applied: %+v", cfg)
	}
	if len(cfg.CustomCreds) != 2 || cfg.CustomCreds[0] != "root:toor" || cfg.CustomCreds[1] != "admin:admin" {
		t.Fatalf("custom creds = %v, want [root:toor admin:admin]", cfg.CustomCreds)
	}
	if cfg.AuditLogFile != "audit2.log" {
		t.Fatalf("AuditLogFile = %q, want audit2.log", cfg.AuditLogFile)
	}
	if len(cfg.ReconAgents) != 1 || cfg.ReconAgents[0] != "fofa" || cfg.ReconLimit != 25 {
		t.Fatalf("recon compatibility flags not applied: %+v", cfg)
	}
}

func TestParseArgsCustomCredsFile(t *testing.T) {
	dir := t.TempDir()
	credsFile := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(credsFile, []byte("admin:admin\nroot:toor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseArgs([]string{"dddd", "-t", "1.1.1.1", "-upf", credsFile})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.CustomCreds) != 2 {
		t.Fatalf("CustomCreds = %v, want 2 items", cfg.CustomCreds)
	}
	if cfg.CustomCreds[0] != "admin:admin" || cfg.CustomCreds[1] != "root:toor" {
		t.Errorf("CustomCreds = %v, want [admin:admin root:toor]", cfg.CustomCreds)
	}
}
