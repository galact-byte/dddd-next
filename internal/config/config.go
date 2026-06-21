package config

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

type Config struct {
	Targets     []string
	TargetsFile string

	Output     string
	OutputType string
	HTMLOutput string
	AuditLog   bool

	Subdomain          bool
	NoSubBrute         bool
	NoPassiveSubfinder bool
	ProxyURL           string

	PingFirst         bool
	TCPPing           bool
	SkipHostDiscovery bool
	NoICMPPing        bool
	SkipCDN           bool
	AllowCDN          bool
	SkipDir           bool
	NoHostBind        bool
	Ports             string
	ExcludePorts      string
	PortsThreshold    int

	OnlyIPPort           bool
	AllowLocalAreaDomain bool
	LowPerception        bool
	ReconLimit           int
	ReconAgents          []string
	HunterPageSize       int
	HunterMaxPages       int

	FullScan          bool
	DisableGeneralPoc bool

	Severity        []string
	ExcludeSeverity []string
	Tags            []string
	ExcludeTags     []string

	NoBrute      bool
	NoPoc        bool
	NoGoPoc      bool
	NoInteractsh bool

	CustomCreds     []string
	CustomCredsFile string

	PocName string

	InteractshServer string
	InteractshToken  string

	ProxyTest    bool
	ProxyTestURL string

	ScanType              string
	SYNScanRate           int
	TCPPortScanThreads    int
	PortScanTimeout       int
	ServiceDetectThreads  int
	ServiceDetectTimeout  int
	SubdomainBruteThreads int
	WebThreads            int
	WebTimeout            int
	GoPocThreads          int

	LogLevel     string
	AuditLogFile string

	APIConfigFilePath     string
	NucleiTemplateDir     string
	WorkflowYamlPath      string
	FingerConfigFilePath  string
	DirSearchYaml         string
	SubdomainWordListFile string
	MasscanPath           string

	Subcommand string
}

func Defaults() Config {
	return Config{
		Output:                "result.txt",
		OutputType:            "text",
		HTMLOutput:            "report.html",
		PortsThreshold:        300,
		ProxyTest:             false,
		ProxyTestURL:          "https://www.baidu.com",
		ScanType:              "tcp",
		SYNScanRate:           10000,
		TCPPortScanThreads:    1000,
		PortScanTimeout:       6,
		ServiceDetectThreads:  500,
		ServiceDetectTimeout:  5,
		SubdomainBruteThreads: 150,
		WebThreads:            200,
		WebTimeout:            10,
		GoPocThreads:          50,
		LogLevel:              "info",
		AuditLogFile:          "audit.log",
		MasscanPath:           "masscan",
	}
}

func ParseArgs(args []string) (Config, error) {
	if len(args) == 0 {
		return Config{}, errors.New("config: args is empty (missing program name)")
	}

	cfg := Defaults()

	if len(args) > 1 {
		switch args[1] {
		case "update":
			cfg.Subcommand = "update"
			return cfg, nil
		case "version", "-v", "--version":
			cfg.Subcommand = "version"
			return cfg, nil
		}
	}

	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var targets stringList
	fs.Var(&targets, "t", "target (repeatable): IP / CIDR / Range / URL / Domain / search query")
	fs.Var(&targets, "target", "target (legacy long alias)")
	fs.StringVar(&cfg.TargetsFile, "tf", "", "file containing targets, one per line")

	fs.StringVar(&cfg.Output, "o", cfg.Output, "result output file")
	fs.StringVar(&cfg.Output, "output", cfg.Output, "result output file (legacy long alias)")
	fs.StringVar(&cfg.OutputType, "ot", cfg.OutputType, "output format: text | json")
	fs.StringVar(&cfg.OutputType, "output-type", cfg.OutputType, "output format: text | json (legacy long alias)")
	fs.StringVar(&cfg.HTMLOutput, "ho", cfg.HTMLOutput, "HTML report file (empty disables)")
	fs.StringVar(&cfg.HTMLOutput, "html-output", cfg.HTMLOutput, "HTML report file (legacy long alias)")
	fs.BoolVar(&cfg.AuditLog, "a", cfg.AuditLog, "enable audit log")

	fs.BoolVar(&cfg.Subdomain, "sd", cfg.Subdomain, "enumerate subdomains for domain targets")
	fs.BoolVar(&cfg.Subdomain, "subdomain", cfg.Subdomain, "enumerate subdomains (legacy long alias)")
	fs.BoolVar(&cfg.NoSubBrute, "nsb", cfg.NoSubBrute, "skip active subdomain brute-force")
	fs.BoolVar(&cfg.NoSubBrute, "no-subdomain-brute", cfg.NoSubBrute, "skip active subdomain brute-force (legacy long alias)")
	fs.BoolVar(&cfg.NoPassiveSubfinder, "ns", cfg.NoPassiveSubfinder, "skip passive subdomain enumeration (subfinder)")
	fs.BoolVar(&cfg.NoPassiveSubfinder, "no-subfinder", cfg.NoPassiveSubfinder, "skip passive subdomain enumeration (legacy long alias)")
	fs.StringVar(&cfg.ProxyURL, "proxy", cfg.ProxyURL, "HTTP/SOCKS5 proxy URL")

	fs.BoolVar(&cfg.PingFirst, "ping", cfg.PingFirst, "ICMP-ping first, only scan responding hosts")
	fs.BoolVar(&cfg.TCPPing, "tp", cfg.TCPPing, "TCP-connect liveness probe (use with or instead of -ping)")
	fs.BoolVar(&cfg.TCPPing, "tcp-ping", cfg.TCPPing, "TCP-connect liveness probe (legacy long alias)")
	fs.BoolVar(&cfg.SkipHostDiscovery, "Pn", cfg.SkipHostDiscovery, "disable host discovery (legacy compatibility)")
	fs.BoolVar(&cfg.NoICMPPing, "nip", cfg.NoICMPPing, "disable ICMP host discovery (legacy alias)")
	fs.BoolVar(&cfg.NoICMPPing, "no-icmp-ping", cfg.NoICMPPing, "disable ICMP host discovery (legacy long alias)")
	fs.BoolVar(&cfg.SkipCDN, "skip-cdn", cfg.SkipCDN, "skip CDN/WAF-fronted domains entirely")
	fs.BoolVar(&cfg.AllowCDN, "ac", cfg.AllowCDN, "allow scanning CDN assets (default: skip)")
	fs.BoolVar(&cfg.AllowCDN, "allow-cdn", cfg.AllowCDN, "allow scanning CDN assets (legacy long alias)")
	fs.BoolVar(&cfg.SkipDir, "no-dir", cfg.SkipDir, "skip product-path probing")
	fs.BoolVar(&cfg.SkipDir, "nd", cfg.SkipDir, "skip product-path probing (legacy alias)")
	fs.BoolVar(&cfg.NoHostBind, "nhb", cfg.NoHostBind, "disable domain-bound (vhost) asset probing")
	fs.BoolVar(&cfg.NoHostBind, "no-host-bind", cfg.NoHostBind, "disable domain-bound asset probing (legacy long alias)")
	fs.BoolVar(&cfg.OnlyIPPort, "oip", cfg.OnlyIPPort, "pull recon assets as IP:Port instead of Domain:Port")
	fs.BoolVar(&cfg.AllowLocalAreaDomain, "ld", cfg.AllowLocalAreaDomain, "keep recon assets resolving to LAN/private IPs")
	fs.BoolVar(&cfg.AllowLocalAreaDomain, "local-domain", cfg.AllowLocalAreaDomain, "keep recon assets resolving to LAN/private IPs (legacy long alias)")
	fs.BoolVar(&cfg.LowPerception, "lpm", cfg.LowPerception, "Hunter low-perception mode: fingerprint from Hunter's banner without probing")
	fs.BoolVar(&cfg.LowPerception, "low-perception-mode", cfg.LowPerception, "Hunter low-perception mode (legacy long alias)")
	fs.IntVar(&cfg.ReconLimit, "limit", cfg.ReconLimit, "max assets to pull per recon (fofa/hunter/quake) query (0 = 100)")
	fs.IntVar(&cfg.ReconLimit, "fmc", cfg.ReconLimit, "FOFA max result count (legacy alias)")
	fs.IntVar(&cfg.ReconLimit, "fofa-max-count", cfg.ReconLimit, "FOFA max result count (legacy long alias)")
	fs.IntVar(&cfg.ReconLimit, "qmc", cfg.ReconLimit, "Quake max result count (legacy alias)")
	fs.IntVar(&cfg.ReconLimit, "quake-max-count", cfg.ReconLimit, "Quake max result count (legacy long alias)")
	fs.IntVar(&cfg.HunterPageSize, "hps", cfg.HunterPageSize, "Hunter page size (legacy alias)")
	fs.IntVar(&cfg.HunterPageSize, "hunter-page-size", cfg.HunterPageSize, "Hunter page size (legacy long alias)")
	fs.IntVar(&cfg.HunterMaxPages, "hmpc", cfg.HunterMaxPages, "Hunter max page count (legacy alias)")
	fs.IntVar(&cfg.HunterMaxPages, "hunter-max-page-count", cfg.HunterMaxPages, "Hunter max page count (legacy long alias)")
	fs.StringVar(&cfg.Ports, "p", cfg.Ports, "port spec: \"80,443,8000-8100\" or \"all\" for 1-65535")
	fs.StringVar(&cfg.Ports, "port", cfg.Ports, "port spec (legacy long alias)")
	fs.StringVar(&cfg.ExcludePorts, "np", cfg.ExcludePorts, "exclude ports (comma-separated)")
	fs.StringVar(&cfg.ExcludePorts, "no-port", cfg.ExcludePorts, "exclude ports (legacy long alias)")
	fs.IntVar(&cfg.PortsThreshold, "pmc", cfg.PortsThreshold, "max open ports per IP before dropping it as firewalled")
	fs.IntVar(&cfg.PortsThreshold, "ports-max-count", cfg.PortsThreshold, "max open ports per IP (legacy long alias)")

	fs.BoolVar(&cfg.FullScan, "full", cfg.FullScan, "run all nuclei templates")
	fs.BoolVar(&cfg.DisableGeneralPoc, "no-general", cfg.DisableGeneralPoc, "skip General-Poc set in precise mode")
	fs.BoolVar(&cfg.DisableGeneralPoc, "dgp", cfg.DisableGeneralPoc, "skip General-Poc set in precise mode (legacy alias)")
	fs.BoolVar(&cfg.DisableGeneralPoc, "disable-general-poc", cfg.DisableGeneralPoc, "skip General-Poc set (legacy long alias)")

	var severity, excludeSeverity, tags, excludeTags, customCreds stringList
	fs.Var(&severity, "severity", "nuclei severity filter (repeatable)")
	fs.Var(&severity, "s", "nuclei severity filter (legacy alias)")
	fs.Var(&excludeSeverity, "exclude-severity", "exclude nuclei severities (repeatable)")
	fs.Var(&tags, "tags", "nuclei template tags (repeatable)")
	fs.Var(&excludeTags, "exclude-tags", "nuclei template tags to exclude (repeatable)")
	fs.Var(&excludeTags, "et", "nuclei template tags to exclude (legacy alias)")

	fs.BoolVar(&cfg.NoBrute, "no-brute", cfg.NoBrute, "skip weak-credential brute-force")
	fs.BoolVar(&cfg.NoBrute, "nb", cfg.NoBrute, "skip weak-credential brute-force (legacy alias)")
	fs.BoolVar(&cfg.NoPoc, "no-poc", cfg.NoPoc, "skip all POC/exploit checks")
	fs.BoolVar(&cfg.NoPoc, "npoc", cfg.NoPoc, "skip all POC/exploit checks (legacy alias)")
	fs.BoolVar(&cfg.NoGoPoc, "ngp", cfg.NoGoPoc, "skip gopocs only (nuclei+shiro still run)")
	fs.BoolVar(&cfg.NoGoPoc, "no-golang-poc", cfg.NoGoPoc, "skip gopocs only (legacy alias)")
	fs.BoolVar(&cfg.NoInteractsh, "ni", cfg.NoInteractsh, "disable interactsh OOB server")
	fs.BoolVar(&cfg.NoInteractsh, "no-interactsh", cfg.NoInteractsh, "disable interactsh OOB server (legacy long alias)")

	fs.Var(&customCreds, "up", "custom credential user:pass (repeatable)")
	fs.Var(&customCreds, "username-password", "custom credential user:pass (legacy long alias)")
	fs.StringVar(&cfg.CustomCredsFile, "upf", cfg.CustomCredsFile, "custom credential file (user:pass per line)")
	fs.StringVar(&cfg.CustomCredsFile, "username-password-file", cfg.CustomCredsFile, "custom credential file (legacy long alias)")

	fs.StringVar(&cfg.PocName, "poc", cfg.PocName, "fuzzy-match POC template by name/id")
	fs.StringVar(&cfg.PocName, "poc-name", cfg.PocName, "fuzzy-match POC template by name/id (legacy alias)")

	fs.StringVar(&cfg.InteractshServer, "iserver", cfg.InteractshServer, "custom interactsh server URL")
	fs.StringVar(&cfg.InteractshServer, "interactsh-server", cfg.InteractshServer, "custom interactsh server URL (legacy long alias)")
	fs.StringVar(&cfg.InteractshToken, "itoken", cfg.InteractshToken, "interactsh auth token")
	fs.StringVar(&cfg.InteractshToken, "interactsh-token", cfg.InteractshToken, "interactsh auth token (legacy long alias)")

	fs.BoolVar(&cfg.ProxyTest, "pt", cfg.ProxyTest, "test proxy before use")
	fs.BoolVar(&cfg.ProxyTest, "proxy-test", cfg.ProxyTest, "test proxy before use (legacy long alias)")
	fs.StringVar(&cfg.ProxyTestURL, "ptu", cfg.ProxyTestURL, "URL for proxy test")
	fs.StringVar(&cfg.ProxyTestURL, "proxy-test-url", cfg.ProxyTestURL, "URL for proxy test (legacy long alias)")

	fs.StringVar(&cfg.ScanType, "st", cfg.ScanType, "scan type: tcp (connect) | syn (requires npcap/admin)")
	fs.StringVar(&cfg.ScanType, "scan-type", cfg.ScanType, "scan type (legacy long alias)")
	fs.IntVar(&cfg.SYNScanRate, "sst", cfg.SYNScanRate, "SYN scan packet rate (default 10000)")
	fs.IntVar(&cfg.SYNScanRate, "syn-scan-threads", cfg.SYNScanRate, "SYN scan rate/threads (legacy long alias)")
	fs.IntVar(&cfg.TCPPortScanThreads, "tst", cfg.TCPPortScanThreads, "TCP port scan threads")
	fs.IntVar(&cfg.TCPPortScanThreads, "tcp-scan-threads", cfg.TCPPortScanThreads, "TCP port scan threads (legacy long alias)")
	fs.IntVar(&cfg.PortScanTimeout, "pst", cfg.PortScanTimeout, "TCP port scan timeout (seconds)")
	fs.IntVar(&cfg.PortScanTimeout, "port-scan-timeout", cfg.PortScanTimeout, "TCP port scan timeout (legacy long alias)")
	fs.IntVar(&cfg.ServiceDetectThreads, "tc", cfg.ServiceDetectThreads, "service detection threads")
	fs.IntVar(&cfg.ServiceDetectThreads, "nmap-threads", cfg.ServiceDetectThreads, "service detection threads (legacy long alias)")
	fs.IntVar(&cfg.ServiceDetectTimeout, "nto", cfg.ServiceDetectTimeout, "service detection timeout (seconds)")
	fs.IntVar(&cfg.ServiceDetectTimeout, "nmap-timeout", cfg.ServiceDetectTimeout, "service detection timeout (legacy long alias)")
	fs.IntVar(&cfg.SubdomainBruteThreads, "sbt", cfg.SubdomainBruteThreads, "subdomain brute-force threads")
	fs.IntVar(&cfg.SubdomainBruteThreads, "subdomain-brute-threads", cfg.SubdomainBruteThreads, "subdomain brute-force threads (legacy long alias)")
	fs.IntVar(&cfg.WebThreads, "wt", cfg.WebThreads, "Web probe threads")
	fs.IntVar(&cfg.WebThreads, "web-threads", cfg.WebThreads, "Web probe threads (legacy long alias)")
	fs.IntVar(&cfg.WebTimeout, "wto", cfg.WebTimeout, "Web probe timeout (seconds)")
	fs.IntVar(&cfg.WebTimeout, "web-timeout", cfg.WebTimeout, "Web probe timeout (legacy long alias)")
	fs.IntVar(&cfg.GoPocThreads, "gpt", cfg.GoPocThreads, "GoPoC threads")
	fs.IntVar(&cfg.GoPocThreads, "golang-poc-threads", cfg.GoPocThreads, "GoPoC threads (legacy long alias)")

	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug | info | warn | error")
	fs.StringVar(&cfg.AuditLogFile, "alf", cfg.AuditLogFile, "audit log filename")
	fs.StringVar(&cfg.AuditLogFile, "audit-log-filename", cfg.AuditLogFile, "audit log filename (legacy long alias)")

	fs.StringVar(&cfg.APIConfigFilePath, "acf", cfg.APIConfigFilePath, "API config file (legacy alias)")
	fs.StringVar(&cfg.APIConfigFilePath, "api-config-file", cfg.APIConfigFilePath, "API config file (legacy long alias)")
	fs.StringVar(&cfg.NucleiTemplateDir, "nt", cfg.NucleiTemplateDir, "nuclei/POC template directory (legacy alias)")
	fs.StringVar(&cfg.NucleiTemplateDir, "nuclei-template", cfg.NucleiTemplateDir, "nuclei/POC template directory (legacy long alias)")
	fs.StringVar(&cfg.WorkflowYamlPath, "wy", cfg.WorkflowYamlPath, "fingerprint-to-POC mapping yaml (legacy alias)")
	fs.StringVar(&cfg.WorkflowYamlPath, "workflow-yaml", cfg.WorkflowYamlPath, "fingerprint-to-POC mapping yaml (legacy long alias)")
	fs.StringVar(&cfg.FingerConfigFilePath, "fy", cfg.FingerConfigFilePath, "fingerprint yaml file (legacy alias)")
	fs.StringVar(&cfg.FingerConfigFilePath, "finger-yaml", cfg.FingerConfigFilePath, "fingerprint yaml file (legacy long alias)")
	fs.StringVar(&cfg.DirSearchYaml, "dy", cfg.DirSearchYaml, "product-path probe yaml file (legacy alias)")
	fs.StringVar(&cfg.DirSearchYaml, "dir-yaml", cfg.DirSearchYaml, "product-path probe yaml file (legacy long alias)")
	fs.StringVar(&cfg.SubdomainWordListFile, "swl", cfg.SubdomainWordListFile, "subdomain wordlist file (legacy alias)")
	fs.StringVar(&cfg.SubdomainWordListFile, "subdomain-word-list", cfg.SubdomainWordListFile, "subdomain wordlist file (legacy long alias)")
	fs.StringVar(&cfg.MasscanPath, "mp", cfg.MasscanPath, "masscan path (accepted for legacy compatibility)")
	fs.StringVar(&cfg.MasscanPath, "masscan-path", cfg.MasscanPath, "masscan path (legacy long alias)")

	var useHunter, useFofa, useQuake bool
	fs.BoolVar(&useHunter, "hunter", false, "query Hunter for recon assets (legacy compatibility)")
	fs.BoolVar(&useFofa, "fofa", false, "query FOFA for recon assets (legacy compatibility)")
	fs.BoolVar(&useQuake, "quake", false, "query Quake for recon assets (legacy compatibility)")

	if err := fs.Parse(args[1:]); err != nil {
		return cfg, fmt.Errorf("config: parse flags: %w", err)
	}

	if useHunter || useFofa || useQuake {
		if useFofa {
			cfg.ReconAgents = append(cfg.ReconAgents, "fofa")
		}
		if useHunter {
			cfg.ReconAgents = append(cfg.ReconAgents, "hunter")
		}
		if useQuake {
			cfg.ReconAgents = append(cfg.ReconAgents, "quake")
		}
	}

	cfg.Targets = append(cfg.Targets, targets...)
	cfg.Severity = append(cfg.Severity, severity...)
	cfg.ExcludeSeverity = append(cfg.ExcludeSeverity, excludeSeverity...)
	cfg.Tags = append(cfg.Tags, tags...)
	cfg.ExcludeTags = append(cfg.ExcludeTags, excludeTags...)
	cfg.CustomCreds = append(cfg.CustomCreds, customCreds...)

	if cfg.TargetsFile != "" {
		fileTargets, err := readLines(cfg.TargetsFile)
		if err != nil {
			return cfg, fmt.Errorf("config: read targets file: %w", err)
		}
		cfg.Targets = append(cfg.Targets, fileTargets...)
	}

	if cfg.CustomCredsFile != "" {
		fileCreds, err := readLines(cfg.CustomCredsFile)
		if err != nil {
			return cfg, fmt.Errorf("config: read custom creds file: %w", err)
		}
		cfg.CustomCreds = append(cfg.CustomCreds, fileCreds...)
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if c.Subcommand != "" {
		return nil
	}
	if len(c.Targets) == 0 {
		return errors.New("config: no targets supplied (-t or -tf required)")
	}
	switch c.OutputType {
	case "text", "json":
	default:
		return fmt.Errorf("config: invalid output type %q (want text|json)", c.OutputType)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: invalid log level %q", c.LogLevel)
	}
	return nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		_ = os.Setenv(key, val)
	}
	return scanner.Err()
}
