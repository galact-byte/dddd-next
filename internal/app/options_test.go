package app

import (
	"path/filepath"
	"reflect"
	"testing"

	"dddd-next/internal/config"
)

func TestShouldRunGoPocsHonorsSkipFlags(t *testing.T) {
	if !shouldRunGoPocs(config.Config{}) {
		t.Fatal("default config should run GoPoC checks")
	}
	for name, cfg := range map[string]config.Config{
		"no-brute": {NoBrute: true},
		"ngp":      {NoGoPoc: true},
		"no-poc":   {NoPoc: true},
		"poc":      {PocName: "CVE-2021-29441"},
	} {
		t.Run(name, func(t *testing.T) {
			if shouldRunGoPocs(cfg) {
				t.Fatalf("%s should disable GoPoC checks", name)
			}
		})
	}
}

func TestShouldRunShiroHonorsPOCControls(t *testing.T) {
	if !shouldRunShiro(config.Config{}) {
		t.Fatal("default config should run Shiro checks")
	}
	for name, cfg := range map[string]config.Config{
		"no-poc": {NoPoc: true},
		"poc":    {PocName: "CVE-2021-29441"},
	} {
		t.Run(name, func(t *testing.T) {
			if shouldRunShiro(cfg) {
				t.Fatalf("%s should disable Shiro checks", name)
			}
		})
	}
}

func TestBuildNucleiOptionsHonorsCLIControls(t *testing.T) {
	cfg := config.Config{
		ProxyURL:         "http://127.0.0.1:7890",
		Severity:         []string{"critical", "high"},
		ExcludeSeverity:  []string{"info"},
		Tags:             []string{"rce"},
		ExcludeTags:      []string{"dos"},
		NoInteractsh:     true,
		InteractshServer: "https://oob.example",
		InteractshToken:  "token-1",
	}

	opts := buildNucleiOptions(cfg)

	if !reflect.DeepEqual(opts.Proxy, []string{"http://127.0.0.1:7890"}) {
		t.Fatalf("Proxy = %v", opts.Proxy)
	}
	if opts.Severities != "critical,high" {
		t.Fatalf("Severities = %q", opts.Severities)
	}
	if opts.ExcludeSeverities != "info" {
		t.Fatalf("ExcludeSeverities = %q", opts.ExcludeSeverities)
	}
	if !reflect.DeepEqual(opts.Tags, []string{"rce"}) {
		t.Fatalf("Tags = %v", opts.Tags)
	}
	if !reflect.DeepEqual(opts.ExcludeTags, []string{"dos"}) {
		t.Fatalf("ExcludeTags = %v", opts.ExcludeTags)
	}
	if !opts.NoInteractsh || opts.InteractshServer != "https://oob.example" || opts.InteractshToken != "token-1" {
		t.Fatalf("interactsh options not propagated: %+v", opts)
	}
}

func TestBuildHTTPProbeOptionsHonorsWebFlags(t *testing.T) {
	cfg := config.Config{WebThreads: 17, WebTimeout: 9, ProxyURL: "socks5://127.0.0.1:1080"}

	opts := buildHTTPProbeOptions(cfg, []string{"example.com"}, nil)

	if opts.Threads != 17 {
		t.Fatalf("Threads = %d, want 17", opts.Threads)
	}
	if opts.TimeoutSeconds != 9 {
		t.Fatalf("TimeoutSeconds = %d, want 9", opts.TimeoutSeconds)
	}
	if opts.Proxy != "socks5://127.0.0.1:1080" {
		t.Fatalf("Proxy = %q", opts.Proxy)
	}
}

func TestBuildGoPocOptionsHonorsThreadsAndCreds(t *testing.T) {
	dir := filepath.Join("configs", "dict")
	cfg := config.Config{GoPocThreads: 11, CustomCreds: []string{"admin:admin"}}

	opts := buildGoPocOptions(cfg, dir)

	if opts.DictDir != dir {
		t.Fatalf("DictDir = %q, want %q", opts.DictDir, dir)
	}
	if opts.Threads != 11 {
		t.Fatalf("Threads = %d, want 11", opts.Threads)
	}
	if !reflect.DeepEqual(opts.CustomCreds, []string{"admin:admin"}) {
		t.Fatalf("CustomCreds = %v", opts.CustomCreds)
	}
}

func TestPassiveSubfinderAndCDNControls(t *testing.T) {
	if shouldRunPassiveSubfinder(config.Config{NoPassiveSubfinder: true}) {
		t.Fatal("-ns should disable passive subfinder")
	}
	if !shouldDropCDN(config.Config{SkipCDN: true}) {
		t.Fatal("-skip-cdn should drop CDN assets")
	}
	if shouldDropCDN(config.Config{SkipCDN: true, AllowCDN: true}) {
		t.Fatal("-ac should override -skip-cdn")
	}
}

func TestFilterPOCNamesByFuzzyName(t *testing.T) {
	names := []string{"nacos-default-token", "CVE-2021-29441", "springboot-env"}

	got := filterPOCNamesByQuery(names, "29441")

	if !reflect.DeepEqual(got, []string{"CVE-2021-29441"}) {
		t.Fatalf("filter by cve substring = %v", got)
	}

	got = filterPOCNamesByQuery(names, "NACOS")
	if !reflect.DeepEqual(got, []string{"nacos-default-token"}) {
		t.Fatalf("case-insensitive filter = %v", got)
	}
}
