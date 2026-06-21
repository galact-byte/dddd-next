package app

import (
	"strings"

	"dddd-next/internal/config"
	"dddd-next/internal/discovery/httpprobe"
	"dddd-next/internal/scanner/gopocs"
	"dddd-next/internal/scanner/nuclei"
)

func shouldRunGoPocs(cfg config.Config) bool {
	return !cfg.NoBrute && !cfg.NoGoPoc && !cfg.NoPoc && strings.TrimSpace(cfg.PocName) == ""
}

func shouldRunShiro(cfg config.Config) bool {
	return !cfg.NoPoc && strings.TrimSpace(cfg.PocName) == ""
}

func shouldRunPassiveSubfinder(cfg config.Config) bool {
	return !cfg.NoPassiveSubfinder
}

func shouldDropCDN(cfg config.Config) bool {
	return cfg.SkipCDN && !cfg.AllowCDN
}

func buildNucleiOptions(cfg config.Config) nuclei.Options {
	opts := nuclei.DefaultOptions()
	if cfg.ProxyURL != "" {
		opts.Proxy = []string{cfg.ProxyURL}
	}
	if len(cfg.Severity) > 0 {
		opts.Severities = strings.Join(cfg.Severity, ",")
	}
	if len(cfg.ExcludeSeverity) > 0 {
		opts.ExcludeSeverities = strings.Join(cfg.ExcludeSeverity, ",")
	}
	opts.Tags = append([]string(nil), cfg.Tags...)
	opts.ExcludeTags = append([]string(nil), cfg.ExcludeTags...)
	opts.NoInteractsh = cfg.NoInteractsh
	opts.InteractshServer = cfg.InteractshServer
	opts.InteractshToken = cfg.InteractshToken
	return opts
}

func buildHTTPProbeOptions(cfg config.Config, targets []string, requestPaths []string) httpprobe.Options {
	return httpprobe.Options{
		Targets:         targets,
		RequestPaths:    requestPaths,
		TechDetect:      true,
		FollowRedirects: true,
		Proxy:           cfg.ProxyURL,
		Threads:         cfg.WebThreads,
		TimeoutSeconds:  cfg.WebTimeout,
	}
}

func buildGoPocOptions(cfg config.Config, dictDir string) gopocs.Options {
	opts := gopocs.DefaultOptions(dictDir)
	if cfg.GoPocThreads > 0 {
		opts.Threads = cfg.GoPocThreads
	}
	opts.CustomCreds = append([]string(nil), cfg.CustomCreds...)
	return opts
}

func filterPOCNamesByQuery(names []string, query string) []string {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return names
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if strings.Contains(strings.ToLower(name), query) {
			out = append(out, name)
		}
	}
	return out
}
