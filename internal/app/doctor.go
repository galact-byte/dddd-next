package app

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"dddd-next/internal/config"
	"dddd-next/internal/fingerprint"
	"dddd-next/internal/scanner/nuclei"
	"dddd-next/internal/scanner/pocmap"
)

type RuleReport struct {
	Rules     int
	Templates int
	Problems  []string
}

// CheckRules checks the rules and templates used by precise mode. It neither
// creates configuration nor compiles protocols that could execute init scripts.
func CheckRules(ctx context.Context, cfg config.Config, configDir string) RuleReport {
	var report RuleReport
	if ctx.Err() != nil {
		report.Problems = append(report.Problems, ctx.Err().Error())
		return report
	}
	fingerPath := configuredPath(cfg.FingerConfigFilePath, filepath.Join(configDir, "fingers", "finger.yaml"))
	_, stats, err := fingerprint.LoadYAML(fingerPath)
	report.Rules = stats.Compiled
	if err != nil {
		report.Problems = append(report.Problems, err.Error())
	} else {
		if stats.Total == 0 {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: no fingerprint rules", fingerPath))
		}
		if stats.Failed > 0 {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: %d invalid DSL rule(s)", fingerPath, stats.Failed))
		}
		for _, failure := range stats.Failures {
			report.Problems = append(report.Problems, fmt.Sprintf("%s [%s]: %v", fingerPath, failure.Name, failure.Err))
		}
	}
	p := &Pipeline{cfg: cfg, configDir: configDir}
	mapping, err := pocmap.Load(p.workflowYamlPath())
	if err != nil {
		report.Problems = append(report.Problems, err.Error())
		return report
	}
	names := mapping.POCNames()
	if len(names) == 0 {
		report.Problems = append(report.Problems, fmt.Sprintf("%s: no mapped POCs", p.workflowYamlPath()))
	}
	root := p.nucleiTemplateDir()
	index := make(map[string]string)
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".yaml") {
			name := strings.ToLower(strings.TrimSuffix(d.Name(), ".yaml"))
			if _, exists := index[name]; !exists {
				index[name] = path
			}
		}
		return nil
	})
	if walkErr != nil && !os.IsNotExist(walkErr) {
		report.Problems = append(report.Problems, fmt.Sprintf("%s: %v", root, walkErr))
	}
	for _, name := range names {
		if ctx.Err() != nil {
			report.Problems = append(report.Problems, ctx.Err().Error())
			break
		}
		file, ok := index[strings.ToLower(name)]
		templateRoot := root
		if !ok {
			templateRoot = p.legacyPOCDir()
			file = filepath.Join(templateRoot, name+".yaml")
		}
		if err := nuclei.ValidateTemplate(file, templateRoot); err != nil {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		report.Templates++
	}
	return report
}
