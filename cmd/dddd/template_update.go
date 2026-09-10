package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"dddd-next/internal/config"
	"dddd-next/internal/updater"
)

func parseUpdateArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("dddd update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var dir string
	fs.StringVar(&dir, "nt", "", "template directory (remembered after successful update)")
	fs.StringVar(&dir, "nuclei-template", "", "template directory")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 0 {
		return "", fmt.Errorf("unexpected update argument: %s", fs.Arg(0))
	}
	var invalid bool
	fs.Visit(func(f *flag.Flag) {
		if strings.TrimSpace(f.Value.String()) == "" {
			invalid = true
		}
	})
	if invalid {
		return "", errors.New("template directory must not be empty")
	}
	return dir, nil
}

func applyTemplateSettings(cfg *config.Config) error {
	if strings.TrimSpace(cfg.NucleiTemplateDir) != "" || cfg.NoPoc {
		return nil
	}
	path, err := templateSettingsPath()
	if err != nil {
		return err
	}
	cfg.SavedNucleiTemplateDir, err = loadTemplateDir(path)
	return err
}

func templateSettingsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, appName, "templates.json"), nil
}

type templateSettings struct {
	Directory string `json:"directory"`
}

func loadTemplateDir(path string) (string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read template settings %s: %w", path, err)
	}
	var settings templateSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return "", fmt.Errorf("parse template settings %s: %w", path, err)
	}
	if !filepath.IsAbs(settings.Directory) {
		return "", fmt.Errorf("template settings %s must contain an absolute directory", path)
	}
	return settings.Directory, nil
}

func saveTemplateDir(path, dir string) error {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(templateSettings{Directory: absolute}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	// Write beside the destination so a failed write cannot truncate the saved choice.
	file, err := os.CreateTemp(filepath.Dir(path), ".templates-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func updateTemplates(ctx context.Context, explicit, configDir, settingsPath string, runner updater.GitRunner) error {
	dir := explicit
	if dir == "" {
		saved, err := loadTemplateDir(settingsPath)
		if err != nil {
			return err
		}
		dir = saved
	}
	sources := updater.DefaultSources(configDir)
	if dir != "" {
		absolute, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		sources[0].Dir = absolute
	}
	fmt.Printf("dddd-next update -> %s\n", sources[0].Dir)
	fmt.Println("(set HTTPS_PROXY if behind a restricted network)")
	u := updater.New(sources)
	if runner != nil {
		u.WithRunner(runner)
	}
	results := u.Update(ctx)
	fmt.Print(updater.Summary(results))
	for _, result := range results {
		if result.Action == updater.ActionFailed {
			return result.Err
		}
	}
	if explicit != "" {
		if err := saveTemplateDir(settingsPath, sources[0].Dir); err != nil {
			return fmt.Errorf("templates updated, but could not save directory: %w", err)
		}
		fmt.Printf("[*] remembered template directory: %s\n", sources[0].Dir)
	}
	return nil
}
