package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dddd-next/internal/config"
)

func TestNucleiModesUseSelectedTemplateRoot(t *testing.T) {
	if root := os.Getenv("DDDD_TEMPLATE_ROOT_HELPER"); root != "" {
		runTemplateRootFixture(t, root)
		return
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<title>Isolation fixture</title>")
		if r.URL.Path == "/selected-root-payload" {
			fmt.Fprint(w, "isolation-positive-marker")
		}
	}))
	defer server.Close()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"precise", "poc", "full"} {
		for _, location := range []string{"default", "saved", "explicit", "legacy"} {
			if mode == "full" && location == "legacy" {
				continue
			}
			t.Run(mode+"/"+location, func(t *testing.T) {
				fixture := t.TempDir()
				configDir := filepath.Join(fixture, "configs")
				root := filepath.Join(configDir, "nuclei-templates")
				if location == "legacy" {
					root = filepath.Join(configDir, "pocs", "legacy")
				} else if location != "default" {
					root = filepath.Join(fixture, "selected-templates")
				}
				write := func(path, content string) {
					t.Helper()
					if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
				}
				write(filepath.Join(configDir, "fingers", "finger.yaml"), "Isolation-App:\n  - 'title=\"Isolation fixture\"'\n")
				write(filepath.Join(configDir, "pocs", "mapping.yaml"), "Isolation-App:\n  type: [root]\n  pocs: [isolation-positive]\n")
				write(filepath.Join(configDir, "dict", "shirokeys.txt"), "kPH+bIxk5D2deZiIxcaaaA==\n")
				templateDir, payload := filepath.Join(root, "http"), "helpers/isolation.txt"
				if location == "legacy" {
					templateDir, payload = root, `["selected-root-payload"]`
				} else {
					write(filepath.Join(root, "helpers", "isolation.txt"), "selected-root-payload\n")
				}
				for _, tc := range []struct{ id, marker string }{
					{"isolation-positive", "isolation-positive-marker"},
					{"isolation-negative", "isolation-absent-marker"},
				} {
					write(filepath.Join(templateDir, tc.id+".yaml"), fmt.Sprintf(`id: %s
info:
  name: Local template root fixture
  author: dddd-next
  severity: info
  tags: isolation
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{word}}"
    payloads:
      word: %s
    matchers:
      - type: word
        words: ["%s"]
`, tc.id, payload, tc.marker))
				}
				// The SDK retains template handles on Windows; the parent owns the
				// fixture so cleanup happens after the real scanning process exits.
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, "-test.run=^TestNucleiModesUseSelectedTemplateRoot$", "-test.count=1")
				cmd.Env = append(os.Environ(), "DDDD_TEMPLATE_ROOT_HELPER="+fixture,
					"DDDD_TEMPLATE_ROOT_MODE="+mode, "DDDD_TEMPLATE_ROOT_LOCATION="+location,
					"DDDD_TEMPLATE_ROOT_TARGET="+server.URL)
				for _, key := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"} {
					cmd.Env = append(cmd.Env, key+"="+filepath.Join(fixture, "user"))
				}
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("scan process: %v\n%s", err, output)
				}
			})
		}
	}
}

func runTemplateRootFixture(t *testing.T, fixture string) {
	t.Helper()
	configDir := filepath.Join(fixture, "configs")
	cfg := config.Defaults()
	cfg.Targets = []string{os.Getenv("DDDD_TEMPLATE_ROOT_TARGET")}
	cfg.SkipDir, cfg.NoHostBind, cfg.NoBrute, cfg.NoInteractsh = true, true, true, true
	cfg.DisableGeneralPoc = true
	cfg.OutputType, cfg.Output = "json", filepath.Join(fixture, "result.json")
	cfg.HTMLOutput = ""
	location := os.Getenv("DDDD_TEMPLATE_ROOT_LOCATION")
	if location != "default" && location != "legacy" {
		cfg.SavedNucleiTemplateDir = filepath.Join(fixture, "selected-templates")
	}
	if location == "explicit" {
		cfg.SavedNucleiTemplateDir = filepath.Join(fixture, "unused-saved-templates")
		cfg.NucleiTemplateDir = filepath.Join(fixture, "selected-templates")
	}
	mode := os.Getenv("DDDD_TEMPLATE_ROOT_MODE")
	cfg.FullScan = mode == "full"
	if mode == "poc" {
		cfg.PocName = "isolation"
	}
	pipeline, err := New(cfg, configDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runErr := pipeline.Run(ctx)
	closeErr := pipeline.Close()
	if runErr != nil || closeErr != nil {
		t.Fatalf("run: %v; close: %v", runErr, closeErr)
	}
	data, err := os.ReadFile(cfg.Output)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var record struct {
			Kind    string              `json:"kind"`
			Finding struct{ ID string } `json:"finding"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.Kind == "finding" {
			ids = append(ids, record.Finding.ID)
		}
	}
	if len(ids) != 1 || ids[0] != "isolation-positive" {
		t.Fatalf("findings = %v, want only isolation-positive\n%s", ids, data)
	}
}
