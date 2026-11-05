package nuclei

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	nucleiconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

// A subprocess is required because the SDK reads configuration in package init.
func TestSDKConfigIsolation(t *testing.T) {
	if os.Getenv("DDDD_ISOLATION_HELPER") == "1" {
		root, err := os.UserConfigDir()
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(root, "dddd-next", "nuclei")
		if got := nucleiconfig.DefaultConfig.GetConfigDir(); got != want {
			t.Fatalf("SDK config directory = %q, want %q", got, want)
		}
		if os.Getenv("DDDD_ISOLATION_CASE") == "blocked-ignore-file" {
			opts := DefaultOptions()
			opts.TemplatesDir = filepath.Join(root, "selected-templates")
			if scanner, err := New(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "prepare ignore file") {
				if scanner != nil {
					_ = scanner.Close()
				}
				t.Fatalf("blocked ignore file: %v", err)
			}
			return
		}
		if err := ensureIgnoreFile(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(want, ".nuclei-ignore"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "external-tag") {
			t.Fatal("inherited standalone Nuclei ignore tags")
		}
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"existing", "missing", "invalid", "inherited-directory", "private-ignore", "blocked-private-directory", "blocked-ignore-file", "missing-user-config-root"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			configRoot := root
			if runtime.GOOS == "darwin" {
				configRoot = filepath.Join(root, "Library", "Application Support")
			}
			standalone := filepath.Join(configRoot, "nuclei")
			external := filepath.Join(root, "external-config")
			private := filepath.Join(configRoot, "dddd-next", "nuclei")
			preserved := make(map[string][]byte)
			write := func(path, content string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				preserved[path] = []byte(content)
			}
			if name != "missing" {
				config := `{"nuclei-templates-directory":"standalone-templates","nuclei-templates-version":"v1.0.0"}`
				if name == "invalid" {
					config = "invalid JSON sentinel\n"
				}
				write(filepath.Join(standalone, ".templates-config.json"), config)
				write(filepath.Join(standalone, ".nuclei-ignore"), "tags: [external-tag]\nfiles: []\n")
			}
			if name == "private-ignore" {
				write(filepath.Join(private, ".nuclei-ignore"), "tags: [private-tag]\nfiles: []\n")
			}
			if name == "blocked-private-directory" {
				write(filepath.Join(configRoot, "dddd-next"), "blocked directory sentinel\n")
			}
			if name == "blocked-ignore-file" {
				if err := os.MkdirAll(filepath.Join(private, ".nuclei-ignore"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			env := map[string]string{
				"DDDD_ISOLATION_HELPER": "1",
				"DDDD_ISOLATION_CASE":   name,
				"NUCLEI_CONFIG_DIR":     "",
			}
			for _, key := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"} {
				env[key] = root
			}
			if name == "missing-user-config-root" {
				for _, key := range []string{"HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME"} {
					env[key] = ""
				}
			}
			if name == "inherited-directory" {
				write(filepath.Join(external, ".templates-config.json"), `{"nuclei-templates-directory":"external-templates"}`)
				write(filepath.Join(external, ".nuclei-ignore"), "tags: [external-tag]\nfiles: []\n")
				env["NUCLEI_CONFIG_DIR"] = external
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestSDKConfigIsolation$", "-test.count=1")
			cmd.Env = isolationEnv(env)
			cmd.Dir = root
			output, err := cmd.CombinedOutput()
			if name == "blocked-private-directory" || name == "missing-user-config-root" {
				if err == nil || !strings.Contains(string(output), "nuclei configuration") {
					t.Errorf("blocked configuration: error=%v, output=%s", err, output)
				}
			} else if err != nil {
				t.Errorf("isolated SDK process: %v\n%s", err, output)
			}
			for path, want := range preserved {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("configuration changed at %s: %q, %v", path, got, err)
				}
			}
			if name == "missing" {
				if _, err := os.Stat(standalone); !os.IsNotExist(err) {
					t.Errorf("standalone Nuclei directory was created: %v", err)
				}
			}
		})
	}
}

func isolationEnv(overrides map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[strings.ToUpper(key)]; !replaced {
			env = append(env, entry)
		}
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	return env
}
