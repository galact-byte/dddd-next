package pocmap

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleMapping = `Liferay:
  type:
    - root
  pocs:
    - liferay-portal
    - CVE-2020-7961
Shiro:
  type:
    - base
  pocs:
    - shiro-detect
General-Poc-Log4j2:
  type:
    - root
  pocs:
    - CVE-2021-44228
    - CVE-2021-45046
General-Poc-Leak:
  type:
    - root
  pocs:
    - CVE-2021-44228
    - git-config
`

func writeMapping(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "mapping.yaml")
	if err := os.WriteFile(path, []byte(sampleMapping), 0o644); err != nil {
		t.Fatalf("write mapping: %v", err)
	}
	return path
}

func touchPOCs(t *testing.T, dir string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n+".yaml"), []byte("id: "+n+"\n"), 0o644); err != nil {
			t.Fatalf("touch %s: %v", n, err)
		}
	}
}

func TestLoadSplitsGeneralAndDedupes(t *testing.T) {
	m, err := Load(writeMapping(t, t.TempDir()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := m.Products(); got != 2 {
		t.Errorf("Products() = %d, want 2", got)
	}
	// CVE-2021-44228 sits under both General-Poc entries → collapses to one.
	if got := m.GeneralPocs(); len(got) != 3 {
		t.Errorf("GeneralPocs() = %v, want 3 unique", got)
	}
}

func TestResolveMatchesProductAndGeneral(t *testing.T) {
	dir := t.TempDir()
	path := writeMapping(t, dir)
	pocDir := filepath.Join(dir, "legacy")
	// CVE-2020-7961 left uncreated → must be skipped as missing.
	touchPOCs(t, pocDir, "liferay-portal", "CVE-2021-44228", "CVE-2021-45046", "git-config")

	m, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out, stats := m.Resolve(map[string][]string{
		"http://a": {"Liferay"},
		"http://b": {"Unknown-Product"},
	}, pocDir, true)

	if got := out["http://a"]; len(got) != 4 {
		t.Errorf("target a = %v, want 4 (liferay-portal + 3 general)", got)
	}
	if got := out["http://b"]; len(got) != 3 {
		t.Errorf("target b = %v, want 3 (general only)", got)
	}
	if stats.UnknownNames != 1 {
		t.Errorf("UnknownNames = %d, want 1", stats.UnknownNames)
	}
	if stats.MissingFiles == 0 {
		t.Error("MissingFiles = 0, want >0 (CVE-2020-7961 absent)")
	}
}

func TestResolveWithoutGeneral(t *testing.T) {
	dir := t.TempDir()
	path := writeMapping(t, dir)
	pocDir := filepath.Join(dir, "legacy")
	touchPOCs(t, pocDir, "liferay-portal")

	m, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out, _ := m.Resolve(map[string][]string{"http://a": {"Liferay"}}, pocDir, false)
	if got := out["http://a"]; len(got) != 1 {
		t.Errorf("target a = %v, want only liferay-portal", got)
	}
}

func TestUnionDeduplicates(t *testing.T) {
	all := Union(map[string][]string{
		"a": {"/p/x.yaml", "/p/y.yaml"},
		"b": {"/p/y.yaml", "/p/z.yaml"},
	})
	if len(all) != 3 {
		t.Errorf("Union = %v, want 3 unique", all)
	}
}
