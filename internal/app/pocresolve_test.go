package app

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"dddd-next/internal/config"
)

// TestFreshTemplateIndexPrefersUpdated verifies precise mode can locate a
// maintained template nested under nuclei-templates/ by lowercased basename —
// the mechanism that lets `dddd update` override the frozen legacy/ copy
// (e.g. the req-condition-broken CVE-2021-29441).
func TestFreshTemplateIndexPrefersUpdated(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nuclei-templates", "http", "cves", "2021")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(nested, "CVE-2021-29441.yaml")
	if err := os.WriteFile(want, []byte("id: CVE-2021-29441\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &Pipeline{configDir: dir}
	idx := p.freshTemplateIndex()

	got, ok := idx["cve-2021-29441"] // mapping name lowercased
	if !ok {
		t.Fatalf("index missing cve-2021-29441; keys=%v", keysOf(idx))
	}
	if got != want {
		t.Fatalf("path mismatch: want %s, got %s", want, got)
	}

	// Index is cached: a second call returns the same map without rewalking.
	if &idx == nil || p.freshTemplateIndex() == nil {
		t.Fatal("cached index should be non-nil")
	}
}

// TestFreshTemplateIndexMissingDir confirms precise mode degrades to
// legacy-only (empty index, no panic) when `dddd update` was never run.
func TestFreshTemplateIndexMissingDir(t *testing.T) {
	p := &Pipeline{configDir: t.TempDir()} // no nuclei-templates/ inside
	if got := p.freshTemplateIndex(); len(got) != 0 {
		t.Fatalf("expected empty index for missing dir, got %d entries", len(got))
	}
}

func TestResolvePOCTargetsHonorsNacosRootType(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pocs", "legacy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pocs", "mapping.yaml"), []byte(`Alibaba-Nacos:
  type:
    - root
    - dir
  pocs:
    - CVE-2021-29442
`), 0o644); err != nil {
		t.Fatal(err)
	}
	wantPOC := filepath.Join(dir, "pocs", "legacy", "CVE-2021-29442.yaml")
	if err := os.WriteFile(wantPOC, []byte("id: CVE-2021-29442\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &Pipeline{configDir: dir}
	got := p.resolvePOCTargets(map[string][]string{
		"http://nacos.local/nacos/": {"Alibaba-Nacos"},
	})

	if _, ok := got["http://nacos.local"]; !ok {
		t.Fatalf("root target missing for Nacos path hit; got %v", keysOfTargetPOCs(got))
	}
	if _, ok := got["http://nacos.local/nacos/"]; ok {
		t.Fatalf("base path target should not be used without base type; got %v", keysOfTargetPOCs(got))
	}
	if paths := got["http://nacos.local"]; len(paths) != 1 || paths[0] != wantPOC {
		t.Fatalf("root POCs = %v, want [%s]", paths, wantPOC)
	}
}

func TestResolvePOCTargetsUsesConfiguredWorkflowAndTemplateDir(t *testing.T) {
	dir := t.TempDir()
	templateDir := filepath.Join(dir, "custom-pocs")
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workflowPath := filepath.Join(dir, "custom-workflow.yaml")
	if err := os.WriteFile(workflowPath, []byte(`Alibaba-Nacos:
  type:
    - root
  pocs:
    - CVE-2021-29441
`), 0o644); err != nil {
		t.Fatal(err)
	}
	wantPOC := filepath.Join(templateDir, "CVE-2021-29441.yaml")
	if err := os.WriteFile(wantPOC, []byte("id: CVE-2021-29441\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &Pipeline{
		configDir: filepath.Join(dir, "unused-default-config"),
		cfg: config.Config{
			WorkflowYamlPath:  workflowPath,
			NucleiTemplateDir: templateDir,
		},
	}
	got := p.resolvePOCTargets(map[string][]string{
		"http://nacos.local/nacos/": {"Alibaba-Nacos"},
	})

	if paths := got["http://nacos.local"]; len(paths) != 1 || paths[0] != wantPOC {
		t.Fatalf("custom workflow/template result = %v, want [%s]", paths, wantPOC)
	}
}

func TestResolvePOCsByQueryDoesNotRequireFingerprintMapping(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nuclei-templates", "http", "cves", "2021")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(nested, "CVE-2021-29441.yaml")
	if err := os.WriteFile(want, []byte("id: CVE-2021-29441\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &Pipeline{configDir: dir}
	got := p.resolvePOCsByQuery("29441")

	if len(got) != 1 || got[0] != want {
		t.Fatalf("resolvePOCsByQuery = %v, want [%s]", got, want)
	}
}

func TestDirectPOCTargetsUseWebRoots(t *testing.T) {
	got := directPOCTargets([]string{
		"http://nacos.local:8848",
		"http://nacos.local:8848/nacos/",
		"https://app.local/admin/",
	})
	want := []string{"http://nacos.local:8848", "https://app.local"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("directPOCTargets = %v, want %v", got, want)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfTargetPOCs(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
