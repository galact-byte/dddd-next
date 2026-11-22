package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"dddd-next/internal/config"
)

func TestCheckRulesUsesSameFirstTemplateAsScan(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"fingers/finger.yaml": "Demo:\n  - 'body=\"fixture\"'\n",
		"pocs/mapping.yaml":   "Demo:\n  pocs: [demo]\n",
		"nuclei-templates/a/demo.yaml": `id: demo
info:
  name: Demo
  author: test
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["fixture"]
`,
		"nuclei-templates/z/demo.yaml": "invalid yaml: [",
	}
	for name, data := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	report := CheckRules(context.Background(), config.Defaults(), root)
	if report.Templates != 1 || len(report.Problems) != 0 {
		t.Fatalf("doctor selected a different template than scan: %+v", report)
	}
}
