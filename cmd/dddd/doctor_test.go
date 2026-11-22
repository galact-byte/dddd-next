package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDoctorCLIWithoutTargets(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"fingers/finger.yaml": "Demo:\n  - 'body=\"fixture\"'\n",
		"pocs/mapping.yaml":   "Demo:\n  pocs: [demo]\n",
		"pocs/legacy/demo.yaml": `id: demo
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
	if code := runCLI([]string{"dddd", "doctor", "-config-dir", root}); code != 0 {
		t.Fatalf("valid doctor exit=%d", code)
	}
	if err := os.Remove(filepath.Join(root, "pocs/legacy/demo.yaml")); err != nil {
		t.Fatal(err)
	}
	if code := runCLI([]string{"dddd", "doctor", "-config-dir", root}); code != 1 {
		t.Fatalf("missing template exit=%d", code)
	}
	missing := filepath.Join(root, "must-not-create")
	if code := runCLI([]string{"dddd", "doctor", "-config-dir", missing}); code != 1 {
		t.Fatalf("missing config exit=%d", code)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("doctor modified config root: %v", err)
	}
	if code := runCLI([]string{"dddd", "doctor", "--help"}); code != 0 {
		t.Fatalf("help exit=%d", code)
	}
	if code := runCLI([]string{"dddd", "doctor", "-unknown"}); code != 2 {
		t.Fatalf("invalid args exit=%d", code)
	}
}
