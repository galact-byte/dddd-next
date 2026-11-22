package nuclei

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTemplateOffline(t *testing.T) {
	root := t.TempDir()
	valid := `id: local-check
info:
  name: Local check
  author: test
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["fixture"]
`
	for _, tc := range []struct {
		name, data string
		bad        bool
	}{
		{"valid", valid, false},
		{"syntax", valid + "unknown-field: true\n", true},
		{"matcher", strings.Replace(valid, "type: word", "type: invalid-matcher", 1), true},
		{"missing-name", strings.Replace(valid, "  name: Local check\n", "", 1), true},
		{"no-requests", strings.Split(valid, "http:")[0], true},
		{"inline-payload", strings.Replace(valid, "    matchers:", "    payloads:\n      word: |\n        one\n        two\n    matchers:", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(root, tc.name+".yaml")
			if err := os.WriteFile(file, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			err := ValidateTemplate(file, root)
			if (err != nil) != tc.bad {
				t.Fatalf("error=%v wantBad=%v", err, tc.bad)
			}
		})
	}
}

func TestValidateTemplatePayloadResources(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "payload.yaml")
	data := `id: payload-check
info:
  name: Payload
  author: test
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/{{word}}"]
    payloads:
      word: words.txt
    matchers:
      - type: word
        words: ["fixture"]
`
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTemplate(file, root); err == nil {
		t.Fatal("missing payload file accepted")
	}
	product := filepath.Join(root, "product")
	nested := filepath.Join(product, "v1", "nested.yaml")
	if err := os.MkdirAll(filepath.Dir(nested), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nested, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(product, "words.txt"), []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTemplate(nested, root); err != nil {
		t.Errorf("shared parent dictionary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "words.txt"), []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTemplate(file, root); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	if err := ValidateTemplate("payload.yaml", "."); err != nil {
		t.Fatalf("relative template root: %v", err)
	}
}
