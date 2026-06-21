package configs

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestBundleZipMatchesBaselineConfigFiles(t *testing.T) {
	want := collectBaselineConfigFiles(t)
	got := readBundleZip(t)

	if len(got) != len(want) {
		t.Fatalf("bundle contains %d files, want %d", len(got), len(want))
	}
	for name, wantData := range want {
		gotData, ok := got[name]
		if !ok {
			t.Fatalf("bundle missing %s", name)
		}
		if !bytes.Equal(gotData, wantData) {
			t.Fatalf("bundle file %s is stale", name)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Fatalf("bundle contains unexpected file %s", name)
		}
	}
}

func collectBaselineConfigFiles(t *testing.T) map[string][]byte {
	t.Helper()

	files := map[string][]byte{}
	addFile := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.ToSlash(path)] = data
	}
	addDir := func(path string) {
		t.Helper()
		err := filepath.WalkDir(path, func(filePath string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			data, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(filePath)] = data
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	addFile("api-config.example.yaml")
	addFile("dir.yaml")
	addDir("dict")
	addDir("fingers")
	addFile(filepath.Join("pocs", "mapping.yaml"))
	addDir(filepath.Join("pocs", "legacy"))
	return files
}

func readBundleZip(t *testing.T) map[string][]byte {
	t.Helper()

	reader, err := zip.NewReader(bytes.NewReader(BundleZip), int64(len(BundleZip)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(rc)
		closeErr := rc.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		files[entry.Name] = data
	}
	return files
}
