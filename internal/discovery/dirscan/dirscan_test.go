package dirscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dir.yaml")
	content := "Alibaba-Nacos:\n  - \"/nacos/\"\n  - \"/api/nacos/\"\nphpMyAdmin:\n  - \"/pma/\"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	db, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(db) != 2 {
		t.Fatalf("want 2 products, got %d", len(db))
	}
	got := db.Paths()
	if len(got) != 3 {
		t.Errorf("want 3 unique paths, got %v", got)
	}
	// Paths must be sorted for deterministic probing.
	if got[0] != "/api/nacos/" || got[2] != "/pma/" {
		t.Errorf("paths not sorted: %v", got)
	}
}
