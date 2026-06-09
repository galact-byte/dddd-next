package subbrute

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadWordlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "w.txt")
	if err := os.WriteFile(path, []byte("test\ndev\n\n# comment\nadmin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	words, err := LoadWordlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(words) != 3 {
		t.Fatalf("want 3 words (blank+comment skipped), got %v", words)
	}
}

func TestCandidates(t *testing.T) {
	got := Candidates([]string{"a.com", "b.com"}, []string{"test", "dev"})
	if len(got) != 4 {
		t.Fatalf("2 domains x 2 words = 4 candidates, got %v", got)
	}
	want := map[string]bool{"test.a.com": true, "dev.a.com": true, "test.b.com": true, "dev.b.com": true}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected candidate %q", c)
		}
	}
}

func TestCandidatesDedup(t *testing.T) {
	// Same domain listed twice must not double the candidates.
	got := Candidates([]string{"a.com", "a.com"}, []string{"test"})
	if len(got) != 1 || got[0] != "test.a.com" {
		t.Errorf("want single test.a.com, got %v", got)
	}
}
