// Package dirscan probes well-known product paths (/nacos/, /druid/, ...) on a
// live web root to surface products mounted on a sub-path that the homepage
// fingerprint misses. It is product-path fingerprinting, not a word-list brute.
package dirscan

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// DB maps a product name to the paths that reveal it.
type DB map[string][]string

func Load(path string) (DB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dirscan: read %s: %w", path, err)
	}
	var db DB
	if err := yaml.Unmarshal(b, &db); err != nil {
		return nil, fmt.Errorf("dirscan: parse %s: %w", path, err)
	}
	return db, nil
}

// Paths returns the unique, sorted set of probe paths across all products.
func (db DB) Paths() []string {
	seen := make(map[string]struct{})
	for _, paths := range db {
		for _, p := range paths {
			seen[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out) // deterministic order (maps randomise iteration)
	return out
}
