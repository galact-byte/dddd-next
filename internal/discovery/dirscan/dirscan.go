// Package dirscan probes well-known product paths (/nacos/, /druid/, ...) on a
// live web root to surface products that the homepage fingerprint misses — a
// Nacos console or Druid monitor mounted on a sub-path, say. It is path-based
// active fingerprinting, ported from SleepingBag945/dddd's dir.yaml flow, not a
// generic word-list directory brute.
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
// Callers feed these to httpx's -path (RequestPaths) so it probes each path on
// every live root.
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
