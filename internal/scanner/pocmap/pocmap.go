// Package pocmap maps fingerprint product names to the nuclei POC files that
// target them — upstream dddd's "fingerprint hit → only that product's POCs"
// instead of firing all 13000+ templates at every host. Data lives in
// configs/pocs/mapping.yaml (product → POC names) and configs/pocs/legacy/.
package pocmap

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// General-Poc-* entries aren't tied to a product and run against every target.
const generalPrefix = "General-Poc-"

type rawEntry struct {
	Type []string `yaml:"type"`
	Pocs []string `yaml:"pocs"`
}

type Mapping struct {
	products map[string][]string
	general  []string
}

// Load parses mapping.yaml, splitting General-Poc-* into the deduplicated
// general set and keying the rest by product name.
func Load(path string) (*Mapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pocmap: read %s: %w", path, err)
	}
	raw := make(map[string]rawEntry)
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("pocmap: parse %s: %w", path, err)
	}

	m := &Mapping{products: make(map[string][]string, len(raw))}
	seen := make(map[string]struct{})
	for name, e := range raw {
		if strings.HasPrefix(name, generalPrefix) {
			for _, poc := range e.Pocs {
				if _, dup := seen[poc]; dup {
					continue
				}
				seen[poc] = struct{}{}
				m.general = append(m.general, poc)
			}
			continue
		}
		m.products[name] = e.Pocs
	}
	sort.Strings(m.general)
	return m, nil
}

func (m *Mapping) Products() int         { return len(m.products) }
func (m *Mapping) GeneralPocs() []string { return m.general }

type ResolveStats struct {
	Targets      int
	MatchedNames int
	UnknownNames int
	MissingFiles int
	UniquePOCs   int
}

// Resolve reproduces upstream dddd's GetPocs: each target runs only the POCs
// its fingerprint product names map to (plus the general set when
// includeGeneral), as pocDir/<name>.yaml paths that exist on disk.
func (m *Mapping) Resolve(hits map[string][]string, pocDir string, includeGeneral bool) (map[string][]string, ResolveStats) {
	var stats ResolveStats
	fileCache := make(map[string]string) // poc name → path, "" if not on disk
	uniq := make(map[string]struct{})

	resolvePath := func(poc string) string {
		if path, cached := fileCache[poc]; cached {
			return path
		}
		path := filepath.Join(pocDir, poc+".yaml")
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			path = ""
		}
		fileCache[poc] = path
		return path
	}

	out := make(map[string][]string, len(hits))
	for target, names := range hits {
		seen := make(map[string]struct{})
		var paths []string
		add := func(pocs []string) {
			for _, poc := range pocs {
				path := resolvePath(poc)
				if path == "" {
					stats.MissingFiles++
					continue
				}
				if _, dup := seen[path]; dup {
					continue
				}
				seen[path] = struct{}{}
				paths = append(paths, path)
				uniq[path] = struct{}{}
			}
		}

		for _, name := range names {
			pocs, ok := m.products[name]
			if !ok {
				stats.UnknownNames++
				continue
			}
			stats.MatchedNames++
			add(pocs)
		}
		if includeGeneral {
			add(m.general)
		}

		if len(paths) > 0 {
			sort.Strings(paths)
			out[target] = paths
			stats.Targets++
		}
	}
	stats.UniquePOCs = len(uniq)
	return out, stats
}

// Union is the deduplicated set of every POC path across all targets — the
// input for one batched nuclei scan.
func Union(resolved map[string][]string) []string {
	seen := make(map[string]struct{})
	var all []string
	for _, paths := range resolved {
		for _, p := range paths {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			all = append(all, p)
		}
	}
	sort.Strings(all)
	return all
}
