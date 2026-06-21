// Package pocmap maps fingerprint product names to the nuclei POC files that
// target them — upstream dddd's "fingerprint hit → only that product's POCs"
// instead of firing all 13000+ templates at every host. Data lives in
// configs/pocs/mapping.yaml (product → POC names) and configs/pocs/legacy/.
package pocmap

import (
	"fmt"
	"net/url"
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

type Entry struct {
	RootType bool
	DirType  bool
	BaseType bool
	Pocs     []string
}

type Mapping struct {
	products       map[string]Entry
	general        []string
	generalEntries []Entry
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

	m := &Mapping{products: make(map[string]Entry, len(raw))}
	seen := make(map[string]struct{})
	for name, e := range raw {
		entry := parseEntry(e)
		if strings.HasPrefix(name, generalPrefix) {
			m.generalEntries = append(m.generalEntries, entry)
			for _, poc := range entry.Pocs {
				if _, dup := seen[poc]; dup {
					continue
				}
				seen[poc] = struct{}{}
				m.general = append(m.general, poc)
			}
			continue
		}
		m.products[name] = entry
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
	nameTargets, stats := m.ResolveNamesByTarget(hits, includeGeneral)
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

	out := make(map[string][]string, len(nameTargets))
	stats.Targets = 0
	stats.UniquePOCs = 0
	for target, names := range nameTargets {
		seen := make(map[string]struct{})
		var paths []string
		for _, poc := range names {
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
		if len(paths) > 0 {
			sort.Strings(paths)
			out[target] = paths
			stats.Targets++
		}
	}
	stats.UniquePOCs = len(uniq)
	return out, stats
}

// ResolveNames maps fingerprint hits to the deduplicated set of POC *names*
// (not on-disk paths), letting the caller decide where each name resolves —
// the updated nuclei-templates dir first, legacy/ as fallback. Mirrors
// Resolve's product/general logic but skips the disk lookup.
func (m *Mapping) ResolveNames(hits map[string][]string, includeGeneral bool) ([]string, ResolveStats) {
	nameTargets, stats := m.ResolveNamesByTarget(hits, includeGeneral)
	seen := make(map[string]struct{})
	var names []string
	for _, pocs := range nameTargets {
		for _, poc := range pocs {
			if _, dup := seen[poc]; dup {
				continue
			}
			seen[poc] = struct{}{}
			names = append(names, poc)
		}
	}
	stats.UniquePOCs = len(names)
	sort.Strings(names)
	return names, stats
}

// ResolveNamesByTarget maps fingerprint hits to POC names while preserving the
// workflow target type semantics from upstream dddd: root/base/dir determine
// which URL each POC should run against.
func (m *Mapping) ResolveNamesByTarget(hits map[string][]string, includeGeneral bool) (map[string][]string, ResolveStats) {
	var stats ResolveStats
	out := make(map[string][]string)
	seenByTarget := make(map[string]map[string]struct{})
	uniq := make(map[string]struct{})

	add := func(target string, pocs []string) {
		if target == "" || len(pocs) == 0 {
			return
		}
		if seenByTarget[target] == nil {
			seenByTarget[target] = make(map[string]struct{})
		}
		for _, poc := range pocs {
			if _, dup := seenByTarget[target][poc]; dup {
				continue
			}
			seenByTarget[target][poc] = struct{}{}
			out[target] = append(out[target], poc)
			uniq[poc] = struct{}{}
		}
	}

	for target, hitNames := range hits {
		for _, name := range hitNames {
			entry, ok := m.products[name]
			if !ok {
				stats.UnknownNames++
				continue
			}
			stats.MatchedNames++
			for _, resolvedTarget := range targetsForEntry(entry, target) {
				add(resolvedTarget, entry.Pocs)
			}
		}
		if includeGeneral {
			for _, entry := range m.generalEntries {
				for _, resolvedTarget := range targetsForEntry(entry, target) {
					add(resolvedTarget, entry.Pocs)
				}
			}
		}
	}
	for target := range out {
		sort.Strings(out[target])
	}
	stats.Targets = len(out)
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

func parseEntry(raw rawEntry) Entry {
	entry := Entry{Pocs: append([]string(nil), raw.Pocs...)}
	for _, typ := range raw.Type {
		switch strings.ToLower(strings.TrimSpace(typ)) {
		case "root":
			entry.RootType = true
		case "dir":
			entry.DirType = true
		case "base":
			entry.BaseType = true
		}
	}
	return entry
}

func targetsForEntry(entry Entry, rawTarget string) []string {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return nil
	}
	u, err := url.Parse(rawTarget)
	if err != nil || u.Scheme == "" || u.Host == "" {
		if entry.RootType {
			return []string{rawTarget}
		}
		return nil
	}

	root := u.Scheme + "://" + u.Host
	var out []string
	add := func(target string) {
		if target == "" {
			return
		}
		for _, existing := range out {
			if existing == target {
				return
			}
		}
		out = append(out, target)
	}

	if entry.RootType {
		add(root)
	}
	hasPath := u.Path != "" && u.Path != "/"
	if hasPath && entry.BaseType {
		add(rawTarget)
	}
	if hasPath && entry.DirType {
		add(root)
		trimmed := strings.Trim(strings.TrimSuffix(u.Path, "/"), "/")
		if trimmed != "" {
			parts := strings.Split(trimmed, "/")
			for i := 1; i <= len(parts); i++ {
				add(root + "/" + strings.Join(parts[:i], "/"))
			}
		}
	}
	return out
}
