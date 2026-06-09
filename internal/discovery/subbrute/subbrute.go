// Package subbrute generates subdomain brute-force candidates from a wordlist.
// Resolution is left to the caller (dnsx).
package subbrute

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadWordlist reads one label per line, skipping blanks and # comments.
func LoadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("subbrute: open wordlist %s: %w", path, err)
	}
	defer f.Close()

	var words []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("subbrute: read wordlist %s: %w", path, err)
	}
	return words, nil
}

// Candidates builds the deduplicated "<word>.<domain>" set for every domain.
func Candidates(domains, words []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		for _, w := range words {
			if w == "" {
				continue
			}
			cand := w + "." + d
			if _, ok := seen[cand]; ok {
				continue
			}
			seen[cand] = struct{}{}
			out = append(out, cand)
		}
	}
	return out
}
