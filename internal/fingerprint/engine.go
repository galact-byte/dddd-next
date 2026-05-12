// Package fingerprint loads finger.yaml rules, compiles them via the
// fingerdsl engine, and exposes a Match() API the workflow can call once
// HTTP context (body / title / header / banner / ...) has been gathered.
//
// The YAML loader is hand-rolled rather than using yaml.v3 — this keeps
// the module stdlib-only and matches the very narrow shape of finger.yaml
// (a flat map of `Name: ['expr', 'expr', ...]`). When we eventually pull
// in yaml.v3 for richer schemas, this loader can be swapped behind the
// same Engine constructor without disturbing callers.
package fingerprint

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"dddd-next/internal/types"
	"dddd-next/pkg/fingerdsl"
)

// Rule is one compiled fingerprint rule.
type Rule struct {
	Name       string
	Source     string
	Expression *fingerdsl.Expression
}

// Engine is a read-only collection of compiled rules.
type Engine struct {
	rules []Rule
}

// Size returns the number of compiled rules.
func (e *Engine) Size() int {
	if e == nil {
		return 0
	}
	return len(e.rules)
}

// Match evaluates every rule against ctx, returning the hits.
//
// Matching is O(N) over rules. For 8k+ rules this is ~10ms per target on
// commodity hardware — fine for our scan workload. If profiling later
// shows hot spots we can pre-index by field literal.
func (e *Engine) Match(ctx fingerdsl.Context) []types.Fingerprint {
	if e == nil {
		return nil
	}
	var hits []types.Fingerprint
	for _, r := range e.rules {
		if r.Expression.Eval(ctx) {
			hits = append(hits, types.Fingerprint{
				Name:       r.Name,
				Source:     "rule",
				Confidence: 90,
				Evidence:   r.Source,
			})
		}
	}
	return hits
}

// LoadStats summarises a load operation.
type LoadStats struct {
	Total    int           // total rule lines scanned
	Compiled int           // successfully compiled
	Failed   int           // rejected by DSL parser
	Failures []LoadFailure // first N failures retained for reporting
}

// LoadFailure records one parse error during loading.
type LoadFailure struct {
	Name   string
	Source string
	Err    error
}

// LoadYAML loads rules from a finger.yaml-style file.
//
// Accepted format (a strict subset of YAML; the original dddd file follows
// this shape religiously):
//
//	ProductName:
//	  - 'expression1'
//	  - 'expression2'
//
// Parse errors on individual expressions don't abort the load — they are
// counted in stats.Failed and the first few captured in stats.Failures
// so callers can surface them as warnings.
func LoadYAML(path string) (*Engine, LoadStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, LoadStats{}, fmt.Errorf("fingerprint: open %s: %w", path, err)
	}
	defer f.Close()

	var (
		e       Engine
		stats   LoadStats
		current string
	)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Top-level key line, e.g.  "ProductName:"
		if !startsWithSpace(line) {
			if idx := strings.LastIndex(line, ":"); idx > 0 {
				current = strings.TrimSpace(line[:idx])
			}
			continue
		}

		// List item, e.g.  "  - 'expr'"
		if !strings.HasPrefix(trimmed, "- ") {
			continue
		}
		expr := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))

		// Unwrap YAML single-quoted form  'foo ''bar'' baz'
		if len(expr) >= 2 && expr[0] == '\'' && expr[len(expr)-1] == '\'' {
			expr = expr[1 : len(expr)-1]
			expr = strings.ReplaceAll(expr, "''", "'")
		}
		if expr == "" {
			continue
		}

		stats.Total++
		compiled, err := fingerdsl.Parse(expr)
		if err != nil {
			stats.Failed++
			if len(stats.Failures) < 10 {
				stats.Failures = append(stats.Failures, LoadFailure{
					Name:   current,
					Source: expr,
					Err:    err,
				})
			}
			continue
		}
		stats.Compiled++
		e.rules = append(e.rules, Rule{
			Name:       current,
			Source:     expr,
			Expression: compiled,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, stats, fmt.Errorf("fingerprint: scan: %w", err)
	}
	return &e, stats, nil
}

func startsWithSpace(s string) bool {
	if s == "" {
		return false
	}
	return s[0] == ' ' || s[0] == '\t'
}
