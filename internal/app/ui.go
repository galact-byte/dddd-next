package app

import (
	"fmt"
	"strings"
	"sync"

	"dddd-next/internal/reporter"
	"dddd-next/internal/types"
)

// findingLine formats one finding as a colored process line, severity-tagged.
func findingLine(f types.Finding) string {
	const reset = "\033[0m"
	name := f.ID
	if name == "" {
		name = f.Name
	}
	return fmt.Sprintf("  %s[%s]%s %s  %s", sevColor(f.Severity), strings.ToUpper(string(f.Severity)), reset, name, f.Target)
}

func sevColor(s types.Severity) string {
	switch s {
	case types.SeverityCritical, types.SeverityHigh:
		return "\033[31m"
	case types.SeverityMedium:
		return "\033[33m"
	case types.SeverityLow:
		return "\033[32m"
	default:
		return "\033[36m"
	}
}

// countingReporter wraps a Reporter to tally what was written, so the run can
// print an end-of-scan summary without each stage threading counters back.
type countingReporter struct {
	reporter.Reporter
	mu       sync.Mutex
	fps      int
	findings int
	bySev    map[types.Severity]int
}

func newCountingReporter(r reporter.Reporter) *countingReporter {
	return &countingReporter{Reporter: r, bySev: make(map[types.Severity]int)}
}

func (c *countingReporter) WriteFingerprint(target string, fp types.Fingerprint) error {
	c.mu.Lock()
	c.fps++
	c.mu.Unlock()
	return c.Reporter.WriteFingerprint(target, fp)
}

func (c *countingReporter) WriteFinding(f types.Finding) error {
	c.mu.Lock()
	c.findings++
	c.bySev[f.Severity]++
	c.mu.Unlock()
	return c.Reporter.WriteFinding(f)
}

func (p *Pipeline) printSummary() {
	c := p.counts
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	const dim = "\033[2m"
	const reset = "\033[0m"
	fmt.Printf("%s──────────────── summary ────────────────%s\n", dim, reset)
	fmt.Printf("  fingerprints  %d\n", c.fps)
	if c.findings == 0 {
		fmt.Println("  findings      0")
		return
	}
	fmt.Printf("  findings      %d  %s(critical %d · high %d · medium %d · low %d)%s\n",
		c.findings, dim,
		c.bySev[types.SeverityCritical], c.bySev[types.SeverityHigh],
		c.bySev[types.SeverityMedium], c.bySev[types.SeverityLow], reset)
}
