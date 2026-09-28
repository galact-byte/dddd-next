package app

import (
	"fmt"
	"strings"

	"dddd-next/internal/types"
)

// ── 终端输出标签（对齐原版 dddd 风格）──

const ansiBlue = "\033[34m"
const ansiRed = "\033[31m"
const ansiGreen = "\033[32m"
const ansiYellow = "\033[33m"
const ansiCyan = "\033[36m"
const ansiReset = "\033[0m"

// infof prints a blue [INF] line — stage announcements and summaries.
func infof(format string, args ...any) {
	fmt.Print(ansiBlue + "[INF]" + ansiReset + " ")
	fmt.Printf(format, args...)
}

// infoln is infof with a trailing newline for Println callers.
func infoln(msg string) {
	fmt.Println(ansiBlue + "[INF]" + ansiReset + " " + msg)
}

// warnf prints a red [!] line — errors and non-fatal warnings.
func warnf(format string, args ...any) {
	fmt.Print(ansiRed + "[!]" + ansiReset + " ")
	fmt.Printf(format, args...)
}

// warnln is warnf with a trailing newline.
func warnln(msg string) {
	fmt.Println(ansiRed + "[!]" + ansiReset + " " + msg)
}

// portLine prints an open-port discovery: "  [PortScan] host:port"
func portLine(host string, port int) {
	fmt.Printf("  [PortScan] %s:%d\n", host, port)
}

// svcLine prints a service identification: "  [Service] service://host:port"
func svcLine(service, host string, port int) {
	fmt.Printf("  [Service] %s://%s:%d\n", service, host, port)
}

// webLine prints an HTTP probe result with colored status code and page title.
func webLine(statusCode int, url, title string, fps []string) {
	var sc string
	switch {
	case statusCode >= 200 && statusCode < 300:
		sc = ansiGreen + fmt.Sprintf("%d", statusCode) + ansiReset
	case statusCode >= 300 && statusCode < 400:
		sc = ansiCyan + fmt.Sprintf("%d", statusCode) + ansiReset
	case statusCode >= 400 && statusCode < 500:
		sc = ansiYellow + fmt.Sprintf("%d", statusCode) + ansiReset
	default:
		sc = ansiRed + fmt.Sprintf("%d", statusCode) + ansiReset
	}

	fmt.Printf("  [Web] [%s] %s", sc, url)
	if title != "" {
		fmt.Printf(" [%s]", title)
	}
	if len(fps) > 0 {
		fmt.Printf(" %s[%s]%s", ansiCyan, strings.Join(fps, ","), ansiReset)
	}
	fmt.Println()
}

// findingLine prints a vulnerability finding with severity-colored tag.
func printFinding(f types.Finding) {
	fmt.Println(formatFinding(f))
}

// formatFinding renders one finding as a single terminal line. When the finding
// carries a verified key result (cracked credential, extractor hit, Shiro
// key/mode) it is appended after the target so operators see the payoff without
// opening the report. The detail is sanitized so an attacker-controlled value
// (e.g. a banner echoed back as a password) cannot inject newlines or ANSI
// escapes into the console record.
func formatFinding(f types.Finding) string {
	name := f.ID
	if name == "" {
		name = f.Name
	}
	line := fmt.Sprintf("  %s[%s]%s %s  %s",
		sevColor(f.Severity),
		strings.ToUpper(string(f.Severity)),
		ansiReset,
		name,
		f.Target,
	)
	if d := sanitizeInline(f.Detail); d != "" {
		line += "  " + ansiCyan + d + ansiReset
	} else if d := sanitizeInline(f.Description); d != "" {
		// No structured key result: fall back to the finding's description so
		// unauthorized-access / info-leak POCs (memcached, JDWP, NetBIOS, etc.)
		// still show their payoff on the terminal, mirroring the original dddd.
		line += "  " + ansiCyan + truncateRunes(d, 160) + ansiReset
	}
	return line
}

// truncateRunes shortens s to at most max runes, appending an ellipsis when it
// had to cut, so a long description stays on one readable terminal line.
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// sanitizeInline strips control characters (newlines, tabs, NUL, ANSI escapes)
// from a value destined for a single terminal line, replacing each run with a
// single space and collapsing the result. This keeps one finding on one line
// even when the underlying value came from an untrusted service response.
func sanitizeInline(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == 0x7f || r < 0x20 {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}

func sevColor(s types.Severity) string {
	switch s {
	case types.SeverityCritical, types.SeverityHigh:
		return ansiRed
	case types.SeverityMedium:
		return ansiYellow
	case types.SeverityLow:
		return ansiGreen
	default:
		return ansiCyan
	}
}
