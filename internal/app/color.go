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
	name := f.ID
	if name == "" {
		name = f.Name
	}
	fmt.Printf("  %s[%s]%s %s  %s\n",
		sevColor(f.Severity),
		strings.ToUpper(string(f.Severity)),
		ansiReset,
		name,
		f.Target,
	)
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
