// Package types defines shared domain types used across dddd-next.
//
// Centralizing these prevents import cycles between scanner, discovery and
// reporter packages. Keep this package free of business logic and external
// dependencies — it's the lingua franca, nothing more.
package types

import "time"

// InputType describes the kind of value a user passed via -t.
type InputType int

const (
	InputUnknown InputType = iota
	InputIP
	InputIPPort
	InputIPRange
	InputCIDR
	InputDomain
	InputDomainPort
	InputURL
	InputSearchQuery
	InputFingerImport // a re-imported "[FP] target | name | ..." line (fscan/dddd resume)
)

// String returns the canonical name for use in logs and reports.
func (t InputType) String() string {
	switch t {
	case InputIP:
		return "ip"
	case InputIPPort:
		return "ip:port"
	case InputIPRange:
		return "ip-range"
	case InputCIDR:
		return "cidr"
	case InputDomain:
		return "domain"
	case InputDomainPort:
		return "domain:port"
	case InputURL:
		return "url"
	case InputSearchQuery:
		return "search-query"
	case InputFingerImport:
		return "finger-import"
	default:
		return "unknown"
	}
}

// Target is the smallest unit scanned by any engine.
type Target struct {
	Raw     string
	Type    InputType
	Host    string
	Port    int
	Scheme  string
	URL     string
	Fingers []string // pre-known fingerprints when Type is InputFingerImport
}

// Asset is what a recon source (Hunter / Fofa / Quake) hands back.
type Asset struct {
	Source    string
	Host      string
	Port      int
	URL       string
	Title     string
	Component string
	Banner    string
	IP        string
	Domain    string
}

// Severity matches the nuclei taxonomy.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Fingerprint is a single fingerprint hit on a target.
type Fingerprint struct {
	Name       string
	Target     string
	Source     string
	Confidence int
	Evidence   string
}

// Finding is a vulnerability or weak-credential discovery.
type Finding struct {
	ID           string
	Name         string
	Severity     Severity
	Target       string
	Template     string
	Description  string
	References   []string
	Request      string
	Response     string
	CVSS         float64
	Tags         []string
	DiscoveredAt time.Time
}
