// Package classifier auto-detects what kind of value a target string holds.
//
// The original dddd inspected user input with hand-rolled if/else chains in
// utils.GetInputType. Here we keep the regex/net-parse cascade but expose a
// pure-function API that's trivial to unit test.
package classifier

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"dddd-next/internal/types"
)

var (
	ipRangePattern    = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}-(?:\d{1,3}\.){3}\d{1,3}$`)
	ipPortPattern     = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}$`)
	domainPattern     = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$`)
	domainPortPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+:\d{1,5}$`)
)

// searchQueryHints are the substrings that flag a Hunter/Fofa/Quake query.
// Order matters only for performance; semantic match is "contains any".
var searchQueryHints = []string{
	"icp.name=", "icp.web=", "domain=", "ip=", "app=", "port=",
	"title=", "host=", "body=", "service=", "country=",
	`"`, // any quote-enclosed token strongly implies a search expression
}

// ErrEmptyInput is returned when the input is blank after trimming.
var ErrEmptyInput = errors.New("classifier: empty input")

// Classify identifies the InputType of a single user-supplied string.
//
// It never touches the network; ordering is chosen so the cheapest checks
// run first and ambiguous cases (e.g. URL vs domain) resolve in the user's
// favour. Returns InputUnknown if nothing matches.
func Classify(input string) types.InputType {
	s := normalize(input)
	if s == "" {
		return types.InputUnknown
	}

	if strings.HasPrefix(s, "[FP]") {
		return types.InputFingerImport
	}

	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if _, err := url.Parse(s); err == nil {
			return types.InputURL
		}
	}

	for _, hint := range searchQueryHints {
		if strings.Contains(s, hint) {
			return types.InputSearchQuery
		}
	}

	if _, _, err := net.ParseCIDR(s); err == nil {
		return types.InputCIDR
	}

	if ipRangePattern.MatchString(s) {
		return types.InputIPRange
	}

	if ipPortPattern.MatchString(s) {
		return types.InputIPPort
	}

	if ip := net.ParseIP(s); ip != nil {
		return types.InputIP
	}

	if domainPortPattern.MatchString(s) {
		return types.InputDomainPort
	}

	if domainPattern.MatchString(s) {
		return types.InputDomain
	}

	return types.InputUnknown
}

// Parse converts a raw string into a fully-populated Target.
//
// For aggregate inputs (CIDR / IP-Range / SearchQuery) the caller is
// responsible for expansion — Parse only attaches Type and Raw so the
// downstream pipeline can dispatch correctly.
func Parse(input string) (types.Target, error) {
	s := normalize(input)
	if s == "" {
		return types.Target{}, ErrEmptyInput
	}

	t := types.Target{Raw: s, Type: Classify(s)}

	switch t.Type {
	case types.InputFingerImport:
		target, fingers, err := parseFPLine(s)
		if err != nil {
			return t, err
		}
		t.URL = target
		t.Fingers = fingers
	case types.InputIP, types.InputDomain:
		t.Host = s
	case types.InputIPPort, types.InputDomainPort:
		host, portStr, err := net.SplitHostPort(s)
		if err != nil {
			return t, fmt.Errorf("classifier: split host:port %q: %w", s, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return t, fmt.Errorf("classifier: parse port %q: %w", portStr, err)
		}
		t.Host = host
		t.Port = port
	case types.InputURL:
		u, err := url.Parse(s)
		if err != nil {
			return t, fmt.Errorf("classifier: parse URL %q: %w", s, err)
		}
		t.URL = s
		t.Scheme = u.Scheme
		t.Host = u.Hostname()
		switch {
		case u.Port() != "":
			port, err := strconv.Atoi(u.Port())
			if err != nil {
				return t, fmt.Errorf("classifier: parse URL port %q: %w", u.Port(), err)
			}
			t.Port = port
		case u.Scheme == "https":
			t.Port = 443
		case u.Scheme == "http":
			t.Port = 80
		}
	case types.InputUnknown:
		return t, fmt.Errorf("classifier: unrecognised input %q", s)
	}

	return t, nil
}

// normalize trims whitespace and strips fscan's trailing " open" marker so a
// line like "192.168.1.1:80 open" classifies as an ip:port target.
func normalize(input string) string {
	s := strings.TrimSpace(input)
	if url := extractFscanWebURL(s); url != "" {
		return url
	}
	if strings.HasSuffix(strings.ToLower(s), " open") {
		s = strings.TrimSpace(s[:len(s)-len(" open")])
	}
	return s
}

func extractFscanWebURL(s string) string {
	lower := strings.ToLower(s)
	if !strings.Contains(lower, "webtitle") && !strings.Contains(lower, "infoscan") {
		return ""
	}
	for _, field := range strings.Fields(s) {
		field = strings.Trim(field, `"'()[]<>`)
		field = strings.TrimRight(field, ",;")
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
			return field
		}
	}
	return ""
}

// parseFPLine reads a re-imported fingerprint line in dddd-next's report format:
// "[FP] <target> | <name> | confidence=<n>".
func parseFPLine(s string) (target string, fingers []string, err error) {
	body := strings.TrimSpace(strings.TrimPrefix(s, "[FP]"))
	parts := strings.Split(body, "|")
	if len(parts) < 2 {
		return "", nil, fmt.Errorf("classifier: bad [FP] line %q", s)
	}
	target = strings.TrimSpace(parts[0])
	name := strings.TrimSpace(parts[1])
	if target == "" || name == "" {
		return "", nil, fmt.Errorf("classifier: empty target/name in %q", s)
	}
	return target, []string{name}, nil
}
