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
	s := strings.TrimSpace(input)
	if s == "" {
		return types.InputUnknown
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
	s := strings.TrimSpace(input)
	if s == "" {
		return types.Target{}, ErrEmptyInput
	}

	t := types.Target{Raw: s, Type: Classify(s)}

	switch t.Type {
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
