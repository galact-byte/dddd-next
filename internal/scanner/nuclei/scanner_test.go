package nuclei

import (
	"context"
	"strings"
	"testing"
	"time"

	"dddd-next/internal/types"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	if !o.DisableUpdate {
		t.Error("DisableUpdate should default to true — dddd update owns templates")
	}
	if !o.Silent {
		t.Error("Silent should default to true so SDK callers don't get banner output")
	}
	if o.Concurrency <= 0 || o.HostConcurrency <= 0 {
		t.Errorf("concurrency defaults must be > 0, got Template=%d Host=%d",
			o.Concurrency, o.HostConcurrency)
	}
	if o.ResponseReadSize != 5*1024*1024 {
		t.Errorf("ResponseReadSize default = %d, want %d", o.ResponseReadSize, 5*1024*1024)
	}
}

func TestMapSeverity(t *testing.T) {
	cases := map[string]types.Severity{
		"critical":      types.SeverityCritical,
		"Critical":      types.SeverityCritical,
		"CRITICAL":      types.SeverityCritical,
		" high ":        types.SeverityHigh,
		"medium":        types.SeverityMedium,
		"low":           types.SeverityLow,
		"info":          types.SeverityInfo,
		"informational": types.SeverityInfo,
		"":              types.SeverityInfo,
		"garbage":       types.SeverityInfo,
		"unknown":       types.SeverityInfo,
	}
	for in, want := range cases {
		if got := mapSeverity(in); got != want {
			t.Errorf("mapSeverity(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestSliceCopy(t *testing.T) {
	src := []string{"a", "b"}
	dst := sliceCopy(src)
	src[0] = "MUTATED"
	if dst[0] != "a" {
		t.Errorf("sliceCopy did not isolate: dst[0]=%q after src mutation", dst[0])
	}
	if got := sliceCopy(nil); got != nil {
		t.Errorf("sliceCopy(nil) = %v, want nil", got)
	}
	if got := sliceCopy([]string{}); got != nil {
		t.Errorf("sliceCopy(empty) = %v, want nil for clean JSON output", got)
	}
}

func TestPickTarget(t *testing.T) {
	cases := []struct {
		name string
		ev   output.ResultEvent
		want string
	}{
		{
			name: "matched-at_wins",
			ev:   output.ResultEvent{Matched: "https://x.com/api/v1", URL: "https://x.com", Host: "x.com"},
			want: "https://x.com/api/v1",
		},
		{
			name: "url_wins_when_no_matched",
			ev:   output.ResultEvent{URL: "https://x.com", Host: "x.com", Port: "443"},
			want: "https://x.com",
		},
		{
			name: "host_port_wins_when_no_url",
			ev:   output.ResultEvent{Host: "1.2.3.4", Port: "8080"},
			want: "1.2.3.4:8080",
		},
		{
			name: "host_only",
			ev:   output.ResultEvent{Host: "1.2.3.4"},
			want: "1.2.3.4",
		},
		{
			name: "all_empty",
			ev:   output.ResultEvent{},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickTarget(&tc.ev); got != tc.want {
				t.Errorf("pickTarget = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestToFinding(t *testing.T) {
	now := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)
	ev := &output.ResultEvent{
		TemplateID: "CVE-2024-1234",
		Template:   "cves/2024/CVE-2024-1234.yaml",
		Info: model.Info{
			Name:           "Demo RCE",
			Description:    "A demo finding",
			SeverityHolder: severity.Holder{Severity: severity.High},
			Tags:           stringslice.StringSlice{Value: []string{"cve", "rce"}},
			Reference:      stringslice.NewRawStringSlice("https://example.com/advisory"),
		},
		Host:      "example.com",
		Port:      "443",
		URL:       "https://example.com/vuln",
		Matched:   "https://example.com/vuln?id=1",
		Request:   "GET /vuln?id=1 HTTP/1.1",
		Response:  "HTTP/1.1 500",
		Timestamp: now,
	}
	f := toFinding(ev)

	if f.ID != "CVE-2024-1234" {
		t.Errorf("ID = %q", f.ID)
	}
	if f.Name != "Demo RCE" {
		t.Errorf("Name = %q", f.Name)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("Severity = %s, want high", f.Severity)
	}
	if f.Target != "https://example.com/vuln?id=1" {
		t.Errorf("Target = %q", f.Target)
	}
	if f.Template != "cves/2024/CVE-2024-1234.yaml" {
		t.Errorf("Template = %q", f.Template)
	}
	if f.Description != "A demo finding" {
		t.Errorf("Description = %q", f.Description)
	}
	if len(f.References) != 1 || f.References[0] != "https://example.com/advisory" {
		t.Errorf("References = %v", f.References)
	}
	if len(f.Tags) != 2 || f.Tags[0] != "cve" || f.Tags[1] != "rce" {
		t.Errorf("Tags = %v", f.Tags)
	}
	if !f.DiscoveredAt.Equal(now) {
		t.Errorf("DiscoveredAt = %v, want %v", f.DiscoveredAt, now)
	}
}

func TestToFindingNilReference(t *testing.T) {
	ev := &output.ResultEvent{
		TemplateID: "x",
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Info},
			Tags:           stringslice.StringSlice{},
			Reference:      nil,
		},
		Host: "h",
	}
	f := toFinding(ev)
	if f.References != nil {
		t.Errorf("References should be nil when Reference is nil, got %v", f.References)
	}
	if f.Tags != nil {
		t.Errorf("Tags should be nil for empty StringSlice, got %v", f.Tags)
	}
}

func TestHasFilters(t *testing.T) {
	if hasFilters(nucleilib.TemplateFilters{}) {
		t.Error("empty filters should return false")
	}
	if !hasFilters(nucleilib.TemplateFilters{IDs: []string{"x"}}) {
		t.Error("IDs should mark filters non-empty")
	}
	if !hasFilters(nucleilib.TemplateFilters{Severity: "high"}) {
		t.Error("Severity should mark filters non-empty")
	}
	if !hasFilters(nucleilib.TemplateFilters{Tags: []string{"cve"}}) {
		t.Error("Tags should mark filters non-empty")
	}
}

func TestBuildSDKOptions(t *testing.T) {
	o := DefaultOptions()
	o.TemplatesDir = "/tmp/templates"
	o.TemplateIDs = []string{"CVE-2024-1234"}
	o.Severities = "high,critical"
	o.Proxy = []string{"http://127.0.0.1:7890"}
	opts := buildSDKOptions(o)
	// We can't deeply inspect closures, but we can assert the count grew
	// proportional to which fields were set: TemplatesDir, Filters,
	// Concurrency, Verbosity, Disable-update, Proxy, ResponseReadSize = 7.
	if len(opts) != 7 {
		t.Errorf("expected 7 SDK options, got %d", len(opts))
	}
}

func TestScanRejectsEmptyTargets(t *testing.T) {
	// We don't initialize a real engine — the empty-targets check happens
	// before LoadAllTemplates, so a bare struct is enough to exercise it.
	s := &Scanner{}
	_, _, err := s.Scan(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "no targets") {
		t.Errorf("expected 'no targets' error, got %v", err)
	}
	_, _, err = s.Scan(context.Background(), []string{})
	if err == nil {
		t.Error("expected error for empty target slice")
	}
}

func TestCloseNilSafe(t *testing.T) {
	var s *Scanner
	if err := s.Close(); err != nil {
		t.Errorf("Close on nil *Scanner should be no-op, got %v", err)
	}
	s2 := &Scanner{}
	if err := s2.Close(); err != nil {
		t.Errorf("Close with nil engine should be no-op, got %v", err)
	}
}
