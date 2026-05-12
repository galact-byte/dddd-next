package classifier

import (
	"testing"

	"dddd-next/internal/types"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		want types.InputType
	}{
		{"192.168.1.1", types.InputIP},
		{"10.0.0.1", types.InputIP},
		{"2001:db8::1", types.InputIP},
		{"192.168.1.1:8080", types.InputIPPort},
		{"192.168.1.0/24", types.InputCIDR},
		{"10.0.0.0/8", types.InputCIDR},
		{"192.168.1.1-192.168.1.10", types.InputIPRange},
		{"example.com", types.InputDomain},
		{"sub.example.co.uk", types.InputDomain},
		{"example.com:8080", types.InputDomainPort},
		{"http://example.com", types.InputURL},
		{"https://example.com/path?q=1", types.InputURL},
		{`icp.name="某公司"`, types.InputSearchQuery},
		{`app="Apache"`, types.InputSearchQuery},
		{`title="管理后台"`, types.InputSearchQuery},
		{"", types.InputUnknown},
		{"   ", types.InputUnknown},
		{"!!!garbage!!!", types.InputUnknown},
	}

	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := Classify(c.in)
			if got != c.want {
				t.Errorf("Classify(%q) = %s, want %s", c.in, got, c.want)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	tgt, err := Parse("https://example.com:8443/path")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if tgt.Type != types.InputURL {
		t.Errorf("Type = %s, want url", tgt.Type)
	}
	if tgt.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", tgt.Host)
	}
	if tgt.Port != 8443 {
		t.Errorf("Port = %d, want 8443", tgt.Port)
	}
	if tgt.Scheme != "https" {
		t.Errorf("Scheme = %q, want https", tgt.Scheme)
	}
}

func TestParseURLDefaultPort(t *testing.T) {
	tgt, err := Parse("http://example.com/x")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tgt.Port != 80 {
		t.Errorf("Port = %d, want 80", tgt.Port)
	}
	tgt2, _ := Parse("https://example.com/x")
	if tgt2.Port != 443 {
		t.Errorf("Port = %d, want 443", tgt2.Port)
	}
}

func TestParseIPPort(t *testing.T) {
	tgt, err := Parse("192.168.1.1:8080")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tgt.Host != "192.168.1.1" || tgt.Port != 8080 {
		t.Errorf("got Host=%q Port=%d", tgt.Host, tgt.Port)
	}
}

func TestParseEmpty(t *testing.T) {
	if _, err := Parse(""); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParseUnknown(t *testing.T) {
	if _, err := Parse("@@@garbage@@@"); err == nil {
		t.Error("expected error for unrecognised input")
	}
}
