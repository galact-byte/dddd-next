package cdn

import (
	"net"
	"testing"
)

func TestMatchByCNAME(t *testing.T) {
	cases := []struct {
		name     string
		cnames   []string
		wantCDN  bool
		provider string
	}{
		{"aliyun", []string{"foo.alicdn.com."}, true, "阿里云 CDN"},
		{"tencent", []string{"x.y.dnsv1.com."}, true, "腾讯云 CDN"},
		{"wangsu", []string{"a.lxdns.com."}, true, "网宿 CDN"},
		{"cloudfront", []string{"d111.cloudfront.net."}, true, "AWS CloudFront"},
		{"cdn keyword", []string{"edge.example-cdn.io."}, true, "CNAME keyword: cdn"},
		{"waf keyword", []string{"shield.somewaf.io."}, true, "CNAME keyword: waf"},
		{"no cdn", []string{"mail.example.com."}, false, ""},
		{"empty", nil, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, provider := matchByCNAME(tc.cnames)
			if got != tc.wantCDN {
				t.Fatalf("matchByCNAME(%v) isCDN = %v, want %v", tc.cnames, got, tc.wantCDN)
			}
			if got && provider != tc.provider {
				t.Errorf("provider = %q, want %q", provider, tc.provider)
			}
		})
	}
}

func TestMatchByCNAMECaseInsensitive(t *testing.T) {
	// CNAMEs can come back in mixed case; matching must be case-insensitive.
	if ok, _ := matchByCNAME([]string{"FOO.ALICDN.COM."}); !ok {
		t.Error("upper-case CNAME should still match the alicdn suffix")
	}
}

func TestMatchByIP(t *testing.T) {
	if ok, name := matchByIP([]net.IP{net.ParseIP("223.4.77.85")}); !ok || name != "ALLELINK" {
		t.Errorf("known CDN IP: ok=%v name=%q, want true/ALLELINK", ok, name)
	}
	if ok, _ := matchByIP([]net.IP{net.ParseIP("8.8.8.8")}); ok {
		t.Error("8.8.8.8 must not match the CDN IP list")
	}
}
