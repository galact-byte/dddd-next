package uncover

import (
	"context"
	"testing"

	"github.com/projectdiscovery/uncover/sources"
)

func TestNewFillsDefaults(t *testing.T) {
	s := New(Options{})
	if len(s.opts.Agents) == 0 {
		t.Error("agents should default to fofa/hunter/quake")
	}
	if s.opts.Limit <= 0 {
		t.Error("limit should default")
	}
	if s.opts.Timeout <= 0 {
		t.Error("timeout should default")
	}
}

func TestToAsset(t *testing.T) {
	r := sources.Result{Source: "fofa", IP: "1.2.3.4", Port: 8080, Host: "ex.com", Url: "http://ex.com"}
	a := toAsset(r)
	if a.Source != "fofa" || a.IP != "1.2.3.4" || a.Port != 8080 || a.Host != "ex.com" || a.URL != "http://ex.com" {
		t.Errorf("toAsset = %+v", a)
	}
}

func TestQueryEmptyReturnsError(t *testing.T) {
	s := New(DefaultOptions())
	if _, err := s.Query(context.Background(), "", 0); err == nil {
		t.Error("empty query should return an error")
	}
}
