package app

import (
	"dddd-next/internal/config"
	"testing"
)

func TestReconLinkOnlyForExplicitHunterAndFofa(t *testing.T) {
	for _, tc := range []struct {
		agents []string
		want   bool
	}{
		{nil, false}, {[]string{"fofa"}, false}, {[]string{"hunter"}, false},
		{[]string{"fofa", "hunter"}, true}, {[]string{"fofa", "hunter", "quake"}, true},
	} {
		cfg := config.Defaults()
		cfg.ReconAgents = tc.agents
		opts := buildReconOptions(cfg)
		if opts.HunterFofa != tc.want {
			t.Fatalf("agents=%v linked=%v", tc.agents, opts.HunterFofa)
		}
	}
}
