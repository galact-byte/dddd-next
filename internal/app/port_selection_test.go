package app

import (
	"context"
	"slices"
	"testing"

	"dddd-next/internal/config"
	"dddd-next/internal/discovery/portscan"
)

func TestScanPortSelectionSharedAcrossTCPAndSYN(t *testing.T) {
	for _, tc := range []struct {
		name, ports, exclude string
		want                 []int
		wantErr              bool
	}{
		{"partial", "80,443,8080-8082", "443,8081", []int{80, 8080, 8082}, false},
		{"all excluded", "80,443", "80,443", []int{}, false},
		{"invalid selection", "0", "", nil, true},
		{"invalid exclusion", "80", "broken", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Pipeline{cfg: config.Config{Ports: tc.ports, ExcludePorts: tc.exclude}}
			got, err := p.scanPortList()
			if (err != nil) != tc.wantErr {
				t.Fatalf("ports=%v err=%v", got, err)
			}
			spec, synErr := p.synPortSpec()
			if (synErr != nil) != tc.wantErr {
				t.Fatalf("SYN spec=%q err=%v", spec, synErr)
			}
			if tc.wantErr {
				return
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("ports=%v want=%v", got, tc.want)
			}
			if len(tc.want) == 0 {
				if spec != "" {
					t.Fatalf("empty SYN spec=%q", spec)
				}
				result, ok := p.synScan(context.Background(), []string{"127.0.0.1"})
				if !ok || len(result) != 0 {
					t.Fatalf("empty SYN selection attempted scan/fallback: %v %v", result, ok)
				}
			} else {
				parsed, err := portscan.ParsePortSpec(spec)
				if err != nil || !slices.Equal(parsed, tc.want) {
					t.Fatalf("SYN ports=%v err=%v", parsed, err)
				}
			}
		})
	}
	for _, spec := range []string{"all", "full", "  FULL  "} {
		p := &Pipeline{cfg: config.Config{Ports: spec, ExcludePorts: "2-65534"}}
		got, err := p.scanPortList()
		if err != nil || !slices.Equal(got, []int{1, 65535}) {
			t.Fatalf("%s: got=%v err=%v", spec, got, err)
		}
	}
}
