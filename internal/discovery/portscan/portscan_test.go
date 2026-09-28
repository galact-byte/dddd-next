package portscan

import (
	"context"
	"net"
	"reflect"
	"testing"
)

func TestDetectContiguousRuns(t *testing.T) {
	// Continuous TCP responses are suspicious, not proof that services are fake.
	var results []Result
	for _, p := range []int{22, 80, 443} {
		results = append(results, Result{Host: "10.0.0.1", Port: p})
	}
	for p := 12000; p <= 13000; p++ {
		results = append(results, Result{Host: "10.0.0.1", Port: p})
	}
	// A second host with only scattered real services.
	for _, p := range []int{25, 110, 143} {
		results = append(results, Result{Host: "10.0.0.2", Port: p})
	}

	before := append([]Result(nil), results...)
	observed := DetectContiguousRuns(results, 100)
	if observed["10.0.0.1"] != 1001 || observed["10.0.0.2"] != 0 {
		t.Fatalf("contiguous observations = %v, want only host1:1001", observed)
	}
	if !reflect.DeepEqual(results, before) {
		t.Fatal("anomaly detection changed observed ports or their order")
	}
}

func TestDetectContiguousRunsBoundary(t *testing.T) {
	mk := func(host string, lo, hi int) []Result {
		var rs []Result
		for p := lo; p <= hi; p++ {
			rs = append(rs, Result{Host: host, Port: p})
		}
		return rs
	}
	if got := DetectContiguousRuns(mk("h", 1000, 1099), 100)["h"]; got != 100 {
		t.Errorf("run of exactly 100 should flag 100, got %d", got)
	}
	if got := DetectContiguousRuns(mk("h", 1000, 1098), 100)["h"]; got != 0 {
		t.Errorf("run of 99 should not be flagged, got %d", got)
	}
	rs := mk("h", 1000, 1099)
	rs = append(rs, Result{Host: "h", Port: 1050})
	if got := DetectContiguousRuns(rs, 100)["h"]; got != 100 {
		t.Errorf("duplicate observation split or inflated the run: %d", got)
	}
}

func TestDetectContiguousRunsDisabled(t *testing.T) {
	rs := []Result{{Host: "h", Port: 1}, {Host: "h", Port: 2}}
	for _, threshold := range []int{0, -1} {
		if got := DetectContiguousRuns(rs, threshold); len(got) != 0 {
			t.Errorf("threshold %d should disable warnings, got %v", threshold, got)
		}
	}
	if got := DetectContiguousRuns(nil, 100); len(got) != 0 {
		t.Fatalf("empty input: %v", got)
	}
}

func TestParsePortSpec(t *testing.T) {
	if got, err := ParsePortSpec(""); err != nil || got != nil {
		t.Errorf("empty spec: got %v err %v, want nil/nil (falls back to defaults)", got, err)
	}

	got, err := ParsePortSpec("443,8000-8002,80")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{80, 443, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%d, want %d (sorted+deduped)", i, got[i], want[i])
		}
	}

	if all, err := ParsePortSpec("all"); err != nil || len(all) != 65535 {
		t.Errorf("all: len %d err %v, want 65535/nil", len(all), err)
	}

	for _, bad := range []string{"0", "70000", "abc", "5-1", "80-"} {
		if _, err := ParsePortSpec(bad); err == nil {
			t.Errorf("spec %q should error", bad)
		}
	}
}

func TestExpandHosts(t *testing.T) {
	tests := []struct {
		name    string
		specs   []string
		want    int
		wantErr bool
	}{
		{"single ip", []string{"10.0.0.1"}, 1, false},
		{"cidr /30", []string{"192.168.1.0/30"}, 4, false},
		{"cidr /32", []string{"192.168.1.1/32"}, 1, false},
		{"range", []string{"10.0.0.1-10.0.0.10"}, 10, false},
		{"dedup across specs", []string{"10.0.0.1", "10.0.0.1/32"}, 1, false},
		{"ipv6 cidr unsupported", []string{"2001:db8::/120"}, 0, true},
		{"garbage", []string{"999.1.1.1"}, 0, true},
		{"reversed range", []string{"10.0.0.10-10.0.0.1"}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandHosts(tt.specs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.want {
				t.Fatalf("want %d hosts, got %d (%v)", tt.want, len(got), got)
			}
		})
	}
}

func TestNewNormalizesPorts(t *testing.T) {
	s := New(Options{Ports: []int{80, 80, 443, 0, 70000}})
	if len(s.ports) != 2 {
		t.Fatalf("want 2 ports after dedup/range-filter, got %v", s.ports)
	}

	def := New(Options{})
	if len(def.ports) == 0 {
		t.Fatal("empty options should fall back to DefaultPorts")
	}
}

// TestScanReportsOnlyOpenPorts binds one port (kept open) and one that is
// immediately released (closed), then asserts the scanner reports only the
// open one. Loopback ephemeral-port reuse in the test window is unlikely.
func TestScanReportsOnlyOpenPorts(t *testing.T) {
	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	openPort := open.Addr().(*net.TCPAddr).Port

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	closedLn.Close()

	s := New(Options{Ports: []int{openPort, closedPort}, TimeoutSeconds: 2, Threads: 10})

	var got []Result
	for r := range s.Scan(context.Background(), []string{"127.0.0.1"}) {
		got = append(got, r)
	}

	if len(got) != 1 || got[0].Port != openPort {
		t.Fatalf("want only open port %d, got %v", openPort, got)
	}
}

func TestDefaultPortsCoverage(t *testing.T) {
	if len(DefaultPorts) < 900 {
		t.Fatalf("DefaultPorts len = %d, want ~1000 (TOP1000)", len(DefaultPorts))
	}
	has := func(p int) bool {
		for _, x := range DefaultPorts {
			if x == p {
				return true
			}
		}
		return false
	}
	for _, p := range []int{22, 80, 443, 3306, 6379, 8080, 8848} {
		if !has(p) {
			t.Errorf("DefaultPorts missing %d", p)
		}
	}
}
