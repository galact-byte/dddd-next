package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"dddd-next/internal/audit"
	"dddd-next/internal/config"
	"dddd-next/internal/discovery/portscan"
)

func TestPortThresholdPreservesScatteredServices(t *testing.T) {
	p := &Pipeline{cfg: config.Defaults(), auditor: audit.Disabled()}
	input := []portscan.Result{{Host: "192.0.2.10", Port: 22}}
	for port := 12000; port < 12600; port += 2 {
		input = append(input, portscan.Result{Host: "192.0.2.10", Port: port})
	}
	got := p.retainPortsWithWarnings(input)
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("301 observed ports including SSH must survive anomaly handling: got %d", len(got))
	}
}

func TestScanPortsPreservesRealHTTPServiceDespiteAnomalyThresholds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "real service")
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	cfg := config.Defaults()
	cfg.Ports = fmt.Sprint(port)
	cfg.FirewallRunLen = 1
	cfg.PortsThreshold = 0
	p := &Pipeline{cfg: cfg, auditor: audit.Disabled()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := p.scanPorts(ctx, []string{"127.0.0.1"})
	want := []portscan.Result{{Host: "127.0.0.1", Port: port}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("real HTTP service removed by contiguous-port heuristic: got %v want %v", got, want)
	}
	services := p.detectServices(ctx, got)
	if services[fmt.Sprintf("127.0.0.1:%d", port)] != "http" {
		t.Fatalf("retained port did not reach HTTP service detection: %v", services)
	}
}

func TestPortAnomalyWarningsPreserveContinuousPortsAndAudit(t *testing.T) {
	var input []portscan.Result
	for port := 12000; port <= 13000; port++ {
		input = append(input, portscan.Result{Host: "192.0.2.10", Port: port})
	}
	input = append(input, portscan.Result{Host: "192.0.2.11", Port: 22})
	var log bytes.Buffer
	cfg := config.Defaults()
	p := &Pipeline{cfg: cfg, auditor: audit.NewWriter(&log)}
	if got := p.retainPortsWithWarnings(input); !reflect.DeepEqual(got, input) {
		t.Fatal("mixed hosts or port 12500 removed from a continuous range")
	}
	decoder := json.NewDecoder(&log)
	reasons := make(map[string]bool)
	for decoder.More() {
		var ev audit.Event
		if err := decoder.Decode(&ev); err != nil {
			t.Fatal(err)
		}
		if ev.Action != "port-anomaly" || ev.Detail["host"] != "192.0.2.10" || ev.Detail["action"] != "retained" || ev.Detail["ports"] != float64(1001) {
			t.Fatalf("missing or inaccurate diagnostic: %+v", ev)
		}
		reasons[ev.Detail["reason"].(string)] = true
	}
	if !reasons["contiguous"] || !reasons["count"] {
		t.Fatalf("missing anomaly reason: %v", reasons)
	}
	log.Reset()
	p.cfg.FirewallRunLen, p.cfg.PortsThreshold = 0, 0
	if got := p.retainPortsWithWarnings(input); !reflect.DeepEqual(got, input) || log.Len() != 0 {
		t.Fatal("disabling diagnostics must preserve ports without logging warnings")
	}
}

func TestScanPortsAlreadyCancelledReturnsPromptly(t *testing.T) {
	cfg := config.Defaults()
	cfg.Ports = "1-65535"
	p := &Pipeline{cfg: cfg, auditor: audit.Disabled()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if got := p.scanPorts(ctx, []string{"127.0.0.1"}); len(got) != 0 {
		t.Fatalf("cancelled scan returned %v", got)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancel took %s", elapsed)
	}
}

func TestScanPortsPreservesHostAboveCountThreshold(t *testing.T) {
	var ports []string
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		ports = append(ports, fmt.Sprint(ln.Addr().(*net.TCPAddr).Port))
	}
	cfg := config.Defaults()
	cfg.Ports = strings.Join(ports, ",")
	cfg.PortsThreshold = 2
	cfg.FirewallRunLen = 0
	p := &Pipeline{cfg: cfg, auditor: audit.Disabled()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got := p.scanPorts(ctx, []string{"127.0.0.1"}); len(got) != 3 {
		t.Fatalf("host exceeding warning threshold lost ports: got %d want 3", len(got))
	}
}
