package app

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"dddd-next/internal/audit"
	"dddd-next/internal/config"
	"dddd-next/internal/reporter"
)

func TestScannedUnidentifiedPortIsInAssetCSV(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	var out bytes.Buffer
	assets, err := reporter.NewAssetCSVWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Ports = strconv.Itoa(port)
	p := &Pipeline{cfg: cfg, assets: assets, auditor: audit.Disabled()}
	found := p.scanPorts(context.Background(), []string{"127.0.0.1"})
	if len(found) != 1 {
		t.Fatalf("ports=%v", found)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "127.0.0.1,127.0.0.1,"+strconv.Itoa(port)+",,,,,portscan,open") {
		t.Fatalf("unidentified open port missing: %s", out.String())
	}
}
