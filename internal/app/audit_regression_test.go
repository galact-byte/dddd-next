package app

import (
	"context"
	"dddd-next/internal/audit"
	"dddd-next/internal/config"
	"dddd-next/internal/discovery/portscan"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestAuditTCPExcludeAllDoesNotRestoreDefaults(t *testing.T) {
	var listener net.Listener
	var selected int
	for _, port := range portscan.DefaultPorts {
		if port < 10000 {
			continue
		}
		candidate, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			listener, selected = candidate, port
			break
		}
	}
	if listener == nil {
		t.Fatal("无法建立本地默认端口监听器")
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	cfg := config.Defaults()
	cfg.Ports = strconv.Itoa(selected)
	cfg.ExcludePorts = cfg.Ports
	cfg.PortScanTimeout = 1
	p := &Pipeline{cfg: cfg, auditor: audit.Disabled()}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	got := p.tcpScan(ctx, []string{"127.0.0.1"})
	t.Logf("requested=%s excluded=%s observed=%v", cfg.Ports, cfg.ExcludePorts, got)
	if len(got) != 0 {
		t.Errorf("端口全部排除后仍产生 %d 条开放结果", len(got))
	}
}

func TestAuditSYNRespectsExcludedPorts(t *testing.T) {
	p := &Pipeline{cfg: config.Config{Ports: "80,443", ExcludePorts: "443"}}
	spec, err := p.synPortSpec()
	if err != nil {
		t.Fatal(err)
	}
	got, err := portscan.ParsePortSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SYN 下发的端口列表=%v", got)
	for _, port := range got {
		if port == 443 {
			t.Error("SYN 下发列表仍包含显式排除的 443")
		}
	}
}

func TestAuditDisablingOnlyLivenessProbeRetainsHosts(t *testing.T) {
	cfg := config.Defaults()
	cfg.PingFirst, cfg.NoICMPPing = true, true
	p := &Pipeline{cfg: cfg}
	got := p.hostDiscovery(context.Background(), []string{"127.0.0.1"})
	t.Logf("-ping -nip 的主机结果=%v", got)
	if len(got) != 1 {
		t.Error("禁用唯一启用的存活探测后不应丢掉所有目标")
	}
}
