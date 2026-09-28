package telnetlib

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAuditTelnetFragmentDoesNotPanic(t *testing.T) {
	for name, packet := range map[string][]byte{"split_negotiation": {IAC, DO}, "unfinished_subnegotiation": {IAC, SB, ECHO}} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("普通 TCP 分片导致 panic: %v", r)
				}
			}()
			client := New("127.0.0.1", 23, 0)
			client.serializeResponse(packet)
		})
	}
}

func TestAuditTelnetReaderDoesNotCrashProcess(t *testing.T) {
	if os.Getenv("DDDD_AUDIT_TELNET_CHILD") == "1" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.Write([]byte{IAC, SB, ECHO})
		}()
		client := New("127.0.0.1", listener.Addr().(*net.TCPAddr).Port, time.Second)
		defer client.Close()
		if err := client.Connect(); err != nil {
			t.Fatal(err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAuditTelnetReaderDoesNotCrashProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "DDDD_AUDIT_TELNET_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "panic:") {
			t.Fatalf("子进程环境异常: %v\n%s", err, output)
		}
		t.Fatalf("真实本地 Telnet 连接导致整个测试子进程崩溃: %v\n%s", err, output)
	}
}
