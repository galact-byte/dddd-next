package app

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"dddd-next/internal/config"
)

func TestTCPStageReportsCompletedClosedAndOpenPorts(t *testing.T) {
	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = old; reader.Close(); writer.Close() }()
	cfg := config.Defaults()
	cfg.Ports = strconv.Itoa(open.Addr().(*net.TCPAddr).Port) + "," + strconv.Itoa(closedPort)
	p := &Pipeline{cfg: cfg}
	result := p.tcpScan(context.Background(), []string{"127.0.0.1"})
	writer.Close()
	os.Stderr = old
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || !strings.Contains(string(output), "2/2") || !strings.Contains(string(output), "未成功 1") {
		t.Fatalf("result=%v progress=%s", result, output)
	}
}
