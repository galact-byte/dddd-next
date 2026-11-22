package portscan

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

func TestCompletionIncludesClosedPorts(t *testing.T) {
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
	var completed, failed atomic.Int64
	opts := DefaultOptions()
	opts.Ports = []int{open.Addr().(*net.TCPAddr).Port, closedPort}
	opts.Threads = 1
	opts.OnComplete = func(err error) {
		completed.Add(1)
		if err != nil {
			failed.Add(1)
		}
	}
	n := 0
	for range New(opts).Scan(context.Background(), []string{"127.0.0.1"}) {
		n++
	}
	if n != 1 || completed.Load() != 2 || failed.Load() != 1 {
		t.Fatalf("open=%d completed=%d failed=%d", n, completed.Load(), failed.Load())
	}
}
