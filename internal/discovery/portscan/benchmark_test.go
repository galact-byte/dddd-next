package portscan

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

// This baseline keeps the discovered set fixed while comparing the completion
// hook overhead. It does not represent WAN throughput or a comparison to dddd.
func BenchmarkScanLocal(b *testing.B) {
	var listeners []net.Listener
	var ports []int
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
		if i == 2 {
			ln.Close()
			continue
		}
		listeners = append(listeners, ln)
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()
	}
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()
	expected := map[int]bool{ports[0]: true, ports[1]: true}
	for _, withHook := range []bool{false, true} {
		name := "NoHook"
		if withHook {
			name = "CompletionHook"
		}
		b.Run(name, func(b *testing.B) {
			var completed atomic.Int64
			opts := Options{Ports: ports, Threads: 3, TimeoutSeconds: 1}
			if withHook {
				opts.OnComplete = func(error) { completed.Add(1) }
			}
			scanner := New(opts)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				seen := make(map[int]bool)
				for result := range scanner.Scan(context.Background(), []string{"127.0.0.1"}) {
					seen[result.Port] = true
				}
				if len(seen) != 2 || !seen[ports[0]] || !seen[ports[1]] || seen[ports[2]] {
					b.Fatalf("discovered=%v expected=%v", seen, expected)
				}
			}
			b.StopTimer()
			if withHook && completed.Load() != int64(b.N)*3 {
				b.Fatalf("completed=%d expected=%d", completed.Load(), b.N*3)
			}
			b.ReportMetric(2, "open/scan")
		})
	}
}
