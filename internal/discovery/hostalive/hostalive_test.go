package hostalive

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestPingCommandLoopback exercises the privilege-free ping path against
// loopback, which always answers. Skipped if no ping binary is on PATH.
func TestPingCommandLoopback(t *testing.T) {
	if _, err := exec.LookPath(pingBinary()); err != nil {
		t.Skip("ping binary not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	alive := CheckLive(ctx, []string{"127.0.0.1"}, true)
	if len(alive) != 1 || alive[0] != "127.0.0.1" {
		t.Fatalf("loopback should be alive, got %v", alive)
	}
}

func TestCheckLiveEmpty(t *testing.T) {
	if got := CheckLive(context.Background(), nil, true); got != nil {
		t.Errorf("empty host list should return nil, got %v", got)
	}
}

// TestChecksumValid verifies the ICMP checksum invariant: re-summing a packet
// that already carries its checksum folds to zero.
func TestChecksumValid(t *testing.T) {
	msg := makeEchoRequest("192.168.1.1")
	if msg[0] != 8 {
		t.Errorf("type byte = %d, want 8 (echo request)", msg[0])
	}
	if checksum(msg) != 0 {
		t.Errorf("checksum over a checksummed packet = %#x, want 0", checksum(msg))
	}
}

func TestIdentifierShortHost(t *testing.T) {
	if a, b := identifier(""); a != 0 || b != 0 {
		t.Errorf(`identifier("") = %d,%d, want 0,0 (no panic)`, a, b)
	}
	if a, b := identifier("ab"); a != 'a' || b != 'b' {
		t.Errorf(`identifier("ab") = %d,%d, want 'a','b'`, a, b)
	}
}
