package telnetlib

import (
	"bytes"
	"testing"
)

func TestNegotiationSurvivesEveryReadBoundary(t *testing.T) {
	wire := []byte{'a', IAC, DO, ECHO, IAC, IAC, 'b', IAC, SB, ECHO, ECHO, IAC, SE, IAC, 241, 'c'}
	wantDisplay := []byte{'a', IAC, 'b', 'c'}
	wantReply := []byte{IAC, WILL, ECHO, IAC, SB, ECHO, BINARY, IAC, SE}
	for split := 0; split <= len(wire); split++ {
		c := &Client{}
		var display, reply []byte
		for _, chunk := range [][]byte{wire[:split], wire[split:]} {
			text, commands := c.serializeResponse(chunk)
			display = append(display, text...)
			reply = append(reply, c.makeReplyFromList(commands)...)
		}
		if !bytes.Equal(display, wantDisplay) || !bytes.Equal(reply, wantReply) {
			t.Errorf("split=%d display=%v reply=%v", split, display, reply)
		}
	}
}

func TestShortSubnegotiationDoesNotPanic(t *testing.T) {
	c := &Client{}
	if got := c.makeReply([]byte{IAC, SB, ECHO}); len(got) != 0 {
		t.Fatalf("short command reply=%v", got)
	}
}
