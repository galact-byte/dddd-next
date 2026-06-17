package gopocs

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"dddd-next/internal/types"
)

// DCE/RPC bind exchange buffers for the endpoint mapper (port 135).
var (
	rpcBindReq1  []byte
	rpcBindReq2  []byte
	rpcEndMarker []byte
)

func init() {
	rpcBindReq1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	rpcBindReq2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	rpcEndMarker, _ = hex.DecodeString("0900ffff0000")
}

// probeRPC leaks Windows hostname + NIC IPs via the RPC endpoint mapper (port 135).
func probeRPC(ctx context.Context, host string, port int, timeout time.Duration) (_ *types.Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("rpc: panic recovered: %v", r)
		}
	}()

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(rpcBindReq1); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil {
		return nil, err
	}

	if _, err := conn.Write(rpcBindReq2); err != nil {
		return nil, err
	}
	n, err := conn.Read(buf)
	if err != nil || n < 42 {
		return nil, fmt.Errorf("rpc: bind-ack: %w", err)
	}

	payload := buf[42:n]
	if i := bytes.Index(payload, rpcEndMarker); i >= 0 {
		if i >= 4 {
			payload = payload[:i-4]
		} else {
			return nil, nil
		}
	} else {
		return nil, fmt.Errorf("rpc: end marker not found")
	}

	info := parseRPCBindAck(payload)
	if info.Hostname == "" {
		return nil, nil
	}

	desc := host + " " + info.Hostname
	for _, ip := range info.IPs {
		desc += " => " + ip
	}

	return &types.Finding{
		ID:           "rpc-info-leak",
		Name:         "RPC Endpoint Mapper Information Leak",
		Severity:     types.SeverityInfo,
		Target:       addr,
		Description:  fmt.Sprintf("RPC epmapper (port 135) leaks host identity: %s", desc),
		Tags:         []string{"rpc", "info-leak", "windows"},
		DiscoveredAt: time.Now(),
	}, nil
}

type rpcBindAck struct {
	Hostname string
	IPs      []string
}

func parseRPCBindAck(raw []byte) rpcBindAck {
	var info rpcBindAck

	hostname, consumed := decodeUTF16LEUntilNull(raw)
	info.Hostname = hostname
	if consumed == 0 {
		return info
	}

	hexStr := hex.EncodeToString(raw)
	no7000 := strings.ReplaceAll(hexStr, "0700", "")
	for _, chunk := range strings.Split(no7000, "000000") {
		stripped := strings.ReplaceAll(chunk, "00", "")
		b, err := hex.DecodeString(stripped)
		if err != nil || len(b) == 0 {
			continue
		}
		if ip := net.ParseIP(string(b)); ip != nil {
			info.IPs = append(info.IPs, ip.String())
		}
	}
	return info
}

func decodeUTF16LEUntilNull(b []byte) (string, int) {
	if len(b) < 2 {
		return "", 0
	}
	var u16 []uint16
	pos := 0
	for pos+1 < len(b) {
		cu := binary.LittleEndian.Uint16(b[pos:])
		pos += 2
		if cu == 0 {
			break
		}
		u16 = append(u16, cu)
	}
	if len(u16) == 0 {
		return "", pos
	}
	return string(utf16.Decode(u16)), pos
}
