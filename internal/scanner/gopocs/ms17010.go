package gopocs

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"dddd-next/internal/types"
)

// MS17-010 (EternalBlue) SMB1 detection packets — the decrypted form of upstream
// dddd's AES-wrapped originals (SMB1 magic ff534d42), kept as plaintext hex.
var (
	ms17010Negotiate, _      = hex.DecodeString("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
	ms17010SessionSetup, _   = hex.DecodeString("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
	ms17010TreeConnect, _    = hex.DecodeString("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
	ms17010TransNamedPipe, _ = hex.DecodeString("0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
)

// probeMS17010 runs the EternalBlue (MS17-010) SMB1 detection: negotiate →
// session-setup → tree-connect → trans on \PIPE\, where a final
// STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) marks the host vulnerable. No
// credentials — a pure protocol probe, so it lives outside the Cracker path.
func probeMS17010(ctx context.Context, host string, port int, timeout time.Duration) (*types.Finding, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reply := make([]byte, 1024)

	if _, err := conn.Write(ms17010Negotiate); err != nil {
		return nil, fmt.Errorf("ms17010 negotiate write: %w", err)
	}
	nr, err := conn.Read(reply)
	if err != nil {
		return nil, fmt.Errorf("ms17010 negotiate read: %w", err)
	}
	if nr < 36 {
		return nil, fmt.Errorf("ms17010 negotiate: short response %d bytes", nr)
	}
	status := binary.LittleEndian.Uint32(reply[9:13])
	if status != 0 {
		fmt.Printf("[*] ms17010: %s:%d SMBv1 negotiate failed (NT=0x%08X, patched)\n", host, port, status)
		return nil, nil
	}

	if _, err := conn.Write(ms17010SessionSetup); err != nil {
		return nil, fmt.Errorf("ms17010 session-setup write: %w", err)
	}
	nr, err = conn.Read(reply)
	if err != nil {
		return nil, fmt.Errorf("ms17010 session-setup read: %w", err)
	}
	if nr < 36 {
		return nil, fmt.Errorf("ms17010 session-setup: short response %d bytes", nr)
	}
	status = binary.LittleEndian.Uint32(reply[9:13])
	if status != 0 {
		fmt.Printf("[*] ms17010: %s:%d SMBv1 session failed (NT=0x%08X)\n", host, port, status)
		return nil, nil
	}
	n := nr
	osName := ms17010OS(reply[:n])
	userID := []byte{reply[32], reply[33]}

	// copy before patching: the request templates are package-global and Run is
	// concurrent, so mutating them in place would race across goroutines.
	tree := append([]byte(nil), ms17010TreeConnect...)
	tree[32], tree[33] = userID[0], userID[1]
	if _, err := conn.Write(tree); err != nil {
		return nil, fmt.Errorf("ms17010 tree-connect write: %w", err)
	}
	tn, terr := conn.Read(reply)
	if terr != nil {
		return nil, fmt.Errorf("ms17010 tree-connect read: %w", terr)
	}
	if tn < 36 {
		return nil, fmt.Errorf("ms17010 tree-connect: short response %d bytes", tn)
	}
	treeStatus := binary.LittleEndian.Uint32(reply[9:13])
	if treeStatus != 0 {
		fmt.Printf("[*] ms17010: %s:%d IPC$ tree connect failed (NT=0x%08X)\n", host, port, treeStatus)
		return nil, nil
	}
	treeID := []byte{reply[28], reply[29]}
	_ = tn

	pipe := append([]byte(nil), ms17010TransNamedPipe...)
	pipe[28], pipe[29] = treeID[0], treeID[1]
	pipe[32], pipe[33] = userID[0], userID[1]
	if _, err := conn.Write(pipe); err != nil {
		return nil, err
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return nil, err
	}

	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		desc := "Host is vulnerable to MS17-010 (EternalBlue) SMB remote code execution"
		if osName != "" {
			desc += " — " + osName
		}
		return &types.Finding{
			ID:           "ms17-010",
			Name:         "MS17-010 EternalBlue SMB RCE",
			Severity:     types.SeverityCritical,
			Target:       net.JoinHostPort(host, strconv.Itoa(port)),
			Description:  desc,
			Tags:         []string{"ms17-010", "eternalblue", "smb", "rce"},
			DiscoveredAt: time.Now(),
		}, nil
	}
	fmt.Printf("[*] ms17010: %s:%d trans status=0x%02X%02X%02X%02X (not vulnerable)\n", host, port, reply[9], reply[10], reply[11], reply[12])
	return nil, nil
}

// ms17010OS pulls the OS banner from the session-setup response (best effort;
// the vuln verdict doesn't depend on it).
func ms17010OS(resp []byte) string {
	if len(resp) < 46 || resp[36] == 0 {
		return ""
	}
	s := resp[36:]
	for i := 10; i < len(s)-1; i++ {
		if s[i] == 0 && s[i+1] == 0 {
			return strings.ReplaceAll(string(s[10:i]), "\x00", "")
		}
	}
	return ""
}
