package gopocs

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"dddd-next/internal/types"

	"gopkg.in/yaml.v3"
)

// probeNetBIOS leaks a Windows host's NetBIOS identity (hostname, workgroup/
// domain, OS version) via the UDP 137 name service plus an SMBv1 NTLM negotiate
// on TCP 139. INFO severity. The parsers do fiddly offset arithmetic on
// untrusted responses, so a recover keeps a malformed reply from crashing the scan.
func probeNetBIOS(ctx context.Context, host string, port int, timeout time.Duration) (f *types.Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			f, err = nil, fmt.Errorf("netbios: recovered from %v", r)
		}
	}()

	info := nbnsName(host, timeout) // UDP 137, best-effort

	var sessionReq []byte
	if ss := info.ServerService; ss != "" || info.WorkstationService != "" {
		if ss == "" {
			ss = info.WorkstationService
		}
		sessionReq = append(sessionReq, []byte("\x81\x00\x00D ")...)
		sessionReq = append(sessionReq, netbiosEncode(ss)...)
		sessionReq = append(sessionReq, []byte("\x00 EOENEBFACACACACACACACACACACACACA\x00")...)
	}

	conn, derr := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if derr == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if info2, ok := nbnsNTLM(conn, port, sessionReq); ok {
			joinNetBios(&info, &info2)
		}
	}

	out := info.String()
	if out == "" {
		return nil, nil
	}
	return &types.Finding{
		ID:           "netbios-info-leak",
		Name:         "NetBIOS Information Leak",
		Severity:     types.SeverityInfo,
		Target:       net.JoinHostPort(host, strconv.Itoa(port)),
		Description:  "NetBIOS exposes host/domain identity: " + strings.TrimSpace(out),
		Tags:         []string{"netbios", "info-leak"},
		DiscoveredAt: time.Now(),
	}, nil
}

// nbnsName sends the NBSTAT node-status query to UDP 137 and parses the name
// table. Returns a zero netbiosInfo on any failure (best-effort).
func nbnsName(host string, timeout time.Duration) netbiosInfo {
	query := []byte{102, 102, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32, 67, 75, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 0, 0, 33, 0, 1}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "137"), timeout)
	if err != nil {
		return netbiosInfo{}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return netbiosInfo{}
	}
	resp, _ := readBytesConn(conn)
	info, _ := parseNetBios(resp)
	return info
}

// nbnsNTLM negotiates SMBv1 to extract the NTLM type-2 OS/computer/domain
// fields. ok is false if the exchange yields nothing usable.
func nbnsNTLM(conn net.Conn, port int, sessionReq []byte) (netbiosInfo, bool) {
	if port == 139 && len(sessionReq) > 0 {
		if _, err := conn.Write(sessionReq); err != nil {
			return netbiosInfo{}, false
		}
		if _, err := readBytesConn(conn); err != nil {
			return netbiosInfo{}, false
		}
	}
	if _, err := conn.Write(negotiateSMBv1Data1); err != nil {
		return netbiosInfo{}, false
	}
	if _, err := readBytesConn(conn); err != nil {
		return netbiosInfo{}, false
	}
	if _, err := conn.Write(negotiateSMBv1Data2); err != nil {
		return netbiosInfo{}, false
	}
	ret, err := readBytesConn(conn)
	if err != nil {
		return netbiosInfo{}, false
	}
	info, perr := parseNTLM(ret)
	return info, perr == nil
}

func readBytesConn(conn net.Conn) ([]byte, error) {
	const size = 4096
	buf := make([]byte, size)
	var result []byte
	for {
		count, err := conn.Read(buf)
		if count > 0 {
			result = append(result, buf[:count]...)
		}
		if err != nil || count < size {
			break
		}
	}
	if len(result) > 0 {
		return result, nil
	}
	return result, fmt.Errorf("netbios: empty response")
}

func byteToInt(b byte) (int, error) { return strconv.Atoi(fmt.Sprintf("%v", b)) }

// netbiosEncode applies the first-level NetBIOS name encoding (each byte split
// into two nibbles, offset by 'A').
func netbiosEncode(name string) []byte {
	var out []byte
	for _, a := range fmt.Sprintf("%-16s", name) {
		c := int(a)
		out = append(out, byte((c>>4)+0x41), byte((c&0x0f)+0x41))
	}
	return out
}

var (
	uniqueNames = map[string]string{
		"\x00": "WorkstationService",
		"\x03": "Messenger Service",
		"\x06": "RAS Server Service",
		"\x1F": "NetDDE Service",
		"\x20": "ServerService",
		"\x21": "RAS Client Service",
		"\xBE": "Network Monitor Agent",
		"\xBF": "Network Monitor Application",
		"\x1D": "Master Browser",
		"\x1B": "Domain Master Browser",
	}
	groupNames = map[string]string{
		"\x00": "DomainName",
		"\x1C": "DomainControllers",
		"\x1E": "Browser Service Elections",
	}
	netbiosItemType = map[string]string{
		"\x01\x00": "NetBiosComputerName",
		"\x02\x00": "NetBiosDomainName",
		"\x03\x00": "ComputerName",
		"\x04\x00": "DomainName",
		"\x05\x00": "DNS tree name",
		"\x07\x00": "Time stamp",
	}
	negotiateSMBv1Data1 = []byte{
		0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
		0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
		0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
		0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
		0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
		0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
		0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
	}
	negotiateSMBv1Data2 = []byte{
		0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
		0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
		0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
		0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
		0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
		0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00,
		0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00,
		0x20, 0x00, 0x33, 0x00, 0x37, 0x00, 0x39, 0x00, 0x30, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x50, 0x00, 0x61, 0x00,
		0x63, 0x00, 0x6B, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00,
		0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
		0x33, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

type netbiosInfo struct {
	GroupName          string
	WorkstationService string `yaml:"WorkstationService"`
	ServerService      string `yaml:"ServerService"`
	DomainName         string `yaml:"DomainName"`
	DomainControllers  string `yaml:"DomainControllers"`
	ComputerName       string `yaml:"ComputerName"`
	OsVersion          string `yaml:"OsVersion"`
	NetDomainName      string `yaml:"NetBiosDomainName"`
	NetComputerName    string `yaml:"NetBiosComputerName"`
}

func (info *netbiosInfo) String() (output string) {
	var text string
	if info.ComputerName != "" {
		if !strings.Contains(info.ComputerName, ".") && info.GroupName != "" {
			text = fmt.Sprintf("%s\\%s", info.GroupName, info.ComputerName)
		} else {
			text = info.ComputerName
		}
	} else {
		if info.DomainName != "" {
			text += info.DomainName + "\\"
		} else if info.NetDomainName != "" {
			text += info.NetDomainName + "\\"
		}
		if info.ServerService != "" {
			text += info.ServerService
		} else if info.WorkstationService != "" {
			text += info.WorkstationService
		} else if info.NetComputerName != "" {
			text += info.NetComputerName
		}
	}
	if text == "" {
		return ""
	}
	if info.DomainControllers != "" {
		output = fmt.Sprintf("[+]DC %-24s", text)
	} else {
		output = fmt.Sprintf("%-30s", text)
	}
	if info.OsVersion != "" {
		output += "      " + info.OsVersion
	}
	return output
}

func parseNetBios(input []byte) (netbiosInfo, error) {
	var info netbiosInfo
	if len(input) < 57 {
		return info, fmt.Errorf("netbios: short response")
	}
	data := input[57:]
	num, err := byteToInt(input[56])
	if err != nil {
		return info, err
	}
	var msg string
	for i := 0; i < num; i++ {
		if len(data) < 18*i+16 {
			break
		}
		name := string(data[18*i : 18*i+15])
		flagBit := data[18*i+15 : 18*i+16]
		if groupNames[string(flagBit)] != "" && string(flagBit) != "\x00" {
			msg += fmt.Sprintf("%s: %s\n", groupNames[string(flagBit)], name)
		} else if uniqueNames[string(flagBit)] != "" && string(flagBit) != "\x00" {
			msg += fmt.Sprintf("%s: %s\n", uniqueNames[string(flagBit)], name)
		} else if string(flagBit) == "\x00" || len(data) >= 18*i+18 {
			nameFlags := data[18*i+16 : 18*i+18][0]
			if nameFlags >= 128 {
				msg += fmt.Sprintf("%s: %s\n", groupNames[string(flagBit)], name)
			} else {
				msg += fmt.Sprintf("%s: %s\n", uniqueNames[string(flagBit)], name)
			}
		} else {
			msg += fmt.Sprintf("%s \n", name)
		}
	}
	if len(msg) == 0 {
		return info, fmt.Errorf("netbios: no names")
	}
	if err := yaml.Unmarshal([]byte(msg), &info); err != nil {
		return info, err
	}
	if info.DomainName != "" {
		info.GroupName = info.DomainName
	}
	return info, nil
}

func parseNTLM(ret []byte) (netbiosInfo, error) {
	var info netbiosInfo
	if len(ret) < 47 {
		return info, fmt.Errorf("netbios: short ntlm")
	}
	num1, err := byteToInt(ret[43])
	if err != nil {
		return info, err
	}
	num2, err := byteToInt(ret[44])
	if err != nil {
		return info, err
	}
	length := num1 + num2*256
	if len(ret) < 48+length {
		return info, nil
	}
	osVersion := ret[47+length:]
	tmp := bytes.ReplaceAll(osVersion, []byte{0x00, 0x00}, []byte{124})
	tmp = bytes.ReplaceAll(tmp, []byte{0x00}, []byte{})
	if len(tmp) == 0 {
		return info, nil
	}
	info.OsVersion = strings.Split(string(tmp[:len(tmp)-1]), "|")[0]

	start := bytes.Index(ret, []byte("NTLMSSP"))
	if start < 0 || len(ret) < start+45 {
		return info, nil
	}
	num1, _ = byteToInt(ret[start+40])
	num2, _ = byteToInt(ret[start+41])
	length = num1 + num2*256
	offset, err := byteToInt(ret[start+44])
	if err != nil || len(ret) < start+offset+length {
		return info, nil
	}
	var msg string
	for index := start + offset; index < start+offset+length; {
		if index+4 > len(ret) {
			break
		}
		itemType := ret[index : index+2]
		n1, _ := byteToInt(ret[index+2])
		n2, _ := byteToInt(ret[index+3])
		itemLength := n1 + n2*256
		if index+4+itemLength > len(ret) {
			break
		}
		itemContent := bytes.ReplaceAll(ret[index+4:index+4+itemLength], []byte{0x00}, []byte{})
		index += 4 + itemLength
		if string(itemType) == "\x07\x00" {
			continue // time stamp, not useful
		} else if netbiosItemType[string(itemType)] != "" {
			msg += fmt.Sprintf("%s: %s\n", netbiosItemType[string(itemType)], string(itemContent))
		} else if string(itemType) == "\x00\x00" {
			break
		}
	}
	if err := yaml.Unmarshal([]byte(msg), &info); err != nil {
		return info, err
	}
	return info, nil
}

func joinNetBios(dst, src *netbiosInfo) {
	dst.ComputerName = src.ComputerName
	dst.NetDomainName = src.NetDomainName
	dst.NetComputerName = src.NetComputerName
	if src.DomainName != "" {
		dst.DomainName = src.DomainName
	}
	dst.OsVersion = src.OsVersion
}
