package gopocs

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	smb2 "github.com/projectdiscovery/go-smb2"
)

type smbCracker struct{}

func (smbCracker) Service() string { return "smb" }

func (smbCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: cred.User, Password: cred.Pass}}
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	s, err := d.DialContext(ctx2, conn)
	if err != nil {
		if isSMBAuthFailure(err) {
			return false, nil
		}
		return false, err
	}
	_ = s.Logoff()
	return true, nil
}

// isSMBAuthFailure matches NTLM rejection status codes so a wrong password moves
// to the next credential; protocol/connection errors fall through and drop the
// host (e.g. an SMB1-only server we can't negotiate with).
func isSMBAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "STATUS_LOGON_FAILURE") ||
		strings.Contains(msg, "STATUS_ACCESS_DENIED") ||
		strings.Contains(msg, "STATUS_ACCOUNT_DISABLED") ||
		strings.Contains(msg, "STATUS_ACCOUNT_LOCKED_OUT") ||
		strings.Contains(msg, "STATUS_PASSWORD_EXPIRED")
}
