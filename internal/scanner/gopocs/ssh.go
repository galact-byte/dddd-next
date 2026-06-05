package gopocs

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshCracker struct{}

func (sshCracker) Service() string { return "ssh" }

func (sshCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	cfg := &ssh.ClientConfig{
		User:            cred.User,
		Auth:            []ssh.AuthMethod{ssh.Password(cred.Pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		if isSSHAuthFailure(err) {
			return false, nil
		}
		return false, err
	}
	_ = client.Close()
	return true, nil
}

// isSSHAuthFailure distinguishes a rejected password (keep trying the dict)
// from a transport error (give up on the host).
func isSSHAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods remain")
}
