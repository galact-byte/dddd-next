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
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// Dial with deadline on BOTH TCP connect AND SSH handshake.
	// ssh.Dial's Timeout only covers TCP; the handshake can hang forever.
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	cfg := &ssh.ClientConfig{
		User:            cred.User,
		Auth:            []ssh.AuthMethod{ssh.Password(cred.Pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		if isSSHAuthFailure(err) {
			return false, nil
		}
		return false, err
	}
	_ = ssh.NewClient(c, chans, reqs).Close()
	return true, nil
}

func isSSHAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods remain")
}
