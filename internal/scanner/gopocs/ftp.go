package gopocs

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/jlaffaye/ftp"
)

type ftpCracker struct{}

func (ftpCracker) Service() string { return "ftp" }

func (ftpCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	conn, err := ftp.Dial(net.JoinHostPort(host, strconv.Itoa(port)), ftp.DialWithTimeout(timeout))
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Quit() }()

	if err := conn.Login(cred.User, cred.Pass); err != nil {
		return false, nil // login rejected = wrong credentials
	}
	return true, nil
}
