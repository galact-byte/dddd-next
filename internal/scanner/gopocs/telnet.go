package gopocs

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"dddd-next/internal/scanner/gopocs/telnetlib"
	"dddd-next/internal/types"
)

type telnetCracker struct{}

func (telnetCracker) Service() string { return "telnet" }

// Try opens a fresh connection per credential (Telnet has no reusable auth
// channel) and drives the login mode. UnauthorizedAccess/Closed return an error
// to abandon the endpoint — probeTelnet already reports the former, and brute
// forcing either would only yield misleading "weak credential" hits.
func (telnetCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	client := telnetlib.New(host, port, timeout)
	if err := client.Connect(); err != nil {
		return false, err
	}
	defer client.Close()

	client.ServerType = client.MakeServerType()
	switch client.ServerType {
	case telnetlib.OnlyPassword:
		client.Password = cred.Pass
	case telnetlib.UsernameAndPassword:
		client.UserName = cred.User
		client.Password = cred.Pass
	default:
		return false, errors.New("telnet: no credential login prompt")
	}

	err := client.Login()
	if err == nil {
		return true, nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "login failed") {
		return false, nil
	}
	return false, err
}

// probeTelnet flags a Telnet service that drops straight to a shell with no
// login prompt (UnauthorizedAccess).
func probeTelnet(ctx context.Context, host string, port int, timeout time.Duration) (*types.Finding, error) {
	client := telnetlib.New(host, port, timeout)
	if err := client.Connect(); err != nil {
		return nil, err
	}
	defer client.Close()

	if client.MakeServerType() != telnetlib.UnauthorizedAccess {
		return nil, nil
	}
	return &types.Finding{
		ID:           "telnet-unauthorized",
		Name:         "Telnet Unauthorized Access",
		Severity:     types.SeverityCritical,
		Target:       net.JoinHostPort(host, strconv.Itoa(port)),
		Description:  "Telnet drops to an interactive shell without authentication",
		Tags:         []string{"telnet", "unauthorized"},
		DiscoveredAt: time.Now(),
	}, nil
}
