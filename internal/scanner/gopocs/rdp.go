package gopocs

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
)

func init() { glog.SetLevel(glog.NONE) }

type rdpCracker struct{}

func (rdpCracker) Service() string { return "rdp" }

func (rdpCracker) Try(ctx context.Context, host string, port int, cred Credential, timeout time.Duration) (bool, error) {
	if err := rdpLogin(ctx, host, "", cred.User, cred.Pass, port, timeout); err != nil {
		return false, nil
	}
	return true, nil
}

// rdpLogin attempts one RDP credential via NTLMv2 over the grdp protocol stack.
// grdp reports the outcome through pdu callbacks (success/ready vs error/close)
// rather than a return value, so we bridge that to one error — with a deadline
// so a silent server can't hang the goroutine.
func rdpLogin(ctx context.Context, ip, domain, user, password string, port int, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	tpktLayer := tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, password))
	x := x224.New(tpktLayer)
	mcs := t125.NewMCSClient(x)
	secLayer := sec.NewClient(mcs)
	pduLayer := pdu.NewClient(secLayer)

	secLayer.SetUser(user)
	secLayer.SetPwd(password)
	secLayer.SetDomain(domain)

	tpktLayer.SetFastPathListener(secLayer)
	secLayer.SetFastPathListener(pduLayer)
	pduLayer.SetFastPathSender(tpktLayer)

	if err := x.Connect(); err != nil {
		return err
	}

	var (
		loginErr error
		once     sync.Once
		done     = make(chan struct{})
	)
	finish := func(e error) { once.Do(func() { loginErr = e; close(done) }) }
	pduLayer.On("error", func(e error) { finish(e) })
	pduLayer.On("close", func() { finish(errors.New("rdp: connection closed")) })
	pduLayer.On("success", func() { finish(nil) })
	pduLayer.On("ready", func() { finish(nil) })

	select {
	case <-done:
	case <-ctx.Done():
		loginErr = ctx.Err()
	case <-time.After(timeout):
		loginErr = errors.New("rdp: login timeout")
	}
	return loginErr
}
