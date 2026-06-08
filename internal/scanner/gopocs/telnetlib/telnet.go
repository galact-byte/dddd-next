// Package telnetlib is a minimal Telnet client used only for weak-credential
// and unauthorized-access detection. It speaks just enough of the protocol to
// answer IAC option negotiation, read the login banner, and drive a login
// exchange — it is not a general-purpose Telnet terminal.
//
// Ported from SleepingBag945/dddd's gopocs/telnetlib. Two deliberate changes
// from the original: unused option constants are dropped, and LastResponse is
// mutex-guarded (the original read/wrote it from two goroutines unsynchronised).
package telnetlib

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Telnet protocol bytes (RFC 854). Only the subset the negotiation logic
// touches is defined here.
const (
	IAC  = byte(255) // Interpret As Command
	DONT = byte(254)
	DO   = byte(253)
	WONT = byte(252)
	WILL = byte(251)
	SB   = byte(250) // Subnegotiation Begin
	SE   = byte(240) // Subnegotiation End

	BINARY = byte(0) // 8-bit data path
	ECHO   = byte(1) // echo
	SGA    = byte(3) // suppress go ahead
)

// Server login modes, decided from the banner by MakeServerType.
const (
	Closed = iota
	UnauthorizedAccess
	OnlyPassword
	UsernameAndPassword
)

type Client struct {
	IPAddr     string
	Port       int
	UserName   string
	Password   string
	ServerType int

	conn         net.Conn
	dialTimeout  time.Duration
	mu           sync.Mutex // guards lastResponse against the reader goroutine
	lastResponse string
}

func New(addr string, port int, dialTimeout time.Duration) *Client {
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	return &Client{IPAddr: addr, Port: port, dialTimeout: dialTimeout}
}

func (c *Client) Netloc() string { return fmt.Sprintf("%s:%d", c.IPAddr, c.Port) }

func (c *Client) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// Connect dials the host and starts a background reader that answers option
// negotiation while accumulating display text. The 3s settle wait lets the
// server finish sending its banner/prompt before MakeServerType inspects it.
func (c *Client) Connect() error {
	conn, err := net.DialTimeout("tcp", c.Netloc(), c.dialTimeout)
	if err != nil {
		return err
	}
	c.conn = conn

	go func() {
		for {
			buf, err := c.read()
			if err != nil {
				return
			}
			displayBuf, commandList := c.serializeResponse(buf)
			if len(commandList) > 0 {
				_ = c.write(c.makeReplyFromList(commandList))
			}
			c.appendResponse(displayBuf)
		}
	}()

	time.Sleep(time.Second * 3)
	return nil
}

func (c *Client) appendResponse(b []byte) {
	c.mu.Lock()
	c.lastResponse += string(b)
	c.mu.Unlock()
}

func (c *Client) Clear() {
	c.mu.Lock()
	c.lastResponse = ""
	c.mu.Unlock()
}

func (c *Client) writeContext(s string) { _ = c.write([]byte(s + "\x0d\x00")) }

func (c *Client) readContext() string {
	c.mu.Lock()
	empty := c.lastResponse == ""
	c.mu.Unlock()
	if empty {
		time.Sleep(time.Second)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	resp := strings.ReplaceAll(c.lastResponse, "\x0d\x00", "")
	resp = strings.ReplaceAll(resp, "\x0d\x0a", "\n")
	c.lastResponse = ""
	return resp
}

func (c *Client) read() ([]byte, error) {
	var buf [2048]byte
	n, err := c.conn.Read(buf[0:])
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *Client) write(buf []byte) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second * 3))
	_, err := c.conn.Write(buf)
	return err
}

// serializeResponse splits a raw read into display text and the IAC command
// sequences that need a reply.
func (c *Client) serializeResponse(responseBuf []byte) (displayBuf []byte, commandList [][]byte) {
	for {
		index := bytes.IndexByte(responseBuf, IAC)
		if index == -1 {
			displayBuf = append(displayBuf, responseBuf...)
			break
		}
		if len(responseBuf)-index < 2 {
			displayBuf = append(displayBuf, responseBuf...)
			break
		}
		ch := responseBuf[index+1]
		if ch == IAC {
			displayBuf = append(displayBuf, responseBuf[:index]...)
			responseBuf = responseBuf[index+1:]
			continue
		}
		if ch == DO || ch == DONT || ch == WILL || ch == WONT {
			commandList = append(commandList, responseBuf[index:index+3])
			displayBuf = append(displayBuf, responseBuf[:index]...)
			responseBuf = responseBuf[index+3:]
			continue
		}
		if ch == SB {
			displayBuf = append(displayBuf, responseBuf[:index]...)
			seIndex := bytes.IndexByte(responseBuf, SE)
			commandList = append(commandList, responseBuf[index:seIndex])
			responseBuf = responseBuf[seIndex+1:]
			continue
		}
		break
	}
	return displayBuf, commandList
}

func (c *Client) makeReplyFromList(list [][]byte) []byte {
	var reply []byte
	for _, command := range list {
		reply = append(reply, c.makeReply(command)...)
	}
	return reply
}

// makeReply answers one negotiation command: accept ECHO/SGA, refuse the rest.
// Refusing everything else keeps the session in a plain line-oriented mode the
// login logic can parse.
func (c *Client) makeReply(command []byte) []byte {
	if len(command) < 3 {
		return []byte{}
	}
	verb := command[1]
	option := command[2]

	if option == ECHO || option == SGA {
		switch verb {
		case DO:
			return []byte{IAC, WILL, option}
		case DONT:
			return []byte{IAC, WONT, option}
		case WILL:
			return []byte{IAC, DO, option}
		case WONT:
			return []byte{IAC, DONT, option}
		case SB:
			if command[3] == ECHO {
				return []byte{IAC, SB, option, BINARY, IAC, SE}
			}
		}
		return []byte{}
	}

	switch verb {
	case DO, DONT:
		return []byte{IAC, WONT, option}
	case WILL, WONT:
		return []byte{IAC, DONT, option}
	}
	return []byte{}
}

// MakeServerType inspects the banner's last line to decide the login mode.
func (c *Client) MakeServerType() int {
	responseString := c.readContext()
	response := strings.Split(responseString, "\n")
	lastLine := strings.ToLower(response[len(response)-1])

	if strings.Contains(lastLine, "user") || strings.Contains(lastLine, "name") ||
		strings.Contains(lastLine, "login") || strings.Contains(lastLine, "account") ||
		strings.Contains(lastLine, "用户名") || strings.Contains(lastLine, "登录") {
		return UsernameAndPassword
	}
	if strings.Contains(lastLine, "pass") {
		return OnlyPassword
	}
	if regexp.MustCompile(`^/ #.*`).MatchString(lastLine) {
		return UnauthorizedAccess
	}
	if regexp.MustCompile(`^<[A-Za-z0-9_]+>`).MatchString(lastLine) {
		return UnauthorizedAccess
	}
	if regexp.MustCompile(`^#`).MatchString(lastLine) {
		return UnauthorizedAccess
	}
	if c.isLoginSucceed(responseString) {
		return UnauthorizedAccess
	}
	return Closed
}

func (c *Client) Login() error {
	switch c.ServerType {
	case Closed:
		return errors.New("service is disabled")
	case UnauthorizedAccess:
		return nil
	case OnlyPassword:
		return c.loginForOnlyPassword()
	case UsernameAndPassword:
		return c.loginForUsernameAndPassword()
	}
	return errors.New("unknown server type")
}

func (c *Client) loginForOnlyPassword() error {
	c.Clear()
	c.writeContext(c.Password)
	time.Sleep(time.Second * 3)

	responseString := c.readContext()
	if c.isLoginFailed(responseString) {
		return errors.New("login failed")
	}
	if c.isLoginSucceed(responseString) {
		return nil
	}
	return errors.New("login failed")
}

func (c *Client) loginForUsernameAndPassword() error {
	c.writeContext(c.UserName)
	time.Sleep(time.Second * 3)
	c.Clear()
	c.writeContext(c.Password)
	time.Sleep(time.Second * 5)

	responseString := c.readContext()
	if c.isLoginFailed(responseString) {
		return errors.New("login failed")
	}
	if c.isLoginSucceed(responseString) {
		return nil
	}
	return errors.New("login failed")
}

var loginFailedString = []string{"wrong", "invalid", "fail", "incorrect", "error"}

func (c *Client) isLoginFailed(responseString string) bool {
	responseString = strings.ToLower(responseString)
	if responseString == "" {
		return true
	}
	for _, str := range loginFailedString {
		if strings.Contains(responseString, str) {
			return true
		}
	}
	if regexp.MustCompile("(?is).*pass(word)?:$").MatchString(responseString) {
		return true
	}
	if regexp.MustCompile("(?is).*user(name)?:$").MatchString(responseString) {
		return true
	}
	if regexp.MustCompile("(?is).*login:$").MatchString(responseString) {
		return true
	}
	return false
}

// isLoginSucceed checks for a shell prompt; if inconclusive it sends "?" and
// treats a large reply (help text) as proof of an interactive shell.
func (c *Client) isLoginSucceed(responseString string) bool {
	responseStringArray := strings.Split(responseString, "\n")
	lastLine := responseStringArray[len(responseStringArray)-1]
	if regexp.MustCompile("^[#$].*").MatchString(lastLine) {
		return true
	}
	if regexp.MustCompile("^<[a-zA-Z0-9_]+>.*").MatchString(lastLine) {
		return true
	}
	if regexp.MustCompile("(?:s)last login").MatchString(responseString) {
		return true
	}
	c.Clear()
	c.writeContext("?")
	time.Sleep(time.Second * 3)
	responseString = c.readContext()
	if strings.Count(responseString, "\n") > 6 {
		return true
	}
	if len([]rune(responseString)) > 100 {
		return true
	}
	return false
}
