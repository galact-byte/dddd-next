package gopocs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dddd-next/internal/types"

	"golang.org/x/crypto/ssh"
)

func TestParseDict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "d.txt")
	content := "root : 123456\nadmin : admin\n\n# comment\nredispass\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	creds, err := ParseDict(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 3 {
		t.Fatalf("want 3 creds (blank+comment skipped), got %d: %v", len(creds), creds)
	}
	if creds[0] != (Credential{User: "root", Pass: "123456"}) {
		t.Errorf("creds[0] = %v, want root/123456", creds[0])
	}
	if creds[2] != (Credential{User: "", Pass: "redispass"}) {
		t.Errorf("creds[2] = %v, want password-only redispass", creds[2])
	}
}

func TestRoutableJobsSkipsUnhandledPorts(t *testing.T) {
	e := New(DefaultOptions(""))
	eps := []Endpoint{
		{Host: "1.2.3.4", Port: 22},   // ssh -> routable
		{Host: "1.2.3.4", Port: 8080}, // web -> no cracker, skipped
		{Host: "1.2.3.4", Port: 3306}, // mysql -> routable
		{Host: "1.2.3.4", Port: 6379}, // redis -> routable
	}
	jobs := e.routableJobs(eps)
	if len(jobs) != 3 {
		t.Fatalf("want 3 jobs (8080 skipped), got %v", jobs)
	}
}

func TestSSHCrackerAgainstLocalServer(t *testing.T) {
	host, port := startTestSSHServer(t, "root", "s3cret")
	cr := sshCracker{}
	ctx := context.Background()

	ok, err := cr.Try(ctx, host, port, Credential{User: "root", Pass: "s3cret"}, 3*time.Second)
	if err != nil || !ok {
		t.Fatalf("correct cred: ok=%v err=%v, want true/nil", ok, err)
	}

	ok, err = cr.Try(ctx, host, port, Credential{User: "root", Pass: "wrong"}, 3*time.Second)
	if err != nil || ok {
		t.Fatalf("wrong cred: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestEngineRunEndToEndSSH(t *testing.T) {
	host, port := startTestSSHServer(t, "root", "toor")

	dir := t.TempDir()
	dict := "root : wrong\nroot : toor\nroot : nope\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh.txt"), []byte(dict), 0o644); err != nil {
		t.Fatal(err)
	}

	e := New(DefaultOptions(dir))
	e.servicePorts = map[int]string{port: "ssh"} // route the ephemeral port to ssh

	var findings []types.Finding
	for f := range e.Run(context.Background(), []Endpoint{{Host: host, Port: port}}) {
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Fatalf("want exactly 1 finding (StopOnFirst), got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("severity = %q, want high", findings[0].Severity)
	}
	if findings[0].ID != "weak-credential-ssh" {
		t.Errorf("id = %q, want weak-credential-ssh", findings[0].ID)
	}
}

// startTestSSHServer spins up an in-process SSH server accepting one user/pass,
// so the cracker is exercised against a real handshake without external deps.
func startTestSSHServer(t *testing.T, user, pass string) (string, int) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(p) == pass {
				return nil, nil
			}
			return nil, fmt.Errorf("auth denied")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sshConn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					_ = c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "no sessions")
				}
				_ = sshConn.Close()
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestRoutableJobsRoutesDBPorts(t *testing.T) {
	e := New(DefaultOptions(""))
	jobs := e.routableJobs([]Endpoint{
		{Host: "1.2.3.4", Port: 1433}, // mssql
		{Host: "1.2.3.4", Port: 1521}, // oracle
		{Host: "1.2.3.4", Port: 9999}, // no cracker, skipped
	})
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs (mssql+oracle), got %v", jobs)
	}
	svc := map[string]bool{}
	for _, j := range jobs {
		svc[j.service] = true
	}
	if !svc["mssql"] || !svc["oracle"] {
		t.Errorf("want mssql+oracle routed, got %v", svc)
	}
}

func TestMSSQLAuthFailureDetection(t *testing.T) {
	if !isMSSQLAuthFailure(errors.New("mssql: Login failed for user 'sa'.")) {
		t.Error("login-failed (18456) should be an auth failure")
	}
	if isMSSQLAuthFailure(errors.New("dial tcp: i/o timeout")) {
		t.Error("connection timeout must not be treated as auth failure")
	}
}

func TestOracleAuthAndServiceDetection(t *testing.T) {
	if !isOracleAuthFailure(errors.New("ORA-01017: invalid username/password; logon denied")) {
		t.Error("ORA-01017 should be an auth failure")
	}
	if isOracleAuthFailure(errors.New("ORA-12514: TNS:listener does not know of service")) {
		t.Error("ORA-12514 is service-missing, not an auth failure")
	}
	if !isOracleServiceMissing(errors.New("ORA-12514: TNS:listener does not currently know of service requested")) {
		t.Error("ORA-12514 should be detected as service-missing")
	}
}
