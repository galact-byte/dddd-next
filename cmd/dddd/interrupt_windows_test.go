package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestBinaryInterruptFinalizesReports(t *testing.T) {
	binary := os.Getenv("DDDD_SMOKE_BINARY")
	if binary == "" {
		t.Skip("set DDDD_SMOKE_BINARY to test a built executable")
	}
	root := t.TempDir()
	if data, err := os.ReadFile(binary); err != nil {
		t.Fatal(err)
	} else {
		binary = filepath.Join(root, "dddd.exe")
		if err := os.WriteFile(binary, data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"} {
		t.Setenv(key, filepath.Join(root, "home"))
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	var releaseOnce sync.Once
	finishRequest := func() { releaseOnce.Do(func() { close(release) }) }
	defer finishRequest()
	endpoint := srv.Listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-t", endpoint, "-no-poc", "-no-dir", "-nhb", "-ns", "-csv", "assets.csv", "-ho", "")
	cmd.Dir = root
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	// A targeted CTRL_BREAK reaches Go as os.Interrupt without signaling the test runner.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("early exit: %v\n%s", err, &output)
	case <-ctx.Done():
		<-done
		t.Fatalf("no request: %s", &output)
	}
	signalErr := windows.GenerateConsoleCtrlEvent(syscall.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid))
	finishRequest()
	if signalErr != nil {
		cancel()
	}
	err := <-done
	var exit *exec.ExitError
	if signalErr != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(output.String(), "已取消") || !strings.Contains(output.String(), "context canceled") {
		t.Fatalf("signal=%v exit=%v\n%s", signalErr, err, &output)
	}
	files, err := filepath.Glob(filepath.Join(root, "output", "*", "assets.csv"))
	if err != nil || len(files) != 1 {
		t.Fatalf("CSV files=%v error=%v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff"))).ReadAll()
	if err != nil || len(rows) < 2 || rows[1][0] != "127.0.0.1" || !strings.Contains(rows[1][7], "input") {
		t.Fatalf("partial report=%q err=%v", data, err)
	}
	t.Logf("exit=%d CSV rows=%d\n%s", exit.ExitCode(), len(rows)-1, &output)
}
