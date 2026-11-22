package config

import (
	"runtime"
	"testing"
)

func TestCSVWindowsOutputAliases(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows filename semantics")
	}
	for _, paths := range [][2]string{{"result.txt", "result.txt."}, {"result.txt ", "result.txt"}, {"result.txt", `.. \assets.csv`}} {
		c := Defaults()
		c.Targets = []string{"localhost"}
		c.Output, c.CSVOutput = paths[0], paths[1]
		if err := c.Validate(); err == nil {
			t.Errorf("accepted output pair %q", paths)
		}
	}
}

func TestCSVOutputIsOptInAndRejectsCollisions(t *testing.T) {
	if Defaults().CSVOutput != "" {
		t.Fatal("CSV must not change default output behavior")
	}
	cfg, err := ParseArgs([]string{"dddd", "-t", "192.0.2.1", "-csv", "assets.csv"})
	if err != nil || cfg.CSVOutput != "assets.csv" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"result.txt", "./result.txt", "report.html", "../outside.csv"} {
		cfg.CSVOutput = name
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unsafe/colliding CSV path accepted: %s", name)
		}
	}
	cfg.CSVOutput = "audit.log"
	cfg.AuditLog = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("CSV collides with audit log")
	}
}
