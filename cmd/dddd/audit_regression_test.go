package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditCLIFailsWhenHTMLCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("configs", 0755); err != nil {
		t.Fatal(err)
	}
	finger := filepath.Join(dir, "finger.yaml")
	if err := os.WriteFile(finger, []byte("Audit:\n  - 'title=\"audit\"'\n"), 0644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := captureHelpCLI(t, []string{"dddd", "-t", "[FP] http://127.0.0.1:1 | audit | confidence=90", "-no-poc", "-fy", finger, "-ho", "missing-parent/report.html"})
	matches, err := filepath.Glob(filepath.Join("output", "*", "missing-parent", "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("exit=%d done=%v HTML文件数=%d stderr=%q", code, strings.Contains(stdout, "[*] done."), len(matches), stderr)
	if len(matches) != 0 {
		t.Fatal("测试前提不成立：报告写入成功")
	}
	if code == 0 || strings.Contains(stdout, "[*] done.") || !strings.Contains(stderr, "report.html") {
		t.Errorf("写入失败必须返回非零、报告路径错误且不提示 done: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
