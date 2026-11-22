package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"dddd-next/internal/app"
	"dddd-next/internal/config"
)

func runDoctor(args []string) int {
	fs := flag.NewFlagSet("dddd doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := config.Defaults()
	var root string
	fs.StringVar(&root, "config-dir", "", "existing configuration directory")
	fs.StringVar(&cfg.FingerConfigFilePath, "fy", "", "fingerprint file")
	fs.StringVar(&cfg.WorkflowYamlPath, "wy", "", "POC mapping file")
	fs.StringVar(&cfg.NucleiTemplateDir, "nt", "", "template root directory")
	err := fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Println("用法：dddd doctor [-config-dir <配置目录>] [-fy <指纹文件>] [-wy <映射文件>] [-nt <模板目录>]")
		fmt.Println("离线检查精准模式的指纹、映射和所选模板，不发起扫描、不创建配置、不执行模板脚本。")
		return 0
	}
	if err != nil || fs.NArg() != 0 {
		if err == nil {
			err = fmt.Errorf("unexpected doctor argument: %s", fs.Arg(0))
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if root == "" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		root = filepath.Join(filepath.Dir(exe), "configs")
		if err := applyTemplateSettings(&cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	root, err = filepath.Abs(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	report := app.CheckRules(ctx, cfg, root)
	for _, problem := range report.Problems {
		fmt.Fprintln(os.Stderr, "[doctor]", problem)
	}
	fmt.Printf("[doctor] %d 条有效指纹，%d 个模板通过检查，%d 项问题\n", report.Rules, report.Templates, len(report.Problems))
	fmt.Println("检查范围：模板结构、HTTP 匹配器及 HTTP 字典文件；不保证模板实际执行或目标适用性。")
	if len(report.Problems) > 0 {
		return 1
	}
	return 0
}
