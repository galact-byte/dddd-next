// Package main is the dddd-next CLI entry point.
//
//	dddd -t <target> [flags]   scan mode (default)
//	dddd update                pull latest nuclei-templates
//	dddd upgrade               update the executable
//	dddd upgrade --check       check for a newer executable
//	dddd version               print version
//	dddd help                  usage
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"dddd-next/internal/app"
	"dddd-next/internal/config"
	"dddd-next/internal/updater"
)

const appName = "dddd-next"

var appVersion = "0.1.50"

func main() {
	loadDotEnv()
	os.Exit(runCLI(os.Args))
}

func runCLI(args []string) int {
	if len(args) > 1 {
		switch args[1] {
		case "version", "-v", "--version":
			fmt.Print(versionLine())
			return 0
		case "help", "-h", "--help":
			printHelp()
			return 0
		case "update":
			return runUpdate(args[2:])
		case "upgrade":
			return runBinaryUpdate(args[2:])
		}
	}
	return runScan(args)
}

func versionLine() string {
	return fmt.Sprintf("%s %s\n", appName, appVersion)
}

func runScan(args []string) int {
	cfg, err := config.ParseArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		printHelp()
		return 0
	}
	for _, warning := range cfg.Warnings {
		fmt.Fprintln(os.Stderr, "[warn]", warning)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Run `dddd help` for usage.")
		return 2
	}
	if cfg.ProxyTest {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := config.TestProxy(ctx, cfg.ProxyURL, cfg.ProxyTestURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Printf("[*] proxy test ok: %s via %s\n", cfg.ProxyTestURL, config.RedactURLCredentials(cfg.ProxyURL))
	}

	if err := applyTemplateSettings(&cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	printBanner()

	outDir := setupOutputDir()
	cfg = prepareOutputPaths(cfg, outDir)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	pipeline, err := app.New(cfg, resolveConfigDir())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer pipeline.Close()

	fmt.Printf("\x1b[32m[*]\x1b[0m %d target(s)  ·  %s  ·  output -> %s\n", len(cfg.Targets), scanModeLabel(cfg), outDir)
	if err := pipeline.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("[*] done. results -> %s\n", outDir)
	return 0
}

func setupOutputDir() string {
	ts := time.Now().Format("2006-01-02_150405")
	return createOutputDir("output", ts)
}

func createOutputDir(base, stamp string) string {
	_ = os.MkdirAll(base, 0755)
	for i := 1; ; i++ {
		name := stamp
		if i > 1 {
			name = fmt.Sprintf("%s-%d", stamp, i)
		}
		dir := filepath.Join(base, name)
		err := os.Mkdir(dir, 0755)
		if err == nil {
			return dir
		}
		if os.IsExist(err) {
			continue
		}
		_ = os.MkdirAll(dir, 0755)
		return dir
	}
}

func prepareOutputPaths(cfg config.Config, outDir string) config.Config {
	if cfg.Output != "" {
		cfg.Output = filepath.Join(outDir, cfg.Output)
	}
	if cfg.HTMLOutput != "" {
		cfg.HTMLOutput = filepath.Join(outDir, cfg.HTMLOutput)
	}
	if cfg.AuditLog {
		cfg.AuditLogFile = filepath.Join(outDir, cfg.AuditLogFile)
	}
	return cfg
}

func printBanner() {
	c := "\x1b[36m"
	b := "\x1b[1m"
	d := "\x1b[2m"
	x := "\x1b[0m"
	fmt.Println()
	fmt.Printf("%s     _       _       _       _%s\n", c, x)
	fmt.Printf("%s  __| |   __| |   __| |   __| |%s   %sdddd-next%s\n", c, x, b, x)
	fmt.Printf("%s / _` |  / _` |  / _` |  / _` |%s   %sautomated asset recon + vuln scan%s\n", c, x, d, x)
	fmt.Printf("%s \\__,_|  \\__,_|  \\__,_|  \\__,_|%s   %s%s%s\n", c, x, d, appVersion, x)
	fmt.Println()
}

func scanModeLabel(cfg config.Config) string {
	switch {
	case cfg.LowPerception:
		return "low-perception"
	case cfg.FullScan:
		return "full-nuclei"
	case cfg.NoPoc:
		return "recon-only"
	default:
		return "precise-poc"
	}
}

func printHelp() {
	fmt.Printf(`%s %s — 自动化资产探测与漏洞扫描。

用法：
  dddd -t <目标> [参数]
  dddd <子命令>
  dddd help | -h | --help

同一行列出的参数互为别名，单横杠和双横杠均可使用。

目标与输出：
  -t, -target <目标>                 可重复；IP / CIDR / IP 范围 / IP:端口 / 域名 / URL / 测绘语句 / 本地文件
                                    文件每行一个目标，也支持 fscan "ip:port open" 和 dddd "[FP] ..." 行
  -o, -output <文件>                 结果文件（默认 result.txt）
  -ot, -output-type <text|json>       结果格式（默认 text）
  -ho, -html-output <文件>            HTML 报告（默认 report.html，空字符串关闭）
  -a                                开启审计日志
  -alf, -audit-log-filename <文件>    审计日志文件名（默认 audit.log）
                                    输出保存在 output/<时间戳>/ 下

资产发现：
  -sd, -subdomain                    枚举域名目标的子域名
  -nsb, -no-subdomain-brute           跳过主动子域名字典爆破
  -ns, -no-subfinder                 跳过被动子域名枚举
  -ping                             先做 ICMP 存活探测，仅扫描响应主机（默认关闭）
  -tp, -tcp-ping                     启用 TCP 存活探测，可与 -ping 同用
  -Pn                               关闭主机存活预筛，覆盖 -ping 和 -tp
  -nip, -no-icmp-ping                禁用 ICMP 存活探测，保留 -tp
  -skip-cdn                         排除 CDN/WAF 域名（默认标记但继续探测）
  -ac, -allow-cdn                    允许扫描 CDN 资产，覆盖 -skip-cdn
  -no-dir, -nd                       跳过产品路径探测（/nacos/、/druid/ 等）
  -nhb, -no-host-bind                关闭域名绑定（虚拟主机）资产探测

端口扫描：
  -st, -scan-type <tcp|syn>           TCP connect（默认）或 SYN；Windows SYN 需要 Npcap/管理员权限
  -sst, -syn-scan-threads <数量>      SYN 发包速率（默认 10000）
  -p, -port <端口>                   如 "80,443,8000-8100" 或 "all"；默认精选端口集
  -np, -no-port <端口>               排除端口，逗号分隔
  -pmc, -ports-max-count <数量>       单 IP 开放端口超过此值时视为防火墙干扰并丢弃（默认 300）

测绘：
  -fofa                             使用 FOFA
  -hunter                           使用 Hunter
  -quake                            使用 Quake（引擎开关可组合；未指定时使用三者）
  -limit, -fmc, -fofa-max-count, -qmc, -quake-max-count <数量>
                                    每条测绘语句的资产上限；上述别名共用一个值（0 表示 100）
  -oip                              将测绘资产按 IP:端口导入，替代域名:端口
  -ld, -local-domain                 保留解析到内网/私有 IP 的测绘资产
  -lpm, -low-perception-mode         Hunter 低感知模式，基于 banner 识别指纹，跳过主动资产探测
                                    后续漏洞检测仍可能发请求；仅收集资产时配合 -no-poc
  -hps, -hunter-page-size <数量>      Hunter 低感知模式每页数量（0 表示 100）
  -hmpc, -hunter-max-page-count <数量> Hunter 低感知模式最多页数（0 表示 10）

模板与配置：
  -nt, -nuclei-template <目录>        本次扫描的模板目录，覆盖记住的目录
  -fy, -finger-yaml <文件>            指纹 YAML
  -wy, -workflow-yaml <文件>          指纹到 POC 的映射 YAML
  -dy, -dir-yaml <文件>               产品路径探测 YAML
  -swl, -subdomain-word-list <文件>   子域名字典

漏洞检测：
  -full                             运行全部 Nuclei 模板；默认按指纹精准匹配 POC
  -no-general, -dgp, -disable-general-poc
                                    精准模式跳过与产品无关的 General-Poc 集合
  -severity, -s <级别>               Nuclei 严重度筛选，可重复：critical,high,medium,low,info
  -exclude-severity <级别>           排除 Nuclei 严重度，可重复
  -tags <标签>                       包含 Nuclei 模板标签，可重复
  -exclude-tags, -et <标签>          排除 Nuclei 模板标签，可重复
  -poc, -poc-name <名称>              按模板名称/ID 子串筛选 POC
  -no-brute, -nb                     跳过 GoPoC 弱口令及协议检测，Shiro 检测仍可能执行
  -no-poc, -npoc                     跳过全部 POC/漏洞检测
  -ngp, -no-golang-poc               仅跳过 GoPoC 检测，Nuclei 和 Shiro 仍可能执行
  -ni, -no-interactsh                禁用 Interactsh 带外检测
  -iserver, -interactsh-server <URL>  自定义 Interactsh 服务器
  -itoken, -interactsh-token <令牌>   Interactsh 认证令牌
  -up, -username-password <用户:密码> 自定义凭证，可重复
  -upf, -username-password-file <文件> 自定义凭证文件，每行 用户:密码

并发与超时：
  -tst, -tcp-scan-threads <数量>      TCP 端口扫描并发（默认 1000）
  -pst, -port-scan-timeout <秒>       TCP 端口扫描超时（默认 6）
  -tc, -nmap-threads <数量>           服务识别并发（默认 500）
  -nto, -nmap-timeout <秒>            服务识别超时（默认 5）
  -sbt, -subdomain-brute-threads <数量> 子域名爆破并发（默认 150）
  -wt, -web-threads <数量>            Web 探测并发（默认 200）
  -wto, -web-timeout <秒>             Web 探测超时（默认 10）
  -gpt, -golang-poc-threads <数量>     GoPoC 并发（默认 50）

代理：
  -proxy <URL>                       扫描使用的 HTTP/SOCKS5 代理
  -pt, -proxy-test                   扫描前测试代理（默认关闭）
  -ptu, -proxy-test-url <URL>         代理测试地址（默认 https://www.baidu.com）
  更新和扫描也读取 HTTP_PROXY / HTTPS_PROXY 环境变量。
  Windows CMD：        set HTTPS_PROXY=http://127.0.0.1:7890
  Windows PowerShell： $env:HTTPS_PROXY="http://127.0.0.1:7890"

子命令（单独运行，不与扫描参数混用）：
  upgrade                           升级程序到最新稳定版
  upgrade --check                   只检查程序版本，不下载
  update [-nt <目录>]               更新官方 Nuclei 模板，成功后记住目录
                                    -nuclei-template 是 -nt 的别名
  version, -v, --version             显示版本
  help, -h, --help                   显示帮助
  update --help / upgrade --help     查看对应子命令帮助

测绘 API 配置：
  -t 'app="seeyon"' 等测绘语句使用 FOFA/Hunter/Quake。
  将密钥放入环境变量或 .env（参考 .env.example）：
  FOFA_EMAIL + FOFA_KEY、HUNTER_API_KEY、QUAKE_TOKEN。
  进程环境变量优先，其次为工作目录 .env，再其次为程序目录 .env。
  FOFA_SERVER 可指定兼容服务器的 HTTP(S) 基础地址，默认 https://fofa.info；
  自动追加 /api/v1/search/all，允许路径前缀，仍需配置 FOFA_EMAIL 和 FOFA_KEY。
  免费 FOFA 账号没有 API 配额。

配置目录与更新：
  发行版内置基础配置，优先使用程序同目录、其次工作目录中的 configs/；
  均不存在时释放并使用 ~/Downloads/dddd-next/configs。
  dddd update -nt <目录> 成功后记住目录，后续更新和扫描复用；扫描 -nt 仅覆盖本次。
  目录记录保存在用户配置目录的 dddd-next/templates.json。
  GITHUB_TOKEN 可选，用于程序更新 API 请求（也可通过 .env 配置），
  不会发送给资产下载地址或重定向目标。

基于 SleepingBag945/dddd（MIT License）。
`, appName, appVersion)
}

func runUpdate(args []string) int {
	dir, err := parseUpdateArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "Usage: dddd update [-nt <template-directory>]")
			fmt.Fprintln(os.Stderr, "  -nt, -nuclei-template <目录>  更新官方模板，成功后记住目录")
			return 0
		}
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Usage: dddd update [-nt <template-directory>]")
		return 2
	}
	settingsPath, err := templateSettingsPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := updater.IsAvailable(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Install git from https://git-scm.com/ and ensure it is on PATH.")
		return 2
	}

	if err := updateTemplates(ctx, dir, resolveConfigDir(), settingsPath, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// loadDotEnv loads optional recon and update credentials from the working
// directory and executable directory. Existing environment values take priority.
func loadDotEnv() {
	_ = config.LoadDotEnv(".env")
	if exe, err := os.Executable(); err == nil {
		_ = config.LoadDotEnv(filepath.Join(filepath.Dir(exe), ".env"))
	}
}
