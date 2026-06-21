# dddd-next

> 面向授权环境的自动化资产测绘 + 漏洞扫描工具，对原 dddd 做全功能复刻和全栈升级，覆盖指纹识别、弱口令、nuclei POC、Shiro 专项检测和 HTML 报告。

## 项目定位

`dddd-next` 是对原 [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) 项目的现代化重写。原项目自 2024 年后基本停更，但其依赖的 `nuclei`、`httpx`、`subfinder` 等仍在快速迭代，内置 POC 也已老化。本项目在保留 dddd 设计哲学的基础上，采用现代 Go 标准结构重构，依赖直接跟随 projectdiscovery 主线版本。

> **当前状态**：**全功能复刻 + 全栈升级已达成**——recon 覆盖能力 100%（gopocs 18/18 + 被动指纹 + ICMP + CDN + 产品路径 + 自定义端口 / 全端口 + 子域名爆破 + OOB 盲打）、控制开关 100%（nuclei 过滤 + 阶段跳过 + 自定义凭据）。真实靶场已覆盖 Nacos、DVWA、Tomcat、Shiro、Redis、MySQL、Pikachu、sqli-labs、Vulfocus、WebGoat，并复验 `-t <ip> -p 1-65535` 常用全端口入口。剩余差异主要是性能加速项（masscan 类加速）；功能发现链路已经对齐原版。

## 与原项目的差异（全栈升级）

| 维度 | 原 dddd | dddd-next |
|:---|:---|:---|
| 依赖管理 | `lib/` 内嵌 vendored 改造版 nuclei 等 | go module 直接依赖主线（2 个 `replace`：client-go 依赖冲突修复 + grdp 用 fscan 同款 fork） |
| Nuclei | v3.1.8（2024 初） | v3.8.0（最新），模板量约 5.4× |
| POC 更新 | 依赖二进制重新发布 | `dddd update` 一键拉取官方 nuclei-templates |
| 项目结构 | 扁平（common / lib / gopocs） | 标准 Go（cmd / internal / pkg） |
| 配置注入 | 全局变量 `structs.GlobalConfig` | CLI flag（标准库）+ context |
| 错误处理 | 大量 panic / log.Fatal | error 链 + context 取消 |
| 测试 | 基本无 | 单元 / 回归测试覆盖主链路，并经过多靶场实扫回归 |

## 已实现能力

- 输入自动分类（IP / CIDR / IP-Range / URL / Domain / 测绘语法）
- 主动指纹识别（DSL 支持 `与 / 或 / 非 / 括号` 逻辑，8000+ 规则）
- 被动指纹识别（httpx wappalyzer 技术栈识别，含版本号，喂给 POC 精准选择）
- 产品路径二次指纹（探测 /nacos/、/druid/ 等已知产品路径，发现首页漏掉的子路径产品；`-no-dir` 关闭）
- 子域名枚举：被动 subfinder + 主动字典爆破（1721 词，含泛解析检测，`-nsb` 关闭爆破）+ DNS 解析
- 自研 TCP 端口扫描 + 服务指纹识别（fingerprintx，可识别非标准端口上的服务）
- 自定义 / 全端口扫描（`-p "80,443,8000-8100"`、`-p 1-65535` 或 `-p all`；默认使用原版风格 curated 端口集）
- ICMP 存活探测（`-ping` 可选预筛，大网段提速；默认关闭以免漏掉封 ICMP 的主机）
- CDN / WAF 识别（271 条 CNAME 库，含国内主流厂商；默认标记仍探测，`-skip-cdn` 可排除）
- 指纹 → POC 智能映射（只对命中产品发对应 POC，避免无效请求）
- Nuclei v3 漏洞扫描（默认指纹精准模式，`-full` 切全量）
- 弱口令爆破 **11 种**：SSH / FTP / MySQL / PostgreSQL / Redis / MSSQL / Oracle / MongoDB / SMB / RDP / Telnet
- 漏洞探测：MS17-010（EternalBlue 永恒之蓝）SMB 远程命令执行
- 未授权访问探测：memcached / ADB（安卓调试桥，RCE 等价）/ JDWP（Java 调试，RCE 等价）/ Telnet（直进 shell）
- NetBIOS 信息探测（UDP 137 + TCP 139 NTLM，泄露主机名 / 工作组 / 域 / OS 版本）
- Hunter / Fofa / Quake 测绘 API（`.env` 管理密钥）
- TXT / JSON / HTML 三种报告 + 审计日志；HTML 报告已重做为高密度暗色布局，支持严重度筛选、漏洞详情展开、请求 / 响应复制和指纹资产区

## 对齐原版的状态（Roadmap）

**全功能复刻 + 全栈升级已达成**：

- **gopocs 协议**：原版 18 种已全覆盖（弱口令 11 + 探测型 6 + shiro 专用爆破；含 RPC Endpoint Mapper 信息泄露）
- **recon 覆盖能力 100%**：被动指纹 / ICMP 存活 / CDN 识别 / 产品路径二次指纹 / 自定义端口 / 主动子域名爆破均已补齐；OOB 盲打（interactsh）默认启用
- **控制开关 100%**：nuclei 过滤（`-severity`/`-tags`/`-exclude-*`）、阶段跳过（`-no-brute`/`-no-poc`）、自定义凭据（`-up`/`-upf`）

**剩余主要是性能加速 / 环境增强项（不影响"能发现什么"）**：

- masscan 类超大网段快速扫描（当前 TCP connect 为默认；`-st syn` 可用但依赖 npcap / 管理员权限）
- 自定义 interactsh 服务器（当前用官方公共服务，OOB 盲打已启用）

> 诚实说明：经逐项核对原版 55 个 flag 与主流程，**会影响"能发现什么"的覆盖能力已全部复刻**，控制开关也已补齐。剩余差异主要为性能加速和部署环境增强（不影响发现能力，只影响速度或运维方式）。**dddd-next 真正达成「全功能复刻 + 全栈升级」**，工程质量（依赖 / 结构 / 测试 / 多项 bug 修复）已超越原版。

## 项目结构

```
dddd-next/
├── cmd/dddd/                    # CLI 入口（标准库 flag）
├── internal/
│   ├── app/                     # 主编排 pipeline
│   ├── classifier/              # 输入类型自动识别
│   ├── config/                  # 配置加载（CLI flag + .env）
│   ├── types/                   # 公共类型
│   ├── fingerprint/             # 主动指纹引擎
│   ├── discovery/
│   │   ├── subfinder/           # 子域名枚举
│   │   ├── dnsx/                # DNS 解析
│   │   ├── portscan/            # 自研 TCP 端口扫描
│   │   ├── servicedetect/       # 服务指纹识别（fingerprintx）
│   │   ├── httpprobe/           # HTTP 探测（httpx）
│   │   └── uncover/             # Hunter / Fofa / Quake 测绘
│   ├── scanner/
│   │   ├── nuclei/              # nuclei v3 适配层
│   │   ├── pocmap/              # 指纹 → POC 映射
│   │   └── gopocs/              # 弱口令爆破
│   ├── reporter/                # TXT / JSON / HTML 报告
│   ├── audit/                   # 审计日志
│   └── updater/                 # nuclei-templates 更新
├── pkg/
│   └── fingerdsl/               # 指纹表达式 DSL（可独立复用）
├── configs/
│   ├── fingers/                 # 指纹库 finger.yaml
│   ├── pocs/                    # mapping.yaml（指纹→POC）+ legacy POC 库
│   └── dict/                    # 弱口令字典
└── .env.example                 # 测绘 API 密钥模板（复制为 .env 填入）
```

## 快速开始

```bash
# 构建
go build -o dddd ./cmd/dddd

# 首次使用：拉取最新 nuclei-templates
./dddd update

# 扫描 IP / 网段 / 网站（默认精准 POC + 弱口令 + Shiro 专用检测）
./dddd -t 192.168.1.1
./dddd -t 192.168.1.0/24
./dddd -t http://example.com

# 常用全端口入口：发现 Web 与非 Web 服务后分别进入 POC / 弱口令链路
./dddd -t 192.168.1.1 -p 1-65535

# 指定端口或端口段
./dddd -t 192.168.1.1 -p 80,443,8080,8848,6379,3306
./dddd -t 192.168.1.1 -p 8000-9000

# HTML 报告（默认会生成，也可显式指定；传空字符串关闭）
./dddd -t 192.168.1.1 -p 1-65535 -ho report.html
./dddd -t 192.168.1.1 -ho ''

# 指定 POC 名称 / ID 片段，不依赖指纹映射
./dddd -t http://example.com -poc nacos
./dddd -t http://example.com -poc CVE-2021-29441

# 测绘语法（需先在 .env 配置 Hunter/Fofa/Quake 密钥）
./dddd -t 'app="seeyon"'

# 全量 nuclei 模板（默认是指纹精准模式）
./dddd -t http://example.com -full
```

### 输出文件

每次扫描会创建 `output/<timestamp>/` 目录，默认包含：

- `result.txt`：逐行文本结果，适合 grep / 归档。
- `report.html`：交互式 HTML 报告，适合人工复盘。

也可以通过 `-o`、`-ot json`、`-ho` 改输出位置和格式。

### 已验证靶场

近期真实容器回归覆盖了这些典型场景：

- Nacos：子路径 `/nacos/` 指纹、`CVE-2021-29441` 精准 POC。
- DVWA：根路径相对 302 跳转到登录页后仍能识别并触发默认口令检测。
- Shiro：`/login;jsessionid=...` 跳转不会造成重复弱 key / `shiro-detect` 结果。
- Redis / MySQL：非 Web 服务弱口令链路不依赖 HTTP 探测。
- Tomcat：Manager 路径探测和公开 Manager 检测。
- Pikachu / sqli-labs / Vulfocus / WebGoat：产品路径、通用泄露类 POC、子路径登录页指纹和新版 WebGoat 入口。

### 代理配置（拉取 nuclei-templates 慢/失败时）

`dddd update` 内部调用系统 `git`，会自动尊重 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量。

```bash
# Windows CMD
set HTTPS_PROXY=http://127.0.0.1:7890
# Windows PowerShell
$env:HTTPS_PROXY="http://127.0.0.1:7890"
# Linux / macOS
export HTTPS_PROXY=http://127.0.0.1:7890
```

## 发布 Release

本仓库使用 GitHub Actions + GoReleaser 发布版本。推送 `v*` tag 后会自动：

1. 运行 `go test ./...`。
2. 构建 Windows / Linux / macOS 的 amd64、arm64 二进制。
3. 将二进制、`configs/`、README、LICENSE、`.env.example` 打包。
4. 生成 `checksums.txt` 并创建 GitHub Release。

发布命令示例：

```bash
git tag v0.1.42
git push origin main
git push origin v0.1.42
```

本地预检查可使用：

```bash
goreleaser check
goreleaser release --snapshot --clean
```

GitHub 右上角 About 建议填写：

```text
全功能复刻并全栈升级原 dddd 的自动化资产测绘与漏洞扫描工具，支持全端口、指纹、弱口令、nuclei POC 和 HTML 报告。
```

## 致谢

- [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) — 原项目作者，本项目的设计灵感与指纹库 / POC 格式来源
- [projectdiscovery](https://github.com/projectdiscovery) — nuclei、httpx、subfinder、dnsx、fingerprintx 等核心引擎

## License

MIT License — 详见 [LICENSE](./LICENSE)
