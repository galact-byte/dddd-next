# dddd-next

> 自动化资产测绘 + 漏洞扫描工具，基于最新版 projectdiscovery 工具链重构。

`dddd-next` 是对原 [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) 项目的现代化重写。原项目自 2024 年后基本停更，但其依赖的 `nuclei`、`httpx`、`subfinder` 等仍在快速迭代，内置 POC 也已老化。本项目在保留 dddd 设计哲学的基础上，采用现代 Go 标准结构重构，依赖直接跟随 projectdiscovery 主线版本。

> **当前状态**：核心扫描链路（分类→发现→指纹→POC→弱口令）已扎实，工程质量（依赖管理 / 结构 / 测试）超越原版；gopocs 16/17、被动指纹 / ICMP / CDN / 产品路径探测已补齐。recon 广度尚未完全复刻（缺子域名爆破 / 自定义端口 / interactsh），约为原版功能面的 75%，仍在对齐（见 Roadmap）。

## 与原项目的差异（全栈升级）

| 维度 | 原 dddd | dddd-next |
|:---|:---|:---|
| 依赖管理 | `lib/` 内嵌 vendored 改造版 nuclei 等 | go module 直接依赖主线（2 个 `replace`：client-go 依赖冲突修复 + grdp 用 fscan 同款 fork） |
| Nuclei | v3.1.8（2024 初） | v3.8.0（最新），模板量约 5.4× |
| POC 更新 | 依赖二进制重新发布 | `dddd update` 一键拉取官方 nuclei-templates |
| 项目结构 | 扁平（common / lib / gopocs） | 标准 Go（cmd / internal / pkg） |
| 配置注入 | 全局变量 `structs.GlobalConfig` | CLI flag（标准库）+ context |
| 错误处理 | 大量 panic / log.Fatal | error 链 + context 取消 |
| 测试 | 基本无 | 20 包单元测试全绿 |

## 已实现能力

- 输入自动分类（IP / CIDR / IP-Range / URL / Domain / 测绘语法）
- 主动指纹识别（DSL 支持 `与 / 或 / 非 / 括号` 逻辑，8000+ 规则）
- 被动指纹识别（httpx wappalyzer 技术栈识别，含版本号，喂给 POC 精准选择）
- 产品路径二次指纹（探测 /nacos/、/druid/ 等已知产品路径，发现首页漏掉的子路径产品；`-no-dir` 关闭）
- 子域名枚举（subfinder）+ DNS 解析
- 自研 TCP 端口扫描 + 服务指纹识别（fingerprintx，可识别非标准端口上的服务）
- ICMP 存活探测（`-ping` 可选预筛，大网段提速；默认关闭以免漏掉封 ICMP 的主机）
- CDN / WAF 识别（271 条 CNAME 库，含国内主流厂商；默认标记仍探测，`-skip-cdn` 可排除）
- 指纹 → POC 智能映射（只对命中产品发对应 POC，避免无效请求）
- Nuclei v3 漏洞扫描（默认指纹精准模式，`-full` 切全量）
- 弱口令爆破 **11 种**：SSH / FTP / MySQL / PostgreSQL / Redis / MSSQL / Oracle / MongoDB / SMB / RDP / Telnet
- 漏洞探测：MS17-010（EternalBlue 永恒之蓝）SMB 远程命令执行
- 未授权访问探测：memcached / ADB（安卓调试桥，RCE 等价）/ JDWP（Java 调试，RCE 等价）/ Telnet（直进 shell）
- NetBIOS 信息探测（UDP 137 + TCP 139 NTLM，泄露主机名 / 工作组 / 域 / OS 版本）
- Hunter / Fofa / Quake 测绘 API（`.env` 管理密钥）
- TXT / JSON / HTML 三种报告 + 审计日志

## 对齐原版的状态（Roadmap）

**已对齐**：

- **gopocs 协议**：原版 17 种已覆盖 16（弱口令 11 + 探测型 5）；仅 shiro 未在 gopocs 实现，已由 nuclei 反序列化模板覆盖。
- 被动指纹 / ICMP 存活探测 / CDN 识别 / 产品路径二次指纹均已补齐。

**仍待补（原版有、本版缺，按"不能漏"优先级）**：

- **主动子域名爆破**（当前仅被动 subfinder，漏掉爆破才能发现的子域）
- **自定义 / 全端口扫描**（当前固定 69 端口，服务在其它端口会漏；含 SYN / masscan 加速）
- **interactsh OOB**（盲打 SSRF / 盲 RCE 等带外检测）
- 其余控制开关：severity / exclude-tags 过滤、自定义凭据 `-up/-upf`、按阶段开关等

> 诚实说明：核心扫描链（分类→发现→指纹→POC→弱口令）已扎实且工程质量超越原版，但 recon 广度尚未 100% 复刻。当前约为原版功能面的 **75%**，仍在对齐。

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

# 扫描 IP / 网段 / 网站
./dddd -t 192.168.1.1
./dddd -t 192.168.1.0/24
./dddd -t http://example.com

# 测绘语法（需先在 .env 配置 Hunter/Fofa/Quake 密钥）
./dddd -t 'app="seeyon"'

# 全量 nuclei 模板（默认是指纹精准模式）
./dddd -t http://example.com -full
```

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

## 致谢

- [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) — 原项目作者，本项目的设计灵感与指纹库 / POC 格式来源
- [projectdiscovery](https://github.com/projectdiscovery) — nuclei、httpx、subfinder、dnsx、fingerprintx 等核心引擎

## License

MIT License — 详见 [LICENSE](./LICENSE)
