# dddd-next

> 自动化资产测绘 + 漏洞扫描工具，基于最新版 projectdiscovery 工具链重构。

`dddd-next` 是对原 [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) 项目的现代化重写。原项目自 2024 年后基本停更，但其依赖的 `nuclei`、`httpx`、`subfinder` 等仍在快速迭代，内置 POC 也已老化。本项目在保留 dddd 设计哲学的基础上，采用现代 Go 标准结构重构，依赖直接跟随 projectdiscovery 主线版本。

> **当前状态**：核心扫描链路已全部打通，工程质量（依赖管理 / 结构 / 测试）已超越原版；功能广度约为原版的 75%，仍在对齐中（见下方 Roadmap）。

## 与原项目的差异（全栈升级）

| 维度 | 原 dddd | dddd-next |
|:---|:---|:---|
| 依赖管理 | `lib/` 内嵌 vendored 改造版 nuclei 等 | go module 直接依赖主线（2 个 `replace`：client-go 依赖冲突修复 + grdp 用 fscan 同款 fork） |
| Nuclei | v3.1.8（2024 初） | v3.8.0（最新），模板量约 5.4× |
| POC 更新 | 依赖二进制重新发布 | `dddd update` 一键拉取官方 nuclei-templates |
| 项目结构 | 扁平（common / lib / gopocs） | 标准 Go（cmd / internal / pkg） |
| 配置注入 | 全局变量 `structs.GlobalConfig` | CLI flag（标准库）+ context |
| 错误处理 | 大量 panic / log.Fatal | error 链 + context 取消 |
| 测试 | 基本无 | 19 包单元测试全绿 |

## 已实现能力

- 输入自动分类（IP / CIDR / IP-Range / URL / Domain / 测绘语法）
- 主动指纹识别（DSL 支持 `与 / 或 / 非 / 括号` 逻辑，8000+ 规则）
- 被动指纹识别（httpx wappalyzer 技术栈识别，含版本号，喂给 POC 精准选择）
- 子域名枚举（subfinder）+ DNS 解析
- 自研 TCP 端口扫描 + 服务指纹识别（fingerprintx，可识别非标准端口上的服务）
- ICMP 存活探测（`-ping` 可选预筛，大网段提速；默认关闭以免漏掉封 ICMP 的主机）
- 指纹 → POC 智能映射（只对命中产品发对应 POC，避免无效请求）
- Nuclei v3 漏洞扫描（默认指纹精准模式，`-full` 切全量）
- 弱口令爆破 **11 种**：SSH / FTP / MySQL / PostgreSQL / Redis / MSSQL / Oracle / MongoDB / SMB / RDP / Telnet
- 漏洞探测：MS17-010（EternalBlue 永恒之蓝）SMB 远程命令执行
- 未授权访问探测：memcached / ADB（安卓调试桥，RCE 等价）/ JDWP（Java 调试，RCE 等价）/ Telnet（直进 shell）
- Hunter / Fofa / Quake 测绘 API（`.env` 管理密钥）
- TXT / JSON / HTML 三种报告 + 审计日志

## 对齐原版的待补能力（Roadmap）

为达成对原版的完整功能复刻，仍需补齐：

- **gopocs 协议**（原版 17 种，已覆盖 15 / 缺 NetBIOS 信息收集，shiro 已由 nuclei 模板覆盖）
- **CDN 识别与过滤**

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
