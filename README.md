# dddd-next

> 自动化资产测绘 + 漏洞扫描工具，基于最新版 projectdiscovery 工具链重构。

`dddd-next` 是对原 [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) 项目的现代化重写。原项目自 2024 年后基本停更，但其依赖的 `nuclei`、`httpx`、`subfinder` 等工具仍在快速迭代，且内置 POC 严重老化。本项目在保留 dddd 设计哲学的基础上，采用现代 Go 标准结构重构，依赖直接跟随 projectdiscovery 主线版本。

## 与原项目的差异

| 维度 | 原 dddd | dddd-next |
|:---|:---|:---|
| Go 模块依赖 | `replace` 指向本地 vendored 改造版 | 直接依赖 projectdiscovery 最新主线 |
| Nuclei 版本 | v3.1.8（2024 年初） | 跟随 v3 最新 release |
| POC 更新 | 依赖二进制重新发布 | `dddd update` 命令一键拉取官方 nuclei-templates |
| 项目结构 | 扁平（common / structs / utils / gopocs） | 现代 Go 标准（cmd / internal / pkg） |
| 配置注入 | 全局变量 `structs.GlobalConfig` | context + 依赖注入 |
| 日志 | gologger 混用 | 统一 slog 结构化日志 |
| 错误处理 | 大量 panic / log.Fatal | error 链 + context 取消 |

## 核心能力（与原 dddd 对齐）

- 自动识别输入类型（IP / CIDR / IP-Range / URL / Domain / 测绘语法）
- 主动 + 被动指纹识别，支持 `与 / 或 / 非 / 括号` 逻辑运算
- 子域名枚举（subfinder）+ 暴力破解 + 泛解析过滤
- 端口扫描 + 服务识别
- 指纹 → POC 智能映射，减少无效请求
- Nuclei v3 漏洞扫描
- 11 种协议弱口令爆破（MySQL / MSSQL / PostgreSQL / Oracle / Redis / SSH / SMB / FTP / RDP / Telnet / Shiro）
- Hunter / Fofa / Quake 测绘 API
- TXT / JSON / HTML 三种报告 + 审计日志
- CDN 识别与过滤

## 项目结构

```
dddd-next/
├── cmd/dddd/                    # 命令行入口（cobra）
├── internal/
│   ├── app/                     # 应用编排（workflow）
│   ├── classifier/              # 输入类型自动识别
│   ├── config/                  # 配置加载（CLI flag + YAML）
│   ├── types/                   # 公共类型
│   ├── fingerprint/             # 指纹引擎
│   ├── discovery/
│   │   ├── subdomain/           # 子域名枚举
│   │   ├── portscan/            # 端口扫描
│   │   ├── httpprobe/           # HTTP 探测（httpx）
│   │   ├── uncover/             # Hunter / Fofa / Quake
│   │   └── cdn/                 # CDN 识别
│   ├── scanner/
│   │   ├── nuclei/              # nuclei v3 适配层
│   │   └── gopocs/              # 自研弱口令爆破
│   ├── reporter/                # TXT / JSON / HTML 报告
│   ├── audit/                   # 审计日志
│   └── updater/                 # POC / 模板更新
├── pkg/
│   └── fingerdsl/               # 指纹表达式 DSL（可独立复用）
├── configs/
│   ├── fingers/                 # 指纹库 YAML
│   ├── pocs/custom/             # 用户自定义 POC（nuclei 格式）
│   ├── dict/                    # 弱口令字典
│   └── nuclei-templates/        # 官方模板（git ignored，updater 拉取）
├── docs/                        # 设计文档
└── scripts/                     # 构建脚本
```

## 快速开始

```bash
# 构建
go build -o dddd ./cmd/dddd

# 首次使用：拉取最新 POC 模板
./dddd update

# 扫描 IP
./dddd -t 192.168.1.1

# 扫描网段
./dddd -t 192.168.1.0/24

# 扫描网站
./dddd -t http://example.com

# 红队外网（Hunter ICP 查询）
./dddd -t 'icp.name="某公司"' -hunter -oip
```

## 致谢

- [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) — 原项目作者，本项目的设计灵感与指纹库格式来源
- [projectdiscovery](https://github.com/projectdiscovery) — nuclei、httpx、subfinder、dnsx 等核心引擎

## License

MIT License — 详见 [LICENSE](./LICENSE)
