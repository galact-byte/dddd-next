# dddd-next

## 项目定位

`dddd-next` 是对原 [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) 项目的现代化重写。原项目自 2024 年后基本停更，但其依赖的 `nuclei`、`httpx`、`subfinder` 等仍在快速迭代，内置 POC 也已老化。本项目在保留 dddd 设计哲学的基础上，采用现代 Go 标准结构重构，依赖直接跟随 projectdiscovery 主线版本。

> **当前状态**：核心扫描链路已可用，并经过 Nacos、DVWA、Tomcat、Shiro、Redis、MySQL、Pikachu、sqli-labs、Vulfocus、WebGoat 等靶场回归；常用 `-t <ip> -p 1-65535` 全端口入口已复验。已知差异主要是 masscan 类超大网段加速和部分真实环境下模板兼容性需要持续回归。

## 与原项目的差异

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

- 输入自动分类（IP / CIDR / IP-Range / URL / Domain / 测绘语法）；`-t` 也可逐行加载本地目标文件
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
- Hunter / FOFA / Quake 测绘 API（`.env` 管理密钥，FOFA 支持自定义兼容服务器地址）
- TXT / JSON / HTML 三种报告 + 审计日志；HTML 报告已重做为高密度暗色布局，支持严重度筛选、漏洞详情展开、请求 / 响应复制和指纹资产区

## 兼容状态与已知差异

已对齐或补齐的主链路：

- **gopocs 协议**：弱口令、探测型检测和 Shiro 专项爆破均已实现，含 RPC Endpoint Mapper 信息泄露。
- **recon 覆盖能力**：被动指纹、ICMP 存活、CDN 识别、产品路径二次指纹、自定义端口、全端口、主动子域名爆破和 OOB 盲打均已接入。
- **控制开关**：支持 nuclei 过滤（`-severity`/`-tags`/`-exclude-*`）、阶段跳过（`-no-brute`/`-no-poc`）和自定义凭据（`-up`/`-upf`）。
- **真实回归**：近期覆盖 Nacos、DVWA、Tomcat、Shiro、Redis、MySQL、Pikachu、sqli-labs、Vulfocus、WebGoat，并复验 `-t <ip> -p 1-65535` 入口。

仍需持续关注：

- masscan 类超大网段快速扫描（当前 TCP connect 为默认；`-st syn` 可用但依赖 npcap / 管理员权限）。
- nuclei 官方模板持续变化，个别 CVE 是否命中仍取决于模板兼容性、产品指纹和目标环境条件。
- 生产环境使用前建议先用授权靶标或小范围资产做回归确认。

## 从原版迁移

常用旧参数已保留别名，但参数名兼容不代表默认行为、扫描引擎和配置文件格式完全一致。以下对照原 dddd 2.0.1；使用前可运行 `dddd -h` 查看当前帮助。

### 目标输入

目标输入统一使用 `-t`（保留原版长别名 `-target`）：输入为现有本地文件时逐行加载，否则按 IP、网段、域名、URL 或测绘语句处理。不再提供独立的 `-tf` 参数。

> 版本说明：从 **v0.1.48** 起，文件输入统一使用 `-t`，移除 `-tf`。从 v0.1.47 及更早版本升级时，请将脚本中的 `-tf 文件` 改为 `-t 文件`；v0.1.47 本身读取文件仍需使用 `-tf`。下列示例适用于 v0.1.48 及以后版本。

| 场景 | 原版用法 | dddd-next 用法 |
|:---|:---|:---|
| 单个 IP、网段、域名或 URL | `-t 192.0.2.1` | 相同；`-target` 长别名也可用 |
| 文件逐行输入 | `-t 1.txt` | 相同，自动读取现有本地文件 |
| 多个直接目标 | `-t 192.0.2.1,192.0.2.2` | 重复参数：`-t 192.0.2.1 -t 192.0.2.2`，或使用目标文件；不拆分 `-t` 值中的逗号 |
| 重新导入结果 | `-t result.txt` | 相同；支持 fscan 的 `ip:port open` 和 dddd 的 `[FP] ...` 行，其他历史格式不保证兼容 |

文件相对路径以**运行命令时的工作目录**为准；包含空格的路径需要加引号。文件内容使用 UTF-8（支持 BOM 和 Windows 换行），一行一个目标，空行和 `#` 注释行会跳过。`-t` 优先加载现有本地文件；路径不存在时按直接目标处理，因此文件名或目录写错仍可能进入域名解析。运行前应确认文件路径正确。

```bat
REM 文件逐行输入并扫描全部端口
dddd.exe -t 1.txt -p 1-65535

REM 多个目标可重复使用 -t，也可混合文件和直接目标
dddd.exe -t "目标 列表.txt" -t 192.0.2.1 -p 80,443
```

启动后先核对 `N target(s)` 是否与输入相符。四行 IP 应显示 `4 target(s)`，并进入 `TCP port scanning 4 host(s) x 65535 ports...`；若显示域名解析，应先检查目标输入方式。

### 默认行为和实现差异

| 项目 | 原版行为 | dddd-next 行为 / 对应用法 |
|:---|:---|:---|
| 主机存活探测 | 默认先做 ICMP 探测，`-Pn` 关闭 | 默认直接扫描端口；加 `-ping` 才先做 ICMP 预筛，`-tp` 启用 TCP 存活探测，`-Pn` 可关闭预筛。没有 `[Alive]` 输出不代表没有扫端口 |
| CDN 资产 | 默认跳过，`-ac` 允许扫描 | 默认标记但继续探测；`-skip-cdn` 才排除，`-ac` 可覆盖排除设置 |
| SYN 扫描 | `-st syn` 依赖 masscan，`-mp` 指定路径 | `-st syn` 使用内置 SYN 实现；Windows 依赖 Npcap / 管理员权限，不可用时回退 TCP。`-mp` 仅接受参数，不调用 masscan；`-sst` 表示发包速率 |
| 服务识别 | Nmap 风格探针 | 使用 fingerprintx；`-tc` / `-nto` 仍控制识别并发和超时，识别结果不保证完全一致 |
| 代理预检查 | 默认开启代理测试 | 默认关闭；需要时使用 `-proxy <地址> -pt`，`-ptu` 指定测试 URL |
| 输出位置 | 默认 `result.txt`，HTML 报告需指定 | 默认生成 `output/<时间戳>/result.txt` 和 `report.html`；`-o` / `-ho` 可指定相对文件名，`-ho ""` 关闭 HTML |
| 测绘 API 配置 | `-acf` 指定 YAML | 使用环境变量或 `.env`，字段见 [.env.example](.env.example)；`-acf` 仅接受参数，目前不会加载原版 API YAML |
| 模板和指纹配置 | 默认 `config/` 目录 | 使用 `configs/` 和内置配置释放机制，详见下方“快速开始”；`-nt` / `-fy` / `-wy` 等路径参数仍可用，旧配置内容需按当前格式核对 |

常用旧开关可继续使用：`-npoc` 等同 `-no-poc`，`-nb` 等同 `-no-brute`，`-nd` 等同 `-no-dir`，`-dgp` 等同 `-no-general`，`-s` 等同 `-severity`，`-et` 等同 `-exclude-tags`。`-ngp` 只关闭 GoPoC 检测，Nuclei 和 Shiro 检测仍可能执行；仅做信息收集时使用 `-no-poc`。

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
│   └── updater/                 # 本体自更新与 nuclei-templates 更新
├── pkg/
│   └── fingerdsl/               # 指纹表达式 DSL（可独立复用）
├── configs/
│   ├── fingers/                 # 指纹库 finger.yaml（会编译进单文件二进制）
│   ├── pocs/                    # mapping.yaml（指纹→POC）+ legacy POC 库
│   └── dict/                    # 弱口令字典
└── .env.example                 # 测绘 API 密钥模板（复制为 .env 填入）
```

## 快速开始

Release 版是单文件二进制，不需要手动携带 `configs/` 目录。首次运行时，如果程序同目录和当前工作目录都没有外部 `configs/`，会把内置基础配置释放到用户下载目录：

```text
Windows: %USERPROFILE%\Downloads\dddd-next\configs
Linux:   ~/Downloads/dddd-next/configs
```

如果需要自定义指纹、字典或 legacy POC，把 `configs/` 放到 exe 同目录即可；同目录外部配置优先级最高。下载目录中的内置副本可能随版本刷新覆盖，不建议直接当作长期自定义配置目录。默认 `dddd update` 会把最新 `nuclei-templates` 拉取到当前实际使用的配置目录。

```bash
# 构建
go build -o dddd ./cmd/dddd

# 首次使用：拉取最新 nuclei-templates
./dddd update

# 自行指定模板目录：首次成功后会记住，之后 update 和扫描自动复用
./dddd update -nt /data/nuclei-templates
./dddd update

# 仅本次扫描临时覆盖记住的目录
./dddd -t http://example.com -nt /data/other-nuclei-templates

# 扫描 IP / 网段 / 网站（默认精准 POC + 弱口令 + Shiro 专用检测）
./dddd -t 192.168.1.1
./dddd -t 192.168.1.0/24
./dddd -t http://example.com

# 常用全端口入口：发现 Web 与非 Web 服务后分别进入 POC / 弱口令链路
./dddd -t 192.168.1.1 -p 1-65535

# 从文件逐行加载目标（与直接目标统一使用 -t，版本差异见“从原版迁移”）
./dddd -t targets.txt -p 1-65535

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

### 更新本体与模板

> 本体升级命令从 **v0.1.49** 起支持；v0.1.48 及更早的发行版仅支持 `dddd update` 更新模板。旧版需要先手动下载一次 v0.1.49 或更新版本，之后才能使用 `dddd upgrade` 升级本体。

| 命令 | 行为 |
| --- | --- |
| `dddd upgrade` | 升级程序：下载对应平台的最新稳定版，校验 SHA-256 后替换当前程序 |
| `dddd upgrade --check` | 只检查本体版本，不下载程序、不修改本地文件 |
| `dddd update` | 刷新官方 nuclei 模板，保持原有含义，显示版本及是否有变化 |
| `-nt <目录>` / `-nuclei-template <目录>` | 更新时指定并记住模板目录，扫描时仅覆盖本次使用的模板目录 |

```bash
./dddd upgrade --check
./dddd upgrade
./dddd update -nt /data/nuclei-templates
./dddd -t http://example.com -nt /data/nuclei-templates

# 指定模板目录的长参数写法等效
./dddd update --nuclei-template /data/nuclei-templates
```

`-nt` / `-nuclei-template` 均接受单横杠或双横杠。更新子命令单独运行，不与扫描参数混用；`-up user:pass` 及其长参数 `-username-password` 继续表示自定义凭证。模板更新显示实际目录，已有模板发生变化时显示更新前后的提交版本；成功后记住指定目录，后续更新和扫描自动复用，扫描时指定另一目录仅对本次生效。本体与模板分别更新，普通扫描不自动检查或下载本体更新。

本体更新直接访问本项目 GitHub Release，支持 Windows amd64、Linux amd64/arm64，无需安装 Git。可选配置 `GITHUB_TOKEN` 环境变量或在 `.env` 中填写 `GITHUB_TOKEN=你的令牌`，以提高 GitHub API 的请求限额；访问本公开仓库无需授予写权限。系统环境变量优先于工作目录 `.env`，再优先于程序目录 `.env`。令牌只发送到初始 Release API 请求，不发送到程序/校验和下载地址、任何重定向目标，也不写入日志。未配置时匿名访问；HTTP 401 通常需要检查令牌，403/429 还需检查限额或访问策略。

只安装比当前版本更高的稳定版，不自动降级或安装预发布版。程序会显示当前版本、目标版本和实际替换路径；即使文件改名，仍更新当前正在运行的文件，符号链接启动时更新其指向的程序。更新后退出，下次运行使用新版本。

下载通过 HTTPS 验证服务器证书，并按同一 Release 的 `checksums.txt` 检查文件完整性；这不等同于独立的发布签名。下载、校验或常规替换失败时保留原程序；若极端文件系统错误导致回滚也失败，会明确提示手动恢复。更新要求程序目录可写。Windows 可能保留一个隐藏的 `.程序文件名.old` 旧文件，下次更新会尝试清理；原进程退出后也可手动删除。

### FOFA 官方与自建接口

> `FOFA_SERVER` 从 **v0.1.48** 起支持；v0.1.47 及更早版本无法通过此配置更换服务器。

复制 [.env.example](.env.example) 为 `.env`，放在工作目录或程序所在目录。系统环境变量优先，其次是工作目录 `.env`，最后是程序目录 `.env`；已设置的变量（包括空值）不会被后续文件覆盖。

官方 FOFA 无需设置服务器地址：

```dotenv
FOFA_SERVER=
FOFA_EMAIL=你的邮箱
FOFA_KEY=你的官方Key
```

使用自建反向代理或兼容 FOFA 的服务时，填写该服务的基础地址和凭证：

```dotenv
FOFA_SERVER=https://fofa-gateway.example.com/fofa
FOFA_EMAIL=该服务对应的邮箱
FOFA_KEY=该服务对应的Key
```

程序会请求 `https://fofa-gateway.example.com/fofa/api/v1/search/all`。基础地址允许末尾斜杠和路径前缀，不要填写完整搜索接口、查询参数或 URL 内嵌凭证。清空 `FOFA_SERVER` 即恢复官方地址 `https://fofa.info`，同时换回官方邮箱和 Key。每次运行选择一个 FOFA 服务器。

查询命令保持一致，例如在 Windows CMD 中只使用 FOFA，最多取 100 条：

```bat
dddd.exe -fofa -t "app=\"seeyon\"" -fmc 100
```

Linux / macOS shell 可写为 `./dddd -fofa -t 'app="seeyon"' -fmc 100`。`FOFA_SERVER` 与 `-proxy` 不同：前者选择接口服务器，后者配置访问接口及扫描目标时使用的网络代理。这个设置仅影响 FOFA，Hunter / Quake 继续使用各自的接口。

兼容范围是 FOFA 的 `/api/v1/search/all`：支持 `key`、`email`、`qbase64`、`fields=ip,port,host`、`page`、`size`、`full` 查询参数，以及包含 `error`、`size`、`results` 的 JSON 响应。当前仍要求邮箱和 Key 同时配置，不支持仅 Bearer Token 鉴权或其他返回结构；这类服务需要根据接口文档另行适配。HTTPS 会验证服务器证书，禁止跨服务器或改变协议的重定向。

查询失败会显示警告；如果已有部分结果，仍会继续扫描这些资产。鉴权失败、持续限流和无效返回格式不会被当成正常的零结果。常见状态：`HTTP 401/403` 检查凭证及权限，`HTTP 429` 检查配额或频率，`HTTP 404` 检查基础地址及路径前缀。

若自建服务返回内网 IP，需添加 `-ld` 才会保留这些资产；否则仍按原有规则过滤内网地址，与 API 是否查询成功无关。

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

### 代理配置（更新下载慢或失败时）

`dddd update` 调用系统 `git` 更新模板；`dddd upgrade`（含 `--check`）通过 HTTPS 访问 GitHub。本体和模板更新均读取 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量（本体更新也遵循 `NO_PROXY`）；更新命令不接收扫描用的 `-proxy` 参数。

```bash
# Windows CMD
set HTTPS_PROXY=http://127.0.0.1:7890
# Windows PowerShell
$env:HTTPS_PROXY="http://127.0.0.1:7890"
# Linux / macOS
export HTTPS_PROXY=http://127.0.0.1:7890
```

## 致谢

- [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) — 原项目作者（MIT License），本项目的设计灵感与指纹库 / POC 格式来源
- [projectdiscovery](https://github.com/projectdiscovery) — nuclei、httpx、subfinder、dnsx、fingerprintx 等核心引擎

## License

MIT License — 详见 [LICENSE](./LICENSE)
