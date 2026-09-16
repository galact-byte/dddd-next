# dddd-next

`dddd-next` 是基于 [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) 设计重写的资产探测与漏洞扫描工具，使用 Go 开发，依赖跟随 projectdiscovery 主线。默认根据产品指纹选择 POC，官方 Nuclei 模板可独立更新。

## 主要能力

- 支持 IP、网段、域名、URL、测绘语句和目标文件，接入 FOFA / Hunter / Quake。
- 端口与服务识别、子域名枚举、主动及被动指纹识别、产品路径探测。
- Nuclei 精准 POC、GoPoC 弱口令与协议检测、Shiro 专项检测。
- TXT / JSON / HTML 报告及审计日志；HTML 支持严重度筛选、详情展开和请求 / 响应复制。

## 下载与快速开始

从 [Releases](https://github.com/galact-byte/dddd-next/releases/latest) 下载对应平台的单文件程序：Windows amd64、Linux amd64 / arm64。下文假设重命名为 `dddd.exe` 或 `dddd`；Linux 下载后先运行 `chmod +x dddd`。

发行版内置基础配置，无需手动携带 `configs/`。更新官方模板需要系统安装 Git；完整参数以 `help` 为准。

Windows PowerShell：

```powershell
.\dddd.exe help
.\dddd.exe update
.\dddd.exe -t 192.168.1.1
.\dddd.exe -t targets.txt -p 1-65535
```

Linux：

```bash
./dddd help
./dddd update
./dddd -t 192.168.1.1
./dddd -t targets.txt -p 1-65535
```

默认扫描精选端口，`-p 1-65535` 或 `-p all` 扫描全部端口。默认运行指纹精准 POC、GoPoC 和 Shiro 检测；仅收集资产时加 `-no-poc`。`-no-brute` / `-ngp` 只关闭 GoPoC，Nuclei 和 Shiro 仍可能执行。

`-t` 可读取现有文件：UTF-8、一行一个目标，支持空行和 `#` 注释。相对路径以运行命令时的工作目录为准，有空格需加引号；**路径写错可能被当作域名解析**。启动后核对 `N target(s)`，多个直接目标使用重复的 `-t`。

## 常用示例

下列示例使用 Linux shell；Windows PowerShell 将 `./dddd` 换为 `.\dddd.exe`。

```bash
# 扫描网段或网站
./dddd -t 192.168.1.0/24
./dddd -t http://example.com

# 指定端口，仅做资产探测
./dddd -t 192.168.1.1 -p 80,443,8000-8100 -no-poc

# 按 POC 名称 / ID 片段筛选，或运行全部 Nuclei 模板
./dddd -t http://example.com -poc nacos
./dddd -t http://example.com -full

# FOFA 测绘（先在环境变量或 .env 配置 FOFA_EMAIL 和 FOFA_KEY）
./dddd -fofa -t 'app="seeyon"' -limit 100
```

Windows CMD 的测绘语句需要使用双引号并转义内部引号：

```bat
dddd.exe -fofa -t "app=\"seeyon\"" -limit 100
```

测绘配置参考 [.env.example](.env.example)，必要设置见下节。更完整的示例和排错见[使用指南](docs/usage.md)。

## 配置须知

- **基础配置**：优先使用程序同目录的 `configs/`，其次是工作目录；均不存在时释放到 `~/Downloads/dddd-next/configs`（Windows 为 `%USERPROFILE%\Downloads\dddd-next\configs`）。自定义指纹、字典和 POC 请放在程序同目录，下载目录中的内置副本可能随版本刷新覆盖。
- **API 密钥**：复制 [.env.example](.env.example) 为 `.env`，放在工作目录或程序目录。FOFA 填 `FOFA_EMAIL` + `FOFA_KEY`，Hunter 填 `HUNTER_API_KEY`，Quake 填 `QUAKE_TOKEN`。优先级为进程环境变量 > 工作目录 `.env` > 程序目录 `.env`，已设置的空值也不会被覆盖。免费 FOFA 账号没有 API 配额。
- **测绘引擎**：`-fofa` / `-hunter` / `-quake` 可组合选择，未指定时使用三者。自建 FOFA 用 `FOFA_SERVER` 设置 HTTP(S) 基础地址，程序自动追加 `/api/v1/search/all`，仍需邮箱和 Key；返回内网资产时加 `-ld`，否则会被过滤。
- **模板目录**：`dddd update -nt <目录>` 成功后会记住目录，后续更新和扫描复用；扫描时的 `-nt` 仅覆盖本次。模板与指纹库分别管理，更新官方模板不会自动更新指纹库。

## 扫描结果

每次扫描默认生成 `output/<时间戳>/result.txt` 和 `report.html`。HTML 报告可直接用浏览器打开；`-ot json` 切换结果格式，`-o` / `-ho` 指定相对文件名，`-a` 开启审计日志。

## 更新程序与模板

| 命令 | 用途 |
| --- | --- |
| `dddd upgrade` | 下载、校验并升级程序本体 |
| `dddd upgrade --check` | 只检查程序版本 |
| `dddd update` | 更新官方 Nuclei 模板 |
| `dddd update -nt <目录>` | 更新模板并记住目录；扫描时的 `-nt` 只覆盖本次 |

本体升级从 v0.1.49 起支持，更早版本需先手动下载新版。更新子命令单独运行；`-up user:pass` 仍表示凭证。普通扫描不自动更新程序。

本体升级要求程序目录可写，下载或校验失败会保留原程序，成功后下次启动使用新版。运行 `dddd update --help` / `dddd upgrade --help` 查看帮助；GitHub API 限额不足时可选配置 `GITHUB_TOKEN`。

**更新下载慢或连接失败**时，在当前终端设置代理后重试；更新命令不接受扫描用的 `-proxy` 参数。扫描代理单独使用 `-proxy http://127.0.0.1:7890`，需要预检查时再加 `-pt`。

| 终端 | 更新代理设置（按实际代理地址修改） |
| --- | --- |
| Windows CMD | `set HTTPS_PROXY=http://127.0.0.1:7890` |
| Windows PowerShell | `$env:HTTPS_PROXY="http://127.0.0.1:7890"` |
| Linux shell | `export HTTPS_PROXY=http://127.0.0.1:7890` |

更多细节见[更新说明](docs/usage.md#更新本体与模板)和[代理配置](docs/usage.md#代理配置)。

## 从原版迁移

旧参数名兼容不代表默认行为相同，原版用户请先确认：

- **目标统一使用 `-t`**：现有本地文件自动逐行加载；从 v0.1.48 起移除 `-tf`。多个直接目标重复使用 `-t`，不按逗号拆分。
- **默认不做 ICMP 预筛**：加 `-ping` 才启用，`-Pn` 关闭存活预筛。
- **默认不跳过 CDN**：需要排除时使用 `-skip-cdn`。
- **API 密钥使用环境变量或 `.env`**：不再加载旧版 API YAML。
- **部分参数仅兼容接收**：`-mp` / `-masscan-path`、`-acf` / `-api-config-file`、`-log-level` 不生效，v0.1.50 起显式使用时提示已忽略。

完整的输入格式、默认行为对照和有效旧别名见[迁移指南](docs/migration.md)。

## 已知限制

- 默认使用 TCP connect；`-st syn` 使用内置 SYN，不等同于原版 masscan 的超大网段加速。Windows SYN 需要 Npcap / 管理员权限，不可用时回退 TCP。
- POC 是否命中仍取决于模板兼容性、产品指纹和目标环境；已有靶场回归不能覆盖所有环境。
- Hunter 低感知模式只跳过主动资产探测，后续漏洞检测仍可能发请求；仅收集资产时配合 `-no-poc`。

## 文档

- [使用指南](docs/usage.md)：扫描示例、配置目录、测绘 API、更新和代理。
- [迁移指南](docs/migration.md)：与原 dddd 的行为差异、版本边界和兼容参数。
- [开发指南](docs/development.md)：源码构建、目录结构、依赖及已验证场景。

## 致谢与许可证

- [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd)：原项目及设计、指纹库和 POC 格式来源。
- [projectdiscovery](https://github.com/projectdiscovery)：Nuclei、httpx、subfinder 等核心依赖；服务识别使用 [fingerprintx](https://github.com/praetorian-inc/fingerprintx)。

采用 [MIT License](LICENSE)。
