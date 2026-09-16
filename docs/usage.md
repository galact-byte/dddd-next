# 使用指南

[返回首页](../README.md) · [迁移指南](migration.md) · [开发指南](development.md)

首页保留首次运行必需的说明；本文补充配置、更多示例和排错细节。完整参数及有效别名使用 `dddd help` 查看。

## 扫描示例与检测范围

以下示例使用 Linux shell。Windows PowerShell 将 `./dddd` 换为 `.\dddd.exe`；CMD 可直接使用 `dddd.exe`，测绘语句的引号写法见后文。

```bash
# 多个目标可混合文件和直接目标，文件每行一个目标
./dddd -t "目标 列表.txt" -t 192.0.2.1 -p 80,443

# 全端口或自定义端口段
./dddd -t 192.0.2.1 -p all
./dddd -t 192.0.2.1 -p 8000-9000

# 仅收集资产；可选启用 ICMP 存活预筛
./dddd -t 192.0.2.0/24 -no-poc
./dddd -t 192.0.2.0/24 -ping -no-poc

# 按 POC 名称或 ID 片段筛选，不依赖指纹映射
./dddd -t http://example.com -poc nacos
./dddd -t http://example.com -poc CVE-2021-29441

# 全量 Nuclei 模板；也可按严重度或标签筛选
./dddd -t http://example.com -full
./dddd -t http://example.com -severity critical -severity high

# 子域名枚举；-nsb 跳过主动字典爆破，-ns 跳过被动枚举
./dddd -t example.com -sd
```

默认按产品指纹精准匹配 POC，同时运行通用 POC 集合；`-no-general` 关闭精准模式中的通用集合。默认还会运行 GoPoC 和 Shiro 检测。`-no-brute` / `-ngp` 关闭 GoPoC，不关闭 Nuclei 或 Shiro；`-no-poc` 关闭全部漏洞检测。

| 能力 | 范围 |
| --- | --- |
| 主动指纹 | DSL 支持与、或、非及括号；产品路径探测可发现 `/nacos/`、`/druid/` 等子路径产品，`-no-dir` 关闭路径探测 |
| 被动指纹 | httpx / Wappalyzer 技术栈及版本识别，参与 POC 选择 |
| 子域名与服务 | subfinder 被动枚举、带泛解析检测的字典爆破、DNS 解析、TCP 端口扫描及 fingerprintx 服务识别 |
| 弱口令 | SSH、FTP、MySQL、PostgreSQL、Redis、MSSQL、Oracle、MongoDB、SMB、RDP、Telnet |
| 协议检测 | MS17-010、memcached / ADB / JDWP / Telnet 未授权、NetBIOS 与 RPC Endpoint Mapper 信息探测 |
| 过滤与凭证 | Nuclei 严重度 / 标签过滤、Interactsh 带外检测、自定义凭证 `-up` / `-upf` |

CDN 默认标记但继续探测，`-skip-cdn` 排除，`-ac` 覆盖排除设置。Hunter 低感知模式 `-lpm` 基于测绘返回的 banner 识别指纹，只跳过主动资产探测；后续漏洞检测仍可能发请求，仅收集资产时配合 `-no-poc`。

## 配置目录

Release 版是单文件二进制，内置指纹、字典、映射和 legacy POC 等基础配置。查找 `configs/` 的优先级为：

1. 程序所在目录。
2. 当前工作目录。
3. 两处均不存在时，将内置基础配置释放到用户下载目录并使用：

```text
Windows: %USERPROFILE%\Downloads\dddd-next\configs
Linux:   ~/Downloads/dddd-next/configs
```

自定义指纹、字典或 legacy POC 时，把 `configs/` 放在程序同目录。下载目录中的内置副本可能随版本刷新覆盖，不建议当作长期自定义配置目录。也可用 `-fy`、`-wy`、`-dy`、`-swl` 分别指定指纹、POC 映射、路径探测配置和子域名字典。

未记住或指定其他模板目录时，`dddd update` 会将官方 `nuclei-templates` 拉取到当前实际使用的配置目录。模板目录可单独选择，见下节。

## 更新本体与模板

本体升级命令从 **v0.1.49** 起支持；更早的发行版只有 `dddd update` 更新模板，需要先手动下载一次新版。

| 命令 | 行为 |
| --- | --- |
| `dddd upgrade` | 下载对应平台的最新稳定版，校验 SHA-256 后替换当前程序 |
| `dddd upgrade --check` | 只检查本体版本，不下载程序、不修改本地文件 |
| `dddd update` | 刷新官方 Nuclei 模板，显示版本及是否有变化 |
| `-nt <目录>` / `-nuclei-template <目录>` | 更新时指定并记住模板目录，扫描时仅覆盖本次 |

```bash
./dddd upgrade --check
./dddd upgrade
./dddd update -nt /data/nuclei-templates

# 成功后记住目录，后续更新和扫描自动复用
./dddd update

# 只对这次扫描使用另一个模板目录
./dddd -t http://example.com -nt /data/other-nuclei-templates

# 模板目录参数的长写法等效
./dddd update --nuclei-template /data/nuclei-templates
```

`-nt` / `-nuclei-template` 均接受单横杠或双横杠。更新子命令单独运行，不与扫描参数混用；`-up user:pass` / `-username-password` 继续表示自定义凭证。本体与模板分别更新，普通扫描不自动检查或下载本体更新。

模板更新调用系统 Git，已有模板发生变化时显示更新前后的提交版本。成功后记住指定目录，记录保存在用户配置目录的 `dddd-next/templates.json`。

### 本体下载与替换

本体更新通过 HTTPS 访问本项目 GitHub Release，支持 Windows amd64、Linux amd64 / arm64，无需安装 Git。只安装比当前版本更高的稳定版，不自动降级或安装预发布版。

程序会显示当前版本、目标版本和实际替换路径；即使文件改名，仍更新当前正在运行的文件，符号链接启动时更新其指向的程序。更新后退出，下次运行使用新版本，程序目录须可写。

下载通过 HTTPS 验证服务器证书，并按同一 Release 的 `checksums.txt` 检查文件完整性；这不等同于独立的发布签名。下载、校验或常规替换失败时保留原程序；若极端文件系统错误导致回滚也失败，会明确提示手动恢复。

Windows 可能保留一个隐藏的 `.程序文件名.old` 旧文件，下次更新会尝试清理；原进程退出后也可手动删除。

### GitHub API 限额

可选配置 `GITHUB_TOKEN` 环境变量或在 `.env` 中填写 `GITHUB_TOKEN=你的令牌`，提高 GitHub API 请求限额；访问本公开仓库无需授予写权限。未配置时匿名访问。

令牌只发送到初始 Release API 请求，不发送到程序 / 校验和下载地址、任何重定向目标，也不写入日志。HTTP 401 通常需要检查令牌，403 / 429 还需检查限额或访问策略。下载连接问题见[代理配置](#代理配置)。

## 测绘 API 配置

复制 [.env.example](../.env.example) 为 `.env`，放在工作目录或程序所在目录，填写所需引擎的凭证：FOFA 使用 `FOFA_EMAIL` + `FOFA_KEY`，Hunter 使用 `HUNTER_API_KEY`，Quake 使用 `QUAKE_TOKEN`。免费 FOFA 账号没有 API 配额。

配置优先级：**进程环境变量 > 工作目录 `.env` > 程序目录 `.env`**。已设置的变量（包括空值）不会被后续文件覆盖，`GITHUB_TOKEN` 也遵循该规则。

`-fofa`、`-hunter`、`-quake` 可单独或组合选择测绘引擎；未指定时使用三者。`-limit` 指定每条测绘语句的资产上限，`-fmc` / `-qmc` 为共用同一值的旧别名，0 表示 100。

### FOFA 官方与自建接口

`FOFA_SERVER` 从 **v0.1.48** 起支持，更早版本无法通过此配置更换服务器。

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

Windows CMD 查询示例：

```bat
dddd.exe -fofa -t "app=\"seeyon\"" -fmc 100
```

Linux shell：

```bash
./dddd -fofa -t 'app="seeyon"' -fmc 100
```

`FOFA_SERVER` 选择接口服务器，`-proxy` 配置访问接口及扫描目标时的网络代理，两者作用不同。此设置仅影响 FOFA，Hunter / Quake 继续使用各自接口。

兼容范围是 FOFA 的 `/api/v1/search/all`：支持 `key`、`email`、`qbase64`、`fields=ip,port,host`、`page`、`size`、`full` 查询参数，以及包含 `error`、`size`、`results` 的 JSON 响应。当前仍要求邮箱和 Key 同时配置，不支持仅 Bearer Token 鉴权或其他返回结构；这类服务需根据接口文档另行适配。HTTPS 验证服务器证书，禁止跨服务器或改变协议的重定向。

查询失败会显示警告；如果已有部分结果，仍继续扫描这些资产。鉴权失败、持续限流和无效返回格式不会被当作正常的零结果。

| 错误 | 检查项 |
| --- | --- |
| HTTP 401 / 403 | 凭证及权限 |
| HTTP 429 | 配额或访问频率 |
| HTTP 404 | 基础地址和路径前缀 |

若自建服务返回内网 IP，需添加 `-ld` 才会保留这些资产；否则仍按原有规则过滤，与 API 是否查询成功无关。

## 输出文件

每次扫描创建 `output/<时间戳>/` 目录，默认包含 `result.txt` 和 `report.html`。HTML 支持严重度筛选、漏洞详情展开、请求 / 响应复制和指纹资产查看。

```bash
# JSON 结果和自定义 HTML 文件名
./dddd -t 192.0.2.1 -ot json -o result.json -ho report.html

# 关闭 HTML（本例为 Linux shell 的空字符串写法）
./dddd -t 192.0.2.1 -ho ''

# 开启审计日志，默认文件名 audit.log
./dddd -t 192.0.2.1 -a
```

`-o` / `-ho` 指定输出目录内的相对文件名；`-alf` 设置审计日志文件名。输入文件的相对路径则始终以运行命令时的工作目录为准。

## 代理配置

扫描使用 `-proxy <URL>` 配置 HTTP / SOCKS5 代理。代理预检查默认关闭，`-pt` 开启，`-ptu` 指定测试地址。

```bash
./dddd -t http://example.com -proxy http://127.0.0.1:7890 -pt
```

`dddd update` 调用系统 Git，`dddd upgrade`（含 `--check`）通过 HTTPS 访问 GitHub。本体和模板更新均读取 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量，本体更新也遵循 `NO_PROXY`；更新命令不接收扫描用的 `-proxy` 参数。

Windows CMD：

```bat
set HTTPS_PROXY=http://127.0.0.1:7890
```

Windows PowerShell：

```powershell
$env:HTTPS_PROXY="http://127.0.0.1:7890"
```

Linux shell：

```bash
export HTTPS_PROXY=http://127.0.0.1:7890
```
