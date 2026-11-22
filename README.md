# dddd-next

`dddd-next` 是基于 [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd) 设计重写的资产探测与漏洞扫描工具，使用 Go 开发，核心扫描能力基于 projectdiscovery 等开源组件。

- 支持 IP、网段、域名、URL、目标文件，以及 FOFA / Hunter / Quake 测绘查询。
- 端口与服务识别、子域名枚举、主动及被动指纹识别、产品路径探测。
- 根据产品指纹选择 Nuclei POC，支持 GoPoC 弱口令与协议检测、Shiro 检测。
- 支持 TXT / JSON 结果、资产 CSV，以及可直接在浏览器打开的 HTML 报告。

## 下载与快速开始

从 [Releases](https://github.com/galact-byte/dddd-next/releases/latest) 下载对应平台的程序：Windows amd64、Linux amd64 / arm64、macOS arm64（Apple Silicon）。旧版可能不含全部平台，未发版构建见 [Actions](https://github.com/galact-byte/dddd-next/actions)。

下文将程序重命名为 `dddd.exe` 或 `dddd`。请放在可写目录，基础配置会自动释放到程序旁的 `configs/`；更新官方模板需要安装 Git。

Windows PowerShell：

```powershell
.\dddd.exe update
.\dddd.exe -t 192.168.1.1
.\dddd.exe -t targets.txt -p 1-65535
```

Linux / macOS（先运行 `chmod +x dddd`）：

```bash
./dddd update
./dddd -t 192.168.1.1
./dddd -t targets.txt -p 1-65535
```

默认扫描精选端口，并执行 Nuclei、GoPoC 和 Shiro 漏洞检测；**仅收集资产请加 `-no-poc`**。目标文件使用 UTF-8，一行一个目标；多个直接目标重复使用 `-t`。完整参数运行 `dddd help` 查看。

macOS 版未签名或公证，可能提示无法验证开发者；请核验下载来源及 `checksums.txt` 后再按系统提示允许运行。

## 常用命令

以下使用 Linux shell，Windows PowerShell 将 `./dddd` 换为 `.\dddd.exe`。

```bash
# 扫描网段，仅收集资产
./dddd -t 192.168.1.0/24 -no-poc

# 指定端口，仅收集资产
./dddd -t 192.168.1.1 -p 80,443,8000-8100 -no-poc

# 按 POC 名称或 ID 片段筛选
./dddd -t http://example.com -poc nacos

# FOFA 查询（先配置 FOFA_EMAIL 和 FOFA_KEY）
./dddd -fofa -t 'app="seeyon"' -limit 100
```

测绘凭证可按 [.env.example](.env.example) 填入 `.env`，放在工作目录或程序目录。其他引擎、自建 FOFA 和 Windows CMD 引号写法见[测绘配置](docs/usage.md#测绘-api-配置)。

## 查看结果

扫描结果默认保存在 `output/<时间戳>/`：`result.txt` 为文本结果，`report.html` 为网页报告，支持严重度筛选、漏洞详情和请求 / 响应复制。加 `-ot json` 可改用 JSON 结果，更多输出选项见[使用指南](docs/usage.md#输出文件)。

## 更新

| 命令 | 用途 |
| --- | --- |
| `dddd upgrade` | 更新程序本体 |
| `dddd upgrade --check` | 只检查程序版本 |
| `dddd update` | 更新官方 Nuclei 模板 |
| `dddd update -nt <目录>` | 更新模板并记住目录，供后续更新和扫描使用 |

程序与模板分别更新，普通扫描不会自动更新程序。自定义模板请另存为新文件，直接修改官方模板会阻止更新。更新失败或需要代理时，见[更新说明](docs/usage.md#更新本体与模板)和[代理配置](docs/usage.md#代理配置)。

## 文档

- [使用指南](docs/usage.md)：更多扫描示例、配置、自定义模板、测绘 API 和排错。
- [迁移指南](docs/migration.md)：原版用户请先阅读，目标输入、存活探测、CDN 和部分旧参数的行为有变化。
- [开发指南](docs/development.md)：源码构建、目录结构、依赖及已验证场景。

## 致谢与许可证

- [SleepingBag945/dddd](https://github.com/SleepingBag945/dddd)：原项目及设计、指纹库和 POC 格式来源。
- [projectdiscovery](https://github.com/projectdiscovery)：Nuclei、httpx、subfinder 等核心依赖；服务识别使用 [fingerprintx](https://github.com/praetorian-inc/fingerprintx)。

本项目可由个人和公司免费用于合法内部工作，包括正常经营业务及授权测评；免费分发须保留署名和许可，并标识修改版。对外售卖、集成进收费产品或以软件功能提供收费服务，须另行取得书面商业授权。

完整条款见 [LICENSE](LICENSE)，版权、第三方例外和旧版 MIT 权利见 [NOTICE](NOTICE)。这是自定义源码可用许可，不是 MIT 或 OSI 开源许可；此前合法取得的 MIT 版本及内容仍享有原许可权利。第三方指纹、规则和依赖不因此被重新授权。商业授权请通过本官方仓库联系维护者。
