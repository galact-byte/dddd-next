# 开发指南

[返回首页](../README.md) · [使用指南](usage.md) · [迁移指南](migration.md)

本文记录当前源码的构建入口、模块分工和已有验证范围。依赖版本以 [go.mod](../go.mod) 为准。

## 构建与检查

使用符合 `go.mod` 要求的 Go 工具链（当前为 Go 1.26.3）和 Git，在仓库根目录执行：

```bash
# Linux
go build -o dddd ./cmd/dddd

# Windows
go build -o dddd.exe ./cmd/dddd

# 自动化测试和静态检查
go test ./...
go test -race ./...
go vet ./...
```

构建后的帮助入口为 `dddd help`；使用方式和配置目录见[使用指南](usage.md)。

`httpx v1.9.0` 通过 `go.mod` 的相对路径替换使用 `third_party/httpx/`，修复运行中限速器被按值复制的数据竞争。源码构建需保留该目录，无须额外安装。来源、许可证、四行补丁和以后升级或移除替换的方法见[第三方依赖维护说明](../third_party/README.md)。

## 项目结构

```text
dddd-next/
├── cmd/dddd/                    # CLI 入口（标准库 flag）、更新命令与配置目录选择
├── internal/
│   ├── app/                     # 扫描流程编排
│   ├── classifier/              # 输入类型自动识别
│   ├── config/                  # CLI 参数与 .env 加载
│   ├── nucleiinit/              # SDK 包初始化前隔离 Nuclei 配置目录
│   ├── types/                   # 公共类型
│   ├── fingerprint/             # 主动指纹引擎
│   ├── discovery/
│   │   ├── subfinder/           # 被动子域名枚举
│   │   ├── subbrute/            # 主动子域名字典爆破
│   │   ├── dnsx/                # DNS 解析
│   │   ├── hostalive/           # 主机存活探测
│   │   ├── portscan/            # TCP 端口扫描
│   │   ├── synscan/             # SYN 扫描
│   │   ├── servicedetect/       # 服务识别（fingerprintx）
│   │   ├── httpprobe/           # HTTP 探测（httpx）
│   │   ├── cdn/                 # CDN 识别
│   │   ├── dirscan/             # 产品路径探测
│   │   ├── hunter/              # Hunter 低感知模式
│   │   └── uncover/             # FOFA / Hunter / Quake 测绘
│   ├── scanner/
│   │   ├── nuclei/              # Nuclei v3 适配
│   │   ├── pocmap/              # 指纹到 POC 映射
│   │   ├── gopocs/              # 弱口令与协议检测
│   │   └── shiro/               # Shiro 专项检测
│   ├── reporter/                # TXT / JSON / HTML 报告
│   ├── audit/                   # 审计日志
│   └── updater/                 # 程序本体及 Nuclei 模板更新
├── third_party/httpx/           # httpx v1.9.0 最小并发修复及完整上游源码
├── pkg/fingerdsl/               # 指纹表达式 DSL
├── configs/
│   ├── fingers/                # 编译进程序的基础指纹库
│   ├── pocs/                   # mapping.yaml 与迁移自原版的 legacy POC
│   └── dict/                   # 字典
└── .env.example                # 测绘 API 和更新凭证配置示例
```

`configs/nuclei-templates/` 不纳入 Git，通过 `dddd update` 获取。基础指纹、字典、映射和 legacy POC 则作为发行版内置配置，运行时按目录规则释放或使用外部覆盖。

`internal/scanner/nuclei` 通过空白导入 `internal/nucleiinit`，在上游 SDK 的配置包初始化前将 `NUCLEI_CONFIG_DIR` 指向用户配置目录的 `dddd-next/nuclei`。这个启动包仅依赖上游配置包也依赖的标准库；Go 按导入路径排序初始化依赖已就绪的包，因此当前 `dddd-next/...` 包先于 `github.com/projectdiscovery/...` 初始化。修改模块名、启动包导入路径、该包依赖或升级 SDK 时，必须复核这项约束，运行 `go test ./internal/scanner/nuclei -run '^TestSDKConfigIsolation$' -count=1` 和实际程序冒烟测试，不能把设置环境的操作移到 `main()` 中。

扫描适配层要求始终提供模板根目录，包括显式指定 POC 文件的精准和名称筛选模式；忽略文件使用 SDK 返回的私有路径。`TestNucleiModesUseSelectedTemplateRoot` 通过独立扫描进程和本地 HTTP 服务覆盖三种扫描模式、三种目录来源、根目录下的相对路径字典，以及官方模板目录缺失时的 legacy 回退。Windows 下 SDK 会持有模板文件句柄，测试由父进程在扫描子进程退出后清理临时目录。

## 与原项目的实现差异

| 维度 | 原 dddd | dddd-next |
| --- | --- | --- |
| 依赖管理 | `lib/` 内嵌修改后的依赖 | Go modules 为主；`replace` 处理 client-go、grdp 及本地 httpx 最小补丁 |
| Nuclei | v3.1.8 | 当前依赖 v3.8.0，官方模板独立更新 |
| 项目结构 | common / lib / gopocs 等平铺模块 | cmd / internal / pkg 分层 |
| 配置与流程 | 全局配置变量 | 标准库 CLI flag、配置传递和 context 取消 |
| 测试 | 原版测试较少 | 单元与回归测试覆盖主链路，另有靶场实扫回归记录 |

命令和默认行为的区别以[迁移指南](migration.md)为准，不能仅凭参数名称判断行为相同。FOFA 由本项目适配兼容服务器，其余常规测绘引擎沿用 uncover；Hunter 低感知模式使用独立实现。

## 已验证场景

以下整理自项目已有靶场回归记录，不表示每次文档更新都重新执行实扫，也不保证所有产品版本和环境均可命中：

- Nacos：子路径 `/nacos/` 指纹、`CVE-2021-29441` 精准 POC。
- DVWA：根路径相对 302 跳转到登录页后仍能识别并触发默认口令检测。
- Shiro：`/login;jsessionid=...` 跳转不会造成重复弱 key / `shiro-detect` 结果。
- Redis / MySQL：非 Web 服务弱口令链路不依赖 HTTP 探测。
- Tomcat：Manager 路径探测和公开 Manager 检测。
- Pikachu / sqli-labs / Vulfocus / WebGoat：产品路径、通用泄露类 POC、子路径登录页指纹和新版 WebGoat 入口。
- 全端口入口：`-t <ip> -p 1-65535`，分别进入 Web POC 和非 Web 服务检测链路。

masscan 类超大网段加速和变化中的官方模板兼容性仍需持续回归。

## 发布与历史资料

版本号位于 `cmd/dddd/main.go`，面向用户的发布说明位于 [release_note.md](../release_note.md)。推送 `v*` 标签或手动运行 [Release 工作流](../.github/workflows/release.yml) 时，先调用 [原生构建工作流](../.github/workflows/native-build.yml)，并行验证 Windows amd64、Linux amd64 / arm64、macOS arm64。四个平台全部通过后，由 GoReleaser 使用该说明统一发布四平台单文件程序及校验和；任一平台失败均不会进入发布步骤，其他平台仍继续完成验证。

原生构建工作流也可单独手动运行；普通分支推送和 PR 不自动触发。四个平台分别使用 `windows-latest`、`ubuntu-latest`、`ubuntu-24.04-arm`、`macos-14` runner，先校验 Go 宿主平台，再以 `CGO_ENABLED=0` 运行全仓测试（`go test -trimpath ./...`，与构建复用依赖缓存），使用发行构建参数原生构建程序，并通过 `TestReleaseBinarySmoke` 运行实际程序：版本、帮助、缺目标错误退出、内置配置释放、本地 HTTP 指纹、Nuclei POC 正反例以及 JSON / HTML 报告。测试使用临时目录和本地模板，不下载官方模板或扫描外部目标；还检查版本命令不会创建独立 Nuclei 的配置目录、继承外部配置目录和排除标签不影响扫描、全局配置文件保持原有字节，以及模板根目录下的相对路径字典能正常加载。不覆盖 Gatekeeper 下载隔离、Apple 签名 / 公证或所有操作系统版本。

本地可对已构建的当前平台程序运行相同冒烟检查（路径须指向本机可执行文件）：

```bash
DDDD_SMOKE_BINARY=/absolute/path/to/dddd go test ./cmd/dddd -run '^TestReleaseBinarySmoke$' -count=1 -v
```

原生构建沿用 `cmd/dddd/main.go` 中的版本号。每个平台冒烟检查通过后，将同一个程序和 `checksums.txt`、许可文件打成 `dddd-next_<版本>_<系统>_<架构>.tar.gz`，再上传为 `dddd-next-<系统>-<架构>` Actions 产物（系统名称为 `windows`、`linux` 或 `darwin`），保留 90 天；该平台不通过测试时不会上传。Windows 包内程序名为 `dddd.exe`，其他平台为 `dddd`。使用 tar 保留可执行权限，外层 ZIP 由 Actions 生成。登录 GitHub 后可在成功构建记录的 Artifacts 区域下载，无需升版本、创建标签或发布 Release。

最终 GoReleaser 资产仍单独生成并使用 Release 版本号，不宣称与 Actions 构建包逐字节相同。下一次正式发布时应根据实际内容编写发布说明，注明首次提供的 macOS arm64 资产及未使用 Apple 开发者签名 / 未公证限制，不应追溯修改旧版发布说明。

[ARCHITECTURE.md](ARCHITECTURE.md) 是早期设计稿，包含未落地或已改变的设想，例如 Cobra、统一 slog、模板来源参数等，不应作为当前功能说明；当前行为以代码和使用文档为准。
