# 开发指南

[返回首页](../README.md) · [使用指南](usage.md) · [迁移指南](migration.md)

本文面向需要源码构建或修改程序的开发者，说明构建入口、模块分工、依赖和发布流程。依赖版本以 [go.mod](../go.mod) 为准。

## 构建与检查

使用符合 `go.mod` 要求的 Go 工具链（当前为 Go 1.26.4）和 Git，在仓库根目录执行：

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

`httpx` 通过 `go.mod` 的相对路径替换使用 `third_party/httpx/`，修复运行中限速器被按值复制的数据竞争。源码构建需保留该目录，无须额外安装。来源、许可证、补丁与升级方法见[第三方依赖维护说明](../third_party/README.md)，当前源码版本以[来源记录](../third_party/httpx-upstream.json)为准。

Dependabot 每周集中检查根模块及本地 httpx 模块的 Go 依赖。httpx 版本变化时，自动化先同步完整上游源码、保留补丁并完成测试，再提交回同一依赖 PR；补丁冲突或兼容性检查失败会中止。依赖 PR 仍需审阅，不自动合并或发版；通过验证的升级可单独发布维护版本，也可随功能或修复版本一并交付，由维护者决定。

依赖升级还需满足当前工具链和 `CGO_ENABLED=0` 构建要求：naabu 保留 v2.6.1，grdp 的替换目标保留 v1.0.3。fingerprintx 保留 v1.1.15；v1.1.16 起包含 MongoDB 探测，v1.1.19 在本地回归中会先执行该探测，耗尽非标准端口 HTTP 识别的 10 秒取消期限。go-rod 所用的 fetchup、got，以及 tlsx 所用的 zcrypto 与相关 ProjectDiscovery 基础库存在接口约束，应作为一组升级并验证，不要只提高单个模块版本。

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
│   ├── reporter/                # TXT / JSON / HTML 报告及资产 CSV
│   ├── audit/                   # 审计日志
│   └── updater/                 # 程序本体及 Nuclei 模板更新
├── third_party/httpx/           # httpx 最小并发修复及完整上游模块源码
├── pkg/fingerdsl/               # 指纹表达式 DSL
├── configs/
│   ├── fingers/                # 编译进程序的基础指纹库
│   ├── pocs/                   # mapping.yaml 与迁移自原版的 legacy POC
│   └── dict/                   # 字典
└── .env.example                # 测绘 API 和更新凭证配置示例
```

`configs/nuclei-templates/` 不纳入 Git，通过 `dddd update` 获取。基础指纹、字典、映射和 legacy POC 则作为发行版内置配置，运行时按目录规则释放或使用外部覆盖。

`internal/scanner/nuclei` 通过空白导入 `internal/nucleiinit`，在上游 SDK 的配置包初始化前将 `NUCLEI_CONFIG_DIR` 指向用户配置目录的 `dddd-next/nuclei`。这个启动包仅依赖上游配置包也依赖的标准库；Go 按导入路径排序初始化依赖已就绪的包，因此当前 `dddd-next/...` 包先于 `github.com/projectdiscovery/...` 初始化。修改模块名、启动包导入路径、该包依赖或升级 SDK 时，必须复核这项约束，运行 `go test ./internal/scanner/nuclei -run '^TestSDKConfigIsolation$' -count=1` 和实际程序冒烟测试，不能把设置环境的操作移到 `main()` 中。

扫描适配层要求始终提供模板根目录，包括显式指定 POC 文件的精准和名称筛选模式；忽略文件使用 SDK 返回的私有路径。修改模板选择或资源加载逻辑时，运行 `TestNucleiModesUseSelectedTemplateRoot`，检查三种扫描模式是否都使用选定目录中的模板与相对路径字典。Windows 下 SDK 会持有模板文件句柄，测试应在扫描子进程退出后再清理临时目录。

## 与原项目的实现差异

| 维度 | 原 dddd | dddd-next |
| --- | --- | --- |
| 依赖管理 | `lib/` 内嵌修改后的依赖 | Go modules 为主；`replace` 处理 grdp 及本地 httpx 最小补丁 |
| Nuclei | v3.1.8 | 当前依赖 v3.11.1，官方模板独立更新 |
| 项目结构 | common / lib / gopocs 等平铺模块 | cmd / internal / pkg 分层 |
| 配置与流程 | 全局配置变量 | 标准库 CLI flag、配置传递和 context 取消 |
| 测试 | 原版测试较少 | 单元测试、回归测试和实际程序冒烟测试 |

命令和默认行为的区别以[迁移指南](migration.md)为准，不能仅凭参数名称判断行为相同。FOFA 由本项目适配兼容服务器，其余常规测绘引擎沿用 uncover；Hunter 低感知模式使用独立实现。

## 实际程序测试

修改 CLI、配置加载、扫描流程或报告输出后，除单元测试外，还应构建并运行当前平台程序的冒烟测试：

```bash
go build -trimpath -o dddd ./cmd/dddd
DDDD_SMOKE_BINARY="$PWD/dddd" go test -trimpath ./cmd/dddd -run '^Test(ReleaseBinarySmoke|PriorityBinarySmoke)$' -count=1 -v
```

以上命令适用于 Linux / macOS。Windows 构建为 `dddd.exe`，将 `DDDD_SMOKE_BINARY` 设为该程序的绝对路径，并将 `BinaryInterruptFinalizesReports` 加入测试选择以检查运行中断后的报告收尾。未设置 `DDDD_SMOKE_BINARY` 时，这些用例会跳过，不能作为程序已验证的依据。

测试自行启动本地 HTTP 服务，使用临时配置和模板，无需外部靶场。主要检查帮助与退出码、配置释放、指纹和 POC 正反例、TXT / JSON / HTML 报告、规则体检、资产 CSV 和阶段进度。它们不覆盖所有产品、模板或操作系统版本，也不覆盖 macOS 的下载隔离、签名和公证。

## 发布流程

版本号位于 `cmd/dddd/main.go`，发布说明位于 [release_note.md](../release_note.md)。推送 `v*` 标签或手动运行 [Release 工作流](../.github/workflows/release.yml) 时，先调用 [原生构建工作流](../.github/workflows/native-build.yml)，检查 Windows amd64、Linux amd64 / arm64 和 macOS arm64。各平台运行全仓测试，原生构建程序，再运行上述冒烟；Windows 另测运行中断。全部成功后才由 GoReleaser 生成正式 Release 资产及校验和。

原生构建工作流也可单独手动运行，不随普通分支推送或 PR 自动触发。它使用 `windows-latest`、`ubuntu-latest`、`ubuntu-24.04-arm` 和 `macos-15`，并检查宿主系统及架构；构建参数为 `CGO_ENABLED=0`、`-trimpath` 和 `-ldflags="-s -w -buildid="`。矩阵与命令以工作流文件为准。

每个平台测试成功后会上传包含程序、校验和与许可文件的 Actions 产物，保留 90 天。登录 GitHub 后可在构建记录的 Artifacts 区域下载。Actions 产物使用源码版本号，正式 Release 资产另由 GoReleaser 生成。

发布说明按相对上一已发布版本的实际变化编写，说明使用变化、兼容性和必要的升级步骤。源码构建、测试细节放在本文；本机验收日志、调研笔记和任务记录不属于公开文档。
