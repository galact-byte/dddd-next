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
go vet ./...
```

构建后的帮助入口为 `dddd help`；使用方式和配置目录见[使用指南](usage.md)。

## 项目结构

```text
dddd-next/
├── cmd/dddd/                    # CLI 入口（标准库 flag）、更新命令与配置目录选择
├── internal/
│   ├── app/                     # 扫描流程编排
│   ├── classifier/              # 输入类型自动识别
│   ├── config/                  # CLI 参数与 .env 加载
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
├── pkg/fingerdsl/               # 指纹表达式 DSL
├── configs/
│   ├── fingers/                # 编译进程序的基础指纹库
│   ├── pocs/                   # mapping.yaml 与迁移自原版的 legacy POC
│   └── dict/                   # 字典
└── .env.example                # 测绘 API 和更新凭证配置示例
```

`configs/nuclei-templates/` 不纳入 Git，通过 `dddd update` 获取。基础指纹、字典、映射和 legacy POC 则作为发行版内置配置，运行时按目录规则释放或使用外部覆盖。

## 与原项目的实现差异

| 维度 | 原 dddd | dddd-next |
| --- | --- | --- |
| 依赖管理 | `lib/` 内嵌修改后的依赖 | Go modules 跟随主线；`replace` 处理 client-go 依赖冲突及 grdp fork |
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

版本号位于 `cmd/dddd/main.go`，面向用户的发布说明位于 [release_note.md](../release_note.md)。推送 `v*` 标签触发 [Release 工作流](../.github/workflows/release.yml)：先运行 `go test ./...`，再由 GoReleaser 使用该说明发布 Windows amd64、Linux amd64 / arm64 单文件程序及校验和。

[ARCHITECTURE.md](ARCHITECTURE.md) 是早期设计稿，包含未落地或已改变的设想，例如 Cobra、统一 slog、模板来源参数等，不应作为当前功能说明；当前行为以代码和使用文档为准。
