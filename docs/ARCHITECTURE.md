# dddd-next 架构设计

## 设计目标

1. **跟随上游**：所有 projectdiscovery 依赖走主线版本，禁止 `replace` 到本地 vendored
2. **POC 不老化**：nuclei 模板通过 `dddd update` 子命令从官方仓库实时拉取，禁止内置过期 POC
3. **可插拔**：指纹引擎、扫描器、信息源、报告器全部接口化，新增能力只需实现接口
4. **现代 Go**：context 贯穿、依赖注入、结构化日志、错误链、无全局可变状态
5. **行为对齐**：CLI 参数、扫描流程、HTML 报告与原 dddd 对齐，便于用户迁移

## 分层

```
┌─────────────────────────────────────────────────────┐
│  cmd/dddd                  (CLI 入口，cobra)         │
├─────────────────────────────────────────────────────┤
│  internal/app              (workflow 编排)           │
├─────────────────┬───────────────┬───────────────────┤
│  classifier     │  fingerprint  │  reporter         │
│  config         │  scanner      │  audit            │
│  discovery/*    │  updater      │                   │
├─────────────────┴───────────────┴───────────────────┤
│  pkg/fingerdsl    (可独立复用的指纹表达式引擎)        │
├─────────────────────────────────────────────────────┤
│  projectdiscovery 全家桶 (nuclei / httpx / subfinder │
│  / dnsx / gologger / uncover)                       │
└─────────────────────────────────────────────────────┘
```

## 核心接口契约

### 输入分类器 `internal/classifier`

```go
type Classifier interface {
    Classify(input string) (Type, error)
}

type Type int
const (
    TypeUnknown Type = iota
    TypeIP
    TypeIPRange
    TypeCIDR
    TypeDomain
    TypeDomainPort
    TypeIPPort
    TypeURL
    TypeSearchQuery   // 测绘语法
)
```

### 指纹引擎 `internal/fingerprint`

```go
type Engine interface {
    Match(ctx context.Context, target Target) ([]Fingerprint, error)
    LoadRules(path string) error
}
```

### 扫描器 `internal/scanner`

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, targets []Target, opts Options) (<-chan Finding, error)
}
```

实现：`NucleiScanner`、`GopocsScanner`（弱口令）

### 信息源 `internal/discovery/uncover`

```go
type Source interface {
    Name() string
    Query(ctx context.Context, query string, limit int) ([]Asset, error)
}
```

实现：`Hunter`、`Fofa`、`Quake`（复用 projectdiscovery/uncover）

### 报告器 `internal/reporter`

```go
type Reporter interface {
    Write(finding Finding) error
    Flush() error
}
```

实现：`TextReporter`、`JSONReporter`、`HTMLReporter`

## POC 老化问题的解决方案

### 根本原因

原 dddd 把 `common/config/pocs/` 目录的 POC 文件**编译时静态绑定**到二进制，更新 POC 必须重新发版。截至 2026 年 5 月，原项目最后一次 release 已是 2024 年中，社区 issue 集中反馈：

- 新 CVE 没有覆盖
- nuclei 官方模板有大量未引入
- 指纹库 finger.yaml 严重落后

### 设计方案

1. **解耦 POC 与二进制**：
   - 二进制内**不再嵌入**任何 POC
   - 启动时检查 `configs/nuclei-templates/` 是否存在，不存在则提示用户运行 `dddd update`

2. **`dddd update` 子命令**（`internal/updater/`）：
   - 默认源：`https://github.com/projectdiscovery/nuclei-templates`（git clone / pull）
   - 可选源：用户自维护的 POC 仓库（通过 `--source` 参数指定）
   - 自动检测 nuclei 版本，匹配兼容的 templates tag
   - 支持代理：`HTTPS_PROXY` 环境变量

3. **指纹库独立更新**：
   - `configs/fingers/finger.yaml` 通过同样机制可拉取（如果未来有 dddd-next 官方指纹仓库）
   - 短期内仍使用从 dddd 迁移过来的本地版本

4. **指纹→POC 映射**：
   - `configs/pocs/mapping.yaml` 单独维护
   - 格式：`fingerprint_name -> [nuclei_template_id1, template_id2, ...]`
   - 命中指纹后只跑相关 POC，减少无效请求（保留原 dddd 的这一核心特性）

## 错误处理与日志

- **日志**：`log/slog`（Go 1.21+ 标准库），统一 JSON 格式输出到 stderr，文件输出可选
- **错误**：返回 `error`，禁止 `panic` / `log.Fatal`，使用 `errors.Join` 聚合并发错误
- **context**：所有 IO 操作必须接受 `context.Context`，支持 `Ctrl+C` 优雅退出
- **结果持久化**：实时 flush，扫描中途终止也能保留已有结果（与原 dddd 行为一致）

## 测试策略

- **单元测试**：`classifier`、`fingerdsl`、`reporter` 模块覆盖率 > 70%
- **集成测试**：通过 `httptest` 起本地 HTTP 服务模拟靶机，验证完整 workflow
- **冒烟测试**：CI 中跑 `dddd -t httpbin.org` 确认主路径不挂

## 决策日志

| 决策 | 理由 |
|:---|:---|
| 不用 GOPROXY 私服 | 避免依赖私有基础设施，直接走 proxy.golang.org |
| 不用 viper | 配置层简单，cobra + 标准库 `flag` 即可，避免 viper 启动开销 |
| 不用 cobra-cli 生成器 | 手写 cobra 命令更清晰，避免冗余样板 |
| nuclei 走 SDK 而非子进程 | 减少进程开销，回调更灵活，与原 dddd 设计一致 |
| 不内置 templates | 解决 POC 老化的根本方案 |
