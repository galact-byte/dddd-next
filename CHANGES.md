# 修改记录 — dddd-next

> **修订记录**
>
> - v0.1.0-init: 项目骨架建立，基于 dddd 原项目重写计划启动
> - v0.1.1-foundation: 数据资产迁移完成；输入分类器 + 配置加载模块上线（31 测试全绿）
> - v0.1.2-engine: 指纹 DSL 引擎、报告生成（TXT/JSON/HTML）、审计日志全部上线（74 测试全绿，DSL 实战 lint 99.96%）
> - v0.1.3-update: updater 子命令上线，nuclei-templates 真实拉取成功（13084 模板，原版仅 2406，**多 5.4 倍**）；fingerprint Engine 完整闭环
> - v0.1.4-httpprobe: 首个 projectdiscovery 外部依赖落地——`httpx v1.9.0` 集成；channel-based API 取代原 dddd 的全局 Map+Mutex 模式；94 测试全绿
> - v0.1.5-nuclei: **最重大引擎集成**——nuclei v3.8.0 public lib SDK 适配层（callback→channel 包装，`ResultEvent`→`Finding` 投影）；项目首个 `replace`（client-go 依赖冲突修复，非 vendored fork，属约定内例外）；`go test ./...` 10 包回归全绿
> - v0.1.6-subfinder-dnsx: 资产发现链路补全——subfinder v2.14.0（被动子域枚举，callback→channel）+ dnsx v1.2.3（DNS 解析，单次 + 并发批量）；无 `replace` 冲突；安全复审 616 依赖 0 攻击载荷；12 包回归全绿
> - v0.1.7-pipeline: **主编排骨架落地**——`internal/app` 把 classifier/subfinder/dnsx/httpx/fingerprint/nuclei/reporter/audit 串成单一扫描工作流；CLI `-t` 扫描模式接入；nm 实测确认 `vulncheck/dotnet` 符号(174)如 Directive 预言入二进制（检测用途，webshell 类 0）；13 包回归全绿
> - v0.1.8-nuclei-localdir: 端到端冒烟揪出并修复 nuclei bug——引擎用了系统全局（另一个 nuclei CLI 写的）模板目录而非本地 `configs/`，init 联网装模板触发 401 崩溃；改用 `SetTemplatesDir`（内存级）指向本地 + `DisableUpdateCheck` 跳过启动联网；本地靶标实测 13 findings 入报告，13 包回归全绿

---

## v0.1.8-nuclei-localdir — nuclei 改用本地模板目录、扫描不再被联网阻断

### 背景：v0.1.7 端到端冒烟揪出的真 bug

主编排骨架落地后首次跑完整链路（本地靶标），nuclei init 直接失败：

- nuclei 引擎的模板目录取自**进程全局** `config.DefaultConfig.TemplatesDirectory`（`lib/sdk_private.go:197`），**不是**我们 `WithTemplatesOrWorkflows` 传入的路径
- 该全局值来自系统里**另一个独立安装的 nuclei CLI** 写入的 `%AppData%/nuclei/.templates-config.json`（指向 `D:\work\CTF\...\templates`）
- init 时发现该目录模板缺失 → 联网拉 GitHub release 安装 → token 失效 401 → `init engine failed`，整条 nuclei 链路崩

### 修复（方案：本地模板 + `dddd update` 联网，职责分离）

`internal/scanner/nuclei/scanner.go`：

- **`config.DefaultConfig.SetTemplatesDir(TemplatesDir)`**（New 中、引擎构造前）：把 nuclei 全局模板目录指向 dddd-next 自己的 `configs/nuclei-templates`。源码确认该 setter **仅改内存、不写磁盘**，不污染系统全局 nuclei 配置
- **`DisableUpdateCheck()` 取代 `WithTemplateUpdateCallback(true,nil)`**：后者只设 `disableTemplatesAutoUpgrade`，不影响 `CanCheckForUpdates()`，init 仍会 `processUpdateCheckResults()` 联网（401 阻断根因）；`DisableUpdateCheck()` 才真正令 `CanCheckForUpdates()=false`，跳过启动联网检查
- **非"禁联网"**：模板更新归 `dddd update`（照常联网拉最新），扫描只用本地模板 → 内网外网都稳

### 端到端验证（本地靶标完整链路）

`python http.server` 起本地靶标 `http://127.0.0.1:18080`，`dddd-next -t` 跑通：

`指纹库 8379 → httpx 探测(识别 Python/SimpleHTTP) → 指纹命中 1 → nuclei init ✓ → 13084 模板加载 → 执行 → findings: 13 → 报告`

- 13 findings 全 info 级（11× HTTP Missing Security Headers + 2× Wappalyzer 技术识别），符合本地空服务预期
- 报告产出：`result.json` 14 条（1 fingerprint + 13 finding）+ HTML 19K
- 完整回归 **13 包全绿**

### 已知小瑕疵（后续优化）

- 设了 `Silent=true` 但 nuclei 的 INF 日志（network 模板端口探测）仍漏到 stdout，污染进度——待后续静音

### 文件清单总览

| 操作 | 文件路径 |
| :--- | :--- |
| **修改** | `internal/scanner/nuclei/scanner.go`（SetTemplatesDir + DisableUpdateCheck） |
| **修改** | `cmd/dddd/main.go`（版本 0.1.7-dev → 0.1.8-dev） |

### 测试方式

1. 确保 `configs/nuclei-templates` 有模板（`dddd update` 拉取）
2. 起本地 http 服务，`dddd-next -t http://127.0.0.1:PORT`
3. 期望：nuclei init 不报 401、findings 写入报告；`go test ./...` 13 包全绿

---

## v0.1.7-pipeline — 主编排骨架 + CLI 扫描模式（模块串成工作流）

### 关键成果

- **`internal/app` 编排层落地**：把已完成的 8 个模块串成单一扫描工作流——这是 dddd-next 从"一堆能跑的模块"变成"一个能扫的工具"的关键一跃。
- **CLI 扫描模式接入**：`cmd/dddd` 从只有 `update/version/help`，到 `dddd -t <target>` 真正能发起扫描；版本号 `0.1.2-dev → 0.1.7-dev`。

### 新增文件

#### `internal/app/pipeline.go` + 测试 — 扫描编排层

- **阶段流**：`targets → classify → [子域枚举] → DNS 解析 → 去重 → HTTP 探测 + 指纹 → nuclei → 报告`
- `New(cfg, configDir)`：加载指纹库（`fingers/finger.yaml`）、按 `OutputType` 组装 reporter（text/json + 可选 HTML 的 `NewMulti`）、可选 audit
- **诚实降级**（不静默丢弃）：CIDR/IP 段（端口扫描未实现）、搜索语法（测绘 API 未实现）→ 显式 `[!]` 提示跳过
- **优雅缺失处理**：nuclei 模板目录不存在 → 提示先跑 `dddd update`，跳过漏扫而非崩溃
- `Close()`：`errors.Join` 聚合关闭 reporter + auditor
- 6 个测试（hostPort / dedup / parseTargets 分类分流 / buildReporter text / buildReporter json+html / New 缺指纹库须报错）

#### `cmd/dddd/main.go` — 接入 scan 模式

- `runScan`：`ParseArgs → Validate → app.New → Run`，退出码语义明确（参数错=2 / 运行错=1 / 成功=0）
- help 补全全部 scan flags（`-t/-tf/-o/-ot/-ho/-a/-sd/-proxy/-log-level`）

### 安全验证：Directive 兑现时刻（vulncheck 符号入二进制）

v0.1.5 commit 立的 Directive：**"接入 main 后重跑 `go tool nm` 验证 vulncheck"**。本次 `main → app → nuclei → dsl → vulncheck/dotnet` 真正链接，如约执行：

| 检查 | v0.1.4（httpx） | v0.1.7（接入 main 后） |
| :--- | :--- | :--- |
| 二进制总符号 | — | 119,247 |
| `vulncheck` 符号 | **0**（DCE 消除） | **174**（全是 `go-exploit/dotnet.*`） |
| `webshell`/`bindshell`/`reverse` | 0 | **0**（最危险载荷未链入） |

- **如预言兑现**：v0.1.5 已预告"接入 main 后 nm 会出现 vulncheck 符号"，今实测 174，与预测一致。
- **性质**：`.NET` 反序列化 gadget 生成（检测用途），非 webshell 植入；来源 projectdiscovery 官方库 dsl。
- **决策（主人已拍板接受）**：成品 `dddd-next.exe` 含此类符号，火绒**可能**对二进制报毒——属预期，非异常。火绒隔离原则不变（绝不加白名单）。详见 `docs/DEV_NOTES.md`。

### 测试与验证

- `internal/app`：6 测试全绿
- `go test ./...`：**13 个包回归全绿**（新增 internal/app）；`go vet ./internal/app` 零问题
- 二进制构建成功（147M），CLI 冒烟：`version → 0.1.7-dev`、`help` 完整、缺 target → 退出码 **2**

### 文件清单总览

| 操作 | 文件路径 |
| :--- | :--- |
| **新增** | `internal/app/pipeline.go` |
| **新增** | `internal/app/pipeline_test.go` |
| **修改** | `cmd/dddd/main.go`（接入 `-t` scan 模式 + 版本号 0.1.7-dev） |

### 测试方式

1. `cd D:/Software/VsCode/Program/DDDD/dddd-next`
2. 设缓存路径：`GOPATH=D:/Tools/Go/Cache/goPath`、`GOMODCACHE=D:/Tools/Go/Cache/goCache`
3. `go test ./internal/app/` → 期望 6 测试全 PASS
4. `go test ./...` → 期望 13 包 ok，exit 0
5. 构建后冒烟：`./dddd-next.exe version`（应输出 0.1.7-dev）、`./dddd-next.exe`（无 target 应退出码 2 并提示）

---

## v0.1.6-subfinder-dnsx — 资产发现链路补全（子域枚举 + DNS 解析）

### 关键成果

- 补全"域名→子域→IP"前置链路：subfinder（被动子域枚举）+ dnsx（DNS 解析），与已有 httpx 串成完整资产发现流 `域名 → subfinder → dnsx → httpx → 指纹 → nuclei`
- **无 `replace` 冲突**：subfinder/dnsx 走主线版本干净落地，`go mod tidy` 直接通过（不像 nuclei 需要 client-go replace）

### 新增文件

#### `internal/discovery/subfinder/subfinder.go` + 测试 — 被动子域枚举

- 照 httpprobe 范式：`runner.Options.ResultCallback`（并发回调）→ channel，`Output` 设 `io.Discard`，`DisableUpdateCheck=true`
- errCh 双通道（对齐 nuclei）——因 `EnumerateMultipleDomainsWithCtx` 返回 error，不吞
- 投影 `resolve.HostEntry` → `Result{Host, Domain, Source}`，调用方不 import subfinder 包
- 5 个测试

#### `internal/discovery/dnsx/dnsx.go` + 测试 — DNS 解析

- 包名 `dnsx` + 上游 alias `dnsxlib`（对齐 nuclei/nucleilib 惯例）
- `New`（不连网，仅配置 client）/ `Resolve`（单次，薄封装 Lookup）/ `ResolveMany`（worker-pool 并发；失败不丢 host，写入 `Result.Err`，区分"解析为空"和"未尝试"）
- 6 个测试

### 安全复审（遵守 v0.1.5 commit 立的 Directive）

- `go list -deps subfinder+dnsx`：**616 个传递依赖包，vulncheck/go-exploit 匹配 0**
- 与 nuclei 不同：subfinder/dnsx 不依赖 `projectdiscovery/dsl`，无攻击载荷链入——本次属"无变化"的干净结果

### 测试与验证

- subfinder 5 + dnsx 6 测试全绿
- `go test ./...`：**12 个包回归全绿**（新增 discovery/subfinder、discovery/dnsx）

### 文件清单总览

| 操作 | 文件路径 |
| :--- | :--- |
| **新增** | `internal/discovery/subfinder/subfinder.go` |
| **新增** | `internal/discovery/subfinder/subfinder_test.go` |
| **新增** | `internal/discovery/dnsx/dnsx.go` |
| **新增** | `internal/discovery/dnsx/dnsx_test.go` |
| **修改** | `go.mod`（+subfinder/v2 v2.14.0、dnsx v1.2.3 转 direct） |
| **修改** | `go.sum` |

### 测试方式

1. `cd D:/Software/VsCode/Program/DDDD/dddd-next`
2. 设缓存路径：`GOPATH=D:/Tools/Go/Cache/goPath`、`GOMODCACHE=D:/Tools/Go/Cache/goCache`
3. `go test ./internal/discovery/subfinder/ ./internal/discovery/dnsx/` → 期望 11 测试全 PASS
4. `go test ./...` → 期望 12 包 ok，exit 0

---

## v0.1.5-nuclei — nuclei v3.8.0 引擎适配层（dddd-next 最核心的集成）

### 关键成果

- **整个项目最重大的引擎集成**：把 `github.com/projectdiscovery/nuclei/v3 v3.8.0` 的 public lib SDK 包装成 channel-based、对调用方友好的 API——这是 dddd-next "扫描"能力的心脏喵。
- **彻底脱离 fork**：原 dddd 调用自己 fork 的 `exportrunner.ExportRunnerNew`，直接 reach into nuclei 私有包；dddd-next **只用上游公开 lib SDK** 的合同：`NewNucleiEngineCtx → LoadAllTemplates → LoadTargets → ExecuteCallbackWithCtx → Close`。合同之外的能力必须在 SDK 之上重建，不再触碰私有包。
- **投影边界 (projection boundary)**：`output.ResultEvent`（50+ 字段）→ `types.Finding`（~20 字段），调用方**永不 import 任何 nuclei 包**，上游字段 churn 止步于 `toFinding`——和 httpprobe 同一套设计心智。
- **callback→channel 包装**：nuclei 的 callback 式 SDK 被包成 findings channel + errCh，与 `internal/discovery/httpprobe` 暴露 httpx 结果的方式一致，全项目统一心智模型。

### 新增文件

#### `internal/scanner/nuclei/scanner.go`（309 行）+ `scanner_test.go`（235 行）— nuclei 适配层

- **功能**：包装 nuclei v3.8.0 lib SDK，对外提供 `Scanner` + channel API
- **核心 API**：
  ```go
  type Options struct{ TemplatesDir; TemplateIDs; Tags; Severities; Proxy; Concurrency; ... }
  func DefaultOptions() Options          // Concurrency=25, DisableUpdate=true, Silent=true, ResponseReadSize=5MiB
  func New(ctx, opts) (*Scanner, error)
  func (s *Scanner) Scan(ctx, targets) (<-chan types.Finding, <-chan error, error)
  func (s *Scanner) Close() error        // nil-safe，可重复调用
  ```
- **设计要点**：
  - `TemplateIDs` 是**指纹引擎与定向 POC 执行的桥梁**：指纹命中 → 模板 ID 列表 → 只跑这些模板（精准打击，不全量轰炸）
  - `DisableUpdate` 默认 true → `WithTemplateUpdateCallback(true, nil)` 关掉 nuclei 自更新，模板生命周期归 `dddd update` 管，杜绝两套更新机制打架
  - `hasFilters` 守卫：空 filter 会被 nuclei 当成"匹配空集"而非"不过滤"，所以只在真有过滤项时才 `WithTemplateFilters`
  - `pickTarget` 优先级：`Matched`（最精确命中点）> `URL` > `Host:Port` > `Host`
  - `mapSeverity` 把 nuclei severity 归一到 `types.Severity`，未知/空值兜底 `SeverityInfo`，报告排序器永不会收到不认识的等级
  - 切片防御性复制（`sliceCopy`）：`References` / `Tags` 拷贝后交出，杜绝下游通过共享底层数组 mutate nuclei 内部状态；空/nil 输入返回 nil，保持 JSON 干净
  - context 贯穿：channel send 用 `select { case <-ctx.Done(): }`，取消即停
- **测试覆盖**：10 个测试函数（含 `TestPickTarget` 5 子用例，共 15 PASS）——默认值、severity 映射（大小写/空格/未知值兜底）、slice 拷贝隔离、target 优先级、Finding 投影、nil Reference 兜底、filter 守卫、SDK options 构建（基于 `DefaultOptions` 再填 `TemplatesDir/IDs/Severities/Proxy` 后断言产出 **7** 个 option）、空目标拒绝、Close nil 安全

### go.mod：项目首个 `replace` 指令（Constraint 破例记录）

v0.1.4 立过 Constraint：**"无 replace，所有 projectdiscovery 库走主线版本"**。v0.1.5 出现了项目第一个 replace，必须诚实交代为何破例：

- **冲突根因**：nuclei v3.8.0 期望 `gitlab.com/gitlab-org/api/client-go v0.130.1`，但 `go mod tidy` 经由 `github.com/happyhackingspace/dit@v0.0.14` 把它**上拉到 v1.9.1**。两版本 API 不兼容，导致 nuclei 的 `pkg/reporting/trackers/gitlab/gitlab.go` 编译失败（`cannot use user.ID (int64) as int` 等）。
- **确认在链路内**：`go list -test -deps` 验证 gitlab tracker 确实在 nuclei 的导入链里，不是误报。
- **决策**：`replace gitlab.com/gitlab-org/api/client-go => gitlab.com/gitlab-org/api/client-go v0.130.1`
- **为何不违背初衷**：replace 目标是**上游同一模块的另一个发行版本**（v1.9.1 → v0.130.1），**不是本地 vendored fork**。这正属于最初约定中**唯一允许 replace 的场景：上游传递依赖版本冲突修复**。dddd-next 的"不 fork、走主线"原则依旧成立喵。

### 安全审计：vulncheck/go-exploit 经 dsl 包级链入（v0.1.4 结论更新）

遵守 v0.1.4 commit 立的 Directive（"加 nuclei 时重查 vulncheck"），本次复审发现**状态变化**：

- **引入链锁定**：`internal/scanner/nuclei` → `nucleilib` → `projectdiscovery/dsl@v0.8.14/deserialization/dotnet_deserialization.go:10` → `import go-exploit/dotnet`
- **真凶是官方库 dsl**（nuclei 表达式引擎），非野库；`go mod graph` 确认 dsl / httpx / nuclei 三个 projectdiscovery 库都 require go-exploit
- **包级真实 import 4 子包**：`output`(日志) / `random`(随机) / `transform`(编码) / `dotnet`(.NET gadget 生成)，均无 `//go:build` 标签 → **不可裁剪**
- **与 v0.1.4 差异**：v0.1.4 时 `go mod why` 报 "main does not need"（httpx 声明但被 DCE 消除）；v0.1.5 nuclei/dsl 链路**真实 import**，接入 main 后二进制将含 vulncheck 符号
- **最危险载荷未链入**：`payload/webshell` `reverse` `bindshell` 不在 `go list -deps` 结果中，不进二进制
- **决策（主人拍板）**：**接受**——官方依赖、检测用途（非 webshell 植入）、放弃 nuclei 不可行。火绒隔离原则不变（绝不加白名单）。完整脉络见 `docs/DEV_NOTES.md`

### 测试与验证

- `go test ./internal/scanner/nuclei/`：10 测试函数全绿（首次编译 37s，缓存后 ~5s）
- `go test ./...`：**10 个 Go 包全部回归通过**（audit / classifier / config / discovery·httpprobe / fingerprint / reporter / scanner·nuclei / updater / pkg·fingerdsl；cmd/dddd 与 internal/types 无测试文件），exit 0
- 顺带验证 gitlab replace 生效：nuclei 包能 PASS ⟺ gitlab tracker 编译通过（nuclei 适配层导入 `nucleilib`，会拉入 gitlab tracker，编译不过则整包过不了）

### 文件清单总览

| 操作 | 文件路径 |
| :--- | :--- |
| **新增** | `internal/scanner/nuclei/scanner.go` |
| **新增** | `internal/scanner/nuclei/scanner_test.go` |
| **修改** | `go.mod`（+`nuclei/v3 v3.8.0` 直接依赖 + 首个 `replace`） |
| **修改** | `go.sum`（nuclei transitive 依赖） |

### 测试方式

1. `cd D:/Software/VsCode/Program/DDDD/dddd-next`
2. 设缓存路径：`GOPATH=D:/Tools/Go/Cache/goPath`、`GOMODCACHE=D:/Tools/Go/Cache/goCache`
3. 跑 `go test ./internal/scanner/nuclei/ -v` → 期望 10 测试函数全 PASS
4. 跑 `go test ./...` → 期望 10 包 ok，exit 0

---

## v0.1.4-httpprobe — httpx 集成 + 设计哲学边界确立

### 关键成果

- **go.mod 首次引入外部依赖**：`github.com/projectdiscovery/httpx v1.9.0` + `github.com/projectdiscovery/goflags v0.1.74`，共 **169 行 go.mod / 770 行 go.sum**（含 ~160 个 transitive 包）
- **无 `replace` 指令** —— Constraint 守住喵：所有 projectdiscovery 库走主线版本
- **二进制 3.1 MB**，`go tool nm` 验证不含 `vulncheck` 等 transitive 但未引用的攻击载荷包符号

### 新增文件

#### `internal/discovery/httpprobe/probe.go` + 测试 — HTTP 探测包装层

- **功能**：把 `projectdiscovery/httpx/runner` 的 50+ 字段 `Result` 投影成 dddd-next 用得到的 ~20 字段 `Response`，并用 channel 取代原 dddd 的全局 Map+Mutex 状态
- **核心 API**：
  ```go
  type Probe struct{ ... }
  func New(opts Options) *Probe
  func (p *Probe) Run(ctx context.Context) (<-chan Response, error)
  func ToFingerprintContext(r Response) fingerdsl.Context
  ```
- **设计要点**：
  - 投影 (narrowing)：上游 50+ 字段变化不会传染到下游 fingerprint / reporter
  - 切片隔离：`toResponse` 用 `append([]string(nil), x...)` 复制 Technologies / A，杜绝外部 mutation
  - context 贯穿：channel send 用 `select { case <-ctx.Done(): }` 优雅取消
  - `ToFingerprintContext` 直接把 Response 转成 fingerdsl 能消费的 Context，**正式联通"采集→指纹"链路**
- **测试覆盖**：7 个用例（默认值、自定义值、空目标拒绝、字段映射、Err 序列化、slice 隔离、ToFingerprintContext）

### 安全审计：vulncheck/go-exploit 事件

`go mod tidy` 引入的 transitive 依赖中包含 `github.com/vulncheck-oss/go-exploit v1.51.0`——这是 VulnCheck 公司的**漏洞利用框架**，里面 `payload/webshell/` 含真实攻击载荷。

**调查与处置**：
1. `go mod why vulncheck-oss/go-exploit` → "main module does not need" — dddd-next 代码路径不引用
2. `go tool nm dddd-next.exe | grep vulncheck` → **0 个符号** — 二进制完全不链接它
3. 火绒拦截 `webshell.go` / `reverse.go` 等文件 — **完全不影响** build / test / run
4. **结论：保持火绒隔离，绝对不加白名单**

**设计哲学补充**：dddd-next 与原 dddd 一致，定位是**漏洞扫描器**（reconnaissance + detection），不是**漏洞利用器**。要点写入 `docs/DEV_NOTES.md`：
- 扫描和利用应是两套独立工具（关注点分离）
- 自动化"打 webshell"在多数司法管辖区是刑事犯罪
- 内嵌攻击载荷会让整个二进制被杀软全军覆没
- 真需要利用，应该用专用工具（Behinder/Godzilla/Metasploit）跑在隔离环境

### 主人开发环境调整记录

主人把 Go cache 挪到 D 盘脱离系统盘：

| 变量 | 新位置 |
|:---|:---|
| `GOPATH` | `D:\Tools\Go\Cache\goPath` |
| `GOMODCACHE` | `D:\Tools\Go\Cache\goCache`（**不在 GOPATH 下面**，是独立目录） |

详细操作姿势见 `docs/DEV_NOTES.md`。

### 新增文件

| 操作 | 文件路径 |
| :--- | :--- |
| **新增** | `internal/discovery/httpprobe/probe.go` |
| **新增** | `internal/discovery/httpprobe/probe_test.go` |
| **新增** | `docs/DEV_NOTES.md` |
| **修改** | `go.mod`（5 → 169 行，首次外部依赖） |
| **新增** | `go.sum`（770 行） |

---

## 测试方式

```bash
cd D:/Software/VsCode/Program/DDDD/dddd-next
# 当前 shell 已读到正确 GOPATH/GOMODCACHE 的情况：
go test -count=1 ./...
# 否则需要前缀：
GOMODCACHE="D:/Tools/Go/Cache/goCache" GOPATH="D:/Tools/Go/Cache/goPath" go test -count=1 ./...
```

实测结果（共 94 用例全绿）：
- `ok dddd-next/internal/audit             0.964s` (2)
- `ok dddd-next/internal/classifier        0.920s` (24)
- `ok dddd-next/internal/config            0.883s` (7)
- `ok dddd-next/internal/discovery/httpprobe 9.917s` (**7 新增**)
- `ok dddd-next/internal/fingerprint       2.484s` (6)
- `ok dddd-next/internal/reporter          2.212s` (4)
- `ok dddd-next/internal/updater           1.472s` (7)
- `ok dddd-next/pkg/fingerdsl              2.472s` (35 + 实战 lint)

---

## v0.1.3-update — POC 老化痛点根治

### 关键成果

**`dddd update` 端到端实战验证通过**：经 `HTTPS_PROXY=http://127.0.0.1:7890` 在 53 秒内 clone `projectdiscovery/nuclei-templates`（HEAD `faf6aad2`），落地 **13084 个 nuclei 模板（94 MB）**，相比原 dddd 二进制内置的 2406 个 legacy POC **多 5.4 倍**——这就是主人最初提的"POC 不够新"问题的根治证据。

### 新增文件

#### `internal/updater/updater.go` + `git.go` + 测试 — 一键拉取最新 POC

- **功能**：通过系统 `git` 命令拉取任意远程 POC/规则源到本地，支持 clone（首次）/ pull（增量）/ 多源并发
- **设计要点**：
  - 不用 go-git 这种 native git 库，保持 stdlib + os/exec，二进制更小（仅多了 ~30KB）
  - `GitRunner` 接口抽象命令调用，单元测试用 `fakeRunner` mock，零网络依赖
  - `Source` 结构：`Name / URL / Dir / Branch / Depth`，默认浅 clone（depth=1）控制体积
  - 失败隔离：一个源失败不影响后续源，每个源单独的 `Result.Err`
  - 自动尊重 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量（git 原生行为）
- **导出 API**：
  - `New(sources) *Updater` + `WithRunner(r)` / `WithProgress(w)` 链式配置
  - `Update(ctx) []Result` 串行执行所有源
  - `DefaultSources(baseDir)` 返回 canonical 集合（目前只有 nuclei-templates）
  - `Summary(results) string` 生成人类可读总结
- **测试覆盖**：7 个用例（clone 路径、pull 路径、no-change SHA 比较、failure 隔离、invalid source、default sources、summary 格式）
- **实战验证**：成功拉取 13084 个 nuclei 模板（94 MB）

#### `internal/fingerprint/engine.go` + 测试 — 指纹引擎闭环

- **功能**：把 `pkg/fingerdsl` DSL 引擎和 `finger.yaml` 数据资产联通成完整 `Engine`
- **实现原理**：
  - 手写 YAML loader（专为 finger.yaml 的扁平 `Name: ['expr', ...]` 格式），保持 stdlib-only
  - `LoadStats` 返回 total / compiled / failed + 前 10 个失败样本，方便诊断
  - 错误隔离：单条 DSL parse 失败不阻断加载，与 lint 测试统计口径一致
- **接口契约**：
  ```go
  type Engine struct{ ... }
  func LoadYAML(path string) (*Engine, LoadStats, error)
  func (e *Engine) Match(ctx fingerdsl.Context) []types.Fingerprint
  func (e *Engine) Size() int
  ```
- **测试覆盖**：6 个用例（基础加载、Match 命中、bad expression 计数、空文件、nil-safe、实战 finger.yaml 加载）
- **实战加载**：8382 条 / **8379 编译成功** / 3 失败（与 fingerdsl lint 数字完全一致——印证 loader 与 DSL 解耦清晰）

#### `cmd/dddd/main.go` — CLI 子命令路由

- 新增 `update` 子命令：调用 `internal/updater`
- 新增 `help` 子命令：完整使用说明 + 代理配置示例
- 退出码：成功 0、失败 1、git 不可用 2
- 信号处理：`signal.NotifyContext(os.Interrupt)` 允许 Ctrl-C 中断进行中的 clone

---

## 文件清单总览

| 操作 | 文件路径 |
| :--- | :--- |
| **新增** | `internal/updater/updater.go` |
| **新增** | `internal/updater/git.go` |
| **新增** | `internal/updater/updater_test.go` |
| **新增** | `internal/fingerprint/engine.go` |
| **新增** | `internal/fingerprint/engine_test.go` |
| **修改** | `cmd/dddd/main.go`（加入 update / help 子命令） |
| **修改** | `README.md`（补充代理配置章节） |
| **修改** | `CHANGES.md`（本条记录） |

---

## 测试方式

```bash
cd D:/Software/VsCode/Program/DDDD/dddd-next
go test -count=1 ./...   # 7 个 ok 包 + ~87 个单元测试全绿
go build -o dddd-next.exe ./cmd/dddd
./dddd-next.exe help
./dddd-next.exe version
HTTPS_PROXY=http://127.0.0.1:7890 ./dddd-next.exe update   # 端到端实战
```

实测结果：
- 单元测试：updater 7 个用例 + fingerprint 6 个用例全绿
- 实战 update：53.267 秒 clone 13084 个模板（94 MB），HEAD `faf6aad2`
- `configs/nuclei-templates/` 被 `.gitignore` 正确排除，不污染仓库

---

## v0.1.2-engine — 核心引擎第一波

### 新增文件

#### `pkg/fingerdsl/dsl.go` + 测试 — 指纹表达式 DSL 引擎

- **功能**：编译并求值 dddd 原版 finger.yaml 里的指纹表达式
- **语法支持**：
  - 字段匹配：`body / title / header / banner / cert / protocol / icon_hash / favicon_hash`
  - 操作符：`=` 包含、`==` 严格等、`!=` 不等、`~=` 正则
  - 逻辑：`&&` 与、`||` 或、`!` 非、`()` 括号
  - 字符串：双引号包裹，支持 `\" \\ \n \t \r` 转义
- **实现原理**：手写递归下降解析器
  - Lexer (`lexer struct`)：流式 tokenize，支持单/双字符运算符歧义解析（`!` vs `!=`）
  - Parser (`parser struct`)：左结合解析器，遵循优先级 `OR < AND < NOT < primary`
  - AST 节点：`matchNode / andNode / orNode / notNode`
  - 正则缓存 (`rxCache`)：sync.RWMutex 保护的 map，相同 pattern 只编译一次
- **导出 API**：`Parse(src string) (*Expression, error)` + `MustParse` + `Expression.Eval(Context) bool` + `Validate(src) error`
- **测试覆盖**：
  - 35 个核心用例（4 种操作符、逻辑组合、优先级、转义、真实指纹片段、负面用例）
  - **实战 lint：8382 条规则中 8379 通过，通过率 99.96%**，3 条失败全是上游数据错误（YAML 转义损坏、缺字段名、缺引号）

#### `internal/reporter/{reporter,text,json,html}.go` + 测试 — 报告生成

- **功能**：把指纹与漏洞结果以三种格式写出
- **接口契约**：
  ```go
  type Reporter interface {
      WriteFingerprint(target string, fp types.Fingerprint) error
      WriteFinding(f types.Finding) error
      Close() error
  }
  ```
- **实现**：
  - `TextReporter`：每行一条记录，每次 Flush，Ctrl+C 也能保留中间结果（与原 dddd 行为一致）
  - `JSONReporter`：NDJSON，每行一个 `{kind, timestamp, target, fingerprint?, finding?}` 对象，便于 jq / vector 处理
  - `HTMLReporter`：基于 `html/template` 生成自包含报告，含严重度卡片、漏洞表格（请求/响应可展开）、指纹命中表
  - `MultiReporter`：扇出包装器，单个子报告器失败不阻断其他（部分结果优先于事务原子性）
- **设计权衡**：
  - HTML 必须缓冲（聚合统计），不能流式 → 配合 TextReporter 才有崩溃安全
  - 所有写入 `mu.Lock()` 串行化，扇出场景下安全
- **测试覆盖**：4 个集成用例（三格式各一 + Multi 扇出）

#### `internal/audit/audit.go` + 测试 — 审计日志

- **功能**：NDJSON 格式记录所有扫描行为，供事后审计与合规追溯
- **事件类型**：`request / response / error / info`
- **关键设计**：
  - `Disabled()` 工厂返回 no-op Auditor，调用方零判断
  - **nil 安全**：所有方法在 `a == nil` 时安静返回，简化 wire 代码
  - 每条记录后立即 Flush，kill -9 也能留下完整审计轨迹
- **测试覆盖**：2 个集成用例（含 nil-safe 与 disabled 路径）

---

## 文件清单总览

| 操作 | 文件路径 |
| :--- | :--- |
| **新增** | `pkg/fingerdsl/dsl.go` |
| **新增** | `pkg/fingerdsl/dsl_test.go` |
| **新增** | `pkg/fingerdsl/dsl_lint_test.go` |
| **新增** | `internal/reporter/reporter.go` |
| **新增** | `internal/reporter/text.go` |
| **新增** | `internal/reporter/json.go` |
| **新增** | `internal/reporter/html.go` |
| **新增** | `internal/reporter/reporter_test.go` |
| **新增** | `internal/audit/audit.go` |
| **新增** | `internal/audit/audit_test.go` |

---

## 测试方式

```bash
cd D:/Software/VsCode/Program/DDDD/dddd-next
go test -count=1 ./...   # 74 个用例（含 8382 条真实指纹 lint）
go build -o dddd-next.exe ./cmd/dddd  # 2.4MB 可执行文件
```

实测结果：
- `ok dddd-next/internal/audit      0.921s`
- `ok dddd-next/internal/classifier  0.904s`
- `ok dddd-next/internal/config      1.304s`
- `ok dddd-next/internal/reporter   30.545s`（HTML 模板渲染 + JSON encoding 较慢）
- `ok dddd-next/pkg/fingerdsl        0.355s`（含 8382 条规则 lint）

**当前依赖状态**：`go.mod` 仍为零外部依赖，全部基于 stdlib + html/template + encoding/json。

---

## v0.1.1-foundation — 基础模块第一波

### 新增文件

#### `internal/types/types.go` — 公共类型定义

- **功能**：集中所有跨模块共享的领域类型，杜绝 import 循环
- **结构**：
  - `InputType` 枚举（IP / IPPort / IPRange / CIDR / Domain / DomainPort / URL / SearchQuery / Unknown）
  - `Target` — 扫描的最小单位
  - `Asset` — 测绘源（Hunter/Fofa/Quake）返回的资产
  - `Fingerprint` — 单次指纹命中
  - `Finding` — 漏洞/弱口令发现
  - `Severity` — nuclei 兼容的严重等级

#### `internal/classifier/classifier.go` + `_test.go` — 输入分类器

- **功能**：纯函数式自动识别用户 `-t` 输入的类型，零网络调用
- **实现原理**：按"代价从低到高"的顺序级联匹配 URL → 测绘语法 → CIDR → IP-Range → IP:Port → IP → Domain:Port → Domain
- **导出 API**：`Classify(string) InputType` + `Parse(string) (Target, error)`
- **测试覆盖**：24 个用例（含 IPv6、中文测绘语法、多层 TLD 域名、空白、垃圾输入）

#### `internal/config/config.go` + `_test.go` — 配置加载

- **功能**：从 CLI flag 与目标文件构造运行时 `Config`，零外部依赖（仅 stdlib）
- **特色**：`-t` 可重复指定、`-tf` 加载目标文件、内置 `update` / `version` 子命令识别、`Validate()` 校验
- **测试覆盖**：7 个用例

#### 数据资产迁移（来自原 dddd）

| 来源 | 目标 | 说明 |
|:---|:---|:---|
| `common/config/finger.yaml` | `configs/fingers/finger.yaml` | 主指纹库（8382 条规则） |
| `common/config/workflow.yaml` | `configs/pocs/mapping.yaml` | 指纹→POC 映射表 |
| `common/config/subdomains.txt` | `configs/dict/subdomains.txt` | 子域名字典 |
| `common/config/dir.yaml` | `configs/dict/dir.yaml` | 目录爆破字典 |
| `common/config/api-config.yaml` | `configs/api-config.example.yaml` | API 配置范例 |
| `gopocs/dict/*.txt`（11 个） | `configs/dict/` | 11 种协议弱口令字典 |
| `common/config/pocs/`（2406 个） | `configs/pocs/legacy/` | 老版 POC（fallback，待 updater 替换） |

#### `cmd/dddd/main.go` — 最小入口

- **功能**：占位入口，支持 `version`/`-v`/`--help` 平滑过渡
- **当前行为**：仅打印版本与脚手架状态，等待 workflow 编排到位后替换

---

## v0.1.0-init — 项目骨架建立

### 新增文件

- **目录结构**：建立 17 个目录骨架
- **License**：MIT，双重署名（dddd-next contributors + 原作者 SleepingBag945）
- **.gitignore**：排除二进制、缓存、AI 配置文件、本地 nuclei-templates、扫描输出
- **README.md**：项目介绍、与原 dddd 的差异、目录结构、快速开始
- **docs/ARCHITECTURE.md**：详细架构设计与设计决策
- **go.mod**：`module dddd-next` + `go 1.26.3`（暂无外部依赖）
