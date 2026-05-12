# 修改记录 — dddd-next

> **修订记录**
>
> - v0.1.0-init: 项目骨架建立，基于 dddd 原项目重写计划启动
> - v0.1.1-foundation: 数据资产迁移完成；输入分类器 + 配置加载模块上线（31 测试全绿）
> - v0.1.2-engine: 指纹 DSL 引擎、报告生成（TXT/JSON/HTML）、审计日志全部上线（74 测试全绿，DSL 实战 lint 99.96%）
> - v0.1.3-update: updater 子命令上线，nuclei-templates 真实拉取成功（13084 模板，原版仅 2406，**多 5.4 倍**）；fingerprint Engine 完整闭环

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
