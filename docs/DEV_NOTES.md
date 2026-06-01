# 开发环境备忘

> 小幽给未来自己（或者别的 AI）的笔记，避免下次会话踩同样的坑喵～

## Go 环境变量

主人本机自定义了 Go 缓存位置（脱离 C 盘默认路径）：

| 变量 | 值 |
|:---|:---|
| `GOPATH` | `D:\Tools\Go\Cache\goPath` |
| `GOMODCACHE` | `D:\Tools\Go\Cache\goCache` |

**注意**：`GOMODCACHE` 不在 `$GOPATH/pkg/mod` 下面（这是主人的偏好布局），是完全独立的目录。

### 各类操作的正确姿势

**1. 在 cmd / PowerShell 新 shell 里直接跑** —— 默认环境变量已经生效，什么都不用前缀：
```bash
go build ./cmd/dddd
go test ./...
```

**2. 在旧 bash session（环境变量还是改之前的）里跑** —— 必须显式前缀：
```bash
GOMODCACHE="D:/Tools/Go/Cache/goCache" GOPATH="D:/Tools/Go/Cache/goPath" go test ./...
```

**3. 拉新的依赖（go get / go mod tidy）** —— 必须再加代理：
```bash
GOMODCACHE="D:/Tools/Go/Cache/goCache" \
GOPATH="D:/Tools/Go/Cache/goPath" \
HTTPS_PROXY=http://127.0.0.1:7890 \
HTTP_PROXY=http://127.0.0.1:7890 \
go get github.com/projectdiscovery/something@latest
```

## 关于 `github.com/vulncheck-oss/go-exploit`

> ⚠️ 此依赖的状态**随版本变化**，分阶段记录——别照搬旧结论。

### v0.1.4（httpx 阶段）：声明但未链入

httpx 的 go.mod **声明**了 go-exploit，`go mod tidy` 写入 `go.sum`，但 httpx 实际代码路径不 import 它，被链接器 DCE 消除：
- `go mod why github.com/vulncheck-oss/go-exploit` → "main module does not need"
- `go tool nm dddd-next.exe | grep vulncheck` → 0 符号

### v0.1.5（nuclei 阶段）：经 dsl **包级真实 import** ⚠️

nuclei 引入 `projectdiscovery/dsl@v0.8.14`，其 `deserialization/dotnet_deserialization.go:10` **真实 import** `go-exploit/dotnet`（.NET 反序列化 gadget 生成，供 nuclei 模板检测反序列化漏洞）。`go list -deps ./internal/scanner/nuclei` 确认链入 **4 个子包**：

| 子包 | 内容 | 性质 |
|:---|:---|:---|
| `output` | 结构化日志 | 🟢 工具 |
| `random` | 随机数生成 | 🟢 工具 |
| `transform` | 编码/转义/解析 | 🟢 工具 |
| `dotnet` | gadget/viewstate 生成 | 🟡 攻击性 payload 生成（检测用） |

- **不可裁剪**：dsl 是 nuclei 表达式引擎核心，4 子包均无 `//go:build` 标签
- **最危险载荷不在链里**：`payload/webshell` `reverse` `bindshell` **未被引用**，不进二进制（`go list -deps` 不含它们）
- **性质**：检测用途（发探测 payload 判漏洞），非 webshell 植入；来源是 projectdiscovery 官方库
- **决策（主人 2026-06-01 拍板）**：**接受**。全球 nuclei 项目皆如此；放弃 nuclei = 放弃核心扫描能力
- **预期变化**：Task #13 把 nuclei 接入 `cmd/dddd` 后，`go tool nm` 将出现 vulncheck/dotnet 符号，火绒**可能**对二进制报毒——属预期，非异常

### 火绒隔离原则（不变）

- 火绒拦缓存里的 `payload/webshell/*.go` 等真攻击脚本是**正确**行为，**保持隔离，绝不加白名单**
- 新缓存路径（`D:\Tools\Go\Cache\goCache`）下子包文件完整，build/test 正常

## 代理

火绒拦截 webshell 文件是正确行为，与 Go 模块加载无关。Go 拉模块本身走 `proxy.golang.org`（被墙）—— 必须用代理：
```bash
HTTPS_PROXY=http://127.0.0.1:7890 HTTP_PROXY=http://127.0.0.1:7890
```

## 数据资产位置

| 资产 | 位置 |
|:---|:---|
| 指纹库 | `configs/fingers/finger.yaml`（8382 条规则） |
| 字典 | `configs/dict/*.txt`（13 个） |
| nuclei 模板 | `configs/nuclei-templates/`（**.gitignore 排除，运行 `dddd update` 拉取**，~13084 模板） |
| 旧 POC fallback | `configs/pocs/legacy/`（2406 个迁移自原 dddd） |

## 触雷历史

- v0.1.2 时 `.gitignore` 写了无前缀的 `dddd` 模式，把 `cmd/dddd/` 整个目录都给屏蔽了——`commit 97fc0cb` 里**根本没有 main.go**。`commit ec8532a` 修复（改为 `/dddd`）。
- v0.1.3 时拉 httpx 引入了 `vulncheck/go-exploit` transitive 依赖，触发火绒告警——确认无害，保持隔离。
- v0.1.5 接入 nuclei，`vulncheck/go-exploit` 从"声明未链入"升级为"经 `projectdiscovery/dsl` 包级 import `dotnet` 子包"——主人决策**接受**（检测用途、官方依赖、webshell 不在链路），详见上方 vulncheck 章节。
