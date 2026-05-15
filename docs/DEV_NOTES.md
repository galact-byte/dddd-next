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

这个包是某个 projectdiscovery 上游 transitive 依赖**声明**拉过来的，会被 `go mod tidy` 写入 `go.sum`，但 dddd-next 的代码路径**不会**真正 import 它。

**结论**：
- `go mod why github.com/vulncheck-oss/go-exploit` 显示 "main module does not need"
- `go tool nm dddd-next.exe | grep vulncheck` 返回 0 个符号
- 火绒拦截 `payload/webshell/webshell.go` 等文件 **完全不影响** dddd-next 的 build/test/run
- **保持火绒隔离即可**，绝对不要加白名单

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
