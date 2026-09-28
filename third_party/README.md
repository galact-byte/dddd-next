# 本地第三方依赖补丁

## httpx v1.9.0

- 上游模块：`github.com/projectdiscovery/httpx v1.9.0`。
- 本地目录：`third_party/httpx/`，由已安装的该版本模块原样复制。
- 许可证：MIT，保留 `httpx/LICENSE.md`、上游源码和版权声明。
- 接入方式：根目录 `go.mod` 的 `replace`。普通 `go test` / `go build` 自动使用本地副本，不需要临时构建参数。
- 补丁：`httpx-ratelimiter.patch`。除 `runner/runner.go` 四行外，本地副本与上游模块相同；没有改扫描速率、网络超时或公开 API。

### 修复原因

httpx 把已经启动后台协程的 `ratelimit.Limiter` 按值复制。后台协程更新原子计数器时，结构体复制产生数据竞争。补丁将字段保存为指针，并删除三个构造调用前的解引用，避免复制正在使用的限速器。

修复前的 race 证据保存在本地 `build/review-evidence/full-fix/race.txt`；可随仓库运行的回归位于 `internal/discovery/httpprobe/` 和 `internal/app/`，包含 HTTP 指纹、图标采集及取消流程。

### 日常使用与升级

**使用者只需正常更新 dddd 程序，无须单独更新此依赖。** 下列步骤由项目维护者在升级 httpx 时执行：

1. 检查新版本的 `runner/runner.go` 是否已避免复制活动限速器，以及公开 API 是否兼容。
2. 若官方已修复：更新根目录 require 版本并移除 httpx 的 replace，移除不再需要的本地副本与补丁；重新完成下列验证。
3. 若官方尚未修复：将本地目录更新为完整新版源码（含许可证与嵌入资源），重新应用或调整四行补丁，同时更新根目录 require、本文版本号和补丁。仅执行 `go get` 不会绕过现有 replace。
4. 检查 `go list -m -json github.com/projectdiscovery/httpx` 的实际来源，并完成验证：

```bash
go test -p=2 -count=1 -timeout=60s ./...
go test -p=2 -race -count=1 -timeout=90s ./...
go vet -p=2 ./...
go build ./cmd/dddd
```

交付前还要验证 Linux amd64 交叉编译；这不等于 Linux SYN 实机测试。

### 注意事项

- 不修改全局 Go 模块缓存；那样其他开发机和 CI 不会获得修复。
- `.gitignore` 已对本地副本放行，避免上游嵌入的 HTML 被全局 `*.html` 规则漏掉。升级时检查源码与资源是否完整入库。
- 不将此目录复制为另一套项目实现，不额外修改上游业务逻辑；补丁应保持可审查、可移除。
