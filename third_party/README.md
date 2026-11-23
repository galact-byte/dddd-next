# 本地第三方依赖补丁

## httpx

- 上游模块：`github.com/projectdiscovery/httpx`，当前源码版本和上游模块校验和见 [httpx-upstream.json](httpx-upstream.json)。校验和对应未打补丁的官方 Go 模块。
- 本地目录：`third_party/httpx/`，保留上游完整模块源码、许可证与嵌入资源。
- 许可证：MIT，保留 `httpx/LICENSE.md`、上游源码和版权声明。
- 接入方式：根目录 `go.mod` 的 `replace`。普通 `go test` / `go build` 自动使用本地副本，不需要临时构建参数。
- 补丁：[httpx-ratelimiter.patch](httpx-ratelimiter.patch)。将限速器改为指针保存，不改变扫描速率、网络超时或公开 API。

### 修复原因

httpx 把已经启动后台协程的 `ratelimit.Limiter` 按值复制。后台协程更新原子计数器时，结构体复制产生数据竞争。补丁修改字段和三个构造调用，避免复制正在使用的限速器。

相关回归位于 `internal/discovery/httpprobe/` 和 `internal/app/`，包含 HTTP 指纹、图标采集及取消流程。

### 自动维护

Dependabot 每周集中检查 Go 依赖，httpx 也包含在内。根目录的 httpx 版本在依赖更新 PR 中发生变化后，[Sync httpx source](../.github/workflows/httpx-source-sync.yml) 会执行以下流程：

1. 从官方 Go 模块获取对应稳定版本，复制完整源码，在临时目录重新应用限速器补丁。上游已包含相同修复时不重复打补丁；其他冲突明确失败，不改写现有源码和来源记录。
2. 运行 `go mod tidy`、模块校验、全仓测试、相关竞态测试、实际程序构建和两项 CLI 冒烟。
3. 全部通过后，把源码、来源记录及必要的模块变化提交回同一 PR 分支，并重新触发 Dependency checks。分支被其他提交更新时停止写入，不强推覆盖。

准备和测试任务只有读取权限；写入任务只应用限定目录的源码补丁，不运行 PR 代码。整个流程不需要允许 Actions 创建 PR，也不自动合并、打标签或发布版本。普通依赖升级随项目后续功能或修复版本交付。

[Dependency checks](../.github/workflows/dependency-check.yml) 还会核对根模块版本与来源记录，阻止只更新版本号、实际仍用旧本地源码的假升级。同版本的依赖维护不会重新覆盖 httpx 本地模块中的依赖修改。

### 冲突与手动维护

补丁冲突或新版共享依赖与 Nuclei 等组件不兼容时，需要在更新 PR 中修正并重新检查。不要只改来源记录来绕过版本检查。上游采用了另一种等效修复时，也应先人工核实并调整补丁；是否移除本地替换另行决定。

已有依赖 PR 可以从 Actions 中手动运行 Sync httpx source，输入 PR 编号重新同步。仅支持同仓库、以默认分支为目标的未关闭 PR。

本地手动升级示例：

```bash
# 先将根 go.mod 的 httpx require 更新到目标稳定版本
python3 .github/scripts/sync_httpx.py
go mod tidy
python3 .github/scripts/sync_httpx.py --check
go mod verify
go test -p=2 -count=1 ./...
go test -p=2 -race -count=1 ./internal/discovery/httpprobe ./internal/app
go vet -p=2 ./...
```

随后按[开发指南](../docs/development.md#实际程序测试)构建程序并执行冒烟。仅源码复制或版本一致性校验通过，不代表新版已与整个项目兼容；跨平台和原生权限相关能力仍需对应平台检查。

### 注意事项

- 同步工具从 Go 模块缓存复制源码，不向缓存中的文件打补丁。
- `.gitignore` 已对本地副本放行，避免上游嵌入的 HTML 被全局 `*.html` 规则漏掉。升级时检查源码与资源是否完整入库。
- 只保留必要的本地修复，不额外改写上游业务逻辑；补丁应保持可审查、可移除。
