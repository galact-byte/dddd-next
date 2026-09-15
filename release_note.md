- 新增 `dddd upgrade` 升级程序本体，按当前系统和架构下载最新稳定版，校验 SHA-256 后替换；下载或校验失败保留原程序。
- 使用 `dddd upgrade --check` 只检查是否有新版本。普通扫描不自动检查或下载本体更新。
- `dddd update` 继续更新模板，已有模板更新后显示前后提交版本。`-nt` / `-nuclei-template` 在更新时指定并记住模板目录，在扫描时仅覆盖本次使用的目录。
- 支持通过环境变量或 `.env` 配置 `GITHUB_TOKEN`，提高 GitHub API 请求限额；令牌不发送到下载地址或重定向目标。更新可使用 `HTTPS_PROXY` 环境变量。

## 升级说明

v0.1.48 及更早版本需要先手动下载一次 v0.1.49，之后可使用 `dddd upgrade` 升级本体。更新子命令单独运行，不与扫描参数混用；程序目录须可写，升级后下次启动使用新版本。

原有 `dddd update`、`-up user:pass` 凭证参数和模板目录设置继续有效，无需修改旧脚本。

完整变更：[v0.1.48...v0.1.49](https://github.com/galact-byte/dddd-next/compare/v0.1.48...v0.1.49)
