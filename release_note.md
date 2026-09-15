- 支持通过 `.env` 中的 `FOFA_SERVER` 设置兼容 FOFA 协议的服务器地址，留空使用官方接口；仍需配置对应的邮箱和 Key。关联 [#1](https://github.com/galact-byte/dddd-next/issues/1)。
- 测绘查询失败时显示错误原因，后续页失败仍保留已取得的资产继续扫描。
- 恢复原版 `-t 文件` 用法，文件和直接目标统一使用 `-t`；支持 UTF-8 BOM 和 Windows 换行。
- README 补充原版迁移对照、参数及默认行为差异，以及 FOFA 官方和自建配置示例。

## 升级说明

`-tf` 已移除，请将旧脚本中的 `-tf targets.txt` 改为 `-t targets.txt`。文件路径以运行命令时的工作目录为准。

完整变更：[v0.1.47...v0.1.48](https://github.com/galact-byte/dddd-next/compare/v0.1.47...v0.1.48)
