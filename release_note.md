- `dddd help` / `-h` / `--help` 改为中文分组说明，补全生效参数、默认值和旧版有效别名。
- 不再在帮助中列出无效参数。使用 `-mp` / `-masscan-path`、`-acf` / `-api-config-file` 或 `-log-level` 时提示已忽略，并说明迁移方式；保留原有解析兼容，不回显参数值。
- 修复扫描参数后的 `--help` 和 `dddd update --help`：显示帮助并正常退出，不启动扫描或模板更新。
- README 补充帮助入口和旧参数迁移说明。

完整变更：[v0.1.49...v0.1.50](https://github.com/galact-byte/dddd-next/compare/v0.1.49...v0.1.50)
