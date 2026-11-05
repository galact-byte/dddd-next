- dddd-next 的 Nuclei 配置与独立安装的 Nuclei 分开保存到用户配置目录的 `dddd-next/nuclei/`，避免模板状态和忽略规则互相影响。已有 Nuclei 配置不迁移；需要为 dddd-next 设置排除规则时，请使用该目录中的 `.nuclei-ignore` 或扫描参数。
- 修复精准扫描和 `-poc` 模式无法加载所选模板根目录下相对路径字典的问题，保留默认模板目录、已记住目录、`-nt` 指定目录及 legacy POC 回退。
- `dddd upgrade` 现在会同步官方资产名及 `dddd0.1.53.exe` 等文件名中的版本号；固定名称和符号链接入口保持不变，新名称已存在时拒绝覆盖。首次从旧更新器升级仍可能保留旧名，可手动改名一次。需要固定启动路径的脚本或快捷方式请使用 `dddd.exe` 等不带版本号的名称。
- 新增 macOS ARM64（Apple Silicon）构建。macOS 文件未经过 Apple 签名或公证；下载后请核验来源和 SHA-256 校验和。发布流程增加 macOS 原生测试及实际程序冒烟验证。

完整变更：[v0.1.53...v0.1.54](https://github.com/galact-byte/dddd-next/compare/v0.1.53...v0.1.54)
