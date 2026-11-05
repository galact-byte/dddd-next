// Package nucleiinit 在 Nuclei SDK 初始化前隔离当前进程的配置目录。
//
// Go 按导入路径排序初始化依赖已就绪的包。此包路径 dddd-next/internal/nucleiinit
// 排在 github.com/projectdiscovery/nuclei/v3/pkg/catalog/config 之前；此处仅依赖
// 上游配置包同样依赖的标准库 os、path/filepath，确保先设置环境再加载 SDK。
// 不要在此包引入第三方依赖；子进程回归测试会检查初始化顺序和磁盘隔离。
package nucleiinit

import (
	"os"
	"path/filepath"
)

func init() {
	root, err := os.UserConfigDir()
	if err == nil {
		root, err = filepath.Abs(filepath.Join(root, "dddd-next", "nuclei"))
	}
	if err == nil {
		err = os.MkdirAll(root, 0700)
	}
	if err == nil {
		// 只影响当前进程及其子进程，不修改用户或系统的环境变量。
		err = os.Setenv("NUCLEI_CONFIG_DIR", root)
	}
	if err != nil {
		_, _ = os.Stderr.WriteString("dddd-next: isolate nuclei configuration: " + err.Error() + "\n")
		os.Exit(1)
	}
}
