package app

import "golang.org/x/sys/windows"

// Windows cmd.exe ignores ANSI color escapes unless virtual-terminal processing
// is enabled, so the colored output renders as plain white. Turn it on at import
// time; failures (redirected/legacy console) leave output uncolored, not broken.
func init() {
	enableVirtualTerminal(windows.Stdout)
	enableVirtualTerminal(windows.Stderr)
}

func enableVirtualTerminal(h windows.Handle) {
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return
	}
	_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
