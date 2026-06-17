package app

import "fmt"

func greenS(msg string, args ...any) string {
	return fmt.Sprintf("\033[32m[*]\033[0m "+msg, args...)
}
func redS(msg string, args ...any) string {
	return fmt.Sprintf("\033[31m[*]\033[0m "+msg, args...)
}
func cyanS(msg string, args ...any) string {
	return fmt.Sprintf("\033[36m[*]\033[0m "+msg, args...)
}
func yellowS(msg string, args ...any) string {
	return fmt.Sprintf("\033[33m[*]\033[0m "+msg, args...)
}
func blueS(msg string, args ...any) string {
	return fmt.Sprintf("\033[34m[*]\033[0m "+msg, args...)
}
func magentaS(msg string, args ...any) string {
	return fmt.Sprintf("\033[35m[*]\033[0m "+msg, args...)
}
