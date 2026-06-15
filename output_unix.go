//go:build !windows

package main

import (
	"syscall"
	"unsafe"
)

// ---- TTY detection (DR-006) -----------------------------------------------
// isTerminal reports whether fd refers to a terminal. Implemented with a
// single syscall rather than a third-party isatty library (DR-001).
func isTerminal(fd uintptr) bool {
	var termios [256]byte // large enough for any termios struct on Linux/macOS
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		syscall.TIOCGWINSZ, // works on both Linux and macOS to probe a TTY
		uintptr(unsafe.Pointer(&termios[0])),
	)
	return errno == 0
}