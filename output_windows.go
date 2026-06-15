//go:build windows

package main

import (
	"syscall"
)

// ---- TTY detection (DR-006) -----------------------------------------------
// isTerminal reports whether fd refers to a terminal. On Windows we use
// GetConsoleMode which returns an error if the handle is not a console.
func isTerminal(fd uintptr) bool {
	var mode uint32
	err := syscall.GetConsoleMode(syscall.Handle(fd), &mode)
	return err == nil
}