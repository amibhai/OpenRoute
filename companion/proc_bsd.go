//go:build !windows && !linux

package main

import "syscall"

// macOS/BSD have no Pdeathsig: children get their own process group, the
// daemon stops them on exit, and stale ones are cleaned up (after verifying
// their executable) on the next start.
func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
