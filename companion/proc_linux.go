//go:build linux

package main

import "syscall"

// Children get their own process group (so a stop kills tor's pluggable
// transports too) and are killed by the kernel if the daemon dies.
func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
