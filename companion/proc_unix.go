//go:build !windows

package main

import "syscall"

// detachAttr puts sing-box in its own session so it isn't killed with this
// short-lived native-messaging host.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
