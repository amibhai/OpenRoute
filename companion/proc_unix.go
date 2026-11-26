//go:build !windows

package main

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The daemon: its own session, so it isn't killed with the host.
func daemonAttr(_ bool) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// Unix children die with the daemon via process groups (and, on Linux,
// Pdeathsig); nothing to adopt.
func adoptChild(_ int) {}

func exePath(pid int) (string, error) {
	if runtime.GOOS == "linux" {
		return os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	}
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func pidAlive(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}

// Kill a child's whole process group (tor and its pluggable transports).
func killTree(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && pidAlive(pid) {
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
