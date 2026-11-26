//go:build windows

package main

import (
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	createNewProcessGroup  = 0x00000200
	detachedProcess        = 0x00000008
	createNoWindow         = 0x08000000
	createBreakawayFromJob = 0x01000000

	processTerminate               = 0x0001
	processSetQuota                = 0x0100
	processQueryLimitedInformation = 0x1000
	stillActive                    = 259

	jobObjectExtendedLimitInformationClass = 9
	jobObjectLimitKillOnJobClose           = 0x00002000
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW           = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject    = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject   = kernel32.NewProc("AssignProcessToJobObject")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
)

// Children (sing-box, tor): no console window.
func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: createNoWindow, HideWindow: true}
}

// The daemon: detached from the browser's console, and — when the browser's
// job allows it — out of the browser's job, so it survives the short-lived
// native-messaging host.
func daemonAttr(breakaway bool) *syscall.SysProcAttr {
	flags := uint32(createNewProcessGroup | detachedProcess | createNoWindow)
	if breakaway {
		flags |= createBreakawayFromJob
	}
	return &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
}

type jobBasicLimits struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobExtendedLimits struct {
	Basic                 jobBasicLimits
	Io                    ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

var daemonJob syscall.Handle

// A job object that kills every process in it when its last handle closes —
// i.e. when the daemon exits for any reason, crash included.
func ensureJob() syscall.Handle {
	if daemonJob != 0 {
		return daemonJob
	}
	h, _, _ := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return 0
	}
	var info jobExtendedLimits
	info.Basic.LimitFlags = jobObjectLimitKillOnJobClose
	r, _, _ := procSetInformationJobObject.Call(h, jobObjectExtendedLimitInformationClass,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r == 0 {
		syscall.CloseHandle(syscall.Handle(h))
		return 0
	}
	daemonJob = syscall.Handle(h)
	return daemonJob
}

func adoptChild(pid int) {
	job := ensureJob()
	if job == 0 {
		return
	}
	ph, err := syscall.OpenProcess(processTerminate|processSetQuota, false, uint32(pid))
	if err != nil {
		return
	}
	defer syscall.CloseHandle(ph)
	procAssignProcessToJobObject.Call(uintptr(job), uintptr(ph))
}

func exePath(pid int) (string, error) {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	r, _, e := procQueryFullProcessImageNameW.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return "", e
	}
	return syscall.UTF16ToString(buf[:size]), nil
}

func pidAlive(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// Kill a process and everything it started (tor's pluggable transports).
func killTree(pid int) {
	_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)).Run()
}
