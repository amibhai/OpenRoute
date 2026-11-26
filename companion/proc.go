package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Child supervises one helper process (sing-box or tor): starts it, restarts
// it with backoff if it dies, and gives up — reporting why — if it keeps
// dying. Children are owned by the daemon (Windows job object / Linux
// Pdeathsig / process groups), never detached, so they can't outlive it.
type Child struct {
	Name string
	Bin  string
	Args []string
	Dir  string
	Log  string // file receiving the child's stdout/stderr

	reg *ChildRegistry

	mu        sync.Mutex
	cmd       *exec.Cmd
	stopping  bool
	restarts  []time.Time
	lastError string
	failed    bool
	exited    chan struct{}
}

const (
	maxRestarts   = 5
	restartWindow = 2 * time.Minute
)

func (c *Child) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopping = false
	c.failed = false
	c.restarts = nil
	return c.spawnLocked()
}

func (c *Child) spawnLocked() error {
	cmd := exec.Command(c.Bin, c.Args...)
	cmd.Dir = c.Dir
	cmd.SysProcAttr = childAttr()
	if c.Log != "" {
		if f, err := os.OpenFile(c.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			cmd.Stdout, cmd.Stderr = f, f
			defer f.Close() // the child keeps its own handle
		}
	}
	if err := cmd.Start(); err != nil {
		c.lastError = err.Error()
		return fmt.Errorf("start %s: %w", c.Name, err)
	}
	adoptChild(cmd.Process.Pid)
	c.cmd = cmd
	c.exited = make(chan struct{})
	c.reg.Record(c.Name, cmd.Process.Pid, c.Bin)
	go c.wait(cmd, c.exited)
	return nil
}

func (c *Child) wait(cmd *exec.Cmd, exited chan struct{}) {
	err := cmd.Wait()
	close(exited)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != cmd {
		return // superseded by a newer instance
	}
	c.cmd = nil
	c.reg.Forget(c.Name)
	if c.stopping {
		return
	}
	c.lastError = exitReason(err, c.Log)
	now := time.Now()
	recent := c.restarts[:0]
	for _, t := range c.restarts {
		if now.Sub(t) < restartWindow {
			recent = append(recent, t)
		}
	}
	c.restarts = append(recent, now)
	if len(c.restarts) > maxRestarts {
		c.failed = true
		log.Printf("%s keeps exiting (%s) — giving up", c.Name, c.lastError)
		return
	}
	delay := time.Duration(1<<uint(len(c.restarts)-1)) * time.Second
	log.Printf("%s exited (%s); restarting in %s", c.Name, c.lastError, delay)
	time.AfterFunc(delay, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.stopping || c.cmd != nil || c.failed {
			return
		}
		if err := c.spawnLocked(); err != nil {
			c.failed = true
		}
	})
}

func (c *Child) Stop() {
	c.mu.Lock()
	c.stopping = true
	cmd, exited := c.cmd, c.exited
	c.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	killTree(cmd.Process.Pid)
	_ = cmd.Process.Kill()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
	}
}

func (c *Child) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmd != nil
}

func (c *Child) Status() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := map[string]any{"running": c.cmd != nil, "restarts": len(c.restarts), "failed": c.failed}
	if c.lastError != "" {
		st["lastError"] = c.lastError
	}
	if c.cmd != nil && c.cmd.Process != nil {
		st["pid"] = c.cmd.Process.Pid
	}
	return st
}

func exitReason(err error, logPath string) string {
	reason := "exited"
	if err != nil {
		reason = err.Error()
	}
	if tail := tailFile(logPath, 3); tail != "" {
		reason += ": " + tail
	}
	return redact(reason)
}

func tailFile(path string, lines int) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	all := strings.Split(strings.TrimSpace(stripANSI(string(b))), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, " | ")
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < '@' || s[j] > '~') {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ChildRegistry remembers which helper processes this daemon started, so a
// later daemon (after a crash) can clean up stragglers — but only after
// checking a PID still belongs to the same executable, never blindly.
type ChildRegistry struct {
	path string
	mu   sync.Mutex
}

type childRecord struct {
	PID int    `json:"pid"`
	Exe string `json:"exe"`
}

func (r *ChildRegistry) load() map[string]childRecord {
	m := map[string]childRecord{}
	if b, err := os.ReadFile(r.path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (r *ChildRegistry) save(m map[string]childRecord) {
	b, _ := json.Marshal(m)
	_ = os.WriteFile(r.path, b, 0o600)
}

func (r *ChildRegistry) Record(name string, pid int, exe string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.load()
	abs, _ := filepath.Abs(exe)
	m[name] = childRecord{PID: pid, Exe: abs}
	r.save(m)
}

func (r *ChildRegistry) Forget(name string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.load()
	delete(m, name)
	r.save(m)
}

// CleanupOrphans kills helpers left behind by a previous daemon. A recorded
// PID is only killed when the process with that PID is still running the
// very same executable (PIDs get reused after a reboot).
func (r *ChildRegistry) CleanupOrphans() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var killed []string
	for name, rec := range r.load() {
		if !pidAlive(rec.PID) {
			continue
		}
		exe, err := exePath(rec.PID)
		if err != nil || !sameFile(exe, rec.Exe) {
			continue
		}
		killTree(rec.PID)
		killed = append(killed, fmt.Sprintf("%s(%d)", name, rec.PID))
	}
	r.save(map[string]childRecord{})
	return killed
}

func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	if errA == nil && errB == nil {
		return os.SameFile(fa, fb)
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

var errNotFound = errors.New("not found")
