package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	socksPort   = 1080          // local SOCKS/HTTP the browser is pointed at
	clashAddr   = "127.0.0.1:9090" // sing-box Clash API, used for health/latency
	upstreamTag = "proxy"       // outbound tag for the user's transport
)

// Manager owns a *detached* sing-box process plus the known/active profiles.
//
// Native-messaging hosts are short-lived: Chrome starts a fresh copy of us per
// request and closes it after the reply. So sing-box must outlive us — we start
// it detached, track it by PID file, and persist which profile is active to
// disk, so any later invocation can inspect or tear it down.
type Manager struct {
	dir        string
	binPath    string
	cfgPath    string
	profPath   string
	pidPath    string
	activePath string

	mu       sync.Mutex
	profiles []Profile
	activeID string

	tor *Tor // free-network engine (Phase C), managed independently
}

func NewManager(dir string) *Manager {
	m := &Manager{
		dir:        dir,
		cfgPath:    filepath.Join(dir, "singbox.json"),
		profPath:   filepath.Join(dir, "profiles.json"),
		pidPath:    filepath.Join(dir, "singbox.pid"),
		activePath: filepath.Join(dir, "active.txt"),
	}
	m.binPath = findSingBox(dir)
	m.profiles = loadProfiles(m.profPath)
	if b, err := os.ReadFile(m.activePath); err == nil {
		m.activeID = strings.TrimSpace(string(b))
	}
	m.tor = NewTor(dir)
	return m
}

// disconnect stops one engine ("singbox"/"tor") or, by default, both.
func (m *Manager) disconnect(kind string) map[string]any {
	switch kind {
	case "tor":
		return m.tor.Disconnect()
	case "singbox", "companion":
		return m.Disconnect()
	default:
		m.Disconnect()
		m.tor.Disconnect()
		return map[string]any{"ok": true}
	}
}

func singBoxName() string {
	if runtime.GOOS == "windows" {
		return "sing-box.exe"
	}
	return "sing-box"
}

// findSingBox looks next to the data dir, next to our own binary, then on PATH.
func findSingBox(dir string) string {
	name := singBoxName()
	if p := filepath.Join(dir, name); fileExists(p) {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), name); fileExists(p) {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// Connect parses one or more share links into sing-box outbounds, writes the
// config, and (re)starts a detached sing-box so the browser can route through
// 127.0.0.1. Multiple links become a health-checked urltest pool that auto-picks
// the fastest working node and rotates as they come and go.
func (m *Manager) Connect(id, label string, links []string) map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(links) == 0 {
		return errResp("no link(s) provided")
	}
	outbounds := make([]map[string]any, 0, len(links))
	for _, ln := range links {
		ob, err := linkToOutbound(ln)
		if err != nil {
			return errResp("parse link: " + err.Error())
		}
		outbounds = append(outbounds, ob)
	}
	if id == "" {
		id = "companion"
	}
	if label == "" {
		label = "Companion"
	}

	if err := m.writeConfig(outbounds); err != nil {
		return errResp("write config: " + err.Error())
	}
	if err := m.startLocked(); err != nil {
		return errResp(err.Error())
	}

	m.setActiveLocked(id)
	m.upsertProfileLocked(Profile{ID: id, Label: label, Link: strings.Join(links, "\n")})
	return map[string]any{"ok": true, "socksPort": socksPort, "id": id, "count": len(links)}
}

func (m *Manager) Disconnect() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	m.setActiveLocked("")
	return map[string]any{"ok": true}
}

func (m *Manager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"ok":         true,
		"running":    m.clashUp(),
		"socksPort":  socksPort,
		"activeId":   m.activeID,
		"singboxOk":  m.binPath != "",
		"singboxBin": m.binPath,
		"version":    version,
	}
}

// Transports reports known profiles as extension-shaped transports, all pointing
// at the single local SOCKS port (only the active one is live).
func (m *Manager) Transports() []map[string]any {
	m.mu.Lock()
	profs := append([]Profile(nil), m.profiles...)
	activeID := m.activeID
	m.mu.Unlock()

	liveHealth, liveLat := "unknown", 0
	if activeID != "" {
		liveHealth, liveLat = m.probe()
	}

	out := make([]map[string]any, 0, len(profs))
	for _, p := range profs {
		health, lat := "unknown", 0
		if p.ID == activeID {
			health, lat = liveHealth, liveLat
		}
		out = append(out, map[string]any{
			"id": p.ID, "label": p.Label, "scheme": "socks5",
			"host": "127.0.0.1", "port": socksPort, "kind": "companion",
			"health": health, "latencyMs": lat, "builtin": false,
		})
	}
	return out
}

// Health is the compact view the extension's health tick folds in.
func (m *Manager) Health() []map[string]any {
	m.mu.Lock()
	activeID := m.activeID
	m.mu.Unlock()
	if activeID == "" {
		return []map[string]any{}
	}
	health, lat := m.probe()
	return []map[string]any{{"id": activeID, "health": health, "latencyMs": lat}}
}

// ---- internals (callers hold m.mu) -----------------------------------------

func (m *Manager) writeConfig(outbounds []map[string]any) error {
	// Tag each upstream and wrap them in a urltest group, so a pool of upstreams
	// auto-selects the lowest-latency working one and re-tests periodically —
	// free health-checked rotation, and identical machinery for one or many.
	tags := make([]string, 0, len(outbounds))
	outs := make([]any, 0, len(outbounds)+2)
	for i, ob := range outbounds {
		tag := fmt.Sprintf("up-%d", i)
		ob["tag"] = tag
		tags = append(tags, tag)
		outs = append(outs, ob)
	}
	outs = append(outs, map[string]any{
		"type": "urltest", "tag": upstreamTag, "outbounds": tags,
		"url": "http://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50,
	})
	outs = append(outs, map[string]any{"type": "direct", "tag": "direct"})

	cfg := map[string]any{
		"log": map[string]any{
			"level": "warn", "output": filepath.Join(m.dir, "singbox.log"), "timestamp": true,
		},
		"experimental": map[string]any{
			"clash_api": map[string]any{"external_controller": clashAddr},
		},
		// DNS over DoH *through the upstream* — closes the gap that an extension
		// can't force Chrome's Secure DNS. Bootstrap is an IP literal, so no
		// plaintext lookup is needed to reach the resolver.
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"tag": "doh", "address": "https://1.1.1.1/dns-query", "detour": upstreamTag},
			},
			"final":    "doh",
			"strategy": "prefer_ipv4",
		},
		"inbounds": []any{
			map[string]any{
				"type": "mixed", "tag": "in", "listen": "127.0.0.1",
				"listen_port": socksPort, "sniff": true,
			},
		},
		"outbounds": outs,
		"route":     map[string]any{"final": upstreamTag, "auto_detect_interface": true},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.cfgPath, b, 0o600)
}

func (m *Manager) startLocked() error {
	m.stopLocked() // never leave two instances fighting over the port
	if m.binPath == "" {
		return fmt.Errorf("sing-box not found — install it or drop it in %s", m.dir)
	}
	cmd := exec.Command(m.binPath, "run", "-c", m.cfgPath)
	cmd.SysProcAttr = detachAttr() // survive this short-lived host process
	// stdin/stdout/stderr left nil → connected to the null device, so sing-box
	// can never write into our native-messaging stdout channel.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	_ = os.WriteFile(m.pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	_ = cmd.Process.Release() // detach: don't wait/reap, let it run on

	// Best-effort wait for the Clash API to answer before we report success.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.clashUp() {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil
}

func (m *Manager) stopLocked() {
	b, err := os.ReadFile(m.pidPath)
	if err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Kill()
			}
		}
	}
	_ = os.Remove(m.pidPath)
}

func (m *Manager) setActiveLocked(id string) {
	m.activeID = id
	if id == "" {
		_ = os.Remove(m.activePath)
		return
	}
	_ = os.WriteFile(m.activePath, []byte(id), 0o600)
}

func (m *Manager) upsertProfileLocked(p Profile) {
	for i := range m.profiles {
		if m.profiles[i].ID == p.ID {
			m.profiles[i] = p
			_ = saveProfiles(m.profPath, m.profiles)
			return
		}
	}
	m.profiles = append(m.profiles, p)
	_ = saveProfiles(m.profPath, m.profiles)
}

func (m *Manager) clashUp() bool {
	c := &http.Client{Timeout: time.Second}
	resp, err := c.Get("http://" + clashAddr + "/version")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == 200
}

// probe measures upstream reachability/latency via the Clash API delay test.
func (m *Manager) probe() (string, int) {
	target := url.QueryEscape("http://www.gstatic.com/generate_204")
	u := fmt.Sprintf("http://%s/proxies/%s/delay?timeout=3000&url=%s", clashAddr, upstreamTag, target)
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		return "down", 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "down", 0
	}
	var r struct {
		Delay int `json:"delay"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "degraded", 0
	}
	if r.Delay <= 0 {
		return "down", 0
	}
	if r.Delay > 1500 {
		return "degraded", r.Delay
	}
	return "up", r.Delay
}
