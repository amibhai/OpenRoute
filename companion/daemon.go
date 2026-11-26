package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The daemon owns every tunnel: it keeps the desired state, supervises the
// sing-box and tor children, restores them after a restart, and exits when
// no browser has talked to it for a while (taking its children with it).

const defaultIdle = 15 * time.Minute
const maxLinks = 50

type Daemon struct {
	dir       string
	statePath string
	reg       *ChildRegistry
	sb        *SingBox
	tor       *Tor

	mu   sync.Mutex // serializes state changes
	st   *State
	last atomic.Int64
	quit chan struct{}
	once sync.Once
}

func newDaemon(dir string) *Daemon {
	reg := &ChildRegistry{path: filepath.Join(dir, "children.json")}
	d := &Daemon{
		dir:       dir,
		statePath: filepath.Join(dir, "state.json"),
		reg:       reg,
		sb:        newSingBox(dir, reg),
		tor:       newTor(dir, reg),
		st:        loadState(filepath.Join(dir, "state.json")),
		quit:      make(chan struct{}),
	}
	d.last.Store(time.Now().UnixNano())
	return d
}

func runDaemon(_ []string) int {
	dir := dataDir()
	_ = os.MkdirAll(dir, 0o700)
	closeLog := openLog(filepath.Join(dir, "companion.log"))
	defer closeLog()

	ln, err := ipcListen(socketPath(dir))
	if errors.Is(err, errAlreadyRunning) {
		return 0
	}
	if err != nil {
		log.Printf("daemon: cannot listen: %v", err)
		return 1
	}
	d := newDaemon(dir)
	if killed := d.reg.CleanupOrphans(); len(killed) > 0 {
		log.Printf("daemon: cleaned up leftover helpers %v", killed)
	}
	log.Printf("OpenRoute companion daemon %s (data %s)", version, dir)
	go ipcServe(ln, d.handle)
	go d.restore()

	idle := defaultIdle
	if v, err := time.ParseDuration(os.Getenv("OPENROUTE_DAEMON_IDLE")); err == nil && v > 0 {
		idle = v
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	tick := time.NewTicker(minDuration(idle/4, time.Minute))
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if time.Since(time.Unix(0, d.last.Load())) > idle {
				log.Printf("daemon: idle for %s — stopping", idle)
				d.shutdown(ln)
				return 0
			}
		case <-sig:
			d.shutdown(ln)
			return 0
		case <-d.quit:
			d.shutdown(ln)
			return 0
		}
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (d *Daemon) shutdown(ln interface{ Close() error }) {
	d.once.Do(func() {
		d.sb.child.Stop()
		d.tor.Stop()
		_ = ln.Close()
		_ = os.Remove(socketPath(d.dir))
	})
}

// restore brings back whatever was running before (best effort).
func (d *Daemon) restore() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Profile != nil || d.st.DPI {
		if err := d.sb.Apply(d.st, pickDoH()); err != nil {
			log.Printf("restore sing-box: %v", err)
		}
	}
	if d.st.Tor != nil {
		d.st.ensurePorts(&d.st.Ports.TorSocks)
		if err := d.tor.Start(d.st.Tor, d.st.Ports.TorSocks); err != nil {
			log.Printf("restore tor: %v", err)
		}
	}
	_ = d.st.save(d.statePath)
}

func ok(kv ...any) map[string]any {
	m := map[string]any{"ok": true}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func errResp(msg string) map[string]any { return map[string]any{"ok": false, "error": msg} }

func (d *Daemon) handle(req map[string]any) map[string]any {
	d.last.Store(time.Now().UnixNano())
	cmd, _ := req["cmd"].(string)
	if cmd != "ping" && cmd != "health" && cmd != "status" {
		log.Printf("cmd: %s", cmd)
	}
	switch cmd {
	case "ping":
		return ok("cmd", "pong", "version", version, "singbox", d.sb.Info(), "tor", map[string]any{"path": d.tor.bin})
	case "status":
		return d.status()
	case "connect":
		return d.connect(req)
	case "connectDpi":
		return d.connectDPI()
	case "connectTor":
		return d.connectTor(req)
	case "disconnect":
		kind, _ := req["kind"].(string)
		return d.disconnect(kind)
	case "transports":
		return ok("transports", d.transports())
	case "health":
		return ok("transports", d.health())
	case "newIdentity":
		if err := d.tor.NewIdentity(); err != nil {
			return errResp(err.Error())
		}
		return ok()
	case "refreshBridges":
		via, _ := req["viaSocks"].(float64)
		counts, err := d.tor.RefreshBridges(int(via))
		if err != nil {
			return errResp(err.Error())
		}
		return ok("bridges", counts)
	case "shutdown":
		go func() { time.Sleep(100 * time.Millisecond); close(d.quit) }()
		return ok()
	default:
		return errResp("unknown cmd: " + cmd)
	}
}

func toStrings(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func (d *Daemon) connect(req map[string]any) map[string]any {
	links := toStrings(req["links"])
	if l, _ := req["link"].(string); l != "" && len(links) == 0 {
		links = []string{l}
	}
	if sub, _ := req["subscription"].(string); sub != "" {
		fetched, err := d.fetchSubscription(sub)
		if err != nil {
			return errResp("subscription: " + err.Error())
		}
		links = append(links, fetched...)
	}
	if len(links) == 0 {
		return errResp("no share link(s) provided")
	}
	if len(links) > maxLinks {
		return errResp(fmt.Sprintf("too many links (max %d)", maxLinks))
	}
	for _, l := range links { // fail fast, with the reason, before touching anything
		if _, err := parseLink(l); err != nil {
			return errResp(fmt.Sprintf("%s: %v", redactLink(l), err))
		}
	}
	id, _ := req["id"].(string)
	label, _ := req["label"].(string)
	d.mu.Lock()
	defer d.mu.Unlock()
	prev := d.st.Profile
	d.st.Profile = &Profile{ID: firstNonEmpty(id, "companion"), Label: firstNonEmpty(label, "Companion"), Links: links}
	if err := d.sb.Apply(d.st, pickDoH()); err != nil {
		d.st.Profile = prev
		_ = d.sb.Apply(d.st, pickDoH()) // put the previous setup back
		return errResp(err.Error())
	}
	_ = d.st.save(d.statePath)
	return ok("socksPort", d.st.Ports.Pool, "id", d.st.Profile.ID, "count", len(links))
}

func (d *Daemon) connectDPI() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st.DPI = true
	if err := d.sb.Apply(d.st, pickDoH()); err != nil {
		d.st.DPI = false
		_ = d.sb.Apply(d.st, pickDoH())
		return errResp(err.Error())
	}
	_ = d.st.save(d.statePath)
	return ok("transports", d.dpiTransports())
}

func (d *Daemon) connectTor(req map[string]any) map[string]any {
	mode, _ := req["mode"].(string)
	mode = firstNonEmpty(mode, "direct")
	valid := false
	for _, m := range TorModes {
		valid = valid || m == mode
	}
	if !valid {
		return errResp(fmt.Sprintf("unknown tor mode %q", mode))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	want := &TorWant{Mode: mode, Bridges: toStrings(req["bridges"])}
	d.st.ensurePorts(&d.st.Ports.TorSocks)
	if err := d.tor.Start(want, d.st.Ports.TorSocks); err != nil {
		return errResp(err.Error())
	}
	d.st.Tor = want
	_ = d.st.save(d.statePath)
	return ok("socksPort", d.st.Ports.TorSocks, "id", "companion-tor", "mode", mode)
}

func (d *Daemon) disconnect(kind string) map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch kind {
	case "tor":
		d.tor.Stop()
		d.st.Tor = nil
	case "singbox", "companion":
		d.st.Profile = nil
		_ = d.sb.Apply(d.st, pickDoH())
	case "dpi":
		d.st.DPI = false
		_ = d.sb.Apply(d.st, pickDoH())
	default:
		d.tor.Stop()
		d.st.Tor, d.st.Profile, d.st.DPI = nil, nil, false
		_ = d.sb.Apply(d.st, "")
	}
	_ = d.st.save(d.statePath)
	return ok()
}

func (d *Daemon) dpiTransports() []map[string]any {
	return []map[string]any{
		{"id": "companion-dpi-record", "label": "DPI bypass · TLS records", "scheme": "socks5", "host": "127.0.0.1", "port": d.st.Ports.DPIRecord, "kind": "companion", "note": "no server · beats simple SNI filters"},
		{"id": "companion-dpi-segment", "label": "DPI bypass · TCP segments", "scheme": "socks5", "host": "127.0.0.1", "port": d.st.Ports.DPISegment, "kind": "companion", "note": "no server · slower"},
	}
}

// transports: what the extension should have registered right now (it syncs
// these, so a port that had to change after a restart is picked up).
func (d *Daemon) transports() []map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []map[string]any
	if d.st.Profile != nil {
		out = append(out, map[string]any{"id": d.st.Profile.ID, "label": d.st.Profile.Label, "scheme": "socks5", "host": "127.0.0.1", "port": d.st.Ports.Pool, "kind": "companion",
			"note": fmt.Sprintf("%d server(s)", len(d.st.Profile.Links))})
	}
	if d.st.DPI {
		out = append(out, d.dpiTransports()...)
	}
	if d.st.Tor != nil {
		out = append(out, map[string]any{"id": "companion-tor", "label": "Tor (" + d.st.Tor.Mode + ")", "scheme": "socks5", "host": "127.0.0.1", "port": d.st.Ports.TorSocks, "kind": "companion", "note": "free network · slower"})
	}
	return out
}

func (d *Daemon) health() []map[string]any {
	d.mu.Lock()
	st := *d.st
	d.mu.Unlock()
	var out []map[string]any
	if st.Profile != nil {
		h, lat := d.sb.PoolHealth(&st)
		out = append(out, map[string]any{"id": st.Profile.ID, "health": h, "latencyMs": lat})
	}
	if st.DPI {
		h := "down"
		if d.sb.child.Running() && waitListening([]int{st.Ports.DPIRecord, st.Ports.DPISegment}, time.Second) == nil {
			h = "up"
		}
		out = append(out, map[string]any{"id": "companion-dpi-record", "health": h}, map[string]any{"id": "companion-dpi-segment", "health": h})
	}
	if st.Tor != nil {
		h, boot := d.tor.Health()
		out = append(out, map[string]any{"id": "companion-tor", "health": h, "bootstrap": boot})
	}
	return out
}

func (d *Daemon) status() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	state := map[string]any{"dpi": d.st.DPI}
	if d.st.Profile != nil {
		state["profile"] = map[string]any{"id": d.st.Profile.ID, "label": d.st.Profile.Label, "count": len(d.st.Profile.Links)}
	}
	if d.st.Tor != nil {
		state["tor"] = d.st.Tor.Mode
	}
	return ok("version", version, "running", d.sb.child.Running(), "socksPort", d.st.Ports.Pool,
		"singbox", d.sb.Status(), "tor", d.tor.Status(), "state", state)
}

// fetchSubscription downloads a subscription — directly, or through the
// running pool when the subscription host itself is blocked.
func (d *Daemon) fetchSubscription(raw string) ([]string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("subscription must be an http(s) URL")
	}
	try := func(client *http.Client) ([]string, error) {
		resp, err := client.Get(raw)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		if err != nil {
			return nil, err
		}
		return parseSubscription(string(body))
	}
	links, err := try(&http.Client{Timeout: 20 * time.Second})
	if err == nil {
		return links, nil
	}
	if d.st.Profile != nil && d.sb.child.Running() {
		proxy, _ := url.Parse("socks5h://127.0.0.1:" + strconv.Itoa(d.st.Ports.Pool))
		return try(&http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}})
	}
	return nil, err
}
