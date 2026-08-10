package main

import (
	"bufio"
	"fmt"
	"net"
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
	torSocksPort = 9250 // separate from Tor Browser's 9150 so both can coexist
	torCtrlPort  = 9251
)

// Defaults as shipped by Tor Browser. These can drift over time — the extension
// can override the snowflake args / bridge lines if needed.
const snowflakePTArgs = "-url https://1098762253.rsc.cdn77.org/ -front foursquare.com -ice stun:stun.l.google.com:19302,stun:stun.antisip.com:3478 -max 1"
const snowflakeBridge = "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72"

// Tor manages a detached `tor` subprocess with an optional pluggable transport
// (obfs4 or snowflake) for when Tor itself is blocked. It's a free, no-server
// rung of the ladder.
type Tor struct {
	binPath       string
	obfs4Path     string
	snowflakePath string
	dir           string
	torrcPath     string
	pidPath       string
	dataDir       string

	mu     sync.Mutex
	active bool
	mode   string
	label  string
}

func NewTor(dir string) *Tor {
	return &Tor{
		dir:           dir,
		torrcPath:     filepath.Join(dir, "torrc"),
		pidPath:       filepath.Join(dir, "tor.pid"),
		dataDir:       filepath.Join(dir, "tor-data"),
		binPath:       firstExec(dir, "tor"),
		obfs4Path:     firstExec(dir, "lyrebird", "obfs4proxy"),
		snowflakePath: firstExec(dir, "snowflake-client", "snowflake"),
	}
}

func exeName(n string) string {
	if runtime.GOOS == "windows" {
		return n + ".exe"
	}
	return n
}

// firstExec returns the first of names found next to the data dir or on PATH.
func firstExec(dir string, names ...string) string {
	for _, n := range names {
		nn := exeName(n)
		if p := filepath.Join(dir, nn); fileExists(p) {
			return p
		}
		if p, err := exec.LookPath(nn); err == nil {
			return p
		}
	}
	return ""
}

// Connect writes a torrc for the chosen mode and (re)starts a detached tor.
func (t *Tor) Connect(mode, label string, bridges []string) map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()

	if mode == "" {
		mode = "direct"
	}
	if label == "" {
		label = "Tor (" + mode + ")"
	}
	if t.binPath == "" {
		return errResp("tor binary not found — install Tor or drop it in " + t.dir)
	}
	if err := t.writeTorrc(mode, bridges); err != nil {
		return errResp(err.Error())
	}
	if err := t.startLocked(); err != nil {
		return errResp(err.Error())
	}
	t.active, t.mode, t.label = true, mode, label
	return map[string]any{"ok": true, "socksPort": torSocksPort, "id": "companion-tor", "mode": mode}
}

func (t *Tor) Disconnect() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
	t.active = false
	return map[string]any{"ok": true}
}

func (t *Tor) Transports() []map[string]any {
	t.mu.Lock()
	active, mode, label := t.active, t.mode, t.label
	t.mu.Unlock()
	if !active {
		return []map[string]any{}
	}
	health, boot := t.healthLocked()
	return []map[string]any{{
		"id": "companion-tor", "label": label, "scheme": "socks5",
		"host": "127.0.0.1", "port": torSocksPort, "kind": "companion",
		"health": health, "latencyMs": 0, "builtin": false,
		"mode": mode, "bootstrap": boot,
	}}
}

func (t *Tor) Health() []map[string]any {
	t.mu.Lock()
	active := t.active
	t.mu.Unlock()
	if !active {
		return []map[string]any{}
	}
	health, boot := t.healthLocked()
	return []map[string]any{{"id": "companion-tor", "health": health, "latencyMs": 0, "bootstrap": boot}}
}

// ---- internals -------------------------------------------------------------

func (t *Tor) healthLocked() (string, int) {
	p, err := t.bootstrap()
	if err != nil {
		return "down", 0
	}
	if p >= 100 {
		return "up", p
	}
	if p > 0 {
		return "degraded", p
	}
	return "down", p
}

func (t *Tor) writeTorrc(mode string, bridges []string) error {
	if err := os.MkdirAll(t.dataDir, 0o700); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SocksPort 127.0.0.1:%d\n", torSocksPort)
	fmt.Fprintf(&b, "ControlPort 127.0.0.1:%d\n", torCtrlPort)
	b.WriteString("CookieAuthentication 0\n")
	fmt.Fprintf(&b, "DataDirectory %s\n", t.dataDir)
	fmt.Fprintf(&b, "Log warn file %s\n", filepath.Join(t.dir, "tor.log"))

	switch mode {
	case "direct":
		// plain connection to the Tor network
	case "obfs4":
		if t.obfs4Path == "" {
			return fmt.Errorf("obfs4 plugin (lyrebird/obfs4proxy) not found")
		}
		if len(bridges) == 0 {
			return fmt.Errorf("obfs4 mode needs Bridge lines — get them from bridges.torproject.org")
		}
		b.WriteString("UseBridges 1\n")
		fmt.Fprintf(&b, "ClientTransportPlugin obfs4 exec %s\n", t.obfs4Path)
		for _, br := range bridges {
			fmt.Fprintf(&b, "Bridge %s\n", strings.TrimSpace(br))
		}
	case "snowflake":
		if t.snowflakePath == "" {
			return fmt.Errorf("snowflake-client not found")
		}
		b.WriteString("UseBridges 1\n")
		fmt.Fprintf(&b, "ClientTransportPlugin snowflake exec %s %s\n", t.snowflakePath, snowflakePTArgs)
		if len(bridges) == 0 {
			bridges = []string{snowflakeBridge}
		}
		for _, br := range bridges {
			fmt.Fprintf(&b, "Bridge %s\n", strings.TrimSpace(br))
		}
	default:
		return fmt.Errorf("unknown tor mode %q", mode)
	}
	return os.WriteFile(t.torrcPath, []byte(b.String()), 0o600)
}

func (t *Tor) startLocked() error {
	t.stopLocked()
	cmd := exec.Command(t.binPath, "-f", t.torrcPath)
	cmd.SysProcAttr = detachAttr()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tor: %w", err)
	}
	_ = os.WriteFile(t.pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	_ = cmd.Process.Release()

	// Only wait long enough to confirm the control port answers; full bootstrap
	// (esp. over bridges) can take a while and is reported via health instead.
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := t.bootstrap(); err == nil {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	return nil
}

func (t *Tor) stopLocked() {
	if b, err := os.ReadFile(t.pidPath); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
		}
	}
	_ = os.Remove(t.pidPath)
}

// bootstrap asks Tor's control port for its bootstrap percentage (0..100).
func (t *Tor) bootstrap() (int, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", torCtrlPort), 2*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)

	fmt.Fprintf(conn, "AUTHENTICATE\r\n")
	if _, err := r.ReadString('\n'); err != nil {
		return 0, err
	}
	fmt.Fprintf(conn, "GETINFO status/bootstrap-phase\r\n")

	progress := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		if i := strings.Index(line, "PROGRESS="); i >= 0 {
			num := ""
			for _, c := range line[i+len("PROGRESS="):] {
				if c >= '0' && c <= '9' {
					num += string(c)
				} else {
					break
				}
			}
			progress, _ = strconv.Atoi(num)
		}
		if strings.HasPrefix(line, "250 OK") || strings.HasPrefix(line, "550") || strings.HasPrefix(line, "510") {
			break
		}
	}
	fmt.Fprintf(conn, "QUIT\r\n")
	return progress, nil
}
