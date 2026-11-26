package main

import (
	"bufio"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Tor: the free, serverless rung. A supervised `tor` with
//   * cookie-authenticated control port (never unauthenticated),
//   * a SOCKS port chosen free once and kept,
//   * pluggable transports + built-in bridges taken from Tor's own
//     pt_config.json (today's bundles run Snowflake through lyrebird), with a
//     bundled snapshot and an optional fresh Moat fetch as fallbacks,
//   * relative PT paths, so spaces in Windows paths can't break `exec`,
//   * an "auto" mode that tries direct → obfs4 → snowflake → meek until one
//     bootstraps (like Tor Browser's Connection Assist).

//go:embed assets/pt_config.json
var builtinPTConfig []byte

type PTConfig struct {
	RecommendedDefault  string              `json:"recommendedDefault"`
	PluggableTransports map[string]string   `json:"pluggableTransports"`
	Bridges             map[string][]string `json:"bridges"`
}

var TorModes = []string{"direct", "obfs4", "snowflake", "meek", "webtunnel", "auto"}

type Tor struct {
	dir      string
	bin      string
	ptDir    string
	pt       *PTConfig
	ptSource string

	torrc    string
	dataDir  string
	portFile string
	logPath  string
	child    *Child

	mu       sync.Mutex
	mode     string // the mode actually running ("auto" resolves to one of the others)
	autoNote string
	lastErr  string
}

func newTor(dir string, reg *ChildRegistry) *Tor {
	t := &Tor{
		dir:      dir,
		torrc:    filepath.Join(dir, "torrc"),
		dataDir:  filepath.Join(dir, "tor-data"),
		portFile: filepath.Join(dir, "tor-control-port"),
		logPath:  filepath.Join(dir, "tor.log"),
	}
	t.child = &Child{Name: "tor", Log: filepath.Join(dir, "tor.out.log"), reg: reg}
	t.detect()
	return t
}

func torBrowserCandidates() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		var out []string
		for _, base := range []string{filepath.Join(home, "Desktop"), filepath.Join(home, "OneDrive", "Desktop"), os.Getenv("LOCALAPPDATA"), os.Getenv("ProgramFiles")} {
			if base != "" {
				out = append(out, filepath.Join(base, "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"))
			}
		}
		return out
	case "darwin":
		return []string{"/Applications/Tor Browser.app/Contents/MacOS/Tor/tor", filepath.Join(home, "Applications", "Tor Browser.app", "Contents", "MacOS", "Tor", "tor")}
	default:
		return []string{filepath.Join(home, "tor-browser", "Browser", "TorBrowser", "Tor", "tor"),
			filepath.Join(home, ".local", "share", "torbrowser", "tbb", "x86_64", "tor-browser", "Browser", "TorBrowser", "Tor", "tor"),
			"/usr/bin/tor", "/usr/local/bin/tor", "/opt/homebrew/bin/tor"}
	}
}

func (t *Tor) detect() {
	t.bin = findBinary(t.dir, "OPENROUTE_TOR", []string{"tor"}, torBrowserCandidates())
	t.ptDir, t.pt, t.ptSource = "", nil, ""
	if t.bin == "" {
		return
	}
	torDir := filepath.Dir(t.bin)
	for _, d := range []string{
		filepath.Join(torDir, "pluggable_transports"), // Tor Expert Bundle
		filepath.Join(torDir, "PluggableTransports"),  // Tor Browser
		torDir,
	} {
		if fileExists(filepath.Join(d, exeName("lyrebird"))) || fileExists(filepath.Join(d, exeName("obfs4proxy"))) || fileExists(filepath.Join(d, exeName("snowflake-client"))) {
			t.ptDir = d
			break
		}
	}
	if t.ptDir != "" {
		if b, err := os.ReadFile(filepath.Join(t.ptDir, "pt_config.json")); err == nil {
			var c PTConfig
			if json.Unmarshal(b, &c) == nil && len(c.PluggableTransports) > 0 {
				t.pt, t.ptSource = &c, "installed pt_config.json"
			}
		}
	}
	if t.pt == nil {
		t.pt = loadCachedOrBuiltinPT(t.dir)
		t.ptSource = "bundled snapshot"
		if fileExists(filepath.Join(t.dir, "bridges.json")) {
			t.ptSource = "Moat cache"
		}
	}
}

func loadCachedOrBuiltinPT(dir string) *PTConfig {
	var c PTConfig
	_ = json.Unmarshal(builtinPTConfig, &c)
	if b, err := os.ReadFile(filepath.Join(dir, "bridges.json")); err == nil {
		var fresh map[string][]string
		if json.Unmarshal(b, &fresh) == nil && len(fresh) > 0 {
			c.Bridges = fresh
		}
	}
	return &c
}

// torQuote quotes a torrc value (Tor parses C-style escapes inside quotes).
func torQuote(p string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(p, `\`, `\\`), `"`, `\"`) + `"`
}

// pluginLine renders a pt_config plugin line with a PT path relative to tor's
// working directory (no spaces), adding .exe on Windows.
func (t *Tor) pluginLine(key string) (string, error) {
	tmpl, ok := t.pt.PluggableTransports[key]
	if !ok {
		return "", fmt.Errorf("no %s plugin line in %s", key, t.ptSource)
	}
	if t.ptDir == "" {
		return "", errors.New("no pluggable-transport binaries found next to tor (lyrebird/snowflake-client)")
	}
	rel, err := filepath.Rel(filepath.Dir(t.bin), t.ptDir)
	if err != nil {
		rel = t.ptDir
	}
	prefix := ""
	if rel != "." {
		prefix = rel + string(filepath.Separator)
	}
	line := strings.ReplaceAll(tmpl, "${pt_path}", prefix)
	// Binary names: the snapshot is platform-neutral; installed configs already match.
	re := regexp.MustCompile(`exec (\S+)`)
	line = re.ReplaceAllStringFunc(line, func(m string) string {
		bin := strings.TrimPrefix(m, "exec ")
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(bin), ".exe") {
			bin += ".exe"
		}
		return "exec " + bin
	})
	if strings.Contains(prefix, " ") {
		return "", fmt.Errorf("the pluggable-transport folder path contains spaces (%s); move tor to a path without spaces", t.ptDir)
	}
	return line, nil
}

func (t *Tor) transportsFor(mode string, user []string) ([]string, []string, error) {
	var bridges []string
	for _, b := range user {
		if b = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(b), "Bridge ")); b != "" {
			bridges = append(bridges, b)
		}
	}
	var plugin string
	var err error
	switch mode {
	case "obfs4", "meek", "webtunnel":
		plugin, err = t.pluginLine("lyrebird")
	case "snowflake":
		plugin, err = t.pluginLine("snowflake")
	default:
		return nil, nil, fmt.Errorf("unknown tor mode %q", mode)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(bridges) == 0 {
		bridges = t.pt.Bridges[mode]
	}
	if len(bridges) == 0 && mode == "meek" {
		bridges = t.pt.Bridges["meek-azure"]
	}
	if len(bridges) == 0 {
		if mode == "webtunnel" {
			return nil, nil, errors.New("webtunnel needs bridge lines — get them at bridges.torproject.org")
		}
		return nil, nil, fmt.Errorf("no built-in %s bridges available", mode)
	}
	return []string{plugin}, bridges, nil
}

func (t *Tor) writeTorrc(mode string, socksPort int, user []string) error {
	if err := os.MkdirAll(t.dataDir, 0o700); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "DataDirectory %s\n", torQuote(t.dataDir))
	fmt.Fprintf(&b, "SocksPort 127.0.0.1:%d\n", socksPort)
	b.WriteString("ControlPort auto\n")
	fmt.Fprintf(&b, "ControlPortWriteToFile %s\n", torQuote(t.portFile))
	b.WriteString("CookieAuthentication 1\n")
	fmt.Fprintf(&b, "CookieAuthFile %s\n", torQuote(filepath.Join(t.dataDir, "control_auth_cookie")))
	b.WriteString("AvoidDiskWrites 1\nClientOnly 1\n")
	fmt.Fprintf(&b, "Log notice file %s\n", torQuote(t.logPath))
	for _, g := range []string{"geoip", "geoip6"} {
		p := filepath.Join(filepath.Dir(filepath.Dir(t.bin)), "data", g)
		if fileExists(p) {
			key := "GeoIPFile"
			if g == "geoip6" {
				key = "GeoIPv6File"
			}
			fmt.Fprintf(&b, "%s %s\n", key, torQuote(p))
		}
	}
	if mode != "direct" {
		plugins, bridges, err := t.transportsFor(mode, user)
		if err != nil {
			return err
		}
		b.WriteString("UseBridges 1\n")
		for _, p := range plugins {
			b.WriteString(p + "\n")
		}
		for _, br := range bridges {
			fmt.Fprintf(&b, "Bridge %s\n", br)
		}
	}
	return os.WriteFile(t.torrc, []byte(b.String()), 0o600)
}

// Start launches tor in mode ("auto" runs the fallback sequence in the
// background). Returns once tor is up and its control port answers.
func (t *Tor) Start(want *TorWant, socksPort int) error {
	if t.bin == "" {
		t.detect()
	}
	if t.bin == "" {
		return t.fail(fmt.Errorf("tor not found — install Tor Browser or the Tor Expert Bundle, or put tor in %s", t.dir))
	}
	if want.Mode == "auto" {
		go t.auto(want, socksPort)
		return t.startMode("direct", socksPort, nil, "auto: trying direct")
	}
	return t.startMode(want.Mode, socksPort, want.Bridges, "")
}

func (t *Tor) startMode(mode string, socksPort int, bridges []string, note string) error {
	t.child.Stop()
	_ = os.Remove(t.portFile)
	if err := t.writeTorrc(mode, socksPort, bridges); err != nil {
		return t.fail(err)
	}
	t.child.Bin = t.bin
	t.child.Dir = filepath.Dir(t.bin) // so relative PT paths resolve
	t.child.Args = []string{"-f", t.torrc, "--defaults-torrc", os.DevNull}
	if err := t.child.Start(); err != nil {
		return t.fail(err)
	}
	if err := waitListening([]int{socksPort}, 15*time.Second); err != nil {
		t.child.Stop()
		return t.fail(fmt.Errorf("tor didn't come up: %v; %s", err, tailFile(t.logPath, 3)))
	}
	t.mu.Lock()
	t.mode, t.autoNote, t.lastErr = mode, note, ""
	t.mu.Unlock()
	return nil
}

func (t *Tor) auto(want *TorWant, socksPort int) {
	for i, mode := range []string{"direct", "obfs4", "snowflake", "meek"} {
		if i > 0 {
			if err := t.startMode(mode, socksPort, nil, "auto: trying "+mode); err != nil {
				continue
			}
		}
		budget := 90 * time.Second // bridges take longer to bootstrap
		if mode == "direct" {
			budget = 60 * time.Second
		}
		deadline := time.Now().Add(budget)
		for time.Now().Before(deadline) {
			if p, err := t.Bootstrap(); err == nil && p >= 100 {
				t.mu.Lock()
				t.autoNote = "auto: connected via " + mode
				t.mu.Unlock()
				return
			}
			time.Sleep(2 * time.Second)
			t.mu.Lock()
			stillAuto := strings.HasPrefix(t.autoNote, "auto:")
			t.mu.Unlock()
			if !stillAuto {
				return // the user switched modes meanwhile
			}
		}
	}
	t.mu.Lock()
	t.autoNote = "auto: no mode bootstrapped"
	t.mu.Unlock()
}

func (t *Tor) Stop() {
	t.mu.Lock()
	t.autoNote = ""
	t.mode = ""
	t.mu.Unlock()
	t.child.Stop()
}

func (t *Tor) fail(err error) error {
	t.mu.Lock()
	t.lastErr = redact(err.Error())
	t.mu.Unlock()
	return errors.New(t.lastErr)
}

// ---- control port (cookie-authenticated) --------------------------------------

func (t *Tor) controlAddr() (string, error) {
	b, err := os.ReadFile(t.portFile)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "PORT=") {
			return strings.TrimSpace(strings.TrimPrefix(l, "PORT=")), nil
		}
	}
	return "", errors.New("no control port yet")
}

// Control runs commands on tor's control port and returns the reply lines.
func (t *Tor) Control(cmds ...string) ([]string, error) {
	addr, err := t.controlAddr()
	if err != nil {
		return nil, err
	}
	cookie, err := os.ReadFile(filepath.Join(t.dataDir, "control_auth_cookie"))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := readTorReply(conn, r, "AUTHENTICATE "+hex.EncodeToString(cookie)); err != nil {
		return nil, err
	}
	var all []string
	for _, c := range cmds {
		lines, err := readTorReply(conn, r, c)
		if err != nil {
			return nil, err
		}
		all = append(all, lines...)
	}
	fmt.Fprintf(conn, "QUIT\r\n")
	return all, nil
}

func readTorReply(w io.Writer, r *bufio.Reader, cmd string) ([]string, error) {
	if _, err := fmt.Fprintf(w, "%s\r\n", cmd); err != nil {
		return nil, err
	}
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			continue
		}
		code, sep := line[:3], line[3]
		if code[0] != '2' {
			return nil, fmt.Errorf("tor: %s", line)
		}
		lines = append(lines, line[4:])
		if sep == ' ' {
			return lines, nil
		}
	}
}

var reProgress = regexp.MustCompile(`PROGRESS=(\d+)`)

func (t *Tor) Bootstrap() (int, error) {
	lines, err := t.Control("GETINFO status/bootstrap-phase")
	if err != nil {
		return 0, err
	}
	for _, l := range lines {
		if m := reProgress.FindStringSubmatch(l); m != nil {
			return strconv.Atoi(m[1])
		}
	}
	return 0, errors.New("no bootstrap progress")
}

func (t *Tor) NewIdentity() error {
	_, err := t.Control("SIGNAL NEWNYM")
	return err
}

func (t *Tor) Status() map[string]any {
	t.mu.Lock()
	st := map[string]any{"mode": t.mode, "binary": t.bin, "transports": t.ptSource}
	if t.autoNote != "" {
		st["auto"] = t.autoNote
	}
	if t.lastErr != "" {
		st["error"] = t.lastErr
	}
	t.mu.Unlock()
	for k, v := range t.child.Status() {
		st[k] = v
	}
	if t.child.Running() {
		if p, err := t.Bootstrap(); err == nil {
			st["bootstrap"] = p
		}
	}
	return st
}

// Health: up once fully bootstrapped, degraded while bootstrapping.
func (t *Tor) Health() (string, int) {
	if !t.child.Running() {
		return "down", 0
	}
	p, err := t.Bootstrap()
	switch {
	case err != nil:
		return "down", 0
	case p >= 100:
		return "up", p
	case p > 0:
		return "degraded", p
	}
	return "down", p
}

// RefreshBridges fetches Tor's current built-in bridges from the Moat API,
// optionally through a local SOCKS proxy (when bridges.torproject.org is
// blocked directly), and caches them.
func (t *Tor) RefreshBridges(viaSocks int) (map[string]int, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	if viaSocks > 0 {
		proxy, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", viaSocks))
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxy)}
	}
	resp, err := client.Get("https://bridges.torproject.org/moat/circumvention/builtin")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var fresh map[string][]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&fresh); err != nil {
		return nil, fmt.Errorf("moat: %w", err)
	}
	if len(fresh) == 0 {
		return nil, errors.New("moat returned no bridges")
	}
	b, _ := json.MarshalIndent(fresh, "", "  ")
	if err := os.WriteFile(filepath.Join(t.dir, "bridges.json"), b, 0o600); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for k, v := range fresh {
		counts[k] = len(v)
	}
	if t.ptSource != "installed pt_config.json" {
		t.pt.Bridges = fresh
		t.ptSource = "Moat cache"
	}
	return counts, nil
}
