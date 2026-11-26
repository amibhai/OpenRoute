package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// server/install-server.sh and the companion meet in the share links: what
// the script prints has to be what the companion can use. This runs the
// script's generate step with real sing-box, serves the config it wrote, and
// pushes traffic through every link it printed — parsed and configured by the
// companion's own code — on the oldest and the newest supported sing-box.

func findBash() string {
	if runtime.GOOS == "windows" {
		// Git for Windows' bash; never System32\bash.exe, which is WSL (another OS).
		for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramW6432"), `C:\Program Files`} {
			if root == "" {
				continue
			}
			if p := filepath.Join(root, "Git", "bin", "bash.exe"); fileExists(p) {
				return p
			}
		}
		if p, err := exec.LookPath("bash"); err == nil && !strings.Contains(strings.ToLower(p), `\system32\`) {
			return p
		}
		return ""
	}
	p, _ := exec.LookPath("bash")
	return p
}

func TestServerScriptLinksWorkThroughTheCompanion(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real servers")
	}
	bash := findBash()
	if bash == "" {
		needTool(t, "needs bash")
	}
	ran := false
	for _, v := range []string{"1.12", "1.14"} {
		if sb := singBoxBins(t)[v]; sb != "" {
			ran = true
			t.Run(v, func(t *testing.T) { serverScriptE2E(t, bash, sb) })
		}
	}
	if !ran {
		needTool(t, "needs sing-box in .tools (node scripts/setup-tools.mjs sing-box)")
	}
}

func serverScriptE2E(t *testing.T, bash, sb string) {
	version, err := singBoxVersion(sb)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	// The site the user wants, on loopback.
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from the far side")
	}))
	defer site.Close()
	sitePort := site.Listener.Addr().(*net.TCPAddr).Port

	// Reality's cover site: locally, anything serving TLS 1.3 + HTTP/2.
	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	cover.EnableHTTP2 = true
	cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	cover.StartTLS()
	defer cover.Close()

	// Every port this test binds, picked at once: 3 for the server, 2 per client.
	ports := distinctPorts(t, 9)
	vlessPort, ssPort, hy2Port := ports[0], ports[1], ports[2]
	clientPorts := ports[3:]
	script, _ := filepath.Abs(filepath.Join("..", "server", "install-server.sh"))
	gen := exec.Command(bash, filepath.ToSlash(script), "generate",
		"--dir", filepath.ToSlash(dir), "--sing-box", filepath.ToSlash(sb),
		"--host", "127.0.0.1", "--listen", "127.0.0.1",
		"--sni", "reality.test", "--reality-dest", cover.Listener.Addr().String(),
		"--vless-port", strconv.Itoa(vlessPort), "--ss-port", strconv.Itoa(ssPort),
		"--hysteria2", "--hy2-port", strconv.Itoa(hy2Port), "--no-qr")
	out, err := gen.CombinedOutput()
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, out)
	}
	links := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if i := strings.Index(l, "://"); i > 0 {
			links[l[:i]] = strings.TrimSpace(l)
		}
	}
	for _, scheme := range []string{"vless", "ss", "hysteria2"} {
		if links[scheme] == "" {
			t.Fatalf("no %s link in the output:\n%s", scheme, out)
		}
	}
	if !strings.HasPrefix(links["ss"], "ss://2022-blake3-aes-128-gcm:") {
		t.Errorf("SS-2022 links must be SIP002's plain percent-encoded form, got %s", redactLink(links["ss"]))
	}

	// One companion-built client per link, kept for both server phases below.
	clients := map[string]int{}
	for _, scheme := range []string{"vless", "ss", "hysteria2"} {
		p, err := parseLink(links[scheme])
		if err != nil {
			t.Fatalf("the companion can't parse the %s link: %v", scheme, err)
		}
		if err := requireFeatures(version, []Parsed{p}); err != nil {
			// sing-box 1.12 can't check the pinned Hysteria2 certificate;
			// the companion must say so rather than connect unverified.
			if scheme != "hysteria2" || versionAtLeast(version, "1.13.0") || !strings.Contains(err.Error(), "1.13") {
				t.Fatalf("%s on %s: %v", scheme, version, err)
			}
			continue
		}
		pool, clash := clientPorts[0], clientPorts[1]
		clientPorts = clientPorts[2:]
		clients[scheme] = startCompanionClient(t, sb, filepath.Join(dir, "client-"+scheme), p, pool, clash)
	}
	if versionAtLeast(version, "1.13.0") && clients["hysteria2"] == 0 {
		t.Fatal("Hysteria2 should run on sing-box 1.13+")
	}

	target := fmt.Sprintf("http://127.0.0.1:%d/", sitePort)
	// A name that resolves to a private address, standing in for
	// localhost or metadata.google.internal on a real VPS. Both phases
	// point the server's resolver at a stub that knows it; that is the only
	// change to the generated config besides phase 1's missing reject rules.
	byName := fmt.Sprintf("http://internal.test:%d/", sitePort)

	// Phase 1: the generated config without its reject rules (the target
	// is on loopback, which the real config refuses), proving every
	// transport carries traffic end to end.
	stop := runServerConfig(t, sb, testServerConfig(t, dir, true), vlessPort, ssPort)
	for scheme, port := range clients {
		body, err := getWithRetry(port, target)
		if err != nil || body != "hello from the far side" {
			t.Errorf("%s: through the tunnel: %q, %v", scheme, body, err)
		}
	}
	for _, scheme := range []string{"ss", "vless"} {
		if body, err := getWithRetry(clients[scheme], byName); err != nil || body != "hello from the far side" {
			t.Errorf("%s: by name, reject rules removed: %q, %v", scheme, body, err)
		}
	}
	stop()

	// Phase 2: the generated rules exactly as written. The same tunnels
	// must now refuse the loopback target, by address and by a name that
	// resolves to it (what the resolve rule is there for).
	stop = runServerConfig(t, sb, testServerConfig(t, dir, false), vlessPort, ssPort)
	defer stop()
	for _, scheme := range []string{"ss", "vless"} {
		for _, u := range []string{target, byName} {
			if body, err := getThroughSocks(clients[scheme], u); err == nil {
				t.Errorf("%s: the server let a client reach %s (%q); private destinations must be refused", scheme, u, body)
			}
		}
	}
}

// startCompanionClient runs sing-box with the config the companion would
// build for this one link, and returns its local proxy port.
func startCompanionClient(t *testing.T, sb, dir string, p Parsed, poolPort, clashPort int) int {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st := &State{Secret: "test", Ports: Ports{Pool: poolPort, Clash: clashPort}}
	cfg := buildSingBoxConfig(st, []Parsed{p}, "", filepath.Join(dir, "sing-box.log"))
	b, _ := json.MarshalIndent(cfg, "", "  ")
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sb, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("client config rejected: %v\n%s", err, out)
	}
	cmd := exec.Command(sb, "run", "-c", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	if err := waitListening([]int{st.Ports.Pool}, 10*time.Second); err != nil {
		t.Fatalf("client didn't come up: %v; %s", err, tailFile(filepath.Join(dir, "sing-box.log"), 5))
	}
	return st.Ports.Pool
}

func runServerConfig(t *testing.T, sb, path string, tcpPorts ...int) (stop func()) {
	t.Helper()
	var log bytes.Buffer
	cmd := exec.Command(sb, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("server log (%s):\n%s", filepath.Base(path), stripANSI(log.String()))
		}
	}
	if err := waitListening(tcpPorts, 10*time.Second); err != nil {
		stop()
		t.Fatalf("server didn't come up: %v\n%s", err, stripANSI(log.String()))
	}
	return stop
}

// testServerConfig is the generated config with its resolver swapped for a
// stub that maps internal.test to 127.0.0.1, minus the reject rules if asked.
func testServerConfig(t *testing.T, dir string, dropRejects bool) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	dns := cfg["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	if len(servers) != 1 || servers[0].(map[string]any)["tag"] != "system" {
		t.Fatalf("expected one DNS server tagged system, got %v", servers)
	}
	dns["servers"] = []any{map[string]any{"type": "hosts", "tag": "system",
		"predefined": map[string]any{"internal.test": []string{"127.0.0.1"}}}}
	name := "config-test.json"
	if dropRejects {
		route := cfg["route"].(map[string]any)
		rules := route["rules"].([]any)
		var kept []any
		for _, r := range rules {
			if r.(map[string]any)["action"] != "reject" {
				kept = append(kept, r)
			}
		}
		if len(kept) == len(rules) {
			t.Fatal("the generated config should carry reject rules")
		}
		route["rules"] = kept
		name = "config-test-open.json"
	}
	out, _ := json.Marshal(cfg)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestInstalledServerLinks checks a server installed for real by
// install-server.sh (CI's "server-install" job does this on a fresh Ubuntu
// with systemd). OPENROUTE_INSTALLED_LINKS names a copy of its links.txt.
// Through every link, a companion-built client must reach the internet, and
// must be refused a service on the server's own loopback.
func TestInstalledServerLinks(t *testing.T) {
	path := os.Getenv("OPENROUTE_INSTALLED_LINKS")
	if path == "" {
		t.Skip("set OPENROUTE_INSTALLED_LINKS to an installed server's links.txt")
	}
	sb := os.Getenv("OPENROUTE_SINGBOX")
	if sb == "" {
		sb = singBoxBins(t)["1.14"]
	}
	if sb == "" {
		t.Fatal("needs a sing-box client (OPENROUTE_SINGBOX)")
	}
	version, err := singBoxVersion(sb)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var links []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, "://") {
			links = append(links, strings.TrimSpace(l))
		}
	}
	if len(links) == 0 {
		t.Fatalf("no links in %s", path)
	}
	// Something only the server's own loopback can reach: refused, or the
	// config's private-address rules don't hold on the real install.
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "should not be reachable") }))
	defer local.Close()

	dir := t.TempDir()
	for i, link := range links {
		scheme := link[:strings.Index(link, "://")]
		p, err := parseLink(link)
		if err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		if err := requireFeatures(version, []Parsed{p}); err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		pp := distinctPorts(t, 2)
		port := startCompanionClient(t, sb, filepath.Join(dir, strconv.Itoa(i)), p, pp[0], pp[1])
		var status int
		for try := 0; try < 5 && status != http.StatusNoContent; try++ {
			status, err = statusThroughSocks(port, "http://connectivitycheck.gstatic.com/generate_204")
			if status != http.StatusNoContent {
				time.Sleep(time.Second)
			}
		}
		if status != http.StatusNoContent {
			t.Errorf("%s: no internet through the installed server: %d %v", scheme, status, err)
		}
		if body, err := getThroughSocks(port, local.URL); err == nil {
			t.Errorf("%s: the installed server let a client reach its loopback (%q)", scheme, body)
		}
	}
}

func statusThroughSocks(port int, target string) (int, error) {
	proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	resp, err := client.Get(target)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// distinctPorts returns n ports that are free right now for both TCP and
// UDP (Hysteria2 is UDP), and distinct: separate freePort() calls aren't —
// a port the OS just freed can come straight back. All are held open until
// every one is picked.
func distinctPorts(t *testing.T, n int) []int {
	t.Helper()
	var held []io.Closer
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	var ports []int
	for tries := 0; len(ports) < n; tries++ {
		if tries > 50*n {
			t.Fatal("couldn't find enough free ports")
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, ln)
		p := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue // its UDP side is taken
		}
		held = append(held, pc)
		ports = append(ports, p)
	}
	return ports
}

// getWithRetry allows for the first handshake (QUIC in particular) to take
// a moment after the server starts.
func getWithRetry(port int, target string) (string, error) {
	var body string
	var err error
	for i := 0; i < 4; i++ {
		if body, err = getThroughSocks(port, target); err == nil {
			return body, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return body, err
}
