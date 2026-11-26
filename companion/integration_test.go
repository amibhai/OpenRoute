package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary stand in for the companion executable: with
// OPENROUTE_RUN_MAIN=1 it runs main() — so the host it launches can spawn
// `<self> daemon` exactly like the real binary does.
func TestMain(m *testing.M) {
	if os.Getenv("OPENROUTE_RUN_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type nmHost struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func startHost(t *testing.T, env []string) *nmHost {
	t.Helper()
	cmd := exec.Command(os.Args[0]) // no args: "launched by hand" → host mode
	cmd.Env = append(os.Environ(), env...)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return &nmHost{cmd: cmd, in: in, out: bufio.NewReader(out)}
}

func (h *nmHost) call(t *testing.T, msg map[string]any) map[string]any {
	t.Helper()
	if err := writeMessage(h.in, msg); err != nil {
		t.Fatal(err)
	}
	type result struct {
		m   map[string]any
		err error
	}
	ch := make(chan result, 1)
	go func() { m, err := readMessage(h.out); ch <- result{m, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("%v: %v", msg["cmd"], r.err)
		}
		return r.m
	case <-time.After(100 * time.Second):
		t.Fatalf("%v: timed out", msg["cmd"])
	}
	return nil
}

func getThroughSocks(port int, target string) (string, error) {
	proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	resp, err := client.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestEndToEndHostDaemonSingBoxTunnel(t *testing.T) {
	sb := singBoxBins(t)["1.14"]
	if sb == "" {
		t.Skip("needs sing-box 1.14 in .tools")
	}
	dir := t.TempDir()

	// The site we want to reach.
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from the far side")
	}))
	defer site.Close()

	// A real Shadowsocks-2022 server — what install-server.sh sets up on a VPS.
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	psk := base64.StdEncoding.EncodeToString(key)
	ssPort := freePort()
	serverCfg := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{map[string]any{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": ssPort, "method": "2022-blake3-aes-128-gcm", "password": psk}},
		"outbounds": []any{map[string]any{"type": "direct"}},
	}
	b, _ := json.Marshal(serverCfg)
	serverPath := filepath.Join(dir, "server.json")
	_ = os.WriteFile(serverPath, b, 0o600)
	server := exec.Command(sb, "run", "-c", serverPath)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Process.Kill(); _, _ = server.Process.Wait() }()
	if err := waitListening([]int{ssPort}, 10*time.Second); err != nil {
		t.Fatal(err)
	}

	host := startHost(t, []string{"OPENROUTE_RUN_MAIN=1", "OPENROUTE_DATA_DIR=" + dir, "OPENROUTE_SINGBOX=" + sb, "OPENROUTE_DAEMON_IDLE=2m"})
	defer func() { host.in.Close(); _ = host.cmd.Wait() }()
	defer func() { _, _ = ipcCall(socketPath(dir), map[string]any{"cmd": "shutdown"}, 5*time.Second) }()

	pong := host.call(t, map[string]any{"cmd": "ping"})
	if pong["ok"] != true || pong["cmd"] != "pong" {
		t.Fatalf("ping: %v", pong)
	}
	if sbInfo, _ := pong["singbox"].(map[string]any); sbInfo["ok"] != true {
		t.Fatalf("daemon should report a usable sing-box: %v", pong)
	}

	// The SIP002 SS-2022 link format the old parser couldn't read.
	link := fmt.Sprintf("ss://2022-blake3-aes-128-gcm:%s@127.0.0.1:%d#test", url.PathEscape(psk), ssPort)
	res := host.call(t, map[string]any{"cmd": "connect", "id": "companion", "label": "Test VPS", "links": []any{link}})
	if res["ok"] != true {
		t.Fatalf("connect: %v", res)
	}
	poolPort := int(res["socksPort"].(float64))

	body, err := getThroughSocks(poolPort, site.URL)
	if err != nil || body != "hello from the far side" {
		t.Fatalf("through the tunnel: %q %v", body, err)
	}

	// Serverless DPI-bypass transports come up beside it.
	dpi := host.call(t, map[string]any{"cmd": "connectDpi"})
	if dpi["ok"] != true {
		t.Fatalf("connectDpi: %v", dpi)
	}
	for _, tr := range dpi["transports"].([]any) {
		p := int(tr.(map[string]any)["port"].(float64))
		if body, err := getThroughSocks(p, site.URL); err != nil || body != "hello from the far side" {
			t.Errorf("dpi transport %v: %q %v", tr.(map[string]any)["id"], body, err)
		}
	}
	trs := host.call(t, map[string]any{"cmd": "transports"})
	if n := len(trs["transports"].([]any)); n != 3 {
		t.Errorf("expected pool + 2 DPI transports, got %d: %v", n, trs)
	}

	// Negative control: with the server gone, the tunnel must fail (proving
	// the request really went through it).
	_ = server.Process.Kill()
	_, _ = server.Process.Wait()
	if _, err := getThroughSocks(poolPort, site.URL); err == nil {
		t.Error("request succeeded with the server down — it wasn't tunnelled")
	}

	// A bad link is rejected with a reason and leaves the setup untouched.
	bad := host.call(t, map[string]any{"cmd": "connect", "links": []any{"vless://x@h:443?type=xhttp"}})
	if bad["ok"] != false || !strings.Contains(fmt.Sprint(bad["error"]), "XHTTP") {
		t.Errorf("bad link: %v", bad)
	}

	if r := host.call(t, map[string]any{"cmd": "disconnect"}); r["ok"] != true {
		t.Errorf("disconnect: %v", r)
	}
	st := host.call(t, map[string]any{"cmd": "status"})
	if st["running"] != false {
		t.Errorf("sing-box should be stopped after disconnect: %v", st["singbox"])
	}
}
