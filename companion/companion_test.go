package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Helper binaries from the project-local toolchain (.tools/, see
// scripts/setup-tools.mjs). Tests needing them skip when absent.

func toolPath(t *testing.T, glob string) string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join("..", ".tools", filepath.FromSlash(glob)))
	if len(matches) == 0 {
		return ""
	}
	abs, _ := filepath.Abs(matches[len(matches)-1])
	return abs
}

func singBoxBins(t *testing.T) map[string]string {
	bins := map[string]string{}
	for _, v := range []string{"1.12", "1.14"} {
		if p := toolPath(t, "sing-box-"+v+".*/*/"+exeName("sing-box")); p != "" {
			bins[v] = p
		}
	}
	if p := os.Getenv("OPENROUTE_SINGBOX"); p != "" {
		bins["env"] = p
	}
	return bins
}

func TestNMFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	msg := map[string]any{"cmd": "ping", "nested": map[string]any{"x": 1.0}}
	if err := writeMessage(&buf, msg); err != nil {
		t.Fatal(err)
	}
	got, err := readMessage(&buf)
	if err != nil || got["cmd"] != "ping" {
		t.Fatalf("round trip: %v %v", got, err)
	}
	for _, bad := range [][]byte{{0, 0, 0, 0}, {0xff, 0xff, 0xff, 0x7f}, {5, 0, 0, 0, '{'}} {
		if _, err := readMessage(bytes.NewReader(bad)); err == nil {
			t.Errorf("expected an error for %v", bad)
		}
	}
}

// Every config shape the companion generates must pass the REAL `sing-box
// check` on the oldest supported and the latest release.
func TestGeneratedConfigsPassSingBoxCheck(t *testing.T) {
	bins := singBoxBins(t)
	if len(bins) == 0 {
		t.Skip("no sing-box in .tools (run: node scripts/setup-tools.mjs sing-box)")
	}
	links := []string{
		"ss://2022-blake3-aes-128-gcm:YctPZ6U7xPPcU%2Bgp3u%2BH5w%3D%3D@203.0.113.5:8388",
		"vless://4d3c2b1a-0000-4000-8000-000000000001@vps.example.net:443?security=reality&sni=www.microsoft.com&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=0123456789abcdef&flow=xtls-rprx-vision",
		"trojan://pw@t.example.net:443?type=ws&path=%2Ft",
		"hysteria2://pw@h.example.net:443/?obfs=salamander&obfs-password=ob&mport=20000-30000",
		"tuic://4d3c2b1a-0000-4000-8000-000000000003:pw@u.example.net:443?congestion_control=bbr",
		"socks5://u:p@s.example.net:1080",
		"https://u:p@p.example.net:443",
		"wireguard://yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=@wg.example.net:51820?publickey=xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg%3D&address=10.7.0.2",
	}
	var pool []Parsed
	for _, l := range links {
		pool = append(pool, mustParse(t, l))
	}
	ports := Ports{Pool: 21080, DPIRecord: 21081, DPISegment: 21082, Clash: 29090}
	shapes := map[string]struct {
		st   *State
		pool []Parsed
		doh  string
	}{
		"pool+dpi":    {&State{Profile: &Profile{ID: "p"}, DPI: true, Ports: ports, Secret: "s"}, pool, "1.1.1.1"},
		"dpi-only":    {&State{DPI: true, Ports: ports, Secret: "s"}, nil, "8.8.8.8"},
		"single":      {&State{Profile: &Profile{ID: "p"}, Ports: ports, Secret: "s"}, pool[:1], ""},
		"wireguard":   {&State{Profile: &Profile{ID: "p"}, Ports: ports, Secret: "s"}, pool[len(pool)-1:], "1.1.1.1"},
	}
	dir := t.TempDir()
	for name, sh := range shapes {
		cfg := buildSingBoxConfig(sh.st, sh.pool, sh.doh, filepath.Join(dir, "x.log"))
		b, _ := json.MarshalIndent(cfg, "", "  ")
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		for v, bin := range bins {
			if out, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
				t.Errorf("%s rejected by sing-box %s: %s", name, v, stripANSI(string(out)))
			}
		}
	}
}

func TestSingBoxVersionDetection(t *testing.T) {
	for v, bin := range singBoxBins(t) {
		got, err := singBoxVersion(bin)
		if err != nil || !versionAtLeast(got, minSingBox) {
			t.Errorf("%s: version %q %v", v, got, err)
		}
	}
	if versionAtLeast("1.11.9", "1.12.0") || !versionAtLeast("1.12.0", "1.12.0") || !versionAtLeast("2.0.0", "1.12.0") {
		t.Error("versionAtLeast")
	}
}

func TestTorrcFromRealExpertBundle(t *testing.T) {
	torBin := toolPath(t, "tor/tor/"+exeName("tor"))
	if torBin == "" {
		t.Skip("no Tor Expert Bundle in .tools (run: node scripts/setup-tools.mjs tor)")
	}
	t.Setenv("OPENROUTE_TOR", torBin)
	tor := newTor(t.TempDir(), nil)
	if tor.ptSource != "installed pt_config.json" {
		t.Fatalf("should read the bundle's pt_config.json, got %q", tor.ptSource)
	}
	for _, mode := range []string{"direct", "obfs4", "snowflake", "meek"} {
		if err := tor.writeTorrc(mode, 29150, nil); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		b, _ := os.ReadFile(tor.torrc)
		torrc := string(b)
		for _, must := range []string{"SocksPort 127.0.0.1:29150", "CookieAuthentication 1", "ControlPortWriteToFile"} {
			if !strings.Contains(torrc, must) {
				t.Errorf("%s: torrc lacks %q", mode, must)
			}
		}
		if strings.Contains(torrc, "CookieAuthentication 0") {
			t.Errorf("%s: control port must never be unauthenticated", mode)
		}
		if mode == "snowflake" && !strings.Contains(torrc, "ClientTransportPlugin snowflake exec pluggable_transports") {
			t.Errorf("snowflake must run via the bundle's PT (lyrebird today), relative path:\n%s", torrc)
		}
		if mode != "direct" && !strings.Contains(torrc, "Bridge "+mode) && !(mode == "meek" && strings.Contains(torrc, "Bridge meek_lite")) {
			t.Errorf("%s: no built-in bridges in torrc", mode)
		}
		// tor itself must accept the file.
		if out, err := exec.Command(torBin, "--verify-config", "-f", tor.torrc, "--defaults-torrc", os.DevNull).CombinedOutput(); err != nil {
			t.Errorf("%s: tor --verify-config: %s", mode, out)
		}
	}
	if err := tor.writeTorrc("webtunnel", 29150, nil); err == nil {
		t.Error("webtunnel without bridges must explain where to get them")
	}
	if err := tor.writeTorrc("webtunnel", 29150, []string{"Bridge webtunnel 192.0.2.1:443 AAAA url=https://example.org/x"}); err != nil {
		t.Errorf("webtunnel with user bridges: %v", err)
	}
}

func TestBuiltinBridgeSnapshot(t *testing.T) {
	c := loadCachedOrBuiltinPT(t.TempDir())
	for _, k := range []string{"obfs4", "snowflake", "meek"} {
		if len(c.Bridges[k]) == 0 {
			t.Errorf("snapshot has no %s bridges", k)
		}
	}
	if !strings.Contains(c.PluggableTransports["snowflake"], "lyrebird") || strings.Contains(c.PluggableTransports["lyrebird"], ".exe") {
		t.Errorf("snapshot plugin lines must be platform-neutral: %v", c.PluggableTransports)
	}
}

// The supervisor restarts a child that dies, then gives up on a crash loop
// and says why.
func TestSupervisorRestartsThenGivesUp(t *testing.T) {
	if runtime.GOOS == "windows" && os.Getenv("CI") == "" {
		t.Log("spawning short-lived cmd.exe children")
	}
	dir := t.TempDir()
	bin, args := crashingCommand()
	c := &Child{Name: "crasher", Bin: bin, Args: args, Dir: dir, Log: filepath.Join(dir, "c.log"), reg: &ChildRegistry{path: filepath.Join(dir, "children.json")}}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) && !c.Status()["failed"].(bool) {
		time.Sleep(200 * time.Millisecond)
	}
	st := c.Status()
	if !st["failed"].(bool) || st["restarts"].(int) < maxRestarts {
		t.Fatalf("expected a give-up after %d restarts, got %v", maxRestarts, st)
	}
	if !strings.Contains(st["lastError"].(string), "boom") {
		t.Errorf("the reason (log tail) should be reported: %v", st["lastError"])
	}
}

func crashingCommand() (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd.exe", []string{"/c", "echo boom&& exit 3"}
	}
	return "/bin/sh", []string{"-c", "echo boom; exit 3"}
}

// Orphan cleanup never kills a process whose PID was reused by something else.
func TestOrphanCleanupVerifiesExecutable(t *testing.T) {
	dir := t.TempDir()
	reg := &ChildRegistry{path: filepath.Join(dir, "children.json")}
	self, _ := os.Executable()
	reg.Record("sing-box", os.Getpid(), filepath.Join(dir, "not-really-sing-box.exe")) // our PID, other exe
	if killed := reg.CleanupOrphans(); len(killed) != 0 {
		t.Fatalf("killed an unrelated process: %v", killed)
	}
	_ = self
}
