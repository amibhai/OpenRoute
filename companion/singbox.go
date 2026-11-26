package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sing-box orchestration (minimum 1.12; the config uses the 1.12+ schema:
// rule actions, typed DNS servers, default_domain_resolver — verified with
// `sing-box check` on 1.12.x and 1.14.x in the test suite).
//
// One sing-box process serves up to three local inbounds:
//   pool-in      → a server or an auto-rotating pool (urltest) from share links
//   dpi-record   → direct, TLS ClientHello split across TLS records
//   dpi-segment  → direct, TLS ClientHello split across TCP segments
// The two DPI-bypass inbounds need no server at all; they defeat simple
// SNI filters (sing-box's own docs: not a cure for sophisticated DPI). They
// are separate transports so the extension's ladder can try one, then the
// other, then a real tunnel.

const minSingBox = "1.12.0"

type SingBox struct {
	dir     string
	bin     string
	version string
	cfgPath string
	logPath string
	child   *Child
	mu      sync.Mutex
	lastErr string
}

func newSingBox(dir string, reg *ChildRegistry) *SingBox {
	s := &SingBox{
		dir:     dir,
		cfgPath: filepath.Join(dir, "singbox.json"),
		logPath: filepath.Join(dir, "singbox.log"),
	}
	s.child = &Child{Name: "sing-box", Dir: dir, Log: filepath.Join(dir, "singbox.out.log"), reg: reg}
	s.detect()
	return s
}

func (s *SingBox) detect() {
	s.bin = findBinary(s.dir, "OPENROUTE_SINGBOX", []string{"sing-box"}, nil)
	s.version = ""
	if s.bin != "" {
		s.version, _ = singBoxVersion(s.bin)
	}
}

var reSBVersion = regexp.MustCompile(`sing-box version (\d+\.\d+\.\d+)`)

func singBoxVersion(bin string) (string, error) {
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		return "", err
	}
	m := reSBVersion.FindStringSubmatch(string(out))
	if m == nil {
		return "", errors.New("unrecognised `sing-box version` output")
	}
	return m[1], nil
}

func versionAtLeast(v, min string) bool {
	a, b := strings.Split(v, "."), strings.Split(min, ".")
	for i := 0; i < 3; i++ {
		x, _ := strconv.Atoi(at(a, i))
		y, _ := strconv.Atoi(at(b, i))
		if x != y {
			return x > y
		}
	}
	return true
}

func at(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "0"
}

func (s *SingBox) Info() map[string]any {
	return map[string]any{"path": s.bin, "version": s.version, "ok": s.bin != "" && versionAtLeast(s.version, minSingBox)}
}

// buildSingBoxConfig assembles the config for the desired state. doh is the
// IP of a reachable DoH resolver ("" → the system resolver).
func buildSingBoxConfig(st *State, pool []Parsed, doh string, logPath string) map[string]any {
	inbounds := []any{}
	outbounds := []any{}
	endpoints := []any{}
	rules := []any{
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	}
	if len(pool) > 0 {
		inbounds = append(inbounds, map[string]any{"type": "mixed", "tag": "pool-in", "listen": "127.0.0.1", "listen_port": st.Ports.Pool})
		var tags []string
		for i, p := range pool {
			obj := cloneMap(p.Object)
			tag := fmt.Sprintf("up-%d", i)
			obj["tag"] = tag
			if p.Endpoint {
				endpoints = append(endpoints, obj)
			} else {
				outbounds = append(outbounds, obj)
			}
			tags = append(tags, tag)
		}
		// urltest: picks the lowest-latency working member and re-tests, so a
		// pool self-heals; the same machinery serves a single server.
		outbounds = append(outbounds, map[string]any{
			"type": "urltest", "tag": "pool", "outbounds": tags,
			"url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50,
		})
		rules = append(rules, map[string]any{"inbound": []string{"pool-in"}, "action": "route", "outbound": "pool"})
	}
	if st.DPI {
		inbounds = append(inbounds,
			map[string]any{"type": "mixed", "tag": "dpi-record", "listen": "127.0.0.1", "listen_port": st.Ports.DPIRecord},
			map[string]any{"type": "mixed", "tag": "dpi-segment", "listen": "127.0.0.1", "listen_port": st.Ports.DPISegment})
		rules = append(rules,
			map[string]any{"inbound": []string{"dpi-record"}, "protocol": "tls", "action": "route-options", "tls_record_fragment": true},
			map[string]any{"inbound": []string{"dpi-segment"}, "protocol": "tls", "action": "route-options", "tls_fragment": true},
			map[string]any{"inbound": []string{"dpi-record", "dpi-segment"}, "action": "route", "outbound": "direct"})
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	// Domain names reaching sing-box (the browser sends hostnames over
	// SOCKS5) are resolved over DoH, never the possibly-tampered system
	// resolver — unless no DoH resolver is reachable at all.
	resolver := map[string]any{"type": "local", "tag": "resolver"}
	if doh != "" {
		resolver = map[string]any{"type": "https", "tag": "resolver", "server": doh}
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn", "output": logPath, "timestamp": true},
		"dns":       map[string]any{"servers": []any{resolver}, "final": "resolver"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"rules": rules, "final": "direct", "auto_detect_interface": true,
			"default_domain_resolver": "resolver",
		},
		"experimental": map[string]any{"clash_api": map[string]any{
			"external_controller": fmt.Sprintf("127.0.0.1:%d", st.Ports.Clash), "secret": st.Secret,
		}},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	return cfg
}

func cloneMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// Apply makes the running sing-box match st. Errors carry the reason
// (`sing-box check` output or the log tail), never secrets.
func (s *SingBox) Apply(st *State, doh string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.Profile == nil && !st.DPI {
		s.child.Stop()
		s.lastErr = ""
		return nil
	}
	if s.bin == "" {
		s.detect()
	}
	if s.bin == "" {
		return s.fail(fmt.Errorf("sing-box not found — install it (1.12+) or put it in %s", s.dir))
	}
	if !versionAtLeast(s.version, minSingBox) {
		return s.fail(fmt.Errorf("sing-box %s is too old (need %s+)", s.version, minSingBox))
	}
	var pool []Parsed
	if st.Profile != nil {
		for _, l := range st.Profile.Links {
			p, err := parseLink(l)
			if err != nil {
				return s.fail(fmt.Errorf("%s: %w", redactLink(l), err))
			}
			pool = append(pool, p)
		}
	}
	ports := []*int{&st.Ports.Clash}
	if len(pool) > 0 {
		ports = append(ports, &st.Ports.Pool)
	}
	if st.DPI {
		ports = append(ports, &st.Ports.DPIRecord, &st.Ports.DPISegment)
	}
	s.child.Stop() // free our own ports before checking them
	st.ensurePorts(ports...)

	b, _ := json.MarshalIndent(buildSingBoxConfig(st, pool, doh, s.logPath), "", "  ")
	if err := os.WriteFile(s.cfgPath, b, 0o600); err != nil {
		return s.fail(err)
	}
	if out, err := exec.Command(s.bin, "check", "-c", s.cfgPath).CombinedOutput(); err != nil {
		return s.fail(fmt.Errorf("sing-box rejected the config: %s", redact(strings.TrimSpace(stripANSI(string(out))))))
	}
	s.child.Bin = s.bin
	s.child.Args = []string{"run", "-c", s.cfgPath}
	if err := s.child.Start(); err != nil {
		return s.fail(err)
	}
	var listen []int
	for _, p := range ports {
		listen = append(listen, *p)
	}
	if err := waitListening(listen, 8*time.Second); err != nil {
		s.child.Stop()
		return s.fail(fmt.Errorf("sing-box didn't come up: %v; %s", err, tailFile(s.logPath, 3)))
	}
	s.lastErr = ""
	return nil
}

func (s *SingBox) fail(err error) error {
	s.lastErr = redact(err.Error())
	return errors.New(s.lastErr)
}

func (s *SingBox) Status() map[string]any {
	st := s.child.Status()
	st["binary"] = s.Info()
	if s.lastErr != "" {
		st["error"] = s.lastErr
	}
	return st
}

// PoolHealth asks sing-box (Clash API, secret-protected) to measure the pool.
func (s *SingBox) PoolHealth(st *State) (string, int) {
	if !s.child.Running() || st.Profile == nil {
		return "down", 0
	}
	target := url.QueryEscape("https://www.gstatic.com/generate_204")
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/proxies/pool/delay?timeout=5000&url=%s", st.Ports.Clash, target), nil)
	req.Header.Set("Authorization", "Bearer "+st.Secret)
	resp, err := (&http.Client{Timeout: 7 * time.Second}).Do(req)
	if err != nil {
		return "down", 0
	}
	defer resp.Body.Close()
	var r struct {
		Delay int `json:"delay"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&r) != nil || r.Delay <= 0 {
		return "down", 0
	}
	if r.Delay > 1500 {
		return "degraded", r.Delay
	}
	return "up", r.Delay
}

// ---- DoH reachability for sing-box's own resolver ----------------------------

// RFC 8484 §4.1 query for example.com A, as raw bytes.
var probeQuery = []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}

var dohCache struct {
	sync.Mutex
	ip string
	at time.Time
}

// pickDoH returns the first DoH resolver (by IP literal) that answers right
// now, or "" when none does (then sing-box falls back to the system resolver).
func pickDoH() string {
	dohCache.Lock()
	defer dohCache.Unlock()
	if time.Since(dohCache.at) < 10*time.Minute && !dohCache.at.IsZero() {
		return dohCache.ip
	}
	client := &http.Client{Timeout: 3 * time.Second}
	dohCache.ip = ""
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"} {
		req, _ := http.NewRequest("POST", "https://"+ip+"/dns-query", strings.NewReader(string(probeQuery)))
		req.Header.Set("content-type", "application/dns-message")
		req.Header.Set("accept", "application/dns-message")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == 200 && len(body) > 12 && body[3]&0x0f == 0 && (int(body[6])<<8|int(body[7])) > 0 {
			dohCache.ip = ip
			break
		}
	}
	dohCache.at = time.Now()
	return dohCache.ip
}
