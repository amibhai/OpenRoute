package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// State is what SHOULD be running, persisted so a daemon restart (or a
// reboot, or the browser starting again) brings the same tunnels back.
type State struct {
	Profile *Profile `json:"profile,omitempty"` // a server / pool from share links
	DPI     bool     `json:"dpi,omitempty"`     // the serverless DPI-bypass transports
	Tor     *TorWant `json:"tor,omitempty"`
	Ports   Ports    `json:"ports"`
	Secret  string   `json:"secret"` // Clash API secret (random, never leaves this machine)
}

type Profile struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Links []string `json:"links"`
}

type TorWant struct {
	Mode    string   `json:"mode"`
	Bridges []string `json:"bridges,omitempty"`
}

// Ports are picked free once and then kept, so the transports the extension
// registered stay valid across restarts.
type Ports struct {
	Pool       int `json:"pool"`
	DPIRecord  int `json:"dpiRecord"`
	DPISegment int `json:"dpiSegment"`
	Clash      int `json:"clash"`
	TorSocks   int `json:"torSocks"`
}

func loadState(path string) *State {
	st := &State{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, st)
	}
	if st.Secret == "" {
		st.Secret = randomHex(16)
	}
	return st
}

func (s *State) save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ensurePorts assigns any missing port, and re-assigns one that something
// else has taken in the meantime.
// ensurePorts gives every port in need a usable value. It keeps a port that
// is still free, and never hands out one that another of this state's
// listeners holds or that two inbounds would share: either would stop
// sing-box from starting. (A fresh pick from the OS can be a port this state
// already uses, because Apply stops sing-box first and frees them all.)
func (s *State) ensurePorts(need ...*int) {
	isNeeded := func(p *int) bool {
		for _, n := range need {
			if n == p {
				return true
			}
		}
		return false
	}
	taken := map[int]bool{}
	for _, p := range []*int{&s.Ports.Pool, &s.Ports.DPIRecord, &s.Ports.DPISegment, &s.Ports.Clash, &s.Ports.TorSocks} {
		if *p != 0 && !isNeeded(p) {
			taken[*p] = true
		}
	}
	for _, p := range need {
		if *p == 0 || taken[*p] || !portFree(*p) {
			*p = freePortExcept(taken)
		}
		taken[*p] = true
	}
}

func freePortExcept(taken map[int]bool) int {
	for i := 0; i < 50; i++ {
		if p := freePort(); p != 0 && !taken[p] {
			return p
		}
	}
	return 0
}

func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func portFree(p int) bool {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// waitListening returns once every port accepts TCP connections.
func waitListening(ports []int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for _, p := range ports {
		for {
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p), 300*time.Millisecond)
			if err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("nothing is listening on 127.0.0.1:%d", p)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
