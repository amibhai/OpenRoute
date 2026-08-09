// OpenRoute native companion.
//
// A Chrome Native Messaging host that gives the extension the transports a
// browser can't run on its own. It speaks the length-prefixed NM protocol on
// stdin/stdout and drives a local `sing-box` subprocess (Shadowsocks-2022,
// VLESS/Reality, …) exposing a SOCKS proxy on 127.0.0.1 that the extension's
// split-tunnel PAC routes blocked domains through.
//
// std-lib only, so `go build` works with no network/module fetch. The heavy
// transport crypto lives in sing-box (audited), which this process orchestrates
// rather than reimplements.
package main

import (
	"log"
	"os"
	"path/filepath"
)

const version = "0.1.0"

func main() {
	dir := dataDir()
	_ = os.MkdirAll(dir, 0o700)

	// stdout is the NM channel — logs MUST go elsewhere or they corrupt it.
	if lf, err := os.OpenFile(filepath.Join(dir, "companion.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		log.SetOutput(lf)
		defer lf.Close()
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("OpenRoute companion %s starting (data=%s)", version, dir)

	mgr := NewManager(dir)
	// NOTE: we deliberately do NOT stop sing-box when this host exits — Chrome
	// tears the host down after each reply, and the tunnel must outlive it.

	for {
		msg, err := readMessage(os.Stdin)
		if err != nil {
			log.Printf("read loop end: %v", err)
			return // stdin closed → Chrome disconnected → exit
		}
		resp := dispatch(mgr, msg)
		if err := writeMessage(os.Stdout, resp); err != nil {
			log.Printf("write error: %v", err)
			return
		}
	}
}
