package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const hostName = "com.openroute.host"

// dataDir holds the companion's state, configs, logs, the IPC socket and
// (optionally) bundled sing-box/tor binaries. User-private by location
// (%APPDATA% on Windows, the home directory elsewhere) and by mode (0700).
func dataDir() string {
	if d := os.Getenv("OPENROUTE_DATA_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if a := os.Getenv("APPDATA"); a != "" {
			return filepath.Join(a, "OpenRoute")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".openroute")
}

func socketPath(dir string) string { return filepath.Join(dir, "companion.sock") }

func exeName(n string) string {
	if runtime.GOOS == "windows" {
		return n + ".exe"
	}
	return n
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// findBinary looks for a helper (sing-box, tor) in this order: an explicit
// environment override, the data dir, next to this executable, the PATH,
// then any extra well-known locations.
func findBinary(dir, envVar string, names []string, extra []string) string {
	if p := os.Getenv(envVar); p != "" && fileExists(p) {
		return p
	}
	self, _ := os.Executable()
	for _, n := range names {
		nn := exeName(n)
		for _, p := range []string{filepath.Join(dir, nn), filepath.Join(dir, "bin", nn), filepath.Join(filepath.Dir(self), nn)} {
			if fileExists(p) {
				return p
			}
		}
		if p, err := exec.LookPath(nn); err == nil {
			return p
		}
	}
	for _, p := range extra {
		if fileExists(p) {
			return p
		}
	}
	return ""
}
