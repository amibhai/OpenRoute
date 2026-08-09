package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// dataDir is where the companion keeps its generated sing-box config, profiles,
// logs, and (optionally) a bundled sing-box binary.
func dataDir() string {
	if runtime.GOOS == "windows" {
		if a := os.Getenv("APPDATA"); a != "" {
			return filepath.Join(a, "OpenRoute")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".openroute")
}

// Profile is a saved upstream transport (a share link the user pasted).
type Profile struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Link  string `json:"link"`
}

func loadProfiles(path string) []Profile {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var ps []Profile
	if err := json.Unmarshal(b, &ps); err != nil {
		return nil
	}
	return ps
}

func saveProfiles(path string, ps []Profile) error {
	b, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
