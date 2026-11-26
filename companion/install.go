package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// `openroute-companion install` registers the native-messaging host with
// every Chromium- and Firefox-family browser on this machine — no admin
// rights, no IDs to copy: the unpacked extension's ID is pinned by its
// manifest key and allowed out of the box.

type browserTarget struct {
	Name    string
	Family  string // "chromium" | "firefox"
	Dir     string // macOS/Linux: the NativeMessagingHosts directory
	RegKey  string // Windows: HKCU key (without the host name)
	Present bool
}

func browserTargets() []browserTarget {
	home, _ := os.UserHomeDir()
	var out []browserTarget
	add := func(name, family, base, sub string) {
		_, err := os.Stat(base)
		out = append(out, browserTarget{Name: name, Family: family, Dir: filepath.Join(base, sub), Present: err == nil})
	}
	switch runtime.GOOS {
	case "windows":
		reg := func(name, family, key string) {
			out = append(out, browserTarget{Name: name, Family: family, RegKey: `HKCU\Software\` + key + `\NativeMessagingHosts`, Present: true})
		}
		reg("Google Chrome (and forks that read its key: Opera, Thorium…)", "chromium", `Google\Chrome`)
		reg("Chromium", "chromium", `Chromium`)
		reg("Microsoft Edge", "chromium", `Microsoft\Edge`)
		reg("Brave", "chromium", `BraveSoftware\Brave-Browser`)
		reg("Vivaldi", "chromium", `Vivaldi`)
		reg("Yandex Browser", "chromium", `Yandex\YandexBrowser`)
		reg("Firefox (and forks)", "firefox", `Mozilla`)
		reg("LibreWolf", "firefox", `LibreWolf`)
		reg("Waterfox", "firefox", `Waterfox`)
	case "darwin":
		as := filepath.Join(home, "Library", "Application Support")
		for _, c := range [][2]string{
			{"Google Chrome", "Google/Chrome"}, {"Chrome Beta", "Google/Chrome Beta"}, {"Chrome Dev", "Google/Chrome Dev"},
			{"Chrome Canary", "Google/Chrome Canary"}, {"Chromium", "Chromium"}, {"Microsoft Edge", "Microsoft Edge"},
			{"Microsoft Edge Beta", "Microsoft Edge Beta"}, {"Brave", "BraveSoftware/Brave-Browser"}, {"Vivaldi", "Vivaldi"},
			{"Arc", "Arc/User Data"}, {"Yandex Browser", "Yandex/YandexBrowser"}, {"Thorium", "Thorium"},
		} {
			add(c[0], "chromium", filepath.Join(as, filepath.FromSlash(c[1])), "NativeMessagingHosts")
		}
		for _, c := range [][2]string{{"Firefox", "Mozilla"}, {"LibreWolf", "LibreWolf"}, {"Waterfox", "Waterfox"}, {"Zen", "zen"}} {
			add(c[0], "firefox", filepath.Join(as, c[1]), "NativeMessagingHosts")
		}
	default:
		cfg := filepath.Join(home, ".config")
		for _, c := range [][2]string{
			{"Google Chrome", "google-chrome"}, {"Chrome Beta", "google-chrome-beta"}, {"Chrome Dev", "google-chrome-unstable"},
			{"Chromium", "chromium"}, {"Microsoft Edge", "microsoft-edge"}, {"Microsoft Edge Beta", "microsoft-edge-beta"},
			{"Brave", "BraveSoftware/Brave-Browser"}, {"Vivaldi", "vivaldi"}, {"Yandex Browser", "yandex-browser"},
			{"Opera", "opera"}, {"Thorium", "thorium"},
		} {
			add(c[0], "chromium", filepath.Join(cfg, filepath.FromSlash(c[1])), "NativeMessagingHosts")
		}
		for _, c := range [][2]string{{"Firefox", ".mozilla"}, {"LibreWolf", ".librewolf"}, {"Waterfox", ".waterfox"}, {"Floorp", ".floorp"}, {"Zen", ".zen"}} {
			add(c[0], "firefox", filepath.Join(home, c[1]), "native-messaging-hosts")
		}
	}
	return out
}

func hostManifest(family, binPath string, ids []string) map[string]any {
	m := map[string]any{"name": hostName, "description": "OpenRoute native companion", "path": binPath, "type": "stdio"}
	var list []string
	for _, id := range ids {
		isFirefox := strings.Contains(id, "@") || strings.HasPrefix(id, "{")
		if family == "firefox" && isFirefox {
			list = append(list, id)
		} else if family == "chromium" && !isFirefox {
			list = append(list, "chrome-extension://"+id+"/")
		}
	}
	sort.Strings(list)
	if family == "firefox" {
		m["allowed_extensions"] = list
	} else {
		m["allowed_origins"] = list
	}
	return m
}

func runInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	extra := fs.String("extension-id", "", "additional extension IDs to allow (comma-separated), e.g. a store build's ID")
	dry := fs.Bool("dry-run", false, "show what would be done")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir := dataDir()
	if err := os.MkdirAll(filepath.Join(dir, "hosts"), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "install:", err)
		return 1
	}
	bin := filepath.Join(dir, "bin", exeName("openroute-companion"))
	if !*dry {
		if err := copySelf(bin); err != nil {
			fmt.Fprintln(os.Stderr, "install: copying the companion:", err)
			return 1
		}
	}
	ids := append([]string{}, builtinAllowedIDs...)
	for _, id := range strings.Split(*extra, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	if !*dry {
		_ = os.WriteFile(filepath.Join(dir, "allowed-ids.txt"), []byte(strings.Join(ids, "\n")+"\n"), 0o600)
	}
	manifests := map[string]string{}
	for _, family := range []string{"chromium", "firefox"} {
		p := filepath.Join(dir, "hosts", fmt.Sprintf("%s.%s.json", hostName, family))
		b, _ := json.MarshalIndent(hostManifest(family, bin, ids), "", "  ")
		if !*dry {
			if err := os.WriteFile(p, b, 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "install:", err)
				return 1
			}
		}
		manifests[family] = p
	}
	fmt.Printf("OpenRoute companion %s\n  binary: %s\n", version, bin)
	registered := 0
	for _, t := range browserTargets() {
		if !t.Present {
			continue
		}
		var err error
		switch {
		case *dry:
		case t.RegKey != "":
			err = exec.Command("reg", "add", t.RegKey+`\`+hostName, "/ve", "/t", "REG_SZ", "/d", manifests[t.Family], "/f").Run()
		default:
			if err = os.MkdirAll(t.Dir, 0o755); err == nil {
				var b []byte
				if b, err = os.ReadFile(manifests[t.Family]); err == nil {
					err = os.WriteFile(filepath.Join(t.Dir, hostName+".json"), b, 0o644)
				}
			}
		}
		if err != nil {
			fmt.Printf("  ✗ %s: %v\n", t.Name, err)
			continue
		}
		registered++
		fmt.Printf("  ✓ %s\n", t.Name)
	}
	if registered == 0 {
		fmt.Println("  (no supported browser found — install one, then run this again)")
	}
	fmt.Println("Restart the browser (or reload the extension); the popup's companion pill should read \"connected\".")
	return 0
}

func runUninstall(_ []string) int {
	dir := dataDir()
	_, _ = ipcCall(socketPath(dir), map[string]any{"cmd": "shutdown"}, 3*time.Second)
	for _, t := range browserTargets() {
		if t.RegKey != "" {
			_ = exec.Command("reg", "delete", t.RegKey+`\`+hostName, "/f").Run()
		} else {
			_ = os.Remove(filepath.Join(t.Dir, hostName+".json"))
		}
	}
	_ = os.RemoveAll(filepath.Join(dir, "hosts"))
	_ = os.Remove(filepath.Join(dir, "allowed-ids.txt"))
	fmt.Println("Unregistered from all browsers. Your settings stay in", dir, "(delete that folder to remove everything).")
	return 0
}

func copySelf(dst string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if sameFile(self, dst) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(self)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// Stop a running daemon first, or Windows won't let us replace its binary.
	_, _ = ipcCall(socketPath(dataDir()), map[string]any{"cmd": "shutdown"}, 3*time.Second)
	time.Sleep(300 * time.Millisecond)
	return os.Rename(tmp, dst)
}

func runDoctor(_ []string) int {
	dir := dataDir()
	fmt.Printf("OpenRoute companion %s\n  data: %s\n", version, dir)
	if r, err := ipcCall(socketPath(dir), map[string]any{"cmd": "status"}, 5*time.Second); err == nil {
		b, _ := json.MarshalIndent(r, "  ", "  ")
		fmt.Printf("  daemon: running\n  %s\n", b)
	} else {
		fmt.Println("  daemon: not running (it starts when the browser asks for it)")
	}
	sb := newSingBox(dir, nil)
	if sb.bin == "" {
		fmt.Println("  sing-box: NOT FOUND — needed for servers and DPI bypass (https://github.com/SagerNet/sing-box/releases)")
	} else {
		state := "ok"
		if !versionAtLeast(sb.version, minSingBox) {
			state = "TOO OLD (need " + minSingBox + "+)"
		}
		fmt.Printf("  sing-box: %s (%s) %s\n", sb.bin, sb.version, state)
	}
	tor := newTor(dir, nil)
	if tor.bin == "" {
		fmt.Println("  tor: not found — optional (Tor Browser or the Tor Expert Bundle)")
	} else {
		fmt.Printf("  tor: %s · transports: %s · PT dir: %s\n", tor.bin, tor.ptSource, firstNonEmpty(tor.ptDir, "none"))
	}
	for _, t := range browserTargets() {
		switch {
		case t.RegKey != "":
			err := exec.Command("reg", "query", t.RegKey+`\`+hostName, "/ve").Run()
			fmt.Printf("  %-6s %s\n", mark(err == nil), t.Name)
		case t.Present:
			fmt.Printf("  %-6s %s\n", mark(fileExists(filepath.Join(t.Dir, hostName+".json"))), t.Name)
		}
	}
	return 0
}

func mark(ok bool) string {
	if ok {
		return "[ok]"
	}
	return "[--]"
}
