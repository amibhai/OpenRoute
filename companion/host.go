package main

import (
	"bufio"
	"errors"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The native-messaging host: what the browser launches. It speaks the NM
// protocol on stdin/stdout and forwards every request to the daemon,
// starting the daemon first if it isn't running. It holds no state itself,
// so the browser can start and stop it as often as it likes.

// Extension IDs the companion serves out of the box: the stable unpacked
// Chromium ID (pinned by the public key in manifest.json) and the Firefox
// add-on ID. Store IDs are added by `install --extension-id`.
var builtinAllowedIDs = []string{"dbheknchchihhpnmfmjfhcoeconfokof", "openroute@openroute.app"}

func allowedIDs(dir string) map[string]bool {
	m := map[string]bool{}
	for _, id := range builtinAllowedIDs {
		m[id] = true
	}
	if f, err := os.Open(filepath.Join(dir, "allowed-ids.txt")); err == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			if id := strings.TrimSpace(s.Text()); id != "" && !strings.HasPrefix(id, "#") {
				m[id] = true
			}
		}
	}
	return m
}

// callerID extracts who launched us. Chromium passes the caller's origin
// ("chrome-extension://<id>/"); Firefox passes the app-manifest path and the
// add-on ID. No arguments = run by hand (testing).
func callerID(args []string) (string, bool) {
	for _, a := range args {
		if strings.HasPrefix(a, "chrome-extension://") {
			return strings.Trim(strings.TrimPrefix(a, "chrome-extension://"), "/"), true
		}
	}
	if len(args) >= 2 && strings.HasSuffix(strings.ToLower(args[0]), ".json") {
		return args[1], true
	}
	return "", false
}

func runHost(args []string) int {
	dir := dataDir()
	_ = os.MkdirAll(dir, 0o700)
	closeLog := openLog(filepath.Join(dir, "host.log"))
	defer closeLog()

	id, fromBrowser := callerID(args)
	allowed := !fromBrowser || allowedIDs(dir)[id]
	if !allowed {
		log.Printf("host: refusing caller %q", id)
	}
	for {
		msg, err := readMessage(os.Stdin)
		if err != nil {
			return 0 // the browser closed the port
		}
		var resp map[string]any
		if !allowed {
			resp = errResp("this companion isn't set up for extension " + id + " (run: openroute-companion install --extension-id " + id + ")")
		} else {
			resp = forward(dir, msg)
		}
		if err := writeMessage(os.Stdout, resp); err != nil {
			return 1
		}
	}
}

func timeoutFor(cmd string) time.Duration {
	switch cmd {
	case "connect", "connectTor", "connectDpi", "refreshBridges":
		return 90 * time.Second
	}
	return 20 * time.Second
}

func forward(dir string, msg map[string]any) map[string]any {
	cmd, _ := msg["cmd"].(string)
	sock := socketPath(dir)
	resp, err := ipcCall(sock, msg, timeoutFor(cmd))
	if err != nil && isDialError(err) {
		if serr := spawnDaemon(); serr != nil {
			return errResp("couldn't start the companion daemon: " + serr.Error())
		}
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if resp, err = ipcCall(sock, msg, timeoutFor(cmd)); err == nil || !isDialError(err) {
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
	}
	if err != nil {
		return errResp("companion daemon unavailable: " + err.Error())
	}
	return resp
}

func isDialError(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// spawnDaemon starts `<self> daemon` detached. On Windows it first tries to
// break away from the browser's job object, so the daemon (and its tunnels)
// isn't killed with the host; if the job forbids that, it starts inside it.
func spawnDaemon() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	var lastErr error
	for _, breakaway := range []bool{true, false} {
		cmd := exec.Command(self, "daemon")
		cmd.SysProcAttr = daemonAttr(breakaway)
		if lastErr = cmd.Start(); lastErr == nil {
			_ = cmd.Process.Release()
			return nil
		}
	}
	return lastErr
}

// openLog sends the standard logger to a size-capped file. stdout is the
// native-messaging channel, so nothing may ever be printed there.
func openLog(path string) func() {
	if st, err := os.Stat(path); err == nil && st.Size() > 2<<20 {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.SetOutput(discard{})
		return func() {}
	}
	log.SetOutput(redactingWriter{f})
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	return func() { f.Close() }
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

type redactingWriter struct{ f *os.File }

func (w redactingWriter) Write(p []byte) (int, error) {
	_, err := w.f.WriteString(redact(string(p)))
	return len(p), err
}
