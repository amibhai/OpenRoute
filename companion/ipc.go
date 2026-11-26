package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// IPC between the short-lived native-messaging host and the long-lived
// daemon: one newline-delimited JSON request and one response per
// connection, over a Unix-domain socket in the user-private data dir (Go
// supports AF_UNIX on Windows 10 1803+). Nothing listens on a TCP port.

const maxIPCMessage = 4 << 20

var errAlreadyRunning = errors.New("another companion daemon is already running")

func ipcCall(sock string, req map[string]any, timeout time.Duration) (map[string]any, error) {
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(conn, 64<<10)
	line, err := readLine(r)
	if err != nil {
		return nil, fmt.Errorf("daemon reply: %w", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("daemon reply: %w", err)
	}
	return resp, nil
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > maxIPCMessage {
			return nil, errors.New("message too large")
		}
		if !isPrefix {
			return out, nil
		}
	}
}

// ipcListen binds the socket. A leftover socket file from a crashed daemon is
// replaced; a socket somebody answers on means a daemon is already running.
func ipcListen(sock string) (net.Listener, error) {
	ln, err := net.Listen("unix", sock)
	if err == nil {
		_ = os.Chmod(sock, 0o600)
		return ln, nil
	}
	if c, dialErr := net.DialTimeout("unix", sock, time.Second); dialErr == nil {
		c.Close()
		return nil, errAlreadyRunning
	}
	_ = os.Remove(sock)
	ln, err = net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(sock, 0o600)
	return ln, nil
}

func ipcServe(ln net.Listener, handle func(map[string]any) map[string]any) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
			line, err := readLine(bufio.NewReaderSize(c, 64<<10))
			if err != nil {
				return
			}
			var req map[string]any
			resp := map[string]any{"ok": false, "error": "malformed request"}
			if json.Unmarshal(line, &req) == nil {
				resp = handle(req)
			}
			b, _ := json.Marshal(resp)
			_, _ = c.Write(append(b, '\n'))
		}(conn)
	}
}
