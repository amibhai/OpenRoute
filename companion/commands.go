package main

import "log"

// dispatch routes a decoded NM message to the manager and returns the response
// object that will be sent back to the extension.
func dispatch(m *Manager, msg map[string]any) map[string]any {
	cmd, _ := msg["cmd"].(string)
	log.Printf("cmd: %s", cmd)

	switch cmd {
	case "ping":
		return map[string]any{"ok": true, "cmd": "pong", "version": version}

	case "status":
		st := m.Status()
		st["tor"] = m.tor.Transports()
		return st

	case "transports":
		ts := m.Transports()
		ts = append(ts, m.tor.Transports()...)
		return map[string]any{"ok": true, "transports": ts}

	case "health":
		hs := m.Health()
		hs = append(hs, m.tor.Health()...)
		return map[string]any{"ok": true, "transports": hs}

	case "connect":
		links := toStringSlice(msg["links"])
		if len(links) == 0 {
			if l, _ := msg["link"].(string); l != "" {
				links = []string{l}
			}
		}
		id, _ := msg["id"].(string)
		label, _ := msg["label"].(string)
		return m.Connect(id, label, links)

	case "connectTor":
		mode, _ := msg["mode"].(string)
		label, _ := msg["label"].(string)
		return m.tor.Connect(mode, label, toStringSlice(msg["bridges"]))

	case "disconnect":
		kind, _ := msg["kind"].(string)
		return m.disconnect(kind)

	default:
		return map[string]any{"ok": false, "error": "unknown cmd: " + cmd}
	}
}

func errResp(msg string) map[string]any { return map[string]any{"ok": false, "error": msg} }

// toStringSlice pulls a []string out of a decoded JSON array of strings.
func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}
