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
		return m.Status()
	case "transports":
		return map[string]any{"ok": true, "transports": m.Transports()}
	case "health":
		return map[string]any{"ok": true, "transports": m.Health()}
	case "connect":
		link, _ := msg["link"].(string)
		id, _ := msg["id"].(string)
		label, _ := msg["label"].(string)
		return m.Connect(id, label, link)
	case "disconnect":
		return m.Disconnect()
	default:
		return map[string]any{"ok": false, "error": "unknown cmd: " + cmd}
	}
}

func errResp(msg string) map[string]any { return map[string]any{"ok": false, "error": msg} }
