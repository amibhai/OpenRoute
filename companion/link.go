package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// linkToOutbound converts a share link (or raw sing-box outbound JSON) into a
// sing-box outbound object, without the "tag" (Connect sets that).
//
// Supported: ss:// (Shadowsocks / Shadowsocks-2022, SIP002), vless:// (incl.
// TLS + Reality), and a raw "{...}" escape hatch for anything else sing-box
// understands — so an unusual transport is never a hard wall.
func linkToOutbound(link string) (map[string]any, error) {
	link = strings.TrimSpace(link)
	switch {
	case strings.HasPrefix(link, "ss://"):
		return parseSS(link)
	case strings.HasPrefix(link, "vless://"):
		return parseVLESS(link)
	case strings.HasPrefix(link, "{"):
		var m map[string]any
		if err := json.Unmarshal([]byte(link), &m); err != nil {
			return nil, fmt.Errorf("raw outbound JSON: %w", err)
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unsupported link (expected ss://, vless://, or raw {...} JSON)")
	}
}

func parseSS(link string) (map[string]any, error) {
	raw := strings.TrimPrefix(link, "ss://")
	if i := strings.IndexByte(raw, '#'); i >= 0 { // drop the label fragment
		raw = raw[:i]
	}

	var method, password, host string
	var port int

	if at := strings.LastIndexByte(raw, '@'); at >= 0 {
		// SIP002: base64(method:password) @ host:port[?plugin=...]
		userinfo := raw[:at]
		hostport := raw[at+1:]
		if q := strings.IndexByte(hostport, '?'); q >= 0 {
			hostport = hostport[:q]
		}
		mp := strings.SplitN(b64decode(userinfo), ":", 2)
		if len(mp) != 2 {
			return nil, fmt.Errorf("bad shadowsocks userinfo")
		}
		method, password = mp[0], mp[1]
		h, p, err := splitHostPort(hostport)
		if err != nil {
			return nil, err
		}
		host, port = h, p
	} else {
		// Legacy: base64(method:password@host:port)
		dec := b64decode(raw)
		at := strings.LastIndexByte(dec, '@')
		if at < 0 {
			return nil, fmt.Errorf("bad shadowsocks link")
		}
		mp := strings.SplitN(dec[:at], ":", 2)
		if len(mp) != 2 {
			return nil, fmt.Errorf("bad shadowsocks userinfo")
		}
		method, password = mp[0], mp[1]
		h, p, err := splitHostPort(dec[at+1:])
		if err != nil {
			return nil, err
		}
		host, port = h, p
	}

	return map[string]any{
		"type": "shadowsocks", "server": host, "server_port": port,
		"method": method, "password": password,
	}, nil
}

func parseVLESS(link string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	uuid := u.User.Username()
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if uuid == "" || host == "" || port == 0 {
		return nil, fmt.Errorf("bad vless link (need uuid@host:port)")
	}
	q := u.Query()

	out := map[string]any{
		"type": "vless", "server": host, "server_port": port, "uuid": uuid,
	}
	if flow := q.Get("flow"); flow != "" {
		out["flow"] = flow
	}

	switch q.Get("type") {
	case "ws":
		t := map[string]any{"type": "ws", "path": firstNonEmpty(q.Get("path"), "/")}
		if h := q.Get("host"); h != "" {
			t["headers"] = map[string]any{"Host": h}
		}
		out["transport"] = t
	case "grpc":
		out["transport"] = map[string]any{"type": "grpc", "service_name": q.Get("serviceName")}
	}

	switch q.Get("security") {
	case "tls":
		out["tls"] = tlsBlock(q, host, false)
	case "reality":
		out["tls"] = tlsBlock(q, host, true)
	}
	return out, nil
}

func tlsBlock(q url.Values, host string, reality bool) map[string]any {
	tls := map[string]any{
		"enabled":     true,
		"server_name": firstNonEmpty(q.Get("sni"), host),
	}
	if fp := q.Get("fp"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if reality {
		r := map[string]any{"enabled": true, "public_key": q.Get("pbk")}
		if sid := q.Get("sid"); sid != "" {
			r["short_id"] = sid
		}
		tls["reality"] = r
	}
	return tls
}

func b64decode(s string) string {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return string(b)
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return string(b)
	}
	return ""
}

func splitHostPort(hp string) (string, int, error) {
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q", p)
	}
	return h, port, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
