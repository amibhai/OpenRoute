package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Share links → sing-box outbound (or endpoint) objects, without "tag".
//
// Supported: ss:// (SIP002 incl. the SS-2022 percent-encoded form, legacy
// base64, plugins), vless:// (tcp/ws/grpc/http/httpupgrade; tls/reality),
// vmess:// (v2rayN JSON), trojan://, hysteria2:// and hy2://, tuic://,
// socks5:// / socks://, http:// / https:// proxies, wireguard:// (→ an
// endpoint) and raw sing-box outbound JSON. Anything sing-box can't do is
// rejected with a clear reason instead of producing a config that won't start.

type Parsed struct {
	Object   map[string]any
	Endpoint bool   // wireguard: lives in "endpoints", not "outbounds"
	Label    string // from the #fragment, if any
}

var ssMethods = map[string]bool{
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true, "none": true,
}

func parseLink(link string) (Parsed, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return Parsed{}, errors.New("empty link")
	}
	if strings.HasPrefix(link, "{") {
		return parseRawOutbound(link)
	}
	scheme := strings.ToLower(link[:max(0, strings.Index(link, "://"))])
	label := ""
	if i := strings.LastIndex(link, "#"); i >= 0 {
		label, _ = url.PathUnescape(link[i+1:])
		link = link[:i]
	}
	var p Parsed
	var err error
	switch scheme {
	case "ss":
		p, err = parseSS(link)
	case "vless":
		p, err = parseVLESS(link)
	case "vmess":
		p, err = parseVMess(link)
	case "trojan":
		p, err = parseTrojan(link)
	case "hysteria2", "hy2":
		p, err = parseHysteria2(link)
	case "tuic":
		p, err = parseTUIC(link)
	case "socks", "socks5", "socks5h", "socks4", "socks4a":
		p, err = parseSocks(link, scheme)
	case "http", "https":
		p, err = parseHTTPProxy(link, scheme)
	case "wireguard", "wg":
		p, err = parseWireGuard(link)
	case "":
		return Parsed{}, errors.New("not a share link (no scheme)")
	default:
		return Parsed{}, fmt.Errorf("unsupported link type %q (supported: ss, vless, vmess, trojan, hysteria2, tuic, socks5, http(s), wireguard, raw JSON)", scheme)
	}
	if err != nil {
		return Parsed{}, fmt.Errorf("%s link: %w", scheme, err)
	}
	if p.Label == "" {
		p.Label = label
	}
	return p, nil
}

func parseRawOutbound(s string) (Parsed, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return Parsed{}, fmt.Errorf("raw outbound JSON: %w", err)
	}
	t, _ := m["type"].(string)
	if t == "" {
		return Parsed{}, errors.New(`raw outbound JSON needs a "type"`)
	}
	delete(m, "tag")
	return Parsed{Object: m, Endpoint: t == "wireguard"}, nil
}

func hostPort(u *url.URL) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("missing server address")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", u.Port())
	}
	return host, port, nil
}

// Decodes standard or URL-safe base64, padded or not.
func b64(s string) (string, bool) {
	t := strings.TrimRight(strings.TrimSpace(s), "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(t); err == nil {
			return string(b), true
		}
	}
	return "", false
}

func splitServer(hp string) (string, int, error) {
	h, p, err := net.SplitHostPort(strings.TrimSuffix(hp, "/"))
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", p)
	}
	if h == "" {
		return "", 0, errors.New("missing server address")
	}
	return h, port, nil
}

// ---- shadowsocks -------------------------------------------------------------

func parseSS(link string) (Parsed, error) {
	rest := link[strings.Index(link, "://")+3:]
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		rest, query = rest[:i], rest[i+1:]
	}
	rest = strings.TrimSuffix(rest, "/")
	var method, password, hostport string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		userinfo := rest[:at]
		hostport = rest[at+1:]
		if strings.Contains(userinfo, ":") {
			// SIP002 for AEAD-2022: plain "method:password", percent-encoded.
			// (Base64 never contains ':', so this can't be mistaken.)
			parts := strings.SplitN(userinfo, ":", 2)
			m, err1 := url.PathUnescape(parts[0])
			pw, err2 := url.PathUnescape(parts[1])
			if err1 != nil || err2 != nil {
				return Parsed{}, errors.New("bad percent-encoding in userinfo")
			}
			method, password = m, pw
		} else {
			raw, _ := url.PathUnescape(userinfo)
			dec, ok := b64(raw)
			parts := strings.SplitN(dec, ":", 2)
			if !ok || len(parts) != 2 {
				return Parsed{}, errors.New("bad userinfo (expected base64(method:password) or method:password)")
			}
			method, password = parts[0], parts[1]
		}
	} else {
		// Legacy: ss://base64(method:password@host:port)
		dec, ok := b64(rest)
		at := strings.LastIndex(dec, "@")
		parts := strings.SplitN(dec[:max(at, 0)], ":", 2)
		if !ok || at < 0 || len(parts) != 2 {
			return Parsed{}, errors.New("unrecognised format")
		}
		method, password, hostport = parts[0], parts[1], dec[at+1:]
	}
	host, port, err := splitServer(hostport)
	if err != nil {
		return Parsed{}, err
	}
	var plugin, pluginOpts string
	if q, _ := url.ParseQuery(query); q.Get("plugin") != "" {
		parts := strings.SplitN(q.Get("plugin"), ";", 2)
		plugin = parts[0]
		if len(parts) == 2 {
			pluginOpts = parts[1]
		}
	}
	method = strings.ToLower(method)
	if !ssMethods[method] {
		return Parsed{}, fmt.Errorf("unsupported cipher %q", method)
	}
	out := map[string]any{"type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": password}
	if plugin != "" {
		switch plugin {
		case "obfs-local", "simple-obfs":
			out["plugin"] = "obfs-local"
		case "v2ray-plugin":
			out["plugin"] = "v2ray-plugin"
		default:
			return Parsed{}, fmt.Errorf("unsupported plugin %q (sing-box supports obfs-local and v2ray-plugin)", plugin)
		}
		out["plugin_opts"] = pluginOpts
	}
	return Parsed{Object: out}, nil
}

// ---- TLS / transports shared by vless, vmess, trojan --------------------------

func tlsFrom(q url.Values, host string, reality bool) (map[string]any, error) {
	t := map[string]any{"enabled": true, "server_name": firstNonEmpty(q.Get("sni"), q.Get("peer"), host)}
	if alpn := q.Get("alpn"); alpn != "" {
		t["alpn"] = strings.Split(alpn, ",")
	}
	if v := q.Get("allowInsecure"); v == "1" || v == "true" {
		t["insecure"] = true
	}
	if v := q.Get("insecure"); v == "1" || v == "true" {
		t["insecure"] = true
	}
	fp := q.Get("fp")
	if reality && fp == "" {
		fp = "chrome" // sing-box's reality client requires uTLS
	}
	if fp != "" {
		t["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if reality {
		r := map[string]any{"enabled": true, "public_key": q.Get("pbk")}
		if sid := q.Get("sid"); sid != "" {
			r["short_id"] = sid
		}
		t["reality"] = r
	}
	if err := applyPins(t, q); err != nil {
		return nil, err
	}
	return t, nil
}

// applyPins maps certificate pins onto sing-box's TLS options.
//
// pinPublicKeySHA256 (hex or base64; several comma-separated for a key
// rollover) is what OpenRoute's server script prints for its self-signed
// Hysteria2 certificate. It becomes certificate_public_key_sha256 (sing-box
// 1.13+), which sing-box checks *instead of* CA validation — verified
// against the real binary: the right pin connects, a wrong pin and no pin
// are both refused — so no "insecure" is needed or kept.
//
// The standard Hysteria pinSHA256 hashes the whole certificate, which no
// stable sing-box can check. Links usually pair it with insecure=1, and
// honoring that would mean no verification at all, so that combination is
// refused instead of silently downgraded.
func applyPins(t map[string]any, q url.Values) error {
	if raw := firstNonEmpty(q.Get("pinPublicKeySHA256"), q.Get("certificate_public_key_sha256")); raw != "" {
		var pins []string
		for _, p := range splitList(raw) {
			b, err := decodePin(p)
			if err != nil {
				return fmt.Errorf("pinPublicKeySHA256: %w", err)
			}
			pins = append(pins, base64.StdEncoding.EncodeToString(b))
		}
		t["certificate_public_key_sha256"] = pins
		delete(t, "insecure") // the pin is the verification
		return nil
	}
	if t["insecure"] == true && q.Get("pinSHA256") != "" {
		return errors.New("this link turns certificate checks off and relies on pinSHA256 (a whole-certificate fingerprint), which sing-box can't verify; ask for the public-key pin (pinPublicKeySHA256, which OpenRoute's server script prints) or use a server with a real certificate")
	}
	return nil
}

// decodePin accepts a SHA-256 as hex (colons allowed, as openssl prints
// fingerprints) or base64 in any of its spellings.
func decodePin(s string) ([]byte, error) {
	if h := strings.ReplaceAll(strings.TrimSpace(s), ":", ""); len(h) == 64 {
		if b, err := hex.DecodeString(h); err == nil {
			return b, nil
		}
	}
	if b, ok := b64(s); ok && len(b) == sha256Len {
		return []byte(b), nil
	}
	return nil, fmt.Errorf("%q is not a SHA-256 hash (hex or base64)", s)
}

const sha256Len = 32

func transportFrom(kind string, q url.Values, hostHeader, path string) (map[string]any, error) {
	switch kind {
	case "", "tcp", "raw":
		if q.Get("headerType") == "http" {
			return map[string]any{"type": "http", "host": splitList(hostHeader), "path": firstNonEmpty(path, "/")}, nil
		}
		return nil, nil
	case "ws", "websocket":
		t := map[string]any{"type": "ws", "path": firstNonEmpty(path, "/")}
		if hostHeader != "" {
			t["headers"] = map[string]any{"Host": hostHeader}
		}
		if ed := q.Get("ed"); ed != "" {
			if n, err := strconv.Atoi(ed); err == nil {
				t["max_early_data"] = n
				t["early_data_header_name"] = "Sec-WebSocket-Protocol"
			}
		}
		return t, nil
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": firstNonEmpty(q.Get("serviceName"), q.Get("service_name"), path)}, nil
	case "http", "h2":
		t := map[string]any{"type": "http", "path": firstNonEmpty(path, "/")}
		if hostHeader != "" {
			t["host"] = splitList(hostHeader)
		}
		return t, nil
	case "httpupgrade":
		t := map[string]any{"type": "httpupgrade", "path": firstNonEmpty(path, "/")}
		if hostHeader != "" {
			t["host"] = hostHeader
		}
		return t, nil
	case "xhttp", "splithttp":
		return nil, errors.New("transport xhttp/splithttp is Xray-only (sing-box has no XHTTP)")
	case "quic", "kcp", "mkcp":
		return nil, fmt.Errorf("transport %q is not supported by sing-box", kind)
	default:
		return nil, fmt.Errorf("unknown transport %q", kind)
	}
}

// ---- vless -------------------------------------------------------------------

func parseVLESS(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, err
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	uuid := u.User.Username()
	if uuid == "" {
		return Parsed{}, errors.New("missing UUID")
	}
	q := u.Query()
	out := map[string]any{"type": "vless", "server": host, "server_port": port, "uuid": uuid}
	if flow := q.Get("flow"); flow != "" {
		if flow != "xtls-rprx-vision" {
			return Parsed{}, fmt.Errorf("flow %q is not supported by sing-box (only xtls-rprx-vision)", flow)
		}
		out["flow"] = flow
	}
	tr, err := transportFrom(q.Get("type"), q, q.Get("host"), q.Get("path"))
	if err != nil {
		return Parsed{}, err
	}
	if tr != nil {
		out["transport"] = tr
	}
	switch q.Get("security") {
	case "tls", "xtls":
		if out["tls"], err = tlsFrom(q, host, false); err != nil {
			return Parsed{}, err
		}
	case "reality":
		if q.Get("pbk") == "" {
			return Parsed{}, errors.New("reality needs pbk (the server's public key)")
		}
		if out["tls"], err = tlsFrom(q, host, true); err != nil {
			return Parsed{}, err
		}
	case "", "none":
	default:
		return Parsed{}, fmt.Errorf("unknown security %q", q.Get("security"))
	}
	return Parsed{Object: out}, nil
}

// ---- vmess (v2rayN base64 JSON) ---------------------------------------------------

func parseVMess(link string) (Parsed, error) {
	body := strings.TrimPrefix(link, link[:strings.Index(link, "://")+3])
	dec, ok := b64(body)
	if !ok || !strings.HasPrefix(strings.TrimSpace(dec), "{") {
		return Parsed{}, errors.New("expected base64-encoded JSON (v2rayN format)")
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(dec), &v); err != nil {
		return Parsed{}, err
	}
	str := func(k string) string {
		switch x := v[k].(type) {
		case string:
			return x
		case float64:
			return strconv.Itoa(int(x))
		}
		return ""
	}
	host := str("add")
	port, err := strconv.Atoi(str("port"))
	if host == "" || err != nil || port < 1 || port > 65535 {
		return Parsed{}, errors.New("missing/invalid add or port")
	}
	if str("id") == "" {
		return Parsed{}, errors.New("missing id")
	}
	alterID, _ := strconv.Atoi(firstNonEmpty(str("aid"), "0"))
	out := map[string]any{
		"type": "vmess", "server": host, "server_port": port, "uuid": str("id"),
		"security": firstNonEmpty(str("scy"), "auto"), "alter_id": alterID,
	}
	q := url.Values{}
	q.Set("sni", str("sni"))
	q.Set("alpn", str("alpn"))
	q.Set("fp", str("fp"))
	q.Set("headerType", str("type"))
	q.Set("serviceName", str("path"))
	tr, err := transportFrom(str("net"), q, str("host"), str("path"))
	if err != nil {
		return Parsed{}, err
	}
	if tr != nil {
		out["transport"] = tr
	}
	if str("tls") == "tls" {
		if out["tls"], err = tlsFrom(q, firstNonEmpty(str("host"), host), false); err != nil {
			return Parsed{}, err
		}
	}
	return Parsed{Object: out, Label: str("ps")}, nil
}

// ---- trojan --------------------------------------------------------------------

func parseTrojan(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, err
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	password := u.User.Username()
	if password == "" {
		return Parsed{}, errors.New("missing password")
	}
	q := u.Query()
	out := map[string]any{"type": "trojan", "server": host, "server_port": port, "password": password}
	tr, err := transportFrom(q.Get("type"), q, q.Get("host"), q.Get("path"))
	if err != nil {
		return Parsed{}, err
	}
	if tr != nil {
		out["transport"] = tr
	}
	if q.Get("security") != "none" {
		if out["tls"], err = tlsFrom(q, host, q.Get("security") == "reality"); err != nil {
			return Parsed{}, err
		}
	}
	return Parsed{Object: out}, nil
}

// ---- hysteria2 ---------------------------------------------------------------------

func parseHysteria2(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, err
	}
	host := u.Hostname()
	if host == "" {
		return Parsed{}, errors.New("missing server address")
	}
	q := u.Query()
	out := map[string]any{"type": "hysteria2", "server": host}
	portSpec := u.Port()
	if mport := q.Get("mport"); mport != "" {
		portSpec = mport
	}
	if strings.ContainsAny(portSpec, ",-") {
		var ranges []string
		for _, part := range strings.Split(portSpec, ",") {
			ranges = append(ranges, strings.ReplaceAll(strings.TrimSpace(part), "-", ":"))
		}
		out["server_ports"] = ranges
		if p, err := strconv.Atoi(u.Port()); err == nil {
			out["server_port"] = p
		}
	} else {
		p, err := strconv.Atoi(firstNonEmpty(portSpec, "443"))
		if err != nil || p < 1 || p > 65535 {
			return Parsed{}, fmt.Errorf("bad port %q", portSpec)
		}
		out["server_port"] = p
	}
	auth := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		auth += ":" + pw
	}
	if auth != "" {
		out["password"] = auth
	}
	if obfs := q.Get("obfs"); obfs != "" {
		if obfs != "salamander" {
			return Parsed{}, fmt.Errorf("unknown obfs %q", obfs)
		}
		out["obfs"] = map[string]any{"type": "salamander", "password": q.Get("obfs-password")}
	}
	t, err := tlsFrom(q, host, false)
	if err != nil {
		return Parsed{}, err
	}
	if _, ok := t["alpn"]; !ok {
		t["alpn"] = []string{"h3"}
	}
	out["tls"] = t
	return Parsed{Object: out}, nil
}

// ---- tuic -------------------------------------------------------------------------

func parseTUIC(link string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, err
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	pw, _ := u.User.Password()
	if u.User.Username() == "" {
		return Parsed{}, errors.New("missing uuid")
	}
	q := u.Query()
	out := map[string]any{"type": "tuic", "server": host, "server_port": port, "uuid": u.User.Username(), "password": pw}
	if cc := firstNonEmpty(q.Get("congestion_control"), q.Get("congestion")); cc != "" {
		out["congestion_control"] = cc
	}
	if m := q.Get("udp_relay_mode"); m != "" {
		out["udp_relay_mode"] = m
	}
	if q.Get("allow_insecure") == "1" {
		q.Set("insecure", "1")
	}
	t, err := tlsFrom(q, host, false)
	if err != nil {
		return Parsed{}, err
	}
	if _, ok := t["alpn"]; !ok {
		t["alpn"] = []string{"h3"}
	}
	out["tls"] = t
	return Parsed{Object: out}, nil
}

// ---- socks / http upstreams -----------------------------------------------------------

func parseSocks(link, scheme string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, err
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	version := "5"
	if strings.HasPrefix(scheme, "socks4") {
		version = "4a"
	}
	out := map[string]any{"type": "socks", "server": host, "server_port": port, "version": version}
	if u.User != nil {
		user := u.User.Username()
		if dec, ok := b64(user); ok && strings.Contains(dec, ":") && !strings.Contains(user, ":") {
			parts := strings.SplitN(dec, ":", 2) // some clients base64 the userinfo
			out["username"], out["password"] = parts[0], parts[1]
		} else {
			pw, _ := u.User.Password()
			out["username"], out["password"] = user, pw
		}
	}
	return Parsed{Object: out}, nil
}

func parseHTTPProxy(link, scheme string) (Parsed, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Parsed{}, err
	}
	host, port, err := hostPort(u)
	if err != nil {
		return Parsed{}, err
	}
	out := map[string]any{"type": "http", "server": host, "server_port": port}
	if u.User != nil {
		pw, _ := u.User.Password()
		out["username"], out["password"] = u.User.Username(), pw
	}
	if scheme == "https" {
		out["tls"] = map[string]any{"enabled": true, "server_name": host}
	}
	return Parsed{Object: out}, nil
}

// ---- wireguard (manual parse: keys contain '/' and '+') ---------------------------------

func parseWireGuard(link string) (Parsed, error) {
	rest := link[strings.Index(link, "://")+3:]
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		rest, query = rest[:i], rest[i+1:]
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return Parsed{}, errors.New("expected privatekey@host:port")
	}
	priv, _ := url.PathUnescape(rest[:at])
	hp := strings.TrimSuffix(rest[at+1:], "/")
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		return Parsed{}, err
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return Parsed{}, fmt.Errorf("bad port %q", p)
	}
	q, _ := url.ParseQuery(query)
	pub := firstNonEmpty(q.Get("publickey"), q.Get("public_key"), q.Get("peer_public_key"))
	if priv == "" || pub == "" {
		return Parsed{}, errors.New("needs a private key and publickey=")
	}
	addrs := splitList(firstNonEmpty(q.Get("address"), q.Get("ip")))
	if len(addrs) == 0 {
		return Parsed{}, errors.New("needs address= (the interface address, e.g. 10.7.0.2/32)")
	}
	for i, a := range addrs {
		if !strings.Contains(a, "/") {
			if strings.Contains(a, ":") {
				addrs[i] = a + "/128"
			} else {
				addrs[i] = a + "/32"
			}
		}
	}
	peer := map[string]any{"address": h, "port": port, "public_key": pub, "allowed_ips": []string{"0.0.0.0/0", "::/0"}}
	if psk := firstNonEmpty(q.Get("presharedkey"), q.Get("pre_shared_key")); psk != "" {
		peer["pre_shared_key"] = psk
	}
	if r := q.Get("reserved"); r != "" {
		var res []int
		for _, s := range strings.Split(r, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				res = append(res, n)
			}
		}
		if len(res) == 3 {
			peer["reserved"] = res
		}
	}
	out := map[string]any{"type": "wireguard", "address": addrs, "private_key": priv, "peers": []any{peer}}
	if mtu, err := strconv.Atoi(q.Get("mtu")); err == nil && mtu > 0 {
		out["mtu"] = mtu
	}
	return Parsed{Object: out, Endpoint: true}, nil
}

// ---- subscriptions ----------------------------------------------------------------------

// parseSubscription accepts the common subscription bodies: a base64 list of
// links, a plain list of links, or sing-box JSON with "outbounds".
func parseSubscription(body string) ([]string, error) {
	body = strings.TrimSpace(body)
	if strings.HasPrefix(body, "{") {
		var cfg struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(body), &cfg); err != nil {
			return nil, err
		}
		var links []string
		for _, ob := range cfg.Outbounds {
			switch ob["type"] {
			case "direct", "block", "dns", "selector", "urltest", nil:
				continue
			}
			b, _ := json.Marshal(ob)
			links = append(links, string(b))
		}
		return links, nil
	}
	text := body
	if !strings.Contains(body, "://") {
		if dec, ok := b64(strings.ReplaceAll(strings.ReplaceAll(body, "\n", ""), "\r", "")); ok {
			text = dec
		}
	}
	var links []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); strings.Contains(l, "://") {
			links = append(links, l)
		}
	}
	if len(links) == 0 {
		return nil, errors.New("no share links found in the subscription")
	}
	return links, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
