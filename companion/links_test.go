package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func mustParse(t *testing.T, link string) Parsed {
	t.Helper()
	p, err := parseLink(link)
	if err != nil {
		t.Fatalf("parseLink(%q): %v", redactLink(link), err)
	}
	return p
}

func TestShadowsocksForms(t *testing.T) {
	psk := "YctPZ6U7xPPcU+gp3u+H5w=="
	cases := map[string]string{
		// SIP002 for AEAD-2022: plain, percent-encoded — the old parser rejected this.
		"sip002-2022-plain": "ss://2022-blake3-aes-128-gcm:YctPZ6U7xPPcU%2Bgp3u%2BH5w%3D%3D@203.0.113.5:8388#My%20VPS",
		"sip002-base64url":  "ss://" + base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:"+psk)) + "@203.0.113.5:8388",
		"sip002-base64std":  "ss://" + base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:"+psk)) + "@203.0.113.5:8388/",
		"legacy-whole":      "ss://" + base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:"+psk+"@203.0.113.5:8388")),
	}
	for name, link := range cases {
		p := mustParse(t, link)
		o := p.Object
		if o["type"] != "shadowsocks" || o["server"] != "203.0.113.5" || o["server_port"] != 8388 ||
			o["method"] != "2022-blake3-aes-128-gcm" || o["password"] != psk {
			t.Errorf("%s: got %v", name, o)
		}
	}
	if p := mustParse(t, cases["sip002-2022-plain"]); p.Label != "My VPS" {
		t.Errorf("label = %q", p.Label)
	}
	p := mustParse(t, "ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw"))+"@[2001:db8::1]:443?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com")
	if p.Object["server"] != "2001:db8::1" || p.Object["plugin"] != "obfs-local" || p.Object["plugin_opts"] != "obfs=http;obfs-host=example.com" {
		t.Errorf("ipv6 + plugin: %v", p.Object)
	}
	for _, bad := range []string{"ss://bm90aGluZw@h:1", "ss://rc4-md5:pw@h:1", "ss://2022-blake3-aes-128-gcm:pw@h:99999"} {
		if _, err := parseLink(bad); err == nil {
			t.Errorf("expected an error for %s", bad)
		}
	}
}

func TestVLESSReality(t *testing.T) {
	link := "vless://4d3c2b1a-0000-4000-8000-000000000001@vps.example.net:443?encryption=none&security=reality&sni=www.microsoft.com&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=0123456789abcdef&type=tcp&flow=xtls-rprx-vision#R"
	o := mustParse(t, link).Object
	tls := o["tls"].(map[string]any)
	utls := tls["utls"].(map[string]any)
	if utls["fingerprint"] != "chrome" {
		t.Errorf("reality without fp must default to a uTLS fingerprint (sing-box requires it): %v", tls)
	}
	if tls["server_name"] != "www.microsoft.com" || tls["reality"].(map[string]any)["short_id"] != "0123456789abcdef" || o["flow"] != "xtls-rprx-vision" {
		t.Errorf("got %v", o)
	}
	if _, err := parseLink(strings.Replace(link, "&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", "", 1)); err == nil {
		t.Error("reality without pbk must be rejected")
	}
}

func TestVLESSTransports(t *testing.T) {
	ws := mustParse(t, "vless://u@h.example:443?security=tls&type=ws&path=%2Fray&host=cdn.example&ed=2048").Object
	tr := ws["transport"].(map[string]any)
	if tr["type"] != "ws" || tr["path"] != "/ray" || tr["headers"].(map[string]any)["Host"] != "cdn.example" || tr["max_early_data"] != 2048 {
		t.Errorf("ws: %v", tr)
	}
	grpc := mustParse(t, "vless://u@h.example:443?security=tls&type=grpc&serviceName=svc").Object
	if grpc["transport"].(map[string]any)["service_name"] != "svc" {
		t.Errorf("grpc: %v", grpc["transport"])
	}
	_, err := parseLink("vless://u@h.example:443?type=xhttp")
	if err == nil || !strings.Contains(err.Error(), "XHTTP") {
		t.Errorf("xhttp must be refused with a reason, got %v", err)
	}
}

func TestVMess(t *testing.T) {
	j, _ := json.Marshal(map[string]any{"v": "2", "ps": "VM", "add": "v.example.net", "port": "443", "id": "4d3c2b1a-0000-4000-8000-000000000002",
		"aid": "0", "net": "ws", "type": "none", "host": "v.example.net", "path": "/ws", "tls": "tls", "sni": "v.example.net"})
	p := mustParse(t, "vmess://"+base64.StdEncoding.EncodeToString(j))
	if p.Object["type"] != "vmess" || p.Object["server_port"] != 443 || p.Label != "VM" || p.Object["tls"] == nil {
		t.Errorf("got %v", p.Object)
	}
}

func TestTrojanHysteriaTUIC(t *testing.T) {
	tr := mustParse(t, "trojan://p%40ss@t.example.net:443?sni=front.example&type=ws&path=%2Ft").Object
	if tr["password"] != "p@ss" || tr["tls"].(map[string]any)["server_name"] != "front.example" {
		t.Errorf("trojan: %v", tr)
	}
	hy := mustParse(t, "hysteria2://secret@h.example.net:443/?sni=h.example.net&obfs=salamander&obfs-password=ob&mport=20000-30000").Object
	if hy["password"] != "secret" || hy["obfs"].(map[string]any)["type"] != "salamander" {
		t.Errorf("hy2: %v", hy)
	}
	if ports, _ := hy["server_ports"].([]string); len(ports) != 1 || ports[0] != "20000:30000" {
		t.Errorf("hy2 port hopping: %v", hy["server_ports"])
	}
	tu := mustParse(t, "tuic://4d3c2b1a-0000-4000-8000-000000000003:pw@u.example.net:443?congestion_control=bbr&alpn=h3&sni=u.example.net").Object
	if tu["uuid"] == "" || tu["password"] != "pw" || tu["congestion_control"] != "bbr" {
		t.Errorf("tuic: %v", tu)
	}
}

func TestPlainProxiesAndWireGuard(t *testing.T) {
	s := mustParse(t, "socks5://user:pa%3Ass@s.example.net:1080").Object
	if s["type"] != "socks" || s["username"] != "user" || s["password"] != "pa:ss" || s["version"] != "5" {
		t.Errorf("socks: %v", s)
	}
	h := mustParse(t, "https://u:p@p.example.net:443").Object
	if h["type"] != "http" || h["tls"] == nil {
		t.Errorf("https proxy: %v", h)
	}
	wg := mustParse(t, "wireguard://yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=@wg.example.net:51820?publickey=xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg%3D&address=10.7.0.2&reserved=1,2,3")
	if !wg.Endpoint || wg.Object["private_key"] != "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=" {
		t.Errorf("wireguard: %v", wg.Object)
	}
	if addrs := wg.Object["address"].([]string); addrs[0] != "10.7.0.2/32" {
		t.Errorf("address prefix: %v", addrs)
	}
}

func TestRawOutboundAndUnknown(t *testing.T) {
	p := mustParse(t, `{"type":"shadowtls","tag":"x","server":"s","server_port":443}`)
	if p.Object["type"] != "shadowtls" || p.Object["tag"] != nil {
		t.Errorf("raw: %v", p.Object)
	}
	for _, bad := range []string{"", "nonsense", "ftp://x", `{"no":"type"}`} {
		if _, err := parseLink(bad); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}

func TestSubscriptions(t *testing.T) {
	links := "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:443#a\nvless://u@h.example:443?security=tls#b\n"
	for name, body := range map[string]string{
		"plain":  links,
		"base64": base64.StdEncoding.EncodeToString([]byte(links)),
	} {
		got, err := parseSubscription(body)
		if err != nil || len(got) != 2 {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	got, err := parseSubscription(`{"outbounds":[{"type":"direct","tag":"d"},{"type":"trojan","tag":"t","server":"s","server_port":443,"password":"p"}]}`)
	if err != nil || len(got) != 1 || !strings.Contains(got[0], "trojan") {
		t.Errorf("sing-box JSON subscription: %v %v", got, err)
	}
}

func TestRedaction(t *testing.T) {
	in := `connect ss://2022-blake3-aes-128-gcm:SECRETPSK@203.0.113.5:8388 uuid 4d3c2b1a-0000-4000-8000-000000000001 "password":"hunter2" pbk=ABCDEF`
	out := redact(in)
	for _, secret := range []string{"SECRETPSK", "4d3c2b1a-0000-4000-8000-000000000001", "hunter2", "ABCDEF"} {
		if strings.Contains(out, secret) {
			t.Errorf("leaked %q in %q", secret, out)
		}
	}
	if !strings.Contains(out, "203.0.113.5") {
		t.Errorf("server address should stay visible: %q", out)
	}
}

func TestCertificatePinning(t *testing.T) {
	spki := "cf016e91c1f9a7f4227d0c6cab3053e39e05ac8a01f0f59c1ec77f3e38bcccb4" // hex, as the server script prints it
	want := "zwFukcH5p/QifQxsqzBT454FrIoB8PWcHsd/Pji8zLQ="                       // what sing-box wants: std base64
	base := "hysteria2://pw@203.0.113.9:28443/?sni=www.example.com&obfs=salamander&obfs-password=ob"

	for name, q := range map[string]string{
		"hex":             "&pinPublicKeySHA256=" + spki,
		"hex-colons":      "&pinPublicKeySHA256=" + strings.ToUpper(spki[:2]+":"+spki[2:4]) + spki[4:],
		"base64-escaped":  "&pinPublicKeySHA256=zwFukcH5p%2FQifQxsqzBT454FrIoB8PWcHsd%2FPji8zLQ%3D",
		"base64url":       "&pinPublicKeySHA256=zwFukcH5p_QifQxsqzBT454FrIoB8PWcHsd_Pji8zLQ",
		"with-insecure":   "&insecure=1&pinPublicKeySHA256=" + spki, // the pin replaces "insecure"
		"plus-std-pin":    "&pinSHA256=e1af265121d7495daf474f95ea478fbe72e25517b50df7ed32bb2177ab53ff1f&pinPublicKeySHA256=" + spki,
		"sing-box-naming": "&certificate_public_key_sha256=" + spki,
	} {
		o := mustParse(t, base+q).Object
		tls := o["tls"].(map[string]any)
		pins, _ := tls["certificate_public_key_sha256"].([]string)
		if len(pins) != 1 || pins[0] != want {
			t.Errorf("%s: pins = %v, want [%s]", name, tls["certificate_public_key_sha256"], want)
		}
		if _, insecure := tls["insecure"]; insecure {
			t.Errorf("%s: a pinned link must not also turn verification off: %v", name, tls)
		}
	}

	// Two pins for a key rollover.
	o := mustParse(t, base+"&pinPublicKeySHA256="+spki+","+strings.Repeat("ab", 32)).Object
	if pins := o["tls"].(map[string]any)["certificate_public_key_sha256"].([]string); len(pins) != 2 {
		t.Errorf("rollover pins: %v", pins)
	}
	// Pins apply to every TLS-based link, not only Hysteria2.
	o = mustParse(t, "trojan://pw@203.0.113.9:443?security=tls&sni=t.example&pinPublicKeySHA256="+spki).Object
	if _, ok := o["tls"].(map[string]any)["certificate_public_key_sha256"]; !ok {
		t.Errorf("trojan pin dropped: %v", o["tls"])
	}

	// insecure=1 + a whole-certificate pin sing-box can't check would mean no
	// verification at all: refused, not silently downgraded.
	if _, err := parseLink(base + "&insecure=1&pinSHA256=e1af265121d7495daf474f95ea478fbe72e25517b50df7ed32bb2177ab53ff1f"); err == nil || !strings.Contains(err.Error(), "pinPublicKeySHA256") {
		t.Errorf("insecure + pinSHA256 must be refused with a way forward, got %v", err)
	}
	// An explicit insecure-only link stays the user's choice, as before.
	if o := mustParse(t, base+"&insecure=1").Object; o["tls"].(map[string]any)["insecure"] != true {
		t.Errorf("explicit insecure link changed: %v", o["tls"])
	}
	for _, bad := range []string{"nothex", strings.Repeat("ab", 31), "zwFukcH5p"} {
		if _, err := parseLink(base + "&pinPublicKeySHA256=" + bad); err == nil {
			t.Errorf("pin %q should be rejected", bad)
		}
	}
}

func TestPinnedLinksNeedSingBox113(t *testing.T) {
	p := mustParse(t, "hysteria2://pw@203.0.113.9:28443/?sni=s.example&pinPublicKeySHA256="+strings.Repeat("ab", 32))
	if err := requireFeatures("1.12.25", []Parsed{p}); err == nil || !strings.Contains(err.Error(), "1.13") {
		t.Errorf("1.12 + pin: want an actionable error, got %v", err)
	}
	for _, v := range []string{"1.13.0", "1.14.4", "1.15.0-alpha.13"} {
		if err := requireFeatures(v, []Parsed{p}); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	plain := mustParse(t, "hysteria2://pw@203.0.113.9:28443/?sni=s.example")
	if err := requireFeatures("1.12.0", []Parsed{plain}); err != nil {
		t.Errorf("unpinned link on 1.12: %v", err)
	}
}
