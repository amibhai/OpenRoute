package main

import (
	"regexp"
	"strings"
)

// Share links and configs carry secrets (passwords, UUIDs, private keys).
// Nothing secret ever reaches a log file or an error message: redact first.

var (
	reURIUserinfo = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^@/\s]+@`)
	reUUID        = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reSecretKV    = regexp.MustCompile(`(?i)("?(?:password|psk|private_key|uuid|secret|pbk|sid|obfs-password|auth)"?\s*[:=]\s*"?)([^"&\s,}]+)`)
	reVmessBlob   = regexp.MustCompile(`vmess://[A-Za-z0-9+/=_-]{16,}`)
)

func redact(s string) string {
	s = reVmessBlob.ReplaceAllString(s, "vmess://***")
	s = reURIUserinfo.ReplaceAllString(s, "$1***@")
	s = reSecretKV.ReplaceAllString(s, "$1***")
	s = reUUID.ReplaceAllString(s, "********-****-****-****-************")
	return s
}

// A share link as it may appear in logs/UI: scheme and server only.
func redactLink(link string) string {
	l := strings.TrimSpace(link)
	if i := strings.Index(l, "#"); i >= 0 {
		l = l[:i]
	}
	if i := strings.Index(l, "?"); i >= 0 {
		l = l[:i]
	}
	return redact(l)
}
