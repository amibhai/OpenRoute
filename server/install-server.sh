#!/usr/bin/env bash
# OpenRoute — one-command hardened sing-box server.
#
# Stands up Shadowsocks-2022 + VLESS-Reality on a fresh Debian/Ubuntu VPS and
# prints the share links you paste into the extension (Connect via companion).
#
#   sudo bash install-server.sh          # install + start + print links
#   sudo bash install-server.sh --show   # re-print links for an existing install
#
# Override defaults with env vars, e.g.:
#   REALITY_SNI=www.apple.com VLESS_PORT=443 SS_PORT=8443 sudo -E bash install-server.sh
set -euo pipefail

CONFIG_DIR=/etc/sing-box
CONFIG="$CONFIG_DIR/config.json"
ENVFILE="$CONFIG_DIR/openroute.env"

SS_METHOD="2022-blake3-aes-128-gcm"                       # 16-byte key
REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"           # TLS site to borrow (must support TLS1.3)
VLESS_PORT="${VLESS_PORT:-443}"
SS_PORT="${SS_PORT:-$(( (RANDOM % 20000) + 20000 ))}"

need_root() { [ "$(id -u)" -eq 0 ] || { echo "Please run as root (sudo)." >&2; exit 1; }; }

show_links() {
  # shellcheck disable=SC1090
  . "$ENVFILE"
  local ss_b64
  ss_b64="$(printf '%s' "${SS_METHOD}:${SS_PSK}" | base64 -w0 | tr '+/' '-_' | tr -d '=')"
  cat <<BANNER

================================================================
 OpenRoute share links — paste into the extension popup:
   Transports → Connect via companion
================================================================

VLESS-Reality (put this one first; it looks like normal HTTPS):
vless://${UUID}@${SERVER_IP}:${VLESS_PORT}?encryption=none&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp&flow=xtls-rprx-vision#OpenRoute-Reality

Shadowsocks-2022:
ss://${ss_b64}@${SERVER_IP}:${SS_PORT}#OpenRoute-SS

Tip: paste BOTH lines into the pool box (one per line) for auto-failover.
================================================================
BANNER
}

# ---- --show shortcut -------------------------------------------------------
if [ "${1:-}" = "--show" ]; then
  need_root
  [ -f "$ENVFILE" ] || { echo "No saved server yet — run without --show first." >&2; exit 1; }
  show_links
  exit 0
fi

need_root

echo "[1/6] Installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y >/dev/null
  apt-get install -y curl ca-certificates openssl >/dev/null
else
  echo "  (non-apt system; ensure curl + openssl are present)"
fi

echo "[2/6] Installing sing-box..."
if ! command -v sing-box >/dev/null 2>&1; then
  # Official vendor installer (arch detection + systemd unit).
  curl -fsSL https://sing-box.app/install.sh | sh
fi
command -v sing-box >/dev/null 2>&1 || { echo "sing-box install failed." >&2; exit 1; }

echo "[3/6] Generating credentials..."
UUID="$(cat /proc/sys/kernel/random/uuid)"
SS_PSK="$(openssl rand -base64 16)"
SHORT_ID="$(openssl rand -hex 8)"
KEYPAIR="$(sing-box generate reality-keypair)"
REALITY_PRIVATE="$(printf '%s\n' "$KEYPAIR" | awk -F': *' '/PrivateKey/{print $2}')"
REALITY_PUBLIC="$(printf '%s\n' "$KEYPAIR" | awk -F': *' '/PublicKey/{print $2}')"
[ -n "$REALITY_PRIVATE" ] && [ -n "$REALITY_PUBLIC" ] || { echo "reality keypair generation failed." >&2; exit 1; }

SERVER_IP="${SERVER_IP:-$(curl -fsS https://api.ipify.org 2>/dev/null || curl -fsS https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')}"
[ -n "$SERVER_IP" ] || { echo "Could not determine server IP; re-run with SERVER_IP=<your.ip>." >&2; exit 1; }

echo "[4/6] Writing $CONFIG ..."
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG" <<JSON
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": ${VLESS_PORT},
      "users": [ { "uuid": "${UUID}", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_SNI}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${REALITY_SNI}", "server_port": 443 },
          "private_key": "${REALITY_PRIVATE}",
          "short_id": [ "${SHORT_ID}" ]
        }
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "::",
      "listen_port": ${SS_PORT},
      "method": "${SS_METHOD}",
      "password": "${SS_PSK}"
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "rules": [ { "ip_is_private": true, "outbound": "block" } ],
    "final": "direct"
  }
}
JSON
chmod 600 "$CONFIG"

cat > "$ENVFILE" <<ENV
UUID="${UUID}"
SS_PSK="${SS_PSK}"
SS_PORT="${SS_PORT}"
VLESS_PORT="${VLESS_PORT}"
REALITY_SNI="${REALITY_SNI}"
REALITY_PUBLIC="${REALITY_PUBLIC}"
SHORT_ID="${SHORT_ID}"
SERVER_IP="${SERVER_IP}"
ENV
chmod 600 "$ENVFILE"

echo "[5/6] Validating config & starting service..."
sing-box check -c "$CONFIG"
systemctl enable sing-box >/dev/null 2>&1 || true
systemctl restart sing-box
sleep 1
if ! systemctl is-active --quiet sing-box; then
  echo "sing-box failed to start — check: journalctl -u sing-box -n 40" >&2
  exit 1
fi

# Open the firewall if ufw is managing it.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${VLESS_PORT}"/tcp >/dev/null 2>&1 || true
  ufw allow "${SS_PORT}"/tcp >/dev/null 2>&1 || true
  ufw allow "${SS_PORT}"/udp >/dev/null 2>&1 || true
  echo "  ufw: opened ${VLESS_PORT}/tcp and ${SS_PORT}/tcp+udp"
fi

echo "[6/6] Done. sing-box is active."
show_links
