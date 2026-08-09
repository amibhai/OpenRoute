#!/usr/bin/env sh
# Installs the OpenRoute native companion for Chrome/Chromium on macOS or Linux.
#
#   ./install-unix.sh <your-unpacked-extension-id> [path-to-sing-box]
#
# Find the extension id at chrome://extensions (Developer mode).
set -eu

EXT_ID="${1:-}"
SINGBOX="${2:-}"
if [ -z "$EXT_ID" ]; then
  echo "usage: $0 <extension-id> [path-to-sing-box]" >&2
  exit 1
fi

COMPANION="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$COMPANION/bin/openroute-host"

echo "Building companion (go build)..."
mkdir -p "$COMPANION/bin"
( cd "$COMPANION" && go build -o "$BIN" . )

DATA="$HOME/.openroute"
mkdir -p "$DATA"
if [ -n "$SINGBOX" ]; then
  cp "$SINGBOX" "$DATA/sing-box"
  chmod +x "$DATA/sing-box" || true
  echo "Bundled sing-box from $SINGBOX"
fi

case "$(uname -s)" in
  Darwin)
    DIRS="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts
$HOME/Library/Application Support/Chromium/NativeMessagingHosts" ;;
  *)
    DIRS="$HOME/.config/google-chrome/NativeMessagingHosts
$HOME/.config/chromium/NativeMessagingHosts" ;;
esac

echo "$DIRS" | while IFS= read -r d; do
  [ -z "$d" ] && continue
  mkdir -p "$d"
  cat > "$d/com.openroute.host.json" <<EOF
{
  "name": "com.openroute.host",
  "description": "OpenRoute native companion",
  "path": "$BIN",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXT_ID/"
  ]
}
EOF
  echo "wrote $d/com.openroute.host.json"
done

echo "Installed."
echo "  binary: $BIN"
echo "Reload the extension, open the popup — companion should read 'connected'."
