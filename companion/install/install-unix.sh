#!/usr/bin/env sh
# Installs the OpenRoute companion for every supported browser on this
# machine (macOS or Linux): Chrome, Chromium, Edge, Brave, Vivaldi, Opera,
# Arc, Yandex, Firefox, LibreWolf, Waterfox, Floorp, Zen. No root needed.
#
#   ./install-unix.sh [--sing-box /path/to/sing-box] [--extension-id <id>[,<id>]]
#
# Uses a prebuilt openroute-companion next to this script if present;
# otherwise builds from source (needs Go 1.21+). --extension-id is only
# needed for store builds — the unpacked extension's ID is allowed already.
set -eu

SINGBOX=""
EXTID=""
while [ $# -gt 0 ]; do
  case "$1" in
    --sing-box) SINGBOX="$2"; shift 2 ;;
    --extension-id) EXTID="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
COMPANION="$(cd "$HERE/.." && pwd)"
BIN="$COMPANION/bin/openroute-companion"

if [ -x "$HERE/openroute-companion" ]; then
  BIN="$HERE/openroute-companion"
else
  command -v go >/dev/null 2>&1 || { echo "Go isn't installed and there's no prebuilt binary next to this script. Get a release build, or install Go from https://go.dev/dl/" >&2; exit 1; }
  echo "Building the companion (go build)..."
  mkdir -p "$COMPANION/bin"
  ( cd "$COMPANION" && go build -trimpath -ldflags "-s -w" -o "$BIN" . )
fi

if [ -n "$SINGBOX" ]; then
  mkdir -p "$HOME/.openroute"
  cp "$SINGBOX" "$HOME/.openroute/sing-box"
  chmod +x "$HOME/.openroute/sing-box"
  echo "Using sing-box from $SINGBOX"
fi

if [ -n "$EXTID" ]; then
  "$BIN" install --extension-id "$EXTID"
else
  "$BIN" install
fi
"$BIN" doctor
