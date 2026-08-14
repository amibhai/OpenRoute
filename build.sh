#!/usr/bin/env bash
# Packages OpenRoute into distributable zips (Chrome/Edge + Firefox).
# Output: dist/openroute-{chrome,firefox}-<ver>.zip   Requires: zip
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="$ROOT/dist"

VER="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/manifest.json" | head -1)"
echo "Building OpenRoute $VER"

FILES=(background.js doh.js policy.js transports.js ladder.js router.js
       health.js nm-client.js popup.js onboarding.js
       popup.html popup.css onboarding.html onboarding.css
       LICENSE)

command -v zip >/dev/null 2>&1 || { echo "need 'zip' (apt install zip / brew install zip)"; exit 1; }
mkdir -p "$DIST"

build_zip() { # <target> <manifest-src>
  local target="$1" manifest="$2"
  local stage; stage="$(mktemp -d)"
  cp "$ROOT/$manifest" "$stage/manifest.json"
  for f in "${FILES[@]}"; do cp "$ROOT/$f" "$stage/$f"; done
  mkdir -p "$stage/icons"; cp "$ROOT"/icons/*.png "$stage/icons/"
  local zip="$DIST/openroute-$target-$VER.zip"
  rm -f "$zip"
  ( cd "$stage" && zip -qr "$zip" . )
  rm -rf "$stage"
  echo "  $(basename "$zip") ($(du -h "$zip" | cut -f1))"
}

build_zip chrome  manifest.json
build_zip firefox manifest.firefox.json
echo "Done → $DIST"
