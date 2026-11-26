#!/usr/bin/env bash
# Packages OpenRoute for every browser. Thin wrapper around scripts/build.mjs
# (needs Node.js 22+; zero npm dependencies).
#   ./build.sh [targets...] [--no-zip]
set -euo pipefail
exec node "$(cd "$(dirname "$0")" && pwd)/scripts/build.mjs" "$@"
