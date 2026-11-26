# Packages OpenRoute for every browser. Thin wrapper around scripts/build.mjs
# (needs Node.js 22+; zero npm dependencies).
#   powershell -ExecutionPolicy Bypass -File build.ps1 [targets...] [--no-zip]
$ErrorActionPreference = "Stop"
& node (Join-Path $PSScriptRoot "scripts\build.mjs") @args
exit $LASTEXITCODE
