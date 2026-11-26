# Installs the OpenRoute companion for every supported browser on this PC
# (Chrome, Edge, Brave, Vivaldi, Opera, Chromium, Yandex, Firefox and forks).
# Per-user, no administrator rights needed.
#
#   .\install-windows.ps1 [-SingBox C:\path\sing-box.exe] [-ExtensionId <id>[,<id>]]
#
# Uses a prebuilt openroute-companion.exe next to this script if present;
# otherwise builds from source (needs Go 1.21+). -ExtensionId is only needed
# for store builds — the unpacked extension's ID is allowed out of the box.
param(
  [string]$SingBox = "",
  [string]$ExtensionId = ""
)
$ErrorActionPreference = "Stop"

$companion = Split-Path -Parent $PSScriptRoot
$prebuilt = Join-Path $PSScriptRoot "openroute-companion.exe"
$bin = Join-Path $companion "bin\openroute-companion.exe"

if (Test-Path $prebuilt) {
  $bin = $prebuilt
} else {
  $go = Get-Command go -ErrorAction SilentlyContinue
  if (-not $go) { throw "Go isn't installed and no prebuilt openroute-companion.exe is next to this script. Get a release build, or install Go from https://go.dev/dl/" }
  Write-Host "Building the companion (go build)..."
  New-Item -ItemType Directory -Force -Path (Split-Path $bin) | Out-Null
  Push-Location $companion
  try { & $go.Source build -trimpath -ldflags "-s -w" -o $bin . ; if ($LASTEXITCODE -ne 0) { throw "go build failed" } }
  finally { Pop-Location }
}

if ($SingBox -ne "") {
  $dataDir = Join-Path $env:APPDATA "OpenRoute"
  New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
  Copy-Item $SingBox (Join-Path $dataDir "sing-box.exe") -Force
  Write-Host "Using sing-box from $SingBox"
}

$installArgs = @("install")
if ($ExtensionId -ne "") { $installArgs += @("--extension-id", $ExtensionId) }
& $bin @installArgs
if ($LASTEXITCODE -ne 0) { throw "install failed" }
& $bin doctor
