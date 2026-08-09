# Installs the OpenRoute native companion for Chrome/Edge on Windows.
#
#   .\install-windows.ps1 -ExtId <your-unpacked-extension-id> [-SingBox C:\path\sing-box.exe]
#
# Find <ExtId> at chrome://extensions (Developer mode) under the OpenRoute card.
param(
  [Parameter(Mandatory = $true)][string]$ExtId,
  [string]$SingBox = ""
)
$ErrorActionPreference = "Stop"

$companion = Split-Path -Parent $PSScriptRoot          # ...\companion
$bin = Join-Path $companion "bin\openroute-host.exe"

Write-Host "Building companion (go build)..."
New-Item -ItemType Directory -Force -Path (Split-Path $bin) | Out-Null
Push-Location $companion
try { & go build -o $bin . ; if ($LASTEXITCODE -ne 0) { throw "go build failed" } }
finally { Pop-Location }

$dataDir = Join-Path $env:APPDATA "OpenRoute"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
if ($SingBox -ne "") {
  Copy-Item $SingBox (Join-Path $dataDir "sing-box.exe") -Force
  Write-Host "Bundled sing-box from $SingBox"
}

$manifest = [ordered]@{
  name            = "com.openroute.host"
  description     = "OpenRoute native companion"
  path            = $bin
  type            = "stdio"
  allowed_origins = @("chrome-extension://$ExtId/")
} | ConvertTo-Json -Depth 4
$manifestPath = Join-Path $dataDir "com.openroute.host.json"
$manifest | Set-Content -Path $manifestPath -Encoding utf8

# Register the host for Chrome and Edge (per-user, no admin needed).
foreach ($root in @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.openroute.host",
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.openroute.host")) {
  New-Item -Path $root -Force | Out-Null
  Set-ItemProperty -Path $root -Name "(default)" -Value $manifestPath
}

Write-Host "Installed."
Write-Host "  binary:   $bin"
Write-Host "  manifest: $manifestPath"
Write-Host "Reload the extension, open the popup — companion should read 'connected'."
