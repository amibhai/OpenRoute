# Packages OpenRoute into distributable zips (Chrome/Edge + Firefox).
# Output: dist/openroute-chrome-<ver>.zip, dist/openroute-firefox-<ver>.zip
# Run:    powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$dist = Join-Path $root "dist"

$ver = (Get-Content (Join-Path $root "manifest.json") -Raw | ConvertFrom-Json).version
Write-Host "Building OpenRoute $ver"

# What ships in the extension: the manifest plus src/ and the license; icons
# are copied as PNGs only (companion/, server/, tests, docs, tooling excluded).
$items = @("src", "LICENSE")

New-Item -ItemType Directory -Force -Path $dist | Out-Null
Add-Type -AssemblyName System.IO.Compression | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

# Compress-Archive on Windows PowerShell writes backslash separators, which the
# ZIP spec forbids and browser stores reject — so build entries by hand with
# forward slashes.
function New-Zip($zipPath, $stageDir) {
  if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
  $fs = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew)
  $arch = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
  try {
    Get-ChildItem -Path $stageDir -Recurse -File | ForEach-Object {
      $rel = $_.FullName.Substring($stageDir.Length + 1).Replace('\', '/')
      $entry = $arch.CreateEntry($rel, [System.IO.Compression.CompressionLevel]::Optimal)
      $es = $entry.Open()
      $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
      $es.Write($bytes, 0, $bytes.Length)
      $es.Dispose()
    }
  } finally {
    $arch.Dispose(); $fs.Dispose()
  }
}

function Build-Zip($target, $manifestSrc) {
  $stage = Join-Path $env:TEMP ("openroute-" + $target + "-" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path $stage | Out-Null
  Copy-Item (Join-Path $root $manifestSrc) (Join-Path $stage "manifest.json")
  foreach ($i in $items) { Copy-Item (Join-Path $root $i) (Join-Path $stage $i) -Recurse }
  New-Item -ItemType Directory -Force -Path (Join-Path $stage "icons") | Out-Null
  Get-ChildItem (Join-Path $root "icons") -Filter *.png | Copy-Item -Destination (Join-Path $stage "icons")

  $zip = Join-Path $dist ("openroute-" + $target + "-" + $ver + ".zip")
  New-Zip $zip $stage
  Remove-Item $stage -Recurse -Force
  $kb = [math]::Round((Get-Item $zip).Length / 1KB, 1)
  Write-Host ("  " + (Split-Path $zip -Leaf) + " (" + $kb + " KB)")
}

Build-Zip "chrome"  "manifest.json"
Build-Zip "firefox" "manifest.firefox.json"
Write-Host "Done → $dist"
