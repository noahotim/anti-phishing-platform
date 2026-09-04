# PhishGuard auto-updater — run on any other PC (as the logged-in user, no admin needed)
# Downloads the latest signed Firefox build (v1.1.4, Noah URL default, 3-min bypass, auto-popup) and installs it.
# After this one run, future versions auto-update via update_url.

$ErrorActionPreference = "Stop"
$release = "v1.1.4"
$base = "https://github.com/noahotim/anti-phishing-platform/releases/download/$release"
$ffUrl = "$base/phishguard-firefox-signed.xpi"

Write-Output "PhishGuard updater — $release"

# Find Firefox profiles
$profilesRoot = Join-Path $env:APPDATA "Mozilla\Firefox\Profiles"
if (-not (Test-Path $profilesRoot)) { Write-Output "No Firefox profiles found at $profilesRoot"; exit 1 }

$profiles = Get-ChildItem $profilesRoot -Directory
if (-not $profiles) { Write-Output "No profiles found"; exit 1 }

# Download once to temp
$tmp = Join-Path $env:TEMP "phishguard-firefox-signed.xpi"
Write-Output "Downloading $ffUrl ..."
Invoke-WebRequest -Uri $ffUrl -OutFile $tmp -TimeoutSec 60
Write-Output "Downloaded $((Get-Item $tmp).Length) bytes"

# Try to stop Firefox gracefully so the XPI file is not locked
$wasRunning = Get-Process firefox -ErrorAction SilentlyContinue
if ($wasRunning) {
  Write-Output "Firefox is running — will close it briefly to update (session will restore)..."
  Get-Process firefox -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 4
}

$updated = 0
foreach ($p in $profiles) {
  $extDir = Join-Path $p.FullName "extensions"
  if (-not (Test-Path $extDir)) { continue }
  $dst = Join-Path $extDir "phishguard-guard@phishguard.local.xpi"
  try {
    Copy-Item $tmp $dst -Force
    Write-Output "Updated $($p.Name)"
    $updated++
  } catch {
    Write-Output "Failed $($p.Name): $($_.Exception.Message)"
  }
}

if ($wasRunning) {
  Write-Output "Restarting Firefox..."
  Start-Process -FilePath "C:\Program Files\Mozilla Firefox\firefox.exe" -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 3
}

Write-Output "Done — updated $updated profile(s). On next Firefox start, PhishGuard will be v1.1.4 (auto-popup, 3-min bypass, Noah URL)."
Write-Output "Chrome/Edge/Brave/Opera (sideloaded): download phishguard-chrome.zip from https://github.com/noahotim/anti-phishing-platform/releases/tag/$release , unzip, then chrome://extensions → Load unpacked → pick the folder (or click Reload if already loaded)."
