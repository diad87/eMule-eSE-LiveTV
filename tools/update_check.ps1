# update_check.ps1 -- D6: manual auto-update for eMule eSE LiveTV.
#
# Two modes:
#   1) -CheckOnly  -> just print {has_update,version,url,published_at} as JSON.
#                     Used by the Node side to render a "new version" badge.
#   2) (default)   -> interactive flow: check, prompt user, download,
#                     stop running emule + ese-server, replace files,
#                     restart via eSE.vbs.
#
# NEVER runs silently in the background. Always either prints JSON
# (CheckOnly) or shows a GUI MessageBox. Reason: a P2P binary should
# never auto-update without explicit user consent.
#
# Repo source defaults to the canonical GitHub repo. Override with
# -RepoOwner / -RepoName for a fork or with -ReleaseUrl for a fully
# custom feed (must return GitHub-shaped JSON).

[CmdletBinding()]
param(
    [string]$RepoOwner   = 'diad87',
    [string]$RepoName    = 'eMule-eSE-LiveTV',
    [string]$ReleaseUrl  = '',
    [string]$InstallDir  = '',
    [switch]$CheckOnly,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ── 1) Figure out which install we're updating ─────────────────────────────
if (-not $InstallDir) {
    # Default: the directory containing the running eSE.vbs / emule.exe.
    # Search common locations.
    $candidates = @(
        (Split-Path -Parent $PSCommandPath),
        (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
        "$env:USERPROFILE\Desktop\eSE-Package",
        "$env:USERPROFILE\Downloads\eSE-LiveTV-x64",
        "$env:LOCALAPPDATA\eSE"
    ) | Where-Object { Test-Path (Join-Path $_ 'emule.exe') } | Select-Object -First 1
    if ($candidates) { $InstallDir = $candidates }
}

# ── 2) Read current version (from BUILD_INFO.txt) ──────────────────────────
# v8.0.27 FIX: compare the eSE version NUMBER, not a commit SHA / build date.
# BUILD_INFO.txt carries a 'release:  v0.70b-eSE8.0.27' line; we pull the
# X.Y.Z that follows 'eSE'. The old logic looked for a 'commit:' line and a
# 'built ' (no colon) date that this file format never had, so it always
# fell through to "assume update" — the dashboard nagged about an update
# forever, even when running a build NEWER than the published release.
function Get-EseVer([string]$s) {
    if ($s -and ($s -match 'eSE[^0-9]*(\d+)\.(\d+)\.(\d+)')) {
        return "$($Matches[1]).$($Matches[2]).$($Matches[3])"
    }
    if ($s -and ($s -match '(\d+)\.(\d+)\.(\d+)')) {
        return "$($Matches[1]).$($Matches[2]).$($Matches[3])"
    }
    return ''
}
$currentVer = ''
$currentSha = ''
$buildInfoPath = if ($InstallDir) { Join-Path $InstallDir 'BUILD_INFO.txt' } else { '' }
if ($buildInfoPath -and (Test-Path $buildInfoPath)) {
    $bi = Get-Content $buildInfoPath -Raw
    if ($bi -match 'commit:\s*(\w+)') { $currentSha = $Matches[1] }
    $relLine = ($bi -split "`n" | Where-Object { $_ -match '^\s*release' } | Select-Object -First 1)
    $currentVer = Get-EseVer $relLine
    if (-not $currentVer) { $currentVer = Get-EseVer $bi }
}

# ── 3) Fetch latest release info from GitHub ───────────────────────────────
if (-not $ReleaseUrl) {
    $ReleaseUrl = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
}

try {
    $headers = @{ 'Accept' = 'application/vnd.github+json'; 'User-Agent' = 'eMule-eSE-Updater' }
    $rel = Invoke-RestMethod -Uri $ReleaseUrl -Headers $headers -TimeoutSec 15
} catch {
    if ($CheckOnly) {
        # Emit a parseable JSON so the Node side can surface the error.
        @{ has_update = $false; error = "$_" } | ConvertTo-Json -Compress
        exit 0
    }
    Write-Host "Could not reach the release feed: $_" -ForegroundColor Red
    exit 1
}

# tag_name like "v0.70b-eSE-2026-06-01"
$latestTag = $rel.tag_name
$latestSha = if ($rel.target_commitish) { $rel.target_commitish.Substring(0, [Math]::Min(7, $rel.target_commitish.Length)) } else { '' }
$latestDate = $rel.published_at
$asset = $rel.assets | Where-Object { $_.name -like 'eSE-LiveTV-*.zip' } | Select-Object -First 1
$dlUrl = if ($asset) { $asset.browser_download_url } else { '' }

# Is there an update? Compare the eSE version NUMBERS semantically.
#   - update only when the published release is STRICTLY newer than ours.
#   - if either side is unreadable, do NOT flag an update: a perpetual false
#     "new version" badge is worse than silence (the user can check manually).
$latestVer = Get-EseVer $latestTag
$hasUpdate = $false
if ($currentVer -and $latestVer) {
    try { $hasUpdate = ([version]$latestVer -gt [version]$currentVer) } catch { $hasUpdate = $false }
}

if ($CheckOnly) {
    @{
        has_update      = $hasUpdate
        current_version = $currentVer
        current_sha     = $currentSha
        latest_tag      = $latestTag
        latest_version  = $latestVer
        latest_built    = $latestDate
        download_url    = $dlUrl
        release_url     = $rel.html_url
    } | ConvertTo-Json -Compress
    exit 0
}

# ── 4) Interactive flow ────────────────────────────────────────────────────
if (-not $hasUpdate -and -not $Force) {
    Write-Host "You are running the latest version (current $currentVer, latest published $latestTag)." -ForegroundColor Green
    exit 0
}

if (-not $dlUrl) {
    Write-Host "Update $latestTag is available but the release has no eSE-LiveTV-*.zip asset attached." -ForegroundColor Yellow
    Write-Host "Open $($rel.html_url) and download manually."
    exit 1
}

if (-not $InstallDir) {
    Write-Host "Could not auto-detect the install directory. Re-run with -InstallDir 'C:\path\to\eSE-Package'." -ForegroundColor Yellow
    exit 1
}

Add-Type -AssemblyName System.Windows.Forms
$msg = "A new version is available:`n`n" +
       "  Current : $currentVer`n" +
       "  Latest  : $latestTag ($latestDate)`n`n" +
       "Download (~$([math]::Round($asset.size/1MB,1)) MB) and replace the install at`n" +
       "  $InstallDir ?`n`n" +
       "This will stop eMule + ese-server briefly."
$r = [System.Windows.Forms.MessageBox]::Show($msg, "eMule eSE - Update available",
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Information)
if ($r -ne 'Yes') { Write-Host 'Cancelled.'; exit 0 }

# Download
$tmpZip = Join-Path ([IO.Path]::GetTempPath()) ("eSE-update-" + [Guid]::NewGuid().Guid + '.zip')
Write-Host "Downloading $dlUrl -> $tmpZip"
Invoke-WebRequest -Uri $dlUrl -OutFile $tmpZip -TimeoutSec 600 -UseBasicParsing

# Stop running processes (best-effort, ignore failures)
foreach ($p in 'emule', 'ese-server', 'node') {
    Get-Process $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

# Extract over the install dir (overwriting)
Write-Host "Extracting to $InstallDir"
$shell = New-Object -ComObject Shell.Application
Expand-Archive -Path $tmpZip -DestinationPath $InstallDir -Force
Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue

# Re-launch via eSE.vbs if present
$vbs = Join-Path $InstallDir 'eSE.vbs'
if (Test-Path $vbs) {
    Write-Host "Restarting via eSE.vbs"
    Start-Process -FilePath 'wscript.exe' -ArgumentList "`"$vbs`"" -WorkingDirectory $InstallDir
} else {
    Write-Host "eSE.vbs not found at $vbs - start emule.exe manually."
}

Write-Host "Update complete." -ForegroundColor Green
exit 0
