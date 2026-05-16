# build_ese_server.ps1
#
# PreBuildEvent helper for emule.vcxproj Release|x64. Keeps the bundled
# ese-server.exe in sync with srchybrid/eSE/**/*.js source.
#
# Logic:
#   1. If Node + npx are NOT on PATH -> warn and exit 0 (don't fail the
#      C++ build for users who only want emule.exe).
#   2. Compare mtime of newest .js / .json under srchybrid/eSE/ vs the
#      mtime of srchybrid/x64/Release/ese-server.exe.
#   3. If JS is newer (or exe missing) -> run `npm run build`, then
#      copy the produced ese-server.exe into x64/Release/.
#   4. Otherwise -> skip (no-op, fast).
#
# Exit code:
#   0  on success, skip, or recoverable warning.
#   1  only if rebuild was needed AND failed (build will then break loudly).
#
# Run manually:
#   powershell -ExecutionPolicy Bypass -File tools\build_ese_server.ps1
#
[CmdletBinding()]
param(
    [string]$RepoRoot = ''
)

$ErrorActionPreference = 'Continue'

# Resolve script + repo dirs reliably (older PS versions sometimes leave
# $PSScriptRoot empty when invoked via -File).
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $ScriptDir
}
$ese  = Join-Path $RepoRoot 'srchybrid\eSE'
$dest = Join-Path $RepoRoot 'srchybrid\x64\Release\ese-server.exe'
$src  = Join-Path $ese 'ese-server.exe'

function Info($msg) { Write-Host "[build_ese_server] $msg" }
function Warn($msg) { Write-Warning "[build_ese_server] $msg" }

# ── 1) Node availability ────────────────────────────────────────────────────
$node = Get-Command node -ErrorAction SilentlyContinue
$npx  = Get-Command npx  -ErrorAction SilentlyContinue
if (-not $node -or -not $npx) {
    Warn 'Node 18+ / npx not on PATH - skipping ese-server.exe rebuild. Install Node to enable auto-rebuild.'
    exit 0
}

# ── 2) Compare timestamps ───────────────────────────────────────────────────
if (-not (Test-Path $ese)) {
    Warn "Source dir not found: $ese - nothing to build."
    exit 0
}
$jsFiles = Get-ChildItem -Path $ese -Recurse -Include *.js,*.json -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\node_modules\\' }
if (-not $jsFiles) {
    Info 'No JS/JSON sources found - nothing to do.'
    exit 0
}
$newestJs = ($jsFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime

$needsBuild = $false
if (-not (Test-Path $dest)) {
    Info "Destination ese-server.exe missing - rebuild required."
    $needsBuild = $true
} else {
    $destMtime = (Get-Item $dest).LastWriteTime
    if ($newestJs -gt $destMtime) {
        Info ("Source JS newer than dest exe ($newestJs > $destMtime) - rebuild required.")
        $needsBuild = $true
    } else {
        Info ("ese-server.exe up to date (newest JS: $newestJs, exe: $destMtime). Skip.")
    }
}

if (-not $needsBuild) { exit 0 }

# ── 3) Rebuild + copy ───────────────────────────────────────────────────────
Push-Location $ese
try {
    # Install pkg if devDependencies/pkg is missing (first run on a clean clone).
    if (-not (Test-Path (Join-Path $ese 'node_modules\pkg'))) {
        Info 'pkg not installed - running npm install --no-audit --no-fund...'
        & npm install --no-audit --no-fund 2>&1 | ForEach-Object { Write-Host "  [npm] $_" }
        if ($LASTEXITCODE -ne 0) {
            Warn 'npm install failed; aborting rebuild but allowing C++ build to continue.'
            exit 0
        }
    }

    Info 'Running npm run build...'
    & npm run build 2>&1 | ForEach-Object { Write-Host "  [pkg] $_" }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $src)) {
        Warn 'pkg build failed or produced no ese-server.exe; existing bundle (if any) remains in place.'
        # Don't fail the C++ build - old exe still works.
        exit 0
    }

    # Copy into Release. Wait if a previous ese-server.exe is locked by a
    # running process; kill any zombie ese-server first to avoid sharing-violation.
    Info "Copying $src -> $dest"
    $procs = Get-Process ese-server -ErrorAction SilentlyContinue
    if ($procs) {
        Info ("Stopping {0} running ese-server process(es) so we can overwrite the exe..." -f $procs.Count)
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800
    }
    Copy-Item -Path $src -Destination $dest -Force
    if (-not (Test-Path $dest)) {
        Warn 'Copy failed (destination missing after copy) - investigate file locks.'
        exit 1
    }
    $newSize = [math]::Round((Get-Item $dest).Length / 1MB, 1)
    Info "OK - deployed ese-server.exe ($newSize MB) at $dest"
    exit 0
}
finally {
    Pop-Location
}
