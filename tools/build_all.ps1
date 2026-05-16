# build_all.ps1 -- master release pipeline for eMule eSE LiveTV.
#
# One command. End-to-end. Idempotent. Each stage independently skippable.
#
#   ./tools/build_all.ps1                              # full build
#   ./tools/build_all.ps1 -Skip ese                    # reuse existing ese-server.exe
#   ./tools/build_all.ps1 -Skip emule,langs            # only rebuild ese + package
#   ./tools/build_all.ps1 -ReleaseTag v0.70b-eSE7.1    # override version
#   ./tools/build_all.ps1 -DryRun                      # print plan, don't execute
#
# Stages:
#   1. emule.exe     - MSBuild srchybrid/emule.sln Release|x64
#   2. ese-server    - npm ci + npm run build inside srchybrid/eSE/
#   3. langs         - MSBuild each srchybrid/lang/*.vcxproj Dynamic|x64
#   4. package       - build_package.ps1 (zips everything for distribution)
#
# Exit codes: 0 = success; 1 = stage failed; 2 = bad arguments.
#
# IMPORTANT: this script is ASCII-only on purpose. PowerShell 5.1 reads
# script files as ANSI by default; UTF-8 chars without a BOM produce
# mojibake at parse time. See tools/build_ese_server.ps1 for the same
# convention.

[CmdletBinding()]
param(
    [string]   $RepoRoot   = '',
    [string]   $ReleaseTag = 'v0.70b-eSE7.0',
    [string[]] $Skip       = @(),
    [switch]   $DryRun
)

$ErrorActionPreference = 'Stop'
$startedAt = Get-Date

# Resolve repo root
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
    if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition | Split-Path -Parent }
}
if (-not (Test-Path (Join-Path $RepoRoot 'srchybrid\emule.sln'))) {
    Write-Host "ERROR: -RepoRoot doesn't look like the eMule repo (no srchybrid/emule.sln at $RepoRoot)" -ForegroundColor Red
    exit 2
}

$logDir = Join-Path $PSScriptRoot 'build_logs'
New-Item -ItemType Directory $logDir -Force -ErrorAction SilentlyContinue | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# Expose the release tag to child scripts (build_package.ps1 reads ESE_RELEASE_TAG)
$env:ESE_RELEASE_TAG = $ReleaseTag

# ---- Helpers ---------------------------------------------------------
function Header($title) {
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
}
function Step($name, [scriptblock]$body) {
    if ($Skip -contains $name) {
        Write-Host "  [skip] Skipped $name (per -Skip)" -ForegroundColor DarkGray
        return $true
    }
    Header "Stage: $name"
    if ($DryRun) {
        Write-Host "  [dry-run] would execute stage" -ForegroundColor DarkGray
        return $true
    }
    $stageStart = Get-Date
    try {
        & $body
        $dur = (Get-Date) - $stageStart
        Write-Host ("  [OK] {0} succeeded in {1:N1}s" -f $name, $dur.TotalSeconds) -ForegroundColor Green
        return $true
    } catch {
        $dur = (Get-Date) - $stageStart
        Write-Host ("  [FAIL] {0} after {1:N1}s: {2}" -f $name, $dur.TotalSeconds, $_) -ForegroundColor Red
        return $false
    }
}
function Find-MSBuild {
    $cmd = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # Env-var names with parens (ProgramFiles(x86)) need ${...} to escape.
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsRoot = & $vswhere -latest -prerelease -products * -requires Microsoft.Component.MSBuild -property installationPath 2>$null
        if ($vsRoot) {
            $cand = Join-Path $vsRoot 'MSBuild\Current\Bin\MSBuild.exe'
            if (Test-Path $cand) { return $cand }
        }
    }
    return $null
}

# ---- Pre-flight summary ----------------------------------------------
Header "eMule eSE LiveTV -- master build"
Write-Host "  Repo root:    $RepoRoot"
Write-Host "  Release tag:  $ReleaseTag"
Write-Host "  Stages:       1.emule  2.ese  3.langs  4.package"
if ($Skip) { Write-Host "  Skipping:     $($Skip -join ', ')" -ForegroundColor Yellow }
if ($DryRun) { Write-Host "  Mode:         DRY RUN (no actions)" -ForegroundColor Yellow }
Write-Host "  Logs:         $logDir"

$msbuild = Find-MSBuild
if (-not $msbuild) {
    if ($DryRun) {
        Write-Host "  MSBuild:      NOT FOUND (dry-run continues; real run would fail)" -ForegroundColor Yellow
    } else {
        Write-Host "ERROR: MSBuild not found. Install Visual Studio 2022 + 'Desktop development with C++'." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  MSBuild:      $msbuild"
}

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "WARNING: npm not on PATH. Stage 'ese' will fail unless you skip it." -ForegroundColor Yellow
}

# ---- Stage 1: emule.exe ----------------------------------------------
$ok = Step 'emule' {
    $log = Join-Path $logDir "emule-$stamp.log"
    Write-Host "  msbuild Release|x64 -> $log"
    & $msbuild (Join-Path $RepoRoot 'srchybrid\emule.sln') `
        /p:Configuration=Release /p:Platform=x64 /m /v:minimal /nologo `
        /fl /flp:"LogFile=$log;Verbosity=normal" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "MSBuild exited $LASTEXITCODE (see $log)" }
    $exe = Join-Path $RepoRoot 'srchybrid\x64\Release\emule.exe'
    if (-not (Test-Path $exe)) { throw "emule.exe not produced at $exe" }
    Write-Host ("  emule.exe = {0:N1} MB" -f ((Get-Item $exe).Length / 1MB))
}
if (-not $ok) { exit 1 }

# ---- Stage 2: ese-server.exe -----------------------------------------
$ok = Step 'ese' {
    $eseDir = Join-Path $RepoRoot 'srchybrid\eSE'
    Push-Location $eseDir
    try {
        if (-not (Test-Path (Join-Path $eseDir 'node_modules\pkg'))) {
            Write-Host "  node_modules/pkg missing - running npm ci..."
            & npm ci --no-audit --no-fund 2>&1 | ForEach-Object { "  [npm] $_" } | Write-Host
            if ($LASTEXITCODE -ne 0) { throw "npm ci failed ($LASTEXITCODE)" }
        }
        # Kill any running ese-server.exe so pkg can overwrite it
        Get-Process ese-server -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "  npm run build (pkg)..."
        & npm run build 2>&1 | ForEach-Object { "  [pkg] $_" } | Write-Host
        if ($LASTEXITCODE -ne 0) { throw "npm run build failed ($LASTEXITCODE)" }
        $exe = Join-Path $eseDir 'ese-server.exe'
        if (-not (Test-Path $exe)) { throw "ese-server.exe not produced" }
        Write-Host ("  ese-server.exe = {0:N1} MB" -f ((Get-Item $exe).Length / 1MB))
    } finally { Pop-Location }
}
if (-not $ok) { exit 1 }

# ---- Stage 3: language DLLs ------------------------------------------
$ok = Step 'langs' {
    $langSrc = Join-Path $RepoRoot 'srchybrid\lang'
    $projs = Get-ChildItem (Join-Path $langSrc '*.vcxproj') -ErrorAction SilentlyContinue
    if (-not $projs) { throw "No language projects found at $langSrc" }
    Write-Host ("  Building {0} language project(s)..." -f $projs.Count)
    $built = 0; $failed = 0
    foreach ($p in $projs) {
        $log = Join-Path $logDir "lang-$($p.BaseName)-$stamp.log"
        & $msbuild $p.FullName /p:Configuration=Dynamic /p:Platform=x64 `
            /v:quiet /nologo /m `
            /fl /flp:"LogFile=$log;ErrorsOnly" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $built++ }
        else { $failed++; Write-Host "    FAILED $($p.BaseName) - see $log" -ForegroundColor DarkYellow }
    }
    $outDir = Join-Path $RepoRoot 'srchybrid\x64\lang'
    $dllCount = if (Test-Path $outDir) { (Get-ChildItem "$outDir\*.dll").Count } else { 0 }
    Write-Host "  Built $built / failed $failed -> $dllCount DLL(s) at $outDir"
    if ($dllCount -eq 0) { throw "No language DLLs produced - check stage logs" }
}
if (-not $ok) { exit 1 }

# ---- Stage 4: package ZIP --------------------------------------------
$ok = Step 'package' {
    $script = Join-Path $RepoRoot 'build_package.ps1'
    if (-not (Test-Path $script)) { throw "build_package.ps1 not found at $script" }
    Write-Host "  Running build_package.ps1 (logs to console)..."
    # Run in-process so we inherit the $env:ESE_RELEASE_TAG override
    & $script
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { throw "build_package.ps1 exited $LASTEXITCODE" }
}
if (-not $ok) { exit 1 }

# ---- Done ------------------------------------------------------------
$totalDur = (Get-Date) - $startedAt
Header "Build complete"
Write-Host ("  Total time: {0:N1} minutes" -f $totalDur.TotalMinutes)
Write-Host "  Release tag: $ReleaseTag"

# Show the produced zip(s) on Desktop
$zips = Get-ChildItem "$env:USERPROFILE\OneDrive\Desktop\eSE-LiveTV-*-x64.zip" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 3
if ($zips) {
    Write-Host ""
    Write-Host "  Latest ZIPs on Desktop:" -ForegroundColor Green
    foreach ($z in $zips) {
        Write-Host ("    {0,-60} {1,8:N1} MB  {2}" -f $z.Name, ($z.Length / 1MB), $z.LastWriteTime)
    }
}
exit 0
