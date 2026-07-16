# build_all.ps1 -- v9 alpha release pipeline (PowerShell 5.1 compatible).
[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [Parameter(Mandatory = $true)][string]$ReleaseTag,
    [string[]]$Skip = @(),
    [string]$FfmpegPath = '',
    [switch]$AllowDirty,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$startedAt = Get-Date
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
$RepoRoot = (Resolve-Path $RepoRoot).Path
$logDir = Join-Path $RepoRoot 'tools\build_logs'
New-Item -ItemType Directory $logDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

function Header([string]$Title) {
    Write-Host "`n$('=' * 72)" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
}
function Stage([string]$Name, [scriptblock]$Body) {
    if ($Skip -contains $Name) { Write-Host "[skip] $Name" -ForegroundColor DarkGray; return }
    Header $Name
    if ($DryRun) { Write-Host '[dry-run]'; return }
    $before = Get-Date
    & $Body
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
    Write-Host ("[PASS] {0} ({1:N1}s)" -f $Name, ((Get-Date) - $before).TotalSeconds) -ForegroundColor Green
}
function Find-MSBuild {
    $cmd = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $root = & $vswhere -latest -prerelease -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($root) {
            $candidate = Join-Path $root 'MSBuild\Current\Bin\MSBuild.exe'
            if (Test-Path $candidate) { return $candidate }
        }
    }
    return $null
}

$msbuild = Find-MSBuild
if (-not $msbuild -and -not $DryRun) { throw 'MSBuild not found (Visual Studio 2022 C++ workload is required).' }
$env:ESE_RELEASE_TAG = $ReleaseTag

Header "eMule eSE $ReleaseTag"
Write-Host "Repo:      $RepoRoot"
Write-Host "MSBuild:   $msbuild"
Write-Host "Skip:      $($Skip -join ', ')"
if ($AllowDirty) { Write-Host 'WARNING: dirty-worktree development mode' -ForegroundColor Yellow }

Stage 'preflight' {
    $args = @{ ReleaseTag = $ReleaseTag; RepoRoot = $RepoRoot }
    if ($AllowDirty) { $args.AllowDirty = $true }
    & (Join-Path $RepoRoot 'tools\release_preflight.ps1') @args
}

Stage 'tests-core' {
    & (Join-Path $RepoRoot 'tools\run_alpha_tests.ps1') -RepoRoot $RepoRoot -Suite Core
}

Stage 'libutp' {
    $project = Join-Path $RepoRoot 'libutp\libutp.vcxproj'
    $outDir = Join-Path $RepoRoot 'libutp\x64\Release'
    $intDir = Join-Path $outDir 'obj'
    $log = Join-Path $logDir "libutp-$stamp.log"
    & $msbuild $project /t:Rebuild /p:Configuration=Release /p:Platform=x64 `
        /p:PlatformToolset=v143 /p:OutDir="$outDir\" /p:IntDir="$intDir\" `
        /v:minimal /nologo /fl /flp:"LogFile=$log;Verbosity=normal"
    if ($LASTEXITCODE -ne 0) { throw "libutp build failed; see $log" }
    if (-not (Test-Path (Join-Path $outDir 'libutp.lib'))) { throw 'libutp.lib was not produced' }
}

Stage 'emule' {
    $log = Join-Path $logDir "emule-$stamp.log"
    & $msbuild (Join-Path $RepoRoot 'srchybrid\emule.sln') /t:Rebuild `
        /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 `
        /m /v:minimal /nologo /fl /flp:"LogFile=$log;Verbosity=normal"
    if ($LASTEXITCODE -ne 0) { throw "emule build failed; see $log" }
    if (-not (Test-Path (Join-Path $RepoRoot 'srchybrid\x64\Release\emule.exe'))) { throw 'emule.exe was not produced' }
}

Stage 'tests-integration' {
    & (Join-Path $RepoRoot 'tools\run_alpha_tests.ps1') -RepoRoot $RepoRoot -Suite Integration
}

Stage 'cleanup-libutp' {
    # libutp is a pinned submodule whose upstream .gitignore predates VS2022.
    # Its x64 output has already been linked into emule.exe; remove only that
    # verified generated directory so the package provenance remains clean.
    $submoduleRoot = (Resolve-Path (Join-Path $RepoRoot 'libutp')).Path.TrimEnd('\') + '\'
    $generated = [IO.Path]::GetFullPath((Join-Path $submoduleRoot 'x64'))
    if (-not $generated.StartsWith($submoduleRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "unsafe libutp cleanup target: $generated"
    }
    if (Test-Path -LiteralPath $generated) { Remove-Item -LiteralPath $generated -Recurse -Force }
    $submoduleStatus = @(& git -C (Join-Path $RepoRoot 'libutp') status --porcelain=v1)
    if ($submoduleStatus.Count -gt 0) { throw 'libutp is dirty after generated-output cleanup' }
}

Stage 'ese' {
    $eseDir = Join-Path $RepoRoot 'srchybrid\eSE'
    Push-Location $eseDir
    try {
        & npm.cmd ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
        & npm.cmd run build
        if ($LASTEXITCODE -ne 0) { throw 'npm run build failed' }
        if (-not (Test-Path (Join-Path $eseDir 'ese-server.exe'))) { throw 'ese-server.exe was not produced' }
    } finally { Pop-Location }
}

Stage 'langs' {
    $projects = Get-ChildItem (Join-Path $RepoRoot 'srchybrid\lang\*.vcxproj')
    foreach ($project in $projects) {
        $log = Join-Path $logDir "lang-$($project.BaseName)-$stamp.log"
        # Language projects share a legacy IntDir. Rebuild would let every
        # project delete the previous project's .res file; Build is the safe
        # deterministic operation once the source tree is clean.
        & $msbuild $project.FullName /t:Build /p:Configuration=Dynamic /p:Platform=x64 `
            /p:PlatformToolset=v143 /m /v:quiet /nologo /fl /flp:"LogFile=$log;ErrorsOnly"
        if ($LASTEXITCODE -ne 0) { throw "language build failed: $($project.Name); see $log" }
    }
    $dlls = @(Get-ChildItem (Join-Path $RepoRoot 'srchybrid\x64\lang\*.dll') -ErrorAction SilentlyContinue)
    if ($dlls.Count -eq 0) { throw 'no language DLLs were produced' }
}

Stage 'package' {
    $args = @{ ReleaseTag = $ReleaseTag; RepoRoot = $RepoRoot }
    if ($FfmpegPath) { $args.FfmpegPath = $FfmpegPath }
    if ($AllowDirty) { $args.AllowDirty = $true }
    & (Join-Path $RepoRoot 'build_package.ps1') @args
}

Stage 'package-smoke' {
    $packageDir = Join-Path $RepoRoot "dist\$ReleaseTag\package"
    foreach ($required in @('emule.exe','ese-server.exe','ffmpeg.exe','ffprobe.exe','config\preferences.ini','config\nodes.dat','BUILD_INFO.txt','SHA256SUMS.txt')) {
        if (-not (Test-Path (Join-Path $packageDir $required) -PathType Leaf)) { throw "package smoke missing $required" }
    }
    $oldTestMode = $env:ESE_TEST_MODE
    $oldPort = $env:ESE_PORT
    $serverProcess = $null
    try {
        $env:ESE_TEST_MODE = '1'
        $env:ESE_PORT = '48123'
        $serverProcess = Start-Process -FilePath (Join-Path $packageDir 'ese-server.exe') -WorkingDirectory $packageDir -PassThru -WindowStyle Hidden
        $ready = $false
        for ($attempt = 0; $attempt -lt 30 -and -not $ready; $attempt++) {
            Start-Sleep -Milliseconds 250
            try {
                $response = Invoke-WebRequest -Uri 'http://127.0.0.1:48123/' -UseBasicParsing -TimeoutSec 2
                $ready = ($response.StatusCode -eq 200)
            } catch { }
        }
        if (-not $ready) { throw 'ese-server.exe startup smoke failed' }
    } finally {
        if ($serverProcess -and -not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue }
        $env:ESE_TEST_MODE = $oldTestMode
        $env:ESE_PORT = $oldPort
    }
    & (Join-Path $packageDir 'ffmpeg.exe') -hide_banner -version 2>&1 | Select-Object -First 1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'ffmpeg smoke failed' }
}

Header 'Release pipeline complete'
Write-Host ("Total: {0:N1} minutes" -f ((Get-Date) - $startedAt).TotalMinutes)
Write-Host "Artifacts: $(Join-Path $RepoRoot "dist\$ReleaseTag")" -ForegroundColor Green
