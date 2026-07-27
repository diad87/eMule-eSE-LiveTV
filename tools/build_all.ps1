# build_all.ps1 -- v9 prerelease pipeline (PowerShell 5.1 compatible).
[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [Parameter(Mandatory = $true)][string]$ReleaseTag,
    [string[]]$Skip = @(),
    [string]$FfmpegPath = '',
    [ValidateRange(0, 64)][int]$MaxCpuCount = 0,
    [switch]$AllowDirty,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$startedAt = Get-Date
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
$RepoRoot = (Resolve-Path $RepoRoot).Path
if ($Skip.Count -gt 0 -and -not $AllowDirty) {
    throw (
        'Official release pipeline gates cannot be skipped. ' +
        'Use -AllowDirty only for an explicitly non-releasable development run.'
    )
}
if ($DryRun -and -not $AllowDirty) {
    throw (
        'An official release pipeline cannot be a dry run. ' +
        'Use -AllowDirty for an explicitly non-releasable preview.'
    )
}
. (Join-Path $RepoRoot 'tools\release_fingerprint.ps1')
$logDir = Join-Path $RepoRoot 'tools\build_logs'
New-Item -ItemType Directory $logDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$emuleBuildStamp = Join-Path $logDir 'emule-release-build.json.log'
$eseBuildStamp = Join-Path $logDir 'ese-release-build.json.log'
$languageBuildStamp = Join-Path $logDir 'languages-release-build.json.log'
$officialHead = ''

function Header([string]$Title) {
    Write-Host "`n$('=' * 72)" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
}
function Stage([string]$Name, [scriptblock]$Body) {
    if ($Skip -contains $Name) { Write-Host "[skip] $Name" -ForegroundColor DarkGray; return }
    Header $Name
    if ($DryRun) { Write-Host '[dry-run]'; return }
    Assert-OfficialHead -Context "before $Name"
    $before = Get-Date
    & $Body
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
    Assert-OfficialHead -Context "after $Name"
    Write-Host ("[PASS] {0} ({1:N1}s)" -f $Name, ((Get-Date) - $before).TotalSeconds) -ForegroundColor Green
}
function Assert-OfficialHead([string]$Context) {
    if (-not $officialHead -or $AllowDirty -or $DryRun) { return }
    $currentHead = (& git -C $RepoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $currentHead -ne $officialHead) {
        throw (
            "Repository HEAD changed during the official release pipeline " +
            "($Context): expected $officialHead, found $currentHead"
        )
    }
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
function Assert-SafeRepositoryPath([string]$Path) {
    $root = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\')
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($full -ne $root -and -not $full.StartsWith(
            $root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Generated-output path escaped the repository: $full"
    }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Generated-output path traverses a reparse point: $($item.FullName)"
            }
        }
        if ($cursor.Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
            return
        }
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent -eq $cursor) {
            throw "Generated-output path has no trusted repository parent: $full"
        }
        $cursor = $parent.TrimEnd('\')
    }
}
function Assert-NoReparseTree([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root)) { return }
    $rootItem = Get-Item -LiteralPath $Root -Force
    if (($rootItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Generated-output root is a reparse point: $($rootItem.FullName)"
    }
    if (-not $rootItem.PSIsContainer) {
        throw "Generated-output root is not a directory: $($rootItem.FullName)"
    }
    $pending = [Collections.Generic.Stack[IO.DirectoryInfo]]::new()
    $pending.Push([IO.DirectoryInfo]$rootItem)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entry in $directory.EnumerateFileSystemInfos()) {
            if (($entry.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Generated-output tree contains a reparse point: $($entry.FullName)"
            }
            if (($entry.Attributes -band
                    [IO.FileAttributes]::Directory) -ne 0) {
                $pending.Push([IO.DirectoryInfo]$entry)
            }
        }
    }
}

$msbuild = Find-MSBuild
if (-not $msbuild -and -not $DryRun) { throw 'MSBuild not found (Visual Studio 2022 C++ workload is required).' }
$msbuildParallelArg = if ($MaxCpuCount -gt 0) { "/m:$MaxCpuCount" } else { '/m' }
$env:ESE_RELEASE_TAG = $ReleaseTag

Header "eMule eSE $ReleaseTag"
Write-Host "Repo:      $RepoRoot"
Write-Host "MSBuild:   $msbuild"
Write-Host "MSBuild parallelism: $msbuildParallelArg"
Write-Host "Skip:      $($Skip -join ', ')"
if ($AllowDirty) { Write-Host 'WARNING: dirty-worktree development mode' -ForegroundColor Yellow }

Stage 'preflight' {
    $args = @{ ReleaseTag = $ReleaseTag; RepoRoot = $RepoRoot }
    if ($AllowDirty) { $args.AllowDirty = $true }
    & (Join-Path $RepoRoot 'tools\release_preflight.ps1') @args
}
if (-not $AllowDirty -and -not $DryRun) {
    $officialHead = (& git -C $RepoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $officialHead) {
        throw 'Could not capture the official release commit'
    }
    Write-Host "Pinned release commit: $officialHead"
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
        $msbuildParallelArg /v:minimal /nologo /fl /flp:"LogFile=$log;Verbosity=normal"
    if ($LASTEXITCODE -ne 0) { throw "emule build failed; see $log" }
    $emuleBinary = Join-Path $RepoRoot 'srchybrid\x64\Release\emule.exe'
    if (-not (Test-Path $emuleBinary)) { throw 'emule.exe was not produced' }
    $expectedVersion = $ReleaseTag -replace '^v0\.70b-eSE', ''
    $fileVersion = (Get-Item -LiteralPath $emuleBinary).VersionInfo.FileVersion
    if ([string]$fileVersion -notlike "*eSE $expectedVersion*") {
        throw "emule.exe version '$fileVersion' does not identify $expectedVersion"
    }
    Write-ReleaseBinaryStamp -RepoRoot $RepoRoot -ReleaseTag $ReleaseTag `
        -Component emule -BinaryPath $emuleBinary -StampPath $emuleBuildStamp
}

Stage 'tests-integration' {
    & (Join-Path $RepoRoot 'tools\run_alpha_tests.ps1') -RepoRoot $RepoRoot -Suite Integration
}

Stage 'cleanup-libutp' {
    # libutp is a pinned submodule whose upstream .gitignore predates VS2022.
    # Its x64 output has already been linked into emule.exe. Historical VS
    # property sheets and command-line OutDir overrides have used three
    # different generated roots; remove only those verified roots so stale
    # output from an earlier build cannot make package provenance fail.
    $submoduleRoot = (Resolve-Path (Join-Path $RepoRoot 'libutp')).Path.TrimEnd('\') + '\'
    foreach ($relativeGenerated in @('x64', 'Build\x64', 'libutp\x64')) {
        $generated = [IO.Path]::GetFullPath((Join-Path $submoduleRoot $relativeGenerated))
        if (-not $generated.StartsWith($submoduleRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "unsafe libutp cleanup target: $generated"
        }
        Assert-SafeRepositoryPath -Path $generated
        if (Test-Path -LiteralPath $generated) {
            Assert-NoReparseTree -Root $generated
            Remove-Item -LiteralPath $generated -Recurse -Force
        }
    }
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
        $eseBinary = Join-Path $eseDir 'ese-server.exe'
        if (-not (Test-Path $eseBinary)) { throw 'ese-server.exe was not produced' }
        Write-ReleaseBinaryStamp -RepoRoot $RepoRoot -ReleaseTag $ReleaseTag `
            -Component ese -BinaryPath $eseBinary -StampPath $eseBuildStamp
    } finally { Pop-Location }
}

Stage 'langs' {
    $projectPaths = @(& git -C $RepoRoot -c core.quotepath=false ls-files -- `
        'srchybrid/lang/*.vcxproj')
    if ($LASTEXITCODE -ne 0 -or $projectPaths.Count -eq 0) {
        throw 'failed to enumerate tracked language projects'
    }
    $projects = @($projectPaths | Sort-Object -Unique | ForEach-Object {
        Get-Item -LiteralPath (Join-Path $RepoRoot $_)
    })
    & (Join-Path $RepoRoot 'tools\check_languages.ps1') -RepoRoot $RepoRoot
    $langOutputDir = Join-Path $RepoRoot 'srchybrid\x64\Release\lang'
    # The projects share one legacy output/intermediate tree and copy each DLL
    # into two mirrors. Remove all three generated roots once, before any Build,
    # so neither MSBuild's incremental checks nor a stale mirror can reuse an
    # earlier release. Rebuild per project is unsafe because each Clean would
    # remove outputs produced by the preceding language.
    foreach ($languageGeneratedRoot in @(
        (Join-Path $RepoRoot 'srchybrid\lang\x64\Dynamic'),
        (Join-Path $RepoRoot 'srchybrid\x64\lang'),
        $langOutputDir
    )) {
        Assert-SafeRepositoryPath -Path $languageGeneratedRoot
        if (Test-Path -LiteralPath $languageGeneratedRoot) {
            Assert-NoReparseTree -Root $languageGeneratedRoot
            Remove-Item -LiteralPath $languageGeneratedRoot -Recurse -Force
        }
    }
    foreach ($project in $projects) {
        $log = Join-Path $logDir "lang-$($project.BaseName)-$stamp.log"
        # Language projects share a legacy IntDir. Rebuild would let every
        # project delete the previous project's .res file; Build is the safe
        # deterministic operation once the source tree is clean.
        & $msbuild $project.FullName /t:Build /p:Configuration=Dynamic /p:Platform=x64 `
            /p:PlatformToolset=v143 $msbuildParallelArg /v:quiet /nologo /fl /flp:"LogFile=$log;ErrorsOnly"
        if ($LASTEXITCODE -ne 0) { throw "language build failed: $($project.Name); see $log" }
    }
    $dlls = @(Get-ChildItem -LiteralPath $langOutputDir -Filter '*.dll' `
        -File -Force -ErrorAction SilentlyContinue)
    if ($dlls.Count -eq 0) { throw 'no language DLLs were produced' }
    & (Join-Path $RepoRoot 'tools\check_languages.ps1') -RepoRoot $RepoRoot `
        -RuntimeDir (Join-Path $RepoRoot 'srchybrid\x64\Release')
    Write-ReleaseLanguageStamp -RepoRoot $RepoRoot -ReleaseTag $ReleaseTag `
        -RuntimeDir (Join-Path $RepoRoot 'srchybrid\x64\Release') `
        -StampPath $languageBuildStamp
}

Stage 'cleanup-generated-metadata' {
    if ($AllowDirty) { return }

    # bundle_client.js and npm ci are deterministic, but autocrlf can leave the
    # bundle or package-lock stat-dirty even when the normalized blobs are
    # unchanged. Refresh the index and reject any real generated-source drift.
    $generatedSources = @(
        'srchybrid/eSE/_player_bundle.js',
        'srchybrid/eSE/package-lock.json'
    )
    & git -C $RepoRoot add -- $generatedSources
    if ($LASTEXITCODE -ne 0) { throw 'failed to refresh generated Node metadata' }
    $staged = @(& git -C $RepoRoot diff --cached --name-only)
    if ($LASTEXITCODE -ne 0) { throw 'failed to inspect generated metadata' }
    if ($staged.Count -gt 0) {
        throw "generated source drifted during build: $($staged -join ', ')"
    }
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
    $packageRootPrefix = [IO.Path]::GetFullPath($packageDir).TrimEnd('\') + '\'
    $verifiedHashes = 0
    foreach ($line in Get-Content -LiteralPath (Join-Path $packageDir 'SHA256SUMS.txt')) {
        if ($line -notmatch '^([0-9A-Fa-f]{64})  (.+)$') {
            throw "package smoke malformed SHA256SUMS line: $line"
        }
        $expectedHash = $matches[1].ToUpperInvariant()
        $relativePath = $matches[2].Replace('/', '\')
        $candidatePath = [IO.Path]::GetFullPath((Join-Path $packageDir $relativePath))
        if (-not $candidatePath.StartsWith($packageRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "package smoke SHA256SUMS path escapes package: $relativePath"
        }
        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            throw "package smoke SHA256SUMS entry is missing: $relativePath"
        }
        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidatePath).Hash
        if ($actualHash -ne $expectedHash) {
            throw "package smoke hash mismatch: $relativePath"
        }
        $verifiedHashes++
    }
    if ($verifiedHashes -eq 0) { throw 'package smoke SHA256SUMS is empty' }
    Write-Host "Package hashes: $verifiedHashes verified"
    & (Join-Path $RepoRoot 'tools\check_languages.ps1') -RepoRoot $RepoRoot -RuntimeDir $packageDir
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
                $response = Invoke-WebRequest `
                    -Uri 'http://127.0.0.1:48123/api/status' `
                    -UseBasicParsing -TimeoutSec 2
                $ready = ($response.StatusCode -eq 200)
            } catch { }
        }
        if (-not $ready) { throw 'ese-server.exe startup smoke failed' }

        $status = $response.Content | ConvertFrom-Json
        $expectedVersion = $ReleaseTag -replace '^v0\.70b-eSE', ''
        if ([string]$status.version -ne $expectedVersion -or
            [bool]$status.hasPublicUrl -or [bool]$status.hasTunnel -or
            [string]$status.remoteAccess -ne 'postponed') {
            throw 'ese-server.exe runtime identity or local-only status is stale'
        }

        $listeners = @(Get-NetTCPConnection -State Listen `
            -OwningProcess $serverProcess.Id -LocalPort 48123 `
            -ErrorAction Stop)
        if ($listeners.Count -eq 0) {
            throw 'ese-server.exe has no inspectable loopback listener'
        }
        $unsafeListeners = @($listeners | Where-Object {
            $_.LocalAddress -notin @('127.0.0.1', '::1')
        })
        if ($unsafeListeners.Count -gt 0) {
            throw (
                'ese-server.exe exposed a non-loopback listener: ' +
                (($unsafeListeners.LocalAddress | Sort-Object -Unique) -join ', ')
            )
        }

        foreach ($closedRoute in @(
            @{ Path = '/api/connect-seed'; Method = 'GET' },
            @{ Path = '/api/tunnel/status'; Method = 'GET' },
            @{ Path = '/api/live/tunnel/start'; Method = 'POST' },
            @{ Path = '/api/live/tunnel/stop'; Method = 'POST' },
            @{ Path = '/api/live/tunnel/status'; Method = 'GET' },
            @{ Path = '/api/eSE/update/check'; Method = 'GET' },
            @{ Path = '/api/live/update_check'; Method = 'POST' },
            @{ Path = '/api/live/update_run'; Method = 'POST' }
        )) {
            $code = 0
            $body = ''
            try {
                $closedResponse = Invoke-WebRequest `
                    -Uri ('http://127.0.0.1:48123' + $closedRoute.Path) `
                    -Method $closedRoute.Method -UseBasicParsing -TimeoutSec 2
                $code = [int]$closedResponse.StatusCode
                $body = [string]$closedResponse.Content
            } catch {
                if ($_.Exception.Response) {
                    $code = [int]$_.Exception.Response.StatusCode
                    $reader = New-Object IO.StreamReader(
                        $_.Exception.Response.GetResponseStream()
                    )
                    try { $body = $reader.ReadToEnd() }
                    finally { $reader.Dispose() }
                } else {
                    throw
                }
            }
            if ($code -ne 410) {
                throw "ese-server.exe route did not fail closed: $($closedRoute.Path) ($code)"
            }
            $closedPayload = $body | ConvertFrom-Json
            if ([string]$closedPayload.reason -notin @(
                    'remote_access_postponed', 'manual_updates_only')) {
                throw "ese-server.exe returned an unexpected closure reason: $($closedRoute.Path)"
            }
        }
    } finally {
        if ($serverProcess -and -not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue }
        $env:ESE_TEST_MODE = $oldTestMode
        $env:ESE_PORT = $oldPort
    }
    & (Join-Path $packageDir 'ffmpeg.exe') -hide_banner -version 2>&1 | Select-Object -First 1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'ffmpeg smoke failed' }
}

if ($AllowDirty) {
    Header 'Development pipeline complete (NOT RELEASABLE)'
    if ($Skip.Count -gt 0) {
        Write-Host "Skipped gates: $($Skip -join ', ')" -ForegroundColor Yellow
    }
} else {
    Header 'Release pipeline complete'
}
Write-Host ("Total: {0:N1} minutes" -f ((Get-Date) - $startedAt).TotalMinutes)
Write-Host "Artifacts: $(Join-Path $RepoRoot "dist\$ReleaseTag")" -ForegroundColor Green
