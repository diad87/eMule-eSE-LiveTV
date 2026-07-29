[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)][string]$BuildManifest,
    [ValidateRange(1, 900)][int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$exe = (Resolve-Path -LiteralPath $Executable).Path
$manifestPath = (Resolve-Path -LiteralPath $BuildManifest).Path
$root = [IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $root) { throw 'OutputRoot already exists; refuse to mix MOD-0.2 evidence.' }
New-Item -ItemType Directory -Path $root | Out-Null
$stdout = Join-Path $root 'selftest.stdout.log'
$stderr = Join-Path $root 'selftest.stderr.log'
$markerPath = Join-Path $root 'mod02-selftest-markers.log'
if (Test-Path -LiteralPath $markerPath) { throw 'MOD-0.2 marker file unexpectedly pre-exists.' }

$criticalSourceRelativePaths = @(
    'srchybrid/EmuleDlg.cpp',
    'srchybrid/LiveTunnel.cpp', 'srchybrid/LiveTunnel.h',
    'srchybrid/LiveCellQueue.cpp', 'srchybrid/LiveCellQueue.h',
    'srchybrid/WebServer.cpp', 'srchybrid/WebServer.h',
    'srchybrid/LiveStreamManager.cpp', 'srchybrid/LiveStreamManager.h'
)
$identityHeaderRelativePath = 'srchybrid/Mod02BuildIdentity.h'
$cleanCheckRelativePaths = @($criticalSourceRelativePaths + $identityHeaderRelativePath)

function Get-Mod02SourceIdentity([string]$Root, [string[]]$RelativePaths) {
    $lines = @()
    foreach ($relativePath in $RelativePaths) {
        $path = Join-Path $Root $relativePath
        if (-not (Test-Path -LiteralPath $path)) { throw "Missing critical source: $relativePath" }
        $rawHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines += "$relativePath=$rawHash"
    }
    $payload = [Text.UTF8Encoding]::new($false).GetBytes([string]::Join("`n", $lines))
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($payload))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
try {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    throw "MOD-0.2 build manifest is invalid JSON: $($_.Exception.Message)"
}
$requiredManifestFields = @('schema', 'source_commit', 'source_identity_sha256', 'executable_sha256')
$actualManifestFields = @($manifest.PSObject.Properties.Name | Sort-Object)
$expectedManifestFields = @($requiredManifestFields | Sort-Object)
$manifestFieldsDiffer = [bool](Compare-Object $actualManifestFields $expectedManifestFields)
if (($actualManifestFields.Count -ne $expectedManifestFields.Count) -or
    $manifestFieldsDiffer -or
    ($manifest.schema -ne 'ese.mod02.build-manifest/v1')) {
    throw 'MOD-0.2 build manifest must use the exact v1 schema and fields.'
}
foreach ($field in @('source_commit', 'source_identity_sha256', 'executable_sha256')) {
    $value = [string]$manifest.$field
    if ([string]::IsNullOrWhiteSpace($value)) { throw "MOD-0.2 build manifest has an empty $field." }
}
if (($manifest.source_identity_sha256 -notmatch '^[0-9a-f]{64}$') -or
    ($manifest.executable_sha256 -notmatch '^[0-9a-f]{64}$')) {
    throw 'MOD-0.2 build manifest hashes must be lowercase SHA-256 values.'
}

$actualCommit = (& git -C $sourceRoot rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0) { throw 'Unable to determine source commit for MOD-0.2 evidence.' }
if ($actualCommit -ne $manifest.source_commit.ToLowerInvariant()) {
    throw "Source commit mismatch: manifest has $($manifest.source_commit), found $actualCommit."
}
$dirtyCriticalSources = & git -C $sourceRoot status --porcelain -- $cleanCheckRelativePaths
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect critical source cleanliness for MOD-0.2 evidence.' }
if ($dirtyCriticalSources) {
    throw "Build manifest requires a clean critical source tree: $($dirtyCriticalSources -join '; ')"
}
$sourceTreeClean = $true
$sourceIdentity = Get-Mod02SourceIdentity $sourceRoot $criticalSourceRelativePaths
if ($sourceIdentity -ne $manifest.source_identity_sha256) {
    throw "Critical source identity mismatch: manifest has $($manifest.source_identity_sha256), found $sourceIdentity."
}

$executableHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($executableHash -ne $manifest.executable_sha256) {
    throw 'Executable SHA-256 mismatch; refusing to run an unexpected artifact.'
}
$criticalSources = $criticalSourceRelativePaths | ForEach-Object { Join-Path $sourceRoot $_ }
$latestSourceWriteUtc = ($criticalSources | ForEach-Object {
    (Get-Item -LiteralPath $_).LastWriteTimeUtc
} | Sort-Object -Descending | Select-Object -First 1)
$executableWriteUtc = (Get-Item -LiteralPath $exe).LastWriteTimeUtc
if ($executableWriteUtc -lt $latestSourceWriteUtc) {
    throw 'Executable is older than a characterized source seam; rebuild before running MOD-0.2.'
}

$process = Start-Process -FilePath $exe -ArgumentList '--portable','--ignoreinstances','--selftest' `
    -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr -PassThru
$timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
$taskkillStarted = $false
$taskkillFinished = $true
$taskkillExitCode = $null
$terminationConfirmed = $true
if ($timedOut) {
    $taskkillStarted = $true
    $taskkillOut = Join-Path $root 'taskkill.stdout.log'
    $taskkillErr = Join-Path $root 'taskkill.stderr.log'
    $taskkill = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\taskkill.exe') `
        -ArgumentList '/PID', "$($process.Id)", '/T', '/F' -WindowStyle Hidden `
        -RedirectStandardOutput $taskkillOut -RedirectStandardError $taskkillErr -PassThru
    $taskkillFinished = $taskkill.WaitForExit(10000)
    if ($taskkillFinished) {
        $taskkillExitCode = [int]$taskkill.ExitCode
    } else {
        try { $taskkill.Kill() } catch { }
    }
    $terminationConfirmed = $process.WaitForExit(5000)
}
$exitCode = if ($timedOut -or -not $terminationConfirmed) { $null } else { [int]$process.ExitCode }
$expectedMarkers = @(
    "SOURCE $sourceIdentity",
    'BEGIN CLiveTunnel', 'PASS CLiveTunnel',
    'BEGIN CWebServer', 'PASS CWebServer',
    'BEGIN CLiveStreamManager', 'PASS CLiveStreamManager'
)
$markersVerified = $false
$markerHash = $null
$observedMarkers = @()
if (-not $timedOut -and $terminationConfirmed -and (Test-Path -LiteralPath $markerPath)) {
    $actualMarkers = [IO.File]::ReadAllLines($markerPath)
    $markersVerified = ([string]::Join("`n", $actualMarkers) -ceq [string]::Join("`n", $expectedMarkers))
    $observedMarkers = @($actualMarkers | ForEach-Object {
        if ($expectedMarkers -contains $_) { $_ } else { 'UNRECOGNIZED_MARKER' }
    })
    $markerHash = (Get-FileHash -LiteralPath $markerPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
$summary = [ordered]@{
    schema = 'ese.mod02.stream-selftest/v1'
    build_manifest_sha256 = $manifestHash
    source_commit = $actualCommit
    source_identity_sha256 = $sourceIdentity
    source_tree_clean = $sourceTreeClean
    executable_sha256 = $executableHash
    executable_write_utc = $executableWriteUtc.ToString('o')
    latest_critical_source_write_utc = $latestSourceWriteUtc.ToString('o')
    timeout_seconds = $TimeoutSeconds
    timed_out = $timedOut
    taskkill_started = $taskkillStarted
    taskkill_finished = $taskkillFinished
    taskkill_exit_code = $taskkillExitCode
    termination_confirmed = $terminationConfirmed
    exit_code = $exitCode
    expected_markers = $expectedMarkers
    observed_markers_sanitized = $observedMarkers
    markers_verified = $markersVerified
    marker_sha256 = $markerHash
    verdict = if ((-not $timedOut) -and $terminationConfirmed -and ($exitCode -eq 0) -and $markersVerified) { 'PASS' } else { 'FAIL' }
    command = '--portable --ignoreinstances --selftest'
    isolation = 'portable unique output root; no UI'
}
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $root 'summary.json') -Encoding UTF8
if ($timedOut) { throw "MOD-0.2 stream selftest timed out after $TimeoutSeconds seconds (termination_confirmed=$terminationConfirmed)." }
if (-not $terminationConfirmed) { throw 'MOD-0.2 stream selftest termination was not confirmed within five seconds.' }
if ($exitCode -ne 0) { throw "MOD-0.2 stream selftest failed: $exitCode" }
if (-not $markersVerified) { throw 'MOD-0.2 stream selftest exited without the exact source and coordinator proof markers.' }
Write-Host 'MOD-0.2 stream selftest PASS'
