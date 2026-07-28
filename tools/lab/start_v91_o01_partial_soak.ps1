[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][int]$SourceProcessId,
    [Parameter(Mandatory = $true)][int]$ViewerProcessId,
    [Parameter(Mandatory = $true)][string]$CandidatePackage,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidateRange(600, 86400)][int]$DurationSeconds = 43200,
    [string]$Commit = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$candidate = Get-LabCandidateInfo -PackagePath $CandidatePackage `
    -ExpectedCommit $Commit
foreach ($id in $SourceProcessId, $ViewerProcessId) {
    $process = Get-Process -Id $id -ErrorAction SilentlyContinue
    if (-not $process) {
        throw "Required eMule process is unavailable: $id"
    }
    if ((Get-LabSha256 -Path $process.Path) -ne $candidate.emule_sha256) {
        throw "Process $id is not running the exact candidate binary"
    }
}

$output = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $output) {
    throw "OutputRoot already exists: $output"
}
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
$logs = New-LabDirectory -Path (Join-Path $output 'logs')
$specs = @(
    [ordered]@{
        name = 'source'
        script = Join-Path $PSScriptRoot 'soak_monitor.ps1'
        args = @(
            '-NodeRole', 'A', '-BaseUrl', 'http://127.0.0.1:4811',
            '-TargetProcessId', [string]$SourceProcessId, '-RequireProcess',
            '-DurationSeconds', [string]$DurationSeconds,
            '-IntervalSeconds', '60', '-MaxWorkingSetGrowthMB', '256',
            '-MaxHandleGrowth', '1024',
            '-OutFile', (Join-Path $evidence 'source-summary.json'),
            '-SamplesFile', (Join-Path $evidence 'source-samples.jsonl')
        )
    },
    [ordered]@{
        name = 'viewer'
        script = Join-Path $PSScriptRoot 'soak_monitor.ps1'
        args = @(
            '-NodeRole', 'B', '-BaseUrl', 'http://127.0.0.1:4911',
            '-TargetProcessId', [string]$ViewerProcessId, '-RequireProcess',
            '-DurationSeconds', [string]$DurationSeconds,
            '-IntervalSeconds', '60', '-MaxWorkingSetGrowthMB', '256',
            '-MaxHandleGrowth', '1024',
            '-OutFile', (Join-Path $evidence 'viewer-summary.json'),
            '-SamplesFile', (Join-Path $evidence 'viewer-samples.jsonl')
        )
    },
    [ordered]@{
        name = 'live'
        script = Join-Path $PSScriptRoot 'live_ipv6_soak_monitor.ps1'
        args = @(
            '-BaseUrl', 'http://127.0.0.1:4911',
            '-TargetProcessId', [string]$ViewerProcessId,
            '-ExpectedRemotePort', '6662',
            '-DurationSeconds', [string]$DurationSeconds,
            '-IntervalSeconds', '30',
            '-OutFile', (Join-Path $evidence 'live-summary.json'),
            '-SamplesFile', (Join-Path $evidence 'live-samples.jsonl')
        )
    }
)

$monitors = @()
foreach ($spec in $specs) {
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList (
        @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $spec.script) +
        $spec.args
    ) -RedirectStandardOutput (Join-Path $logs "$($spec.name).stdout.log") `
        -RedirectStandardError (Join-Path $logs "$($spec.name).stderr.log") `
        -WindowStyle Hidden -PassThru
    $monitors += [ordered]@{ name = $spec.name; process_id = $process.Id }
}

$debug = Invoke-RestMethod -Uri 'http://127.0.0.1:4911/api/live/debug' -TimeoutSec 5
$session = [ordered]@{
    schema = 'ese.v91.o01-partial-session/v1'
    case_id = 'V91-O01'
    formal_status = 'BLOCKED'
    formal_limitation = if ($DurationSeconds -ge 43200) {
        'The 12-hour duration is covered, but V91-O01 still requires two physical Windows hosts in T1; this run uses two isolated exact-candidate profiles on one dual-stack H1 with an active IPv6 Live route.'
    } else {
        'V91-O01 requires 12 hours between two physical Windows hosts in T1; this shorter run uses two isolated exact-candidate profiles on one dual-stack H1 with an active IPv6 Live route.'
    }
    candidate_version = $candidate.version
    candidate_commit = $candidate.commit
    candidate_binary_sha256 = $candidate.emule_sha256
    started_at_utc = Get-LabUtcTimestamp
    requested_duration_seconds = $DurationSeconds
    source_process_id = $SourceProcessId
    viewer_process_id = $ViewerProcessId
    host_stack = 'dual-stack'
    active_data_family = 'IPv6'
    initial_counters = $debug.counters
    monitors = $monitors
}
Write-LabJson -Value $session -Path (Join-Path $evidence 'session.json') | Out-Null
Write-Host "V91-O01 partial soak started: $output" -ForegroundColor Green
