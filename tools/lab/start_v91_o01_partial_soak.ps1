[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][int]$SourceProcessId,
    [Parameter(Mandatory = $true)][int]$ViewerProcessId,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidateRange(600, 43200)][int]$DurationSeconds = 19800
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

foreach ($id in $SourceProcessId, $ViewerProcessId) {
    if (-not (Get-Process -Id $id -ErrorAction SilentlyContinue)) {
        throw "Required eMule process is unavailable: $id"
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
    formal_limitation = 'V91-O01 requires 12 hours and T1/T5; this is a 5.5-hour continuation on two isolated exact-candidate profiles on dual-stack H1 with an active IPv6 Live route.'
    candidate_commit = '72a5a41ebeec1bd08bff7ed17df27782930d96e3'
    candidate_binary_sha256 = '82360915292df613320af889e7680c69efcf422df9d8052b3613041a0a42da14'
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
