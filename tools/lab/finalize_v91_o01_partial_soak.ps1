[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$output = (Resolve-Path -LiteralPath $OutputRoot).Path
$evidence = Join-Path $output 'evidence'
$session = Get-Content -LiteralPath (Join-Path $evidence 'session.json') -Raw |
    ConvertFrom-Json
$source = Get-Content -LiteralPath (Join-Path $evidence 'source-summary.json') -Raw |
    ConvertFrom-Json
$viewer = Get-Content -LiteralPath (Join-Path $evidence 'viewer-summary.json') -Raw |
    ConvertFrom-Json
$live = Get-Content -LiteralPath (Join-Path $evidence 'live-summary.json') -Raw |
    ConvertFrom-Json
$last = Get-Content -LiteralPath (Join-Path $evidence 'live-samples.jsonl') -Tail 1 |
    ConvertFrom-Json

$initialReceived = [Int64]$session.initial_counters.chunksReceived
$initialDuplicates = [Int64]$session.initial_counters.duplicateChunksReceived
$finalReceived = [Int64]$last.counters.chunksReceived
$finalDuplicates = [Int64]$last.counters.duplicateChunksReceived
$receivedDelta = $finalReceived - $initialReceived
$duplicateDelta = $finalDuplicates - $initialDuplicates
$deltaRatio = if ($receivedDelta -gt 0) {
    [double]$duplicateDelta / [double]$receivedDelta
} else { [double]::PositiveInfinity }
$initialRatio = if ($initialReceived -gt 0) {
    [double]$initialDuplicates / [double]$initialReceived
} else { 0.0 }
$finalRatio = if ($finalReceived -gt 0) {
    [double]$finalDuplicates / [double]$finalReceived
} else { [double]::PositiveInfinity }
$ratioDrift = $finalRatio - $initialRatio

$failures = [Collections.Generic.List[string]]::new()
foreach ($pair in @(
    [pscustomobject]@{ name = 'source'; verdict = $source.verdict },
    [pscustomobject]@{ name = 'viewer'; verdict = $viewer.verdict },
    [pscustomobject]@{ name = 'live'; verdict = $live.verdict }
)) {
    if ($pair.verdict -ne 'PASS') {
        $failures.Add("$($pair.name) monitor verdict is $($pair.verdict)")
    }
}
if ($receivedDelta -le 0) { $failures.Add('chunk counter did not advance') }
if ([int]$session.requested_duration_seconds -lt 43200) {
    $failures.Add('Soak did not request the mandatory 12-hour duration')
}
if ($duplicateDelta -lt 0) { $failures.Add('duplicate counter moved backwards') }
if ($deltaRatio -gt 0.25) {
    $failures.Add("duplicate delta ratio exceeded 25%: $([Math]::Round($deltaRatio * 100, 3))%")
}
if ($ratioDrift -gt 0.05) {
    $failures.Add("cumulative duplicate ratio accelerated by more than 5 points: $([Math]::Round($ratioDrift * 100, 3))")
}
if ([Int64]$last.counters.peerDisconnects -
    [Int64]$session.initial_counters.peerDisconnects -gt 0) {
    $failures.Add('peer disconnect counter increased')
}
if ([int]$last.ipv4_fallback_count -ne 0) {
    $failures.Add('an IPv4 fallback was observed on the active IPv6 Live route')
}
if ([int]$last.chunks.missing -ne 0) {
    $failures.Add('final playlist window contains missing chunks')
}

$summary = [ordered]@{
    schema = 'ese.v91.o01-partial-summary/v1'
    case_id = 'V91-O01'
    formal_status = 'BLOCKED'
    formal_limitation = $session.formal_limitation
    candidate_commit = $session.candidate_commit
    candidate_binary_sha256 = $session.candidate_binary_sha256
    started_at_utc = $session.started_at_utc
    finished_at_utc = Get-LabUtcTimestamp
    requested_duration_seconds = [int]$session.requested_duration_seconds
    partial_verdict = if ($failures.Count -eq 0) { 'PASS' } else { 'FAIL' }
    monitor_verdicts = [ordered]@{
        source = $source.verdict
        viewer = $viewer.verdict
        live = $live.verdict
    }
    resource_growth = [ordered]@{
        source_working_set_bytes = $source.working_set_growth_bytes
        source_handles = $source.handle_growth
        viewer_working_set_bytes = $viewer.working_set_growth_bytes
        viewer_handles = $viewer.handle_growth
    }
    traffic = [ordered]@{
        chunks_received_delta = $receivedDelta
        duplicate_chunks_delta = $duplicateDelta
        duplicate_delta_ratio = [Math]::Round($deltaRatio, 6)
        initial_cumulative_duplicate_ratio = [Math]::Round($initialRatio, 6)
        final_cumulative_duplicate_ratio = [Math]::Round($finalRatio, 6)
        cumulative_ratio_drift = [Math]::Round($ratioDrift, 6)
        ipv4_fallback_last_sample = [int]$last.ipv4_fallback_count
        missing_chunks_last_sample = [int]$last.chunks.missing
    }
    failures = @($failures)
}
Write-LabJson -Value $summary -Path (Join-Path $evidence 'summary.json') | Out-Null
$outcome = 'BLOCKED'
& (Join-Path $PSScriptRoot 'collect_report.ps1') -RunDirectory $evidence `
    -CaseId 'V91-O01' -Outcome $outcome `
    -Version $(if ($session.candidate_version) {
        [string]$session.candidate_version
    } else {
        'unknown'
    }) `
    -Commit $session.candidate_commit `
    -Notes 'Partial long soak on one physical host; formal 12-hour two-host T1 topology remains unavailable. A partial_verdict failure does not adjudicate the formal case.'
if ($failures.Count -gt 0) {
    throw "V91-O01 partial regression failed; formal status remains BLOCKED: $($failures -join '; ')"
}
Write-Host "V91-O01 partial soak PASS: $evidence" -ForegroundColor Green
