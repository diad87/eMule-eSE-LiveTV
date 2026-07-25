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

$failures = [System.Collections.Generic.List[string]]::new()
foreach ($pair in @(
    [pscustomobject]@{ name = 'source'; verdict = $source.verdict },
    [pscustomobject]@{ name = 'viewer'; verdict = $viewer.verdict },
    [pscustomobject]@{ name = 'live'; verdict = $live.verdict }
)) {
    if ($pair.verdict -ne 'PASS') {
        $failures.Add("$($pair.name) monitor verdict is $($pair.verdict)")
    }
}
if ([int]$live.requested_duration_seconds -lt 7200) {
    $failures.Add('Live monitor did not request the mandatory two-hour duration')
}
if (-not [bool]$last.viewing) { $failures.Add('viewer was not active in the final sample') }
if (-not [bool]$last.playlist_valid) { $failures.Add('playlist was not valid in the final sample') }
if ([int]$last.chunks.missing -ne 0) { $failures.Add('final playlist window contains missing chunks') }
if ([int]$last.ipv6_connection_count -lt 1) { $failures.Add('no IPv6 data connection was observed') }
if ([int]$last.ipv4_fallback_count -ne 0) { $failures.Add('an IPv4 fallback was observed') }
if ([Int64]$last.counters.chunksReceived -le [Int64]$session.initial_chunks_received) {
    $failures.Add('chunk counter did not advance')
}

$summary = [ordered]@{
    schema = 'ese.v91.i02-partial-summary/v1'
    case_id = 'V91-I02'
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
        chunks_received_initial = [Int64]$session.initial_chunks_received
        chunks_received_final = [Int64]$last.counters.chunksReceived
        duplicate_chunks_final = [Int64]$last.counters.duplicateChunksReceived
        ipv6_connections_final = [int]$last.ipv6_connection_count
        ipv4_fallback_final = [int]$last.ipv4_fallback_count
        playlist_chunks_final = [int]$last.chunks.count
        playlist_missing_final = [int]$last.chunks.missing
    }
    failures = @($failures)
}
Write-LabJson -Value $summary -Path (Join-Path $evidence 'summary.json') | Out-Null
$outcome = if ($failures.Count -eq 0) { 'BLOCKED' } else { 'FAIL' }
& (Join-Path $PSScriptRoot 'collect_report.ps1') -RunDirectory $evidence `
    -CaseId 'V91-I02' -Outcome $outcome `
    -Version $(if ($session.candidate_version) {
        [string]$session.candidate_version
    } else {
        'unknown'
    }) `
    -Commit $session.candidate_commit `
    -Notes 'Exact two-hour IPv6 LiveTV run on isolated candidate profiles; formal T5 topology remains unavailable.'
if ($failures.Count -gt 0) {
    throw "V91-I02 partial soak failed: $($failures -join '; ')"
}
Write-Host "V91-I02 partial soak PASS: $evidence" -ForegroundColor Green
