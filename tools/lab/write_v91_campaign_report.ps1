[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EvidenceRoot
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $EvidenceRoot).Path
$ledgerPath = Join-Path $root 'V91-CASE-LEDGER.json'
if (-not (Test-Path -LiteralPath $ledgerPath -PathType Leaf)) {
    throw "Campaign ledger is missing: $ledgerPath"
}
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
if ($ledger.schema -ne 'ese.v91.campaign-ledger/v1' -or $ledger.counts.total -ne 26) {
    throw 'Campaign ledger schema or mandatory case count is invalid.'
}

$executed = @($ledger.cases | Where-Object executed)
$partial = @($ledger.cases | Where-Object {
    $_.execution_state -eq 'PARTIAL_COMPLETE'
})
$failures = @($ledger.cases | Where-Object status -eq 'FAIL')
$blocked = @($ledger.cases | Where-Object status -eq 'BLOCKED')

$summary = [ordered]@{
    schema = 'ese.v91.campaign-final/v1'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    candidate_commit = $ledger.candidate_commit
    candidate_binary_sha256 = $ledger.candidate_binary_sha256
    gate_decision = $ledger.gate_decision
    formal_counts = $ledger.counts
    executed_case_count = $executed.Count
    completed_partial_case_count = $partial.Count
    failing_case_ids = @($failures.id)
    blocked_case_ids = @($blocked.id)
    cases = @($ledger.cases)
}
$jsonPath = Join-Path $root 'V91-CAMPAIGN-FINAL.json'
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding utf8

$manifestItems = [System.Collections.Generic.List[object]]::new()
$evidencePaths = @($ledger.cases.evidence | Sort-Object -Unique)
foreach ($relative in $evidencePaths) {
    $fullPath = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "Ledger evidence is missing while building manifest: $relative"
    }
    $item = Get-Item -LiteralPath $fullPath
    $manifestItems.Add([pscustomobject][ordered]@{
        path = $relative.Replace('\', '/')
        bytes = $item.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $fullPath).Hash.ToLowerInvariant()
    })
}
$manifest = [ordered]@{
    schema = 'ese.v91.evidence-manifest/v1'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    candidate_commit = $ledger.candidate_commit
    candidate_binary_sha256 = $ledger.candidate_binary_sha256
    evidence_file_count = $manifestItems.Count
    files = @($manifestItems)
}
$manifestPath = Join-Path $root 'V91-EVIDENCE-MANIFEST.json'
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('# V9.1 mandatory campaign result')
$lines.Add('')
$lines.Add("- Candidate commit: ``$($ledger.candidate_commit)``")
$lines.Add("- Candidate binary SHA-256: ``$($ledger.candidate_binary_sha256)``")
$lines.Add("- Formal gate: **$($ledger.gate_decision)**")
$lines.Add("- Formal results: $($ledger.counts.pass) PASS, $($ledger.counts.fail) FAIL, $($ledger.counts.blocked) BLOCKED")
$lines.Add("- Executed formally: $($ledger.counts.executed_formal); executed with completed partial evidence: $($ledger.counts.executed_partial)")
$lines.Add('')
$lines.Add('`BLOCKED` is not counted as `PASS`, including cases with useful same-host partial evidence.')
$lines.Add('')
$lines.Add('## Mandatory cases')
$lines.Add('')
$lines.Add('| Case | Formal result | Execution | Reason |')
$lines.Add('|---|---|---|---|')
foreach ($case in $ledger.cases) {
    $reason = ([string]$case.reason).Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ')
    $lines.Add("| ``$($case.id)`` | $($case.status) | $($case.execution_state) | $reason |")
}
$lines.Add('')
$lines.Add('## Release decision')
$lines.Add('')
if ($ledger.gate_decision -eq 'GO') {
    $lines.Add('All mandatory cases passed. This candidate satisfies the formal gate.')
} else {
    $lines.Add('This exact candidate does not satisfy the formal release gate. Resolve every FAIL and execute every BLOCKED case on its required topology before claiming the full matrix.')
}
$markdownPath = Join-Path $root 'V91-CAMPAIGN-FINAL.md'
$lines | Set-Content -LiteralPath $markdownPath -Encoding utf8

Write-Host "Campaign final JSON written: $jsonPath"
Write-Host "Campaign final Markdown written: $markdownPath"
Write-Host "Evidence SHA-256 manifest written: $manifestPath"
