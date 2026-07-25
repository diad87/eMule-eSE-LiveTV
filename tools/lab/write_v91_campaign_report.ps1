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
