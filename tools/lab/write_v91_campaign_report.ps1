[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [string]$LedgerPath = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

function Get-V91ReportProperty {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-V91ReportIdentity {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $commits = [System.Collections.Generic.List[string]]::new()
    $hashes = [System.Collections.Generic.List[string]]::new()
    foreach ($name in 'candidate_commit', 'expected_candidate_commit') {
        $value = [string](Get-V91ReportProperty $Object $name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $commits.Add($value.ToLowerInvariant())
        }
    }
    foreach ($name in 'candidate_binary_sha256', 'candidate_emule_sha256',
        'expected_emule_sha256') {
        $value = [string](Get-V91ReportProperty $Object $name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $hashes.Add($value.ToLowerInvariant())
        }
    }
    $nested = Get-V91ReportProperty $Object 'candidate'
    foreach ($name in 'commit', 'candidate_commit',
        'expected_candidate_commit') {
        $value = [string](Get-V91ReportProperty $nested $name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $commits.Add($value.ToLowerInvariant())
        }
    }
    foreach ($name in 'emule_sha256', 'binary_sha256',
        'candidate_binary_sha256', 'candidate_emule_sha256',
        'expected_emule_sha256', 'emule_sha256_before',
        'emule_sha256_after') {
        $value = [string](Get-V91ReportProperty $nested $name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $hashes.Add($value.ToLowerInvariant())
        }
    }
    $uniqueCommits = @($commits | Sort-Object -Unique)
    $uniqueHashes = @($hashes | Sort-Object -Unique)
    if ($uniqueCommits.Count -gt 1 -or $uniqueHashes.Count -gt 1) {
        throw "$Context contains conflicting candidate identity values."
    }
    return [pscustomobject][ordered]@{
        commit = if ($uniqueCommits.Count -eq 1) {
            $uniqueCommits[0]
        } else { '' }
        emule_sha256 = if ($uniqueHashes.Count -eq 1) {
            $uniqueHashes[0]
        } else { '' }
    }
}

$root = (Resolve-Path -LiteralPath $EvidenceRoot).Path
if (-not $LedgerPath) {
    $LedgerPath = Join-Path $root 'V91-RC-LEDGER.json'
}
$ledgerPath = [IO.Path]::GetFullPath($LedgerPath)
if (-not (Test-Path -LiteralPath $ledgerPath -PathType Leaf)) {
    throw "Campaign ledger is missing: $ledgerPath"
}
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
if ($ledger.schema -ne 'ese.v91.rc-ledger/v2' -or $ledger.counts.total -ne 27) {
    throw 'Campaign ledger schema or mandatory case count is invalid.'
}
if ($null -eq $ledger.candidate -or
    [string]$ledger.candidate.commit -notmatch '^[0-9a-fA-F]{40}$' -or
    [string]$ledger.candidate.emule_sha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'Campaign ledger candidate identity is invalid.'
}
$expectedCommit = ([string]$ledger.candidate.commit).ToLowerInvariant()
$expectedEmuleHash =
    ([string]$ledger.candidate.emule_sha256).ToLowerInvariant()

$expectedIds = @(
    'V91-A01', 'V91-A02',
    'V91-I01', 'V91-I02', 'V91-I03', 'V91-I04', 'V91-I05', 'V91-I06',
    'V91-I07', 'V91-I08', 'V91-D01',
    'V91-P01', 'V91-P02', 'V91-P03',
    'V91-K01', 'V91-K02', 'V91-K03', 'V91-K04',
    'V91-C01', 'V91-C02', 'V91-C03', 'V91-C04',
    'V91-S01', 'V91-S02', 'V91-S03', 'V91-R01', 'V91-O01'
)
$cases = @($ledger.cases)
if ($cases.Count -ne $expectedIds.Count) {
    throw "Campaign ledger must contain exactly $($expectedIds.Count) cases."
}
$expectedIdSet = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
$seenIdSet = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
foreach ($expectedId in $expectedIds) {
    $null = $expectedIdSet.Add($expectedId)
}
foreach ($case in $cases) {
    $caseId = [string]$case.id
    if (-not $expectedIdSet.Contains($caseId) -or
        -not $seenIdSet.Add($caseId)) {
        throw 'Campaign ledger case IDs do not match the normative V91 matrix.'
    }
}
if ($seenIdSet.Count -ne $expectedIdSet.Count) {
    throw 'Campaign ledger is missing a normative V91 case ID.'
}
foreach ($case in $cases) {
    $status = ([string]$case.status).ToUpperInvariant()
    if ($status -notin 'PASS', 'FAIL', 'BLOCKED') {
        throw "$($case.id) has an invalid formal status."
    }
    if ($case.executed -isnot [bool]) {
        throw "$($case.id) executed must be a JSON boolean."
    }
    if ($status -eq 'PASS' -and (
            -not [bool]$case.executed -or
            [string]$case.execution_state -ne 'COMPLETE' -or
            @($case.evidence).Count -eq 0 -or
            [string]::IsNullOrWhiteSpace([string]$case.reason))) {
        throw "$($case.id) has an inadmissible PASS."
    }
}

$executed = @($cases | Where-Object executed)
$partial = @($ledger.cases | Where-Object {
    $_.execution_state -eq 'PARTIAL_COMPLETE'
})
$failures = @($cases | Where-Object status -eq 'FAIL')
$blocked = @($cases | Where-Object status -eq 'BLOCKED')
$passed = @($cases | Where-Object status -eq 'PASS')
$computedCounts = [ordered]@{
    total = $cases.Count
    pass = $passed.Count
    fail = $failures.Count
    blocked = $blocked.Count
    executed = $executed.Count
}
foreach ($name in 'total', 'pass', 'fail', 'blocked', 'executed') {
    if ($ledger.counts.PSObject.Properties.Name -notcontains $name -or
        [int]$ledger.counts.$name -ne [int]$computedCounts.$name) {
        throw "Campaign ledger count '$name' is inconsistent with its cases."
    }
}
$computedDecision = if ($computedCounts.pass -eq $expectedIds.Count -and
    $computedCounts.fail -eq 0 -and $computedCounts.blocked -eq 0) {
    'GO'
} else { 'NO_GO' }
if ([string]$ledger.gate_decision -ne $computedDecision) {
    throw 'Campaign ledger gate decision is inconsistent with its cases.'
}

$jsonPath = Join-Path $root 'V91-CAMPAIGN-FINAL.json'
$manifestPath = Join-Path $root 'V91-EVIDENCE-MANIFEST.json'
$markdownPath = Join-Path $root 'V91-CAMPAIGN-FINAL.md'
$reservedOutputPaths = @($jsonPath, $manifestPath, $markdownPath)
$manifestItems = [System.Collections.Generic.List[object]]::new()
$evidencePaths = @($cases |
    ForEach-Object { @($_.evidence) } |
    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
    Sort-Object -Unique)
$evidenceIdentityByPath = @{}
foreach ($relative in $evidencePaths) {
    try {
        $fullPath = Resolve-LabContainedFile -Root $root `
            -RelativePath $relative
    } catch {
        throw "Ledger evidence is not a contained regular file: $relative"
    }
    if (@($reservedOutputPaths | Where-Object {
            [string]::Equals(
                [IO.Path]::GetFullPath($_),
                [IO.Path]::GetFullPath($fullPath),
                [StringComparison]::OrdinalIgnoreCase)
        }).Count -gt 0) {
        throw "Ledger evidence collides with a generated report path: $relative"
    }
    $identityBound = $false
    if ([IO.Path]::GetExtension($fullPath) -eq '.json') {
        try {
            $evidenceJson = Get-Content -LiteralPath $fullPath -Raw |
                ConvertFrom-Json
        } catch {
            throw "Ledger evidence is invalid JSON: $relative"
        }
        $identity = Get-V91ReportIdentity -Object $evidenceJson `
            -Context "Evidence '$relative'"
        $hasCommit = -not [string]::IsNullOrWhiteSpace(
            [string]$identity.commit)
        $hasHash = -not [string]::IsNullOrWhiteSpace(
            [string]$identity.emule_sha256)
        if ($hasCommit -xor $hasHash) {
            throw "Evidence '$relative' contains an incomplete candidate identity."
        }
        if ($hasCommit) {
            if ([string]$identity.commit -notmatch '^[0-9a-f]{40}$' -or
                [string]$identity.emule_sha256 -notmatch '^[0-9a-f]{64}$' -or
                [string]$identity.commit -ne $expectedCommit -or
                [string]$identity.emule_sha256 -ne $expectedEmuleHash) {
                throw "Evidence '$relative' belongs to another candidate."
            }
            $identityBound = $true
        }
    }
    $evidenceIdentityByPath[[string]$relative] = $identityBound
    $item = Get-Item -LiteralPath $fullPath
    $manifestItems.Add([pscustomobject][ordered]@{
        path = $relative.Replace('\', '/')
        bytes = $item.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $fullPath).Hash.ToLowerInvariant()
    })
}
foreach ($case in $cases) {
    $boundEvidenceCount = @($case.evidence | Where-Object {
        $evidenceIdentityByPath[[string]$_]
    }).Count
    if ([string]$case.status -eq 'PASS' -and
        $boundEvidenceCount -lt 1) {
        throw "$($case.id) PASS has no evidence bound to the ledger candidate."
    }
    if ($case.PSObject.Properties.Name -notcontains
            'identity_evidence_count' -or
        [int]$case.identity_evidence_count -ne $boundEvidenceCount) {
        throw "$($case.id) identity evidence count is inconsistent."
    }
}

$manifest = [ordered]@{
    schema = 'ese.v91.evidence-manifest/v1'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    candidate = $ledger.candidate
    candidate_commit = $ledger.candidate.commit
    candidate_binary_sha256 = $ledger.candidate.emule_sha256
    evidence_file_count = $manifestItems.Count
    files = @($manifestItems)
}

$summary = [ordered]@{
    schema = 'ese.v91.campaign-final/v2'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    candidate = $ledger.candidate
    candidate_commit = $ledger.candidate.commit
    candidate_binary_sha256 = $ledger.candidate.emule_sha256
    gate_decision = $ledger.gate_decision
    formal_counts = $computedCounts
    executed_case_count = $executed.Count
    completed_partial_case_count = $partial.Count
    failing_case_ids = @($failures | ForEach-Object { [string]$_.id })
    blocked_case_ids = @($blocked | ForEach-Object { [string]$_.id })
    cases = @($cases)
}
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('# V9.1 mandatory campaign result')
$lines.Add('')
$lines.Add("- Candidate commit: ``$($ledger.candidate.commit)``")
$lines.Add("- Candidate binary SHA-256: ``$($ledger.candidate.emule_sha256)``")
$lines.Add("- Formal gate: **$($ledger.gate_decision)**")
$lines.Add("- Formal results: $($ledger.counts.pass) PASS, $($ledger.counts.fail) FAIL, $($ledger.counts.blocked) BLOCKED")
$lines.Add("- Executed formally: $($executed.Count); executed with completed partial evidence: $($partial.Count)")
$lines.Add('')
$lines.Add('`BLOCKED` is not counted as `PASS`, including cases with useful same-host partial evidence.')
$lines.Add('')
$lines.Add('## Mandatory cases')
$lines.Add('')
$lines.Add('| Case | Formal result | Execution | Reason |')
$lines.Add('|---|---|---|---|')
foreach ($case in $cases) {
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
$summary | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $jsonPath -Encoding utf8
$manifest | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath $manifestPath -Encoding utf8
$lines | Set-Content -LiteralPath $markdownPath -Encoding utf8

Write-Host "Campaign final JSON written: $jsonPath"
Write-Host "Campaign final Markdown written: $markdownPath"
Write-Host "Evidence SHA-256 manifest written: $manifestPath"
