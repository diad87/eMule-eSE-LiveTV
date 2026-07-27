[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CandidatePackage,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [string]$ResultsPath = '',
    [string]$OutputPath = '',
    [string]$Commit = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

function Get-V91PropertyValue {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-V91CandidateIdentity {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $commits = [System.Collections.Generic.List[string]]::new()
    $hashes = [System.Collections.Generic.List[string]]::new()
    foreach ($name in 'candidate_commit', 'expected_candidate_commit') {
        $value = [string](Get-V91PropertyValue -Object $Object -Name $name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $commits.Add($value.ToLowerInvariant())
        }
    }
    foreach ($name in 'candidate_binary_sha256', 'candidate_emule_sha256',
        'expected_emule_sha256') {
        $value = [string](Get-V91PropertyValue -Object $Object -Name $name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $hashes.Add($value.ToLowerInvariant())
        }
    }

    $nested = Get-V91PropertyValue -Object $Object -Name 'candidate'
    foreach ($name in 'commit', 'candidate_commit',
        'expected_candidate_commit') {
        $value = [string](Get-V91PropertyValue -Object $nested -Name $name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $commits.Add($value.ToLowerInvariant())
        }
    }
    foreach ($name in 'emule_sha256', 'binary_sha256',
        'candidate_binary_sha256', 'candidate_emule_sha256',
        'expected_emule_sha256', 'emule_sha256_before',
        'emule_sha256_after') {
        $value = [string](Get-V91PropertyValue -Object $nested -Name $name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $hashes.Add($value.ToLowerInvariant())
        }
    }

    $uniqueCommits = @($commits | Sort-Object -Unique)
    $uniqueHashes = @($hashes | Sort-Object -Unique)
    if ($uniqueCommits.Count -gt 1) {
        throw "$Context contains conflicting candidate commits."
    }
    if ($uniqueHashes.Count -gt 1) {
        throw "$Context contains conflicting candidate binary hashes."
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

function Assert-V91CandidateIdentity {
    param(
        [Parameter(Mandatory = $true)]$Identity,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$Required
    )

    $hasCommit = -not [string]::IsNullOrWhiteSpace(
        [string]$Identity.commit)
    $hasHash = -not [string]::IsNullOrWhiteSpace(
        [string]$Identity.emule_sha256)
    if ($hasCommit -xor $hasHash) {
        throw "$Context contains an incomplete candidate identity."
    }
    if (-not $hasCommit) {
        if ($Required) {
            throw "$Context is missing its candidate commit and binary hash."
        }
        return $false
    }
    if ([string]$Identity.commit -notmatch '^[0-9a-f]{40}$' -or
        [string]$Identity.emule_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "$Context contains a malformed candidate identity."
    }
    if ([string]$Identity.commit -ne [string]$Expected.commit -or
        [string]$Identity.emule_sha256 -ne
            [string]$Expected.emule_sha256) {
        throw "$Context belongs to another candidate."
    }
    return $true
}

$candidate = Get-LabCandidateInfo -PackagePath $CandidatePackage `
    -ExpectedCommit $Commit
$root = Get-LabFullPath -Path $EvidenceRoot
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "EvidenceRoot does not exist: $root"
}
if (-not $OutputPath) {
    $OutputPath = Join-Path $root 'V91-RC-LEDGER.json'
}
$OutputPath = Get-LabFullPath -Path $OutputPath

$definitions = @(
    [ordered]@{ id = 'V91-A01'; topology = 'build' },
    [ordered]@{ id = 'V91-A02'; topology = 'build' },
    [ordered]@{ id = 'V91-I01'; topology = 'T5' },
    [ordered]@{ id = 'V91-I02'; topology = 'T5' },
    [ordered]@{ id = 'V91-I03'; topology = 'T1/T2' },
    [ordered]@{ id = 'V91-I04'; topology = 'T1/T2' },
    [ordered]@{ id = 'V91-I05'; topology = 'T1' },
    [ordered]@{ id = 'V91-I06'; topology = 'T6' },
    [ordered]@{ id = 'V91-I07'; topology = 'T3' },
    [ordered]@{ id = 'V91-I08'; topology = 'T5' },
    [ordered]@{ id = 'V91-D01'; topology = 'T1/T2' },
    [ordered]@{ id = 'V91-P01'; topology = 'T0/T1' },
    [ordered]@{ id = 'V91-P02'; topology = 'T0/T1' },
    [ordered]@{ id = 'V91-P03'; topology = 'T0' },
    [ordered]@{ id = 'V91-K01'; topology = 'T5' },
    [ordered]@{ id = 'V91-K02'; topology = 'T1' },
    [ordered]@{ id = 'V91-K03'; topology = 'profiles' },
    [ordered]@{ id = 'V91-K04'; topology = 'T1/T5' },
    [ordered]@{ id = 'V91-C01'; topology = 'V1/H2' },
    [ordered]@{ id = 'V91-C02'; topology = 'T0' },
    [ordered]@{ id = 'V91-C03'; topology = 'T0/T1' },
    [ordered]@{ id = 'V91-C04'; topology = 'T0' },
    [ordered]@{ id = 'V91-S01'; topology = 'T5' },
    [ordered]@{ id = 'V91-S02'; topology = 'T5' },
    [ordered]@{ id = 'V91-S03'; topology = 'T1/T5' },
    [ordered]@{ id = 'V91-R01'; topology = 'T3' },
    [ordered]@{ id = 'V91-O01'; topology = 'T1/T5' }
)

$results = @()
$bundleIdentity = Get-V91CandidateIdentity -Object $null `
    -Context 'Results bundle'
$bundleIdentityValid = $false
if ($ResultsPath) {
    $resolvedResults = (Resolve-Path -LiteralPath $ResultsPath).Path
    $parsed = Get-Content -LiteralPath $resolvedResults -Raw | ConvertFrom-Json
    $parsedCases = Get-V91PropertyValue -Object $parsed -Name 'cases'
    $results = if ($null -ne $parsedCases) {
        $bundleIdentity = Get-V91CandidateIdentity -Object $parsed `
            -Context 'Results bundle'
        $bundleIdentityValid = Assert-V91CandidateIdentity `
            -Identity $bundleIdentity -Expected $candidate `
            -Context 'Results bundle'
        @($parsedCases)
    } else {
        @($parsed)
    }
}

$knownIds = @($definitions | ForEach-Object id)
$resultIds = @($results | ForEach-Object {
    [string](Get-V91PropertyValue -Object $_ -Name 'id')
})
if (@($resultIds | Where-Object {
        [string]::IsNullOrWhiteSpace($_)
    }).Count -gt 0) {
    throw 'Every result must contain a case ID.'
}
$unknownIds = @($resultIds | Where-Object { $_ -notin $knownIds })
if ($unknownIds.Count -gt 0) {
    throw "Results contain unknown case IDs: $($unknownIds -join ', ')"
}
$duplicates = @($resultIds | Group-Object | Where-Object Count -gt 1)
if ($duplicates.Count -gt 0) {
    throw "Results contain duplicate case IDs: $($duplicates.Name -join ', ')"
}

$resultById = @{}
foreach ($result in $results) {
    $resultById[[string]$result.id] = $result
}

$cases = foreach ($definition in $definitions) {
    $result = $resultById[$definition.id]
    if ($null -eq $result) {
        [pscustomobject][ordered]@{
            id = $definition.id
            status = 'BLOCKED'
            required_topology = $definition.topology
            executed = $false
            execution_state = 'NOT_RUN'
            reason = 'No result has been reconciled for this exact candidate.'
            evidence = @()
            identity_evidence_count = 0
        }
        continue
    }

    $status = ([string](Get-V91PropertyValue -Object $result `
        -Name 'status')).ToUpperInvariant()
    if ($status -notin 'PASS', 'FAIL', 'BLOCKED') {
        throw "$($definition.id) has invalid status '$status'"
    }
    $executedValue = Get-V91PropertyValue -Object $result -Name 'executed'
    if ($null -ne $executedValue -and $executedValue -isnot [bool]) {
        throw "$($definition.id) executed must be a JSON boolean."
    }
    $executed = $null -ne $executedValue -and [bool]$executedValue
    $executionState = [string](Get-V91PropertyValue -Object $result `
        -Name 'execution_state')
    if ([string]::IsNullOrWhiteSpace($executionState)) {
        $executionState = if ($executed) { 'COMPLETE' } else { 'NOT_RUN' }
    }
    $reason = [string](Get-V91PropertyValue -Object $result -Name 'reason')
    $evidenceValue = Get-V91PropertyValue -Object $result -Name 'evidence'
    $evidence = @()
    if ($null -ne $evidenceValue) {
        $evidence = @($evidenceValue | ForEach-Object { [string]$_ })
    }

    $resultIdentity = Get-V91CandidateIdentity -Object $result `
        -Context "$($definition.id) result"
    $resultIdentityValid = Assert-V91CandidateIdentity `
        -Identity $resultIdentity -Expected $candidate `
        -Context "$($definition.id) result"
    if (-not $resultIdentityValid -and $bundleIdentityValid) {
        $resultIdentity = $bundleIdentity
        $resultIdentityValid = $true
    }
    if (($status -ne 'BLOCKED' -or $executed) -and
        -not $resultIdentityValid) {
        throw "$($definition.id) cannot be adjudicated without exact candidate identity."
    }
    if ($status -eq 'PASS') {
        if (-not $executed -or $executionState -ne 'COMPLETE') {
            throw "$($definition.id) PASS requires executed=true and execution_state=COMPLETE."
        }
        if ([string]::IsNullOrWhiteSpace($reason)) {
            throw "$($definition.id) PASS requires a non-empty reason."
        }
        if ($evidence.Count -eq 0) {
            throw "$($definition.id) PASS requires evidence."
        }
    }

    $identityEvidenceCount = 0
    foreach ($relative in $evidence) {
        if ([string]::IsNullOrWhiteSpace($relative)) {
            throw "$($definition.id) contains an empty evidence path."
        }
        try {
            $artifact = Resolve-LabContainedFile -Root $root `
                -RelativePath $relative
        } catch {
            throw "$($definition.id) evidence is not a contained regular file: $relative"
        }
        if ([IO.Path]::GetExtension($artifact) -eq '.json') {
            try {
                $json = Get-Content -LiteralPath $artifact -Raw |
                    ConvertFrom-Json
            } catch {
                throw "$($definition.id) evidence is invalid JSON: $relative"
            }
            $evidenceIdentity = Get-V91CandidateIdentity -Object $json `
                -Context "$($definition.id) evidence '$relative'"
            if (Assert-V91CandidateIdentity -Identity $evidenceIdentity `
                    -Expected $candidate `
                    -Context "$($definition.id) evidence '$relative'") {
                ++$identityEvidenceCount
            }
        }
    }
    if ($status -eq 'PASS' -and $identityEvidenceCount -eq 0) {
        throw "$($definition.id) PASS requires at least one JSON evidence artifact bound to the exact candidate."
    }

    [pscustomobject][ordered]@{
        id = $definition.id
        status = $status
        required_topology = $definition.topology
        executed = $executed
        execution_state = $executionState
        reason = $reason
        evidence = $evidence
        identity_evidence_count = $identityEvidenceCount
    }
}

if ($cases.Count -ne 27) {
    throw "The normative V91 matrix must contain 27 cases; found $($cases.Count)"
}
$counts = [ordered]@{
    total = $cases.Count
    pass = @($cases | Where-Object status -eq 'PASS').Count
    fail = @($cases | Where-Object status -eq 'FAIL').Count
    blocked = @($cases | Where-Object status -eq 'BLOCKED').Count
    executed = @($cases | Where-Object executed).Count
}
if ($counts.pass + $counts.fail + $counts.blocked -ne $counts.total) {
    throw 'The V91 ledger contains an unaccounted formal status.'
}
$ledger = [ordered]@{
    schema = 'ese.v91.rc-ledger/v2'
    generated_at_utc = Get-LabUtcTimestamp
    candidate = [ordered]@{
        version = $candidate.version
        commit = $candidate.commit
        emule_sha256 = $candidate.emule_sha256
        ese_server_sha256 = $candidate.ese_server_sha256
        build_info_sha256 = $candidate.build_info_sha256
    }
    results_sha256 = if ($ResultsPath) {
        Get-LabSha256 -Path $resolvedResults
    } else { $null }
    normative_source = 'docs/V9_RELEASE_SPECIFICATION.md section 8.6'
    counts = $counts
    gate_decision = if ($counts.pass -eq 27 -and
        $counts.fail -eq 0 -and $counts.blocked -eq 0) {
        'GO'
    } else { 'NO_GO' }
    cases = @($cases)
}

Write-LabJson -Value $ledger -Path $OutputPath | Out-Null
Write-Host "V91 RC ledger written: $OutputPath"
Write-Host "PASS=$($counts.pass) FAIL=$($counts.fail) BLOCKED=$($counts.blocked)"
