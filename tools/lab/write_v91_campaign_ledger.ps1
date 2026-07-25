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
    [ordered]@{ id = 'V91-I03'; topology = 'T1' },
    [ordered]@{ id = 'V91-I04'; topology = 'T1' },
    [ordered]@{ id = 'V91-I05'; topology = 'T1' },
    [ordered]@{ id = 'V91-I06'; topology = 'T6' },
    [ordered]@{ id = 'V91-I07'; topology = 'T3' },
    [ordered]@{ id = 'V91-I08'; topology = 'T5' },
    [ordered]@{ id = 'V91-D01'; topology = 'T1' },
    [ordered]@{ id = 'V91-P01'; topology = 'T0/T1' },
    [ordered]@{ id = 'V91-P02'; topology = 'T0/T1' },
    [ordered]@{ id = 'V91-P03'; topology = 'T0' },
    [ordered]@{ id = 'V91-K01'; topology = 'T5' },
    [ordered]@{ id = 'V91-K02'; topology = 'T1' },
    [ordered]@{ id = 'V91-K03'; topology = 'profiles' },
    [ordered]@{ id = 'V91-K04'; topology = 'T1/T5' },
    [ordered]@{ id = 'V91-C01'; topology = 'V1' },
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
if ($ResultsPath) {
    $resolvedResults = (Resolve-Path -LiteralPath $ResultsPath).Path
    $parsed = Get-Content -LiteralPath $resolvedResults -Raw | ConvertFrom-Json
    $results = if ($parsed.PSObject.Properties.Name -contains 'cases') {
        @($parsed.cases)
    } else {
        @($parsed)
    }
}

$knownIds = @($definitions | ForEach-Object id)
$resultIds = @($results | ForEach-Object { [string]$_.id })
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
        }
        continue
    }

    $status = ([string]$result.status).ToUpperInvariant()
    if ($status -notin 'PASS', 'FAIL', 'BLOCKED') {
        throw "$($definition.id) has invalid status '$status'"
    }
    $evidence = @($result.evidence | ForEach-Object { [string]$_ })
    foreach ($relative in $evidence) {
        if ([IO.Path]::IsPathRooted($relative) -or
            $relative -match '(^|[\\/])\.\.([\\/]|$)') {
            throw "$($definition.id) evidence must be relative to EvidenceRoot: $relative"
        }
        $artifact = Join-Path $root $relative
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
            throw "$($definition.id) evidence is missing: $relative"
        }
        if ([IO.Path]::GetExtension($artifact) -eq '.json') {
            try {
                $json = Get-Content -LiteralPath $artifact -Raw |
                    ConvertFrom-Json
                if (($json.PSObject.Properties.Name -contains
                        'candidate_commit') -and
                    [string]$json.candidate_commit -ne $candidate.commit) {
                    throw "$($definition.id) evidence belongs to another commit: $relative"
                }
                if (($json.PSObject.Properties.Name -contains
                        'candidate_binary_sha256') -and
                    [string]$json.candidate_binary_sha256 -ne
                        $candidate.emule_sha256) {
                    throw "$($definition.id) evidence belongs to another binary: $relative"
                }
            } catch [System.Management.Automation.RuntimeException] {
                throw
            } catch {
                # JSON without candidate identity is still valid supporting
                # evidence; only present identity fields are enforced.
            }
        }
    }

    [pscustomobject][ordered]@{
        id = $definition.id
        status = $status
        required_topology = $definition.topology
        executed = [bool]$result.executed
        execution_state = if ($result.execution_state) {
            [string]$result.execution_state
        } elseif ([bool]$result.executed) {
            'COMPLETE'
        } else {
            'NOT_RUN'
        }
        reason = [string]$result.reason
        evidence = $evidence
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
    normative_source = 'docs/V9_RELEASE_SPECIFICATION.md section 8.6'
    counts = $counts
    gate_decision = if ($counts.pass -eq 27) { 'GO' } else { 'NO_GO' }
    cases = @($cases)
}

Write-LabJson -Value $ledger -Path $OutputPath | Out-Null
Write-Host "V91 RC ledger written: $OutputPath"
Write-Host "PASS=$($counts.pass) FAIL=$($counts.fail) BLOCKED=$($counts.blocked)"
