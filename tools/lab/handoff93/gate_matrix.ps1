<#
.SYNOPSIS
    Builds and validates the G92-93-DEV handoff matrix (H93-01..H93-16).

.DESCRIPTION
    Consumes an operator-maintained verdicts file, cross-checks every cited
    evidence artifact, and enforces the gate's own stop rules:

      - all sixteen rows must exist and be PASS;
      - BLOCKED, SKIP and FAIL never count as PASS;
      - evidence recorded against another commit invalidates the gate;
      - a missing or unreadable artifact is a hard failure, not a warning.

    Emits 'ese.lab.handoff-gate-matrix/v1' plus the handoff-9.3 manifest.
    This script never runs a test and never edits evidence; it only decides
    whether the collected evidence satisfies the gate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VerdictsFile,
    [Parameter(Mandatory = $true)][string]$RunDirectory,
    [Parameter(Mandatory = $true)][string]$Commit,
    [string]$Toolchain = '',
    [string]$OutFile = '',
    [switch]$IncludeSensitive
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\common.ps1')

# Canonical rows. Order and identifiers follow section 26A.2 of
# docs/V9.2_DEVELOPMENT_AND_TEST_PLAN.md. Physical rows cannot be satisfied by
# a purely simulated run.
$canonicalRows = @(
    @{ id = 'H93-01'; group = 'Procedencia';          physical = $false },
    @{ id = 'H93-02'; group = 'Build/regresion';      physical = $false },
    @{ id = 'H93-03'; group = 'Schema';               physical = $false },
    @{ id = 'H93-04'; group = 'Compatibilidad';       physical = $false },
    @{ id = 'H93-05'; group = 'Desacoplamiento';      physical = $false },
    @{ id = 'H93-06'; group = 'Mappers simulados';    physical = $false },
    @{ id = 'H93-07'; group = 'Verificacion';         physical = $false },
    @{ id = 'H93-08'; group = 'Atomicidad';           physical = $false },
    @{ id = 'H93-09'; group = 'Ciclo de vida';        physical = $false },
    @{ id = 'H93-10'; group = 'Topologia';            physical = $false },
    @{ id = 'H93-11'; group = 'Generacion';           physical = $false },
    @{ id = 'H93-12'; group = 'IPv6';                 physical = $false },
    @{ id = 'H93-13'; group = 'Integracion eMule';    physical = $false },
    @{ id = 'H93-14'; group = 'Seguridad/evidencia';  physical = $false },
    @{ id = 'H93-15'; group = 'Fisico corto';         physical = $true  },
    @{ id = 'H93-16'; group = 'Ruta fisica';          physical = $true  }
)

$acceptedVerdicts = @('PASS', 'FAIL', 'BLOCKED', 'SKIP', 'PENDING')

# ConvertFrom-Json yields PSCustomObject, and common.ps1 runs under StrictMode,
# so touching an absent property throws. Optional fields must go through here.
function Get-RowValue {
    param([object]$Row, [Parameter(Mandatory = $true)][string]$Name, [object]$Default = $null)
    if ($null -eq $Row) { return $Default }
    if (@($Row.PSObject.Properties.Name) -contains $Name) { return $Row.$Name }
    return $Default
}

if (-not (Test-Path -LiteralPath $VerdictsFile)) {
    throw "Verdicts file not found: $VerdictsFile"
}
$runRoot = Get-LabFullPath -Path $RunDirectory
if (-not (Test-Path -LiteralPath $runRoot)) {
    throw "Run directory not found: $runRoot"
}
if (-not $OutFile) {
    $OutFile = Join-Path $runRoot 'handoff-9.3\gate-matrix.json'
}

$rawVerdicts = Get-Content -LiteralPath $VerdictsFile -Raw -Encoding UTF8 | ConvertFrom-Json
$declaredRows = Get-RowValue -Row $rawVerdicts -Name 'rows' -Default $null
if ($null -eq $declaredRows) {
    throw "Verdicts file has no 'rows' array"
}

# Index the operator's rows by id so missing entries are detectable.
$byId = @{}
foreach ($row in $declaredRows) {
    $rowId = [string](Get-RowValue -Row $row -Name 'id' -Default '')
    if (-not $rowId) { throw "A row in the verdicts file has no 'id'" }
    if ($byId.ContainsKey($rowId)) { throw "Duplicate row in verdicts file: $rowId" }
    $byId[$rowId] = $row
}

$evaluated = New-Object System.Collections.ArrayList
$blockers = New-Object System.Collections.ArrayList

foreach ($canonical in $canonicalRows) {
    $id = $canonical.id
    $entry = [ordered]@{
        id            = $id
        group         = $canonical.group
        physical      = $canonical.physical
        verdict       = 'MISSING'
        note          = ''
        artifacts     = @()
        artifact_ok   = $true
        commit_ok     = $true
    }

    if (-not $byId.ContainsKey($id)) {
        $entry.verdict = 'MISSING'
        $null = $blockers.Add("$id has no entry in the verdicts file")
        $null = $evaluated.Add($entry)
        continue
    }

    $row = $byId[$id]
    $verdict = ([string](Get-RowValue -Row $row -Name 'verdict' -Default '')).ToUpperInvariant()
    if ($acceptedVerdicts -notcontains $verdict) {
        throw "$id has an unrecognised verdict '$verdict'"
    }
    $entry.verdict = $verdict
    $entry.note = [string](Get-RowValue -Row $row -Name 'note' -Default '')

    # Every cited artifact must exist, hash cleanly, and - when it records a
    # commit of its own - agree with the gate commit.
    $artifactList = New-Object System.Collections.ArrayList
    $declaredArtifacts = Get-RowValue -Row $row -Name 'artifacts' -Default @()
    if ($null -ne $declaredArtifacts) {
        foreach ($relative in $declaredArtifacts) {
            $relativePath = [string]$relative
            $absolute = Join-Path $runRoot $relativePath
            $item = [ordered]@{
                path   = $relativePath
                exists = $false
                sha256 = ''
                bytes  = 0
                schema = ''
                commit = ''
            }
            if (Test-Path -LiteralPath $absolute -PathType Leaf) {
                $item.exists = $true
                $item.sha256 = Get-LabSha256 -Path $absolute
                $item.bytes = (Get-Item -LiteralPath $absolute).Length
                try {
                    $parsed = Get-Content -LiteralPath $absolute -Raw -Encoding UTF8 | ConvertFrom-Json
                    if ($parsed.PSObject.Properties.Name -contains 'schema') {
                        $item.schema = [string]$parsed.schema
                    }
                    if ($parsed.PSObject.Properties.Name -contains 'commit') {
                        $item.commit = [string]$parsed.commit
                        if ($item.commit -and $item.commit -ne $Commit) {
                            $entry.commit_ok = $false
                            $null = $blockers.Add(
                                "$id cites evidence from commit $($item.commit), gate commit is $Commit")
                        }
                    }
                } catch {
                    # Non-JSON evidence (pcap, log) is legitimate; absence of a
                    # parsable body is not an error by itself.
                }
            } else {
                $entry.artifact_ok = $false
                $null = $blockers.Add("$id cites a missing artifact: $relativePath")
            }
            $null = $artifactList.Add($item)
        }
    }
    $entry.artifacts = @($artifactList)

    if ($verdict -eq 'PASS' -and $artifactList.Count -eq 0) {
        $null = $blockers.Add("$id is PASS with no evidence artifact")
    }
    if ($verdict -ne 'PASS') {
        $null = $blockers.Add("$id is $verdict; the gate requires PASS")
    }

    $null = $evaluated.Add($entry)
}

# A physical row may never be satisfied by simulation. The operator declares
# simulation explicitly; we refuse to let it stand as PASS.
foreach ($entry in $evaluated) {
    if ($entry.physical -and $entry.verdict -eq 'PASS' -and $byId.ContainsKey($entry.id)) {
        $row = $byId[$entry.id]
        if ([bool](Get-RowValue -Row $row -Name 'simulated' -Default $false)) {
            $null = $blockers.Add(
                "$($entry.id) is a physical row and cannot PASS from a simulated run")
        }
    }
}

$verdictCounts = [ordered]@{}
foreach ($state in @('PASS', 'FAIL', 'BLOCKED', 'SKIP', 'PENDING', 'MISSING')) {
    $verdictCounts[$state] = @($evaluated | Where-Object { $_.verdict -eq $state }).Count
}

$gateVerdict = 'PASS'
if ($blockers.Count -gt 0) {
    if ($verdictCounts['FAIL'] -gt 0) {
        $gateVerdict = 'FAIL'
    } else {
        $gateVerdict = 'BLOCKED'
    }
}

$matrix = [ordered]@{
    schema          = 'ese.lab.handoff-gate-matrix/v1'
    gate            = 'G92-93-DEV'
    generated_at_utc = Get-LabUtcTimestamp
    commit          = $Commit
    toolchain       = $Toolchain
    run_directory   = $runRoot
    verdict         = $gateVerdict
    verdict_counts  = $verdictCounts
    blockers        = @($blockers)
    rows            = @($evaluated)
}

$safeMatrix = ConvertTo-LabSanitizedValue -InputObject $matrix `
    -RedactAddresses:(-not $IncludeSensitive)
$writtenPath = Write-LabJson -Value $safeMatrix -Path $OutFile

$colour = 'Red'
if ($gateVerdict -eq 'PASS') { $colour = 'Green' }
elseif ($gateVerdict -eq 'BLOCKED') { $colour = 'Yellow' }

Write-Host "Gate matrix written: $writtenPath" -ForegroundColor Green
Write-Host "G92-93-DEV verdict: $gateVerdict" -ForegroundColor $colour
foreach ($blocker in $blockers) {
    Write-Host "  - $blocker" -ForegroundColor Yellow
}

if ($gateVerdict -ne 'PASS') { exit 1 }
