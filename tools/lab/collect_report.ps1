[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunDirectory,
    [Parameter(Mandatory = $true)][string]$CaseId,
    [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'BLOCKED')]
    [string]$Outcome,
    [string]$Version = '',
    [string]$Commit = '',
    [string]$Notes = '',
    [string]$OutFile = '',
    [string]$MarkdownOut = '',
    [switch]$IncludeSensitive
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$runPath = (Resolve-Path -LiteralPath $RunDirectory).Path
if (-not (Test-Path -LiteralPath $runPath -PathType Container)) {
    throw "Run directory is not a directory: $RunDirectory"
}
if ($CaseId -notmatch '^[A-Za-z0-9._-]{1,80}$') {
    throw 'CaseId contains unsupported characters or is longer than 80 characters'
}
if (-not $OutFile) { $OutFile = Join-Path $runPath ('REPORT-{0}.json' -f $CaseId) }
if (-not $MarkdownOut) { $MarkdownOut = Join-Path $runPath ('REPORT-{0}.md' -f $CaseId) }
$outFullPath = Get-LabFullPath -Path $OutFile
$markdownFullPath = Get-LabFullPath -Path $MarkdownOut

if (-not $Commit) {
    try {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $Commit = (& git -C $repoRoot rev-parse HEAD 2>$null).Trim()
    } catch {
        $Commit = ''
    }
}

$evidence = @()
$parseWarnings = @()
$evidenceFailures = @()
foreach ($file in @(Get-ChildItem -LiteralPath $runPath -Recurse -File | Sort-Object FullName)) {
    if ($file.FullName -eq $outFullPath -or $file.FullName -eq $markdownFullPath) { continue }
    $relativePath = Get-LabRelativePath -BasePath $runPath -Path $file.FullName
    $item = [ordered]@{
        path = $relativePath.Replace('\', '/')
        bytes = $file.Length
        sha256 = Get-LabSha256 -Path $file.FullName
        kind = $file.Extension.TrimStart('.').ToLowerInvariant()
    }
    if ($file.Extension -eq '.json') {
        try {
            $parsed = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            if ($parsed.PSObject.Properties.Name -contains 'schema') {
                $item.schema = [string]$parsed.schema
            }
            if ($parsed.PSObject.Properties.Name -contains 'captured_at_utc') {
                $item.captured_at_utc = [string]$parsed.captured_at_utc
            }
            if ($parsed.PSObject.Properties.Name -contains 'node_role') {
                $item.node_role = [string]$parsed.node_role
            }
            if ($parsed.PSObject.Properties.Name -contains 'verdict') {
                $item.verdict = [string]$parsed.verdict
                if ([string]$parsed.verdict -eq 'FAIL') {
                    $evidenceFailures += $relativePath
                }
            }
        } catch {
            $parseWarnings += "Invalid JSON: $relativePath"
        }
    }
    $evidence += [pscustomobject]$item
}

if ($evidence.Count -eq 0) {
    throw "Run directory contains no evidence files: $runPath"
}
if ($Outcome -eq 'PASS' -and $evidenceFailures.Count -gt 0) {
    throw "Cannot publish a PASS report with failed evidence: $($evidenceFailures -join ', ')"
}

$report = [ordered]@{
    schema = 'ese.lab.report/v1'
    generated_at_utc = Get-LabUtcTimestamp
    case_id = $CaseId
    outcome = $Outcome
    build = [ordered]@{
        version = $Version
        commit = $Commit
    }
    notes = Protect-LabText -Value $Notes -RedactAddresses:(-not $IncludeSensitive)
    evidence_count = $evidence.Count
    evidence = $evidence
    warnings = $parseWarnings
    privacy = [ordered]@{
        sensitive_values_included = [bool]$IncludeSensitive
        evidence_contents_embedded = $false
    }
}
$safeReport = ConvertTo-LabSanitizedValue -InputObject $report `
    -RedactAddresses:(-not $IncludeSensitive)
$writtenPath = Write-LabJson -Value $safeReport -Path $outFullPath

$markdownLines = @(
    ('# eSE v9 lab report — {0}' -f $CaseId),
    '',
    ('- Outcome: **{0}**' -f $Outcome),
    ('- Version: `{0}`' -f $(if ($Version) { $Version } else { 'unspecified' })),
    ('- Commit: `{0}`' -f $(if ($Commit) { $Commit } else { 'unspecified' })),
    ('- Generated: `{0}`' -f $report.generated_at_utc),
    ('- Evidence files: {0}' -f $evidence.Count),
    '',
    '## Notes',
    '',
    $(if ($safeReport.notes) { [string]$safeReport.notes } else { 'None.' }),
    '',
    '## Evidence',
    ''
)
foreach ($item in $evidence) {
    $markdownLines += '- `{0}` — {1} bytes — SHA-256 `{2}`' -f $item.path, $item.bytes, $item.sha256
}
if ($parseWarnings.Count -gt 0) {
    $markdownLines += @('', '## Warnings', '')
    foreach ($warning in $parseWarnings) { $markdownLines += "- $warning" }
}
$markdownPath = Write-LabText -Value (($markdownLines -join [Environment]::NewLine) + [Environment]::NewLine) `
    -Path $markdownFullPath

Write-Host "Canonical lab report written: $writtenPath" -ForegroundColor Green
Write-Host "Human-readable report written: $markdownPath"
