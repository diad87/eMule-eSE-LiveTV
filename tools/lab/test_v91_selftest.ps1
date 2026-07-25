[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$Commit = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if ([string]::IsNullOrWhiteSpace($Commit)) {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $Commit = ((& git -C $repoRoot rev-parse HEAD) -join '').Trim()
}
if ($Commit -notmatch '^[0-9a-fA-F]{40}$') {
    throw "Commit must be a full 40-character Git object id: $Commit"
}
$candidateCommit = $Commit.ToLowerInvariant()
$package = (Resolve-Path -LiteralPath $PackagePath).Path
$output = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $output) {
    throw "OutputRoot already exists; refusing to mix evidence: $output"
}
$nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')

& (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
    -SourcePackage $package -OutputRoot $nodes -RunId 'v91-selftest'
$node = Join-Path $nodes 'v91-selftest-a'
$executable = Join-Path $node 'emule.exe'
$stdout = Join-Path $evidence 'selftest.stdout.log'
$stderr = Join-Path $evidence 'selftest.stderr.log'
$started = [DateTime]::UtcNow

$process = Start-Process -FilePath $executable `
    -ArgumentList @('--portable', '--ignoreinstances', '--selftest') `
    -WorkingDirectory $node -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr -WindowStyle Hidden -PassThru -Wait
$process.Refresh()
$exitCode = $process.ExitCode
$finished = [DateTime]::UtcNow
$verdict = if ($exitCode -eq 0) { 'PASS' } else { 'FAIL' }
$packageBinary = Join-Path $package 'emule.exe'

$summary = [ordered]@{
    schema = 'ese.v91.selftest/v1'
    case_id = 'G-SELFTEST'
    candidate_commit = $candidateCommit
    candidate_binary = [ordered]@{
        bytes = (Get-Item -LiteralPath $packageBinary).Length
        sha256 = Get-LabSha256 -Path $packageBinary
    }
    started_at_utc = $started.ToString('o')
    finished_at_utc = $finished.ToString('o')
    duration_seconds = [Math]::Round(($finished - $started).TotalSeconds, 3)
    exit_code = [int]$exitCode
    verdict = $verdict
}
Write-LabJson -Value $summary `
    -Path (Join-Path $evidence 'G-SELFTEST-SUMMARY.json') | Out-Null

& (Join-Path $PSScriptRoot 'collect_report.ps1') `
    -RunDirectory $evidence -CaseId 'G-SELFTEST' -Outcome $verdict `
    -Version '9.1.0-beta.2' -Commit $candidateCommit `
    -Notes 'Frozen release package self-test in an isolated portable profile.'

if ($verdict -ne 'PASS') {
    throw "G-SELFTEST failed with exit code $exitCode"
}
Write-Host "G-SELFTEST PASS: $output" -ForegroundColor Green
