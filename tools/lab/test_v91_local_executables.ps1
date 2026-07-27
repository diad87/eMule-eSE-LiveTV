[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CandidatePackage,
    [Parameter(Mandatory = $true)][string]$TestRoot,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$RepoRoot = '',
    [string]$Commit = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$candidate = Get-LabCandidateInfo -PackagePath $CandidatePackage `
    -ExpectedCommit $Commit
$sourceBefore = Get-LabExactSourceInfo -RepoRoot $RepoRoot `
    -ExpectedCommit $candidate.commit
$tests = (Resolve-Path -LiteralPath $TestRoot).Path
$expectedTestRoot =
    [IO.Path]::GetFullPath((Join-Path $RepoRoot 'srchybrid\tests\build'))
if ($tests -ne $expectedTestRoot) {
    throw "TestRoot must be the candidate worktree test output: $expectedTestRoot"
}
$output = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $output) {
    throw "OutputRoot already exists; refusing to mix evidence: $output"
}
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
$logs = New-LabDirectory -Path (Join-Path $output 'logs')

$expected = @(
    'test_core_regression_policy.exe',
    'test_holepunch_cookie.exe',
    'test_kad_network_policy.exe',
    'test_kad_protocol_policy.exe',
    'test_known2_offsets.exe',
    'test_livebulk.exe',
    'test_livefec.exe',
    'test_livepeerrefresh.exe',
    'test_liveratelimiter.exe',
    'test_partfile_io_policy.exe',
    'test_shared_file_intake_policy.exe',
    'test_shared_file_intake_policy_ab.exe',
    'test_upload_limit_policy.exe'
)

$results = [System.Collections.Generic.List[object]]::new()
foreach ($name in $expected) {
    $executable = Join-Path $tests $name
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Required local test executable is missing: $executable"
    }
    $base = [IO.Path]::GetFileNameWithoutExtension($name)
    $stdout = Join-Path $logs "$base.stdout.log"
    $stderr = Join-Path $logs "$base.stderr.log"
    $started = [DateTime]::UtcNow
    $process = Start-Process -FilePath $executable -WorkingDirectory $tests `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -WindowStyle Hidden -Wait -PassThru
    $finished = [DateTime]::UtcNow
    $results.Add([pscustomobject][ordered]@{
        name = $name
        sha256 = Get-LabSha256 -Path $executable
        started_at_utc = $started.ToString('o')
        finished_at_utc = $finished.ToString('o')
        duration_seconds = [Math]::Round(
            ($finished - $started).TotalSeconds, 3)
        exit_code = $process.ExitCode
        stdout = "logs\$base.stdout.log"
        stderr = "logs\$base.stderr.log"
        verdict = if ($process.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }
    })
}

$candidateAfter = Get-LabCandidateInfo -PackagePath $CandidatePackage `
    -ExpectedCommit $candidate.commit
$sourceAfter = Get-LabExactSourceInfo -RepoRoot $RepoRoot `
    -ExpectedCommit $candidate.commit
$candidateUnchanged =
    $candidateAfter.emule_sha256 -eq $candidate.emule_sha256 -and
    $candidateAfter.ese_server_sha256 -eq $candidate.ese_server_sha256 -and
    $candidateAfter.build_info_sha256 -eq $candidate.build_info_sha256
$failed = @($results | Where-Object verdict -ne 'PASS')
$overallPass = $failed.Count -eq 0 -and $candidateUnchanged
$summary = [ordered]@{
    schema = 'ese.v91.local-executables/v1'
    supported_cases = @('V91-A01', 'V91-A02')
    formal_scope = 'supporting rerun only; the clean build gate proves compilation'
    candidate_version = $candidate.version
    candidate_commit = $candidate.commit
    candidate_binary_sha256 = $candidate.emule_sha256
    candidate_unchanged = $candidateUnchanged
    source = [ordered]@{
        before = $sourceBefore
        after = $sourceAfter
        unchanged = $true
    }
    location_constraint = 'fixed srchybrid/tests/build path in the exact clean candidate worktree'
    build_provenance_unverified = $true
    generated_at_utc = Get-LabUtcTimestamp
    expected_count = $expected.Count
    executed_count = $results.Count
    passed_count = @($results | Where-Object verdict -eq 'PASS').Count
    failed_count = $failed.Count
    verdict = if ($overallPass) { 'PASS' } else { 'FAIL' }
    tests = @($results)
}
Write-LabJson -Value $summary `
    -Path (Join-Path $evidence 'V91-A01-A02-LOCAL-SUMMARY.json') | Out-Null

$outcome = if ($overallPass) { 'PASS' } else { 'FAIL' }
& (Join-Path $PSScriptRoot 'collect_report.ps1') `
    -RunDirectory $output -CaseId 'V91-A01-A02-LOCAL' `
    -Outcome $outcome -Version $candidate.version -Commit $candidate.commit `
    -Notes 'Supporting rerun of 13 worktree-local policy, wire and regression executables; the clean build gate remains authoritative.'

if (-not $candidateUnchanged) {
    throw 'Candidate package changed during the local executable suite'
}
if ($failed.Count -gt 0) {
    throw "Local executable suite failed: $($failed.name -join ', ')"
}
Write-Host "V91 A01/A02 local executable suite PASS: $output" `
    -ForegroundColor Green
