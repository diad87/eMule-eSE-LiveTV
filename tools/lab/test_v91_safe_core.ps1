[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CandidatePackage,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$RepoRoot = '',
    [string]$Commit = ''
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
. (Join-Path $PSScriptRoot 'common.ps1')

function ConvertTo-ProcessArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + $Value.Replace('"', '\"') + '"'
}

$candidateBefore = Get-LabCandidateInfo -PackagePath $CandidatePackage `
    -ExpectedCommit $Commit
$sourceBefore = Get-LabExactSourceInfo -RepoRoot $RepoRoot `
    -ExpectedCommit $candidateBefore.commit
$output = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $output) {
    throw "OutputRoot already exists; refusing to mix evidence: $output"
}
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
$logs = New-LabDirectory -Path (Join-Path $output 'logs')

$powerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
$python = (Get-Command python.exe -ErrorAction Stop).Source
$node = (Get-Command node.exe -ErrorAction Stop).Source
$eSEDirectory = Join-Path $RepoRoot 'srchybrid\eSE'
$candidateRuntime = $candidateBefore.package_path

$cases = @(
    [ordered]@{
        name = 'wp0-lab-toolkit'
        file = $powerShell
        arguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-File', (Join-Path $PSScriptRoot 'test_lab_tools.ps1'),
            '-RepoRoot', $RepoRoot
        )
        working_directory = $RepoRoot
    },
    [ordered]@{
        name = 'language-resources-and-runtime'
        file = $powerShell
        arguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-File', (Join-Path $RepoRoot 'tools\check_languages.ps1'),
            '-RepoRoot', $RepoRoot,
            '-RuntimeDir', $candidateRuntime
        )
        working_directory = $RepoRoot
    },
    [ordered]@{
        name = 'protocol-registry'
        file = $python
        arguments = @((Join-Path $RepoRoot 'tools\check_protocol_registry.py'))
        working_directory = $RepoRoot
    },
    [ordered]@{
        name = 'direct-port-ownership'
        file = $python
        arguments = @((Join-Path $RepoRoot 'tools\check_direct_port_usage.py'))
        working_directory = $RepoRoot
    },
    [ordered]@{
        name = 'address-wire'
        file = $python
        arguments = @((Join-Path $RepoRoot 'tests\test_address_wire.py'))
        working_directory = $RepoRoot
    },
    [ordered]@{
        name = 'server-ipv6-source-wire'
        file = $python
        arguments = @((Join-Path $RepoRoot 'tests\test_foundsources_v6_wire.py'))
        working_directory = $RepoRoot
    },
    [ordered]@{
        name = 'ipv6-callback-wire'
        file = $python
        arguments = @((Join-Path $RepoRoot 'tests\test_callback_v6_wire.py'))
        working_directory = $RepoRoot
    },
    [ordered]@{
        name = 'ipv6-transport-wire'
        file = $python
        arguments = @((Join-Path $RepoRoot 'tests\test_ipv6_transport_wire.py'))
        working_directory = $RepoRoot
    },
    [ordered]@{
        name = 'tunnel-framing'
        file = $python
        arguments = @((Join-Path $RepoRoot 'tests\test_tunnel_framing.py'))
        working_directory = $RepoRoot
    },
    [ordered]@{
        name = 'livetv-node-regression'
        file = $node
        arguments = @('--test', 'test\live_tv_regression.test.js')
        working_directory = $eSEDirectory
    }
)

$results = [System.Collections.Generic.List[object]]::new()
foreach ($case in $cases) {
    $stdout = Join-Path $logs ($case.name + '.stdout.log')
    $stderr = Join-Path $logs ($case.name + '.stderr.log')
    $argumentString = (@($case.arguments | ForEach-Object {
        ConvertTo-ProcessArgument -Value ([string]$_)
    }) -join ' ')
    $started = [DateTime]::UtcNow
    $process = Start-Process -FilePath $case.file -ArgumentList $argumentString `
        -WorkingDirectory $case.working_directory `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -WindowStyle Hidden -Wait -PassThru
    $finished = [DateTime]::UtcNow
    $results.Add([pscustomobject][ordered]@{
        name = $case.name
        executable = Split-Path -Leaf $case.file
        started_at_utc = $started.ToString('o')
        finished_at_utc = $finished.ToString('o')
        duration_seconds = [Math]::Round(
            ($finished - $started).TotalSeconds, 3)
        exit_code = $process.ExitCode
        stdout = "logs\$($case.name).stdout.log"
        stderr = "logs\$($case.name).stderr.log"
        verdict = if ($process.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }
    })
}

$candidateAfter = Get-LabCandidateInfo -PackagePath $CandidatePackage `
    -ExpectedCommit $candidateBefore.commit
$sourceAfter = Get-LabExactSourceInfo -RepoRoot $RepoRoot `
    -ExpectedCommit $candidateBefore.commit
$candidateUnchanged = (
    $candidateBefore.emule_sha256 -eq $candidateAfter.emule_sha256 -and
    $candidateBefore.ese_server_sha256 -eq $candidateAfter.ese_server_sha256 -and
    $candidateBefore.build_info_sha256 -eq $candidateAfter.build_info_sha256
)
$failed = @($results | Where-Object verdict -ne 'PASS')
$overallPass = ($failed.Count -eq 0 -and $candidateUnchanged)
$summary = [ordered]@{
    schema = 'ese.v91.safe-core/v1'
    supported_cases = @('V91-A01', 'V91-A02')
    formal_scope = 'supporting evidence; this does not replace the complete build gates'
    candidate_version = $candidateBefore.version
    candidate_commit = $candidateBefore.commit
    candidate_binary_sha256 = $candidateBefore.emule_sha256
    candidate_server_sha256 = $candidateBefore.ese_server_sha256
    candidate_unchanged = $candidateUnchanged
    source = [ordered]@{
        before = $sourceBefore
        after = $sourceAfter
        unchanged = $true
    }
    generated_at_utc = Get-LabUtcTimestamp
    expected_count = $cases.Count
    executed_count = $results.Count
    passed_count = @($results | Where-Object verdict -eq 'PASS').Count
    failed_count = $failed.Count
    verdict = if ($overallPass) { 'PASS' } else { 'FAIL' }
    tests = @($results)
}
Write-LabJson -Value $summary `
    -Path (Join-Path $evidence 'V91-A01-A02-SAFE-CORE-SUMMARY.json') | Out-Null

$outcome = if ($overallPass) { 'PASS' } else { 'FAIL' }
& (Join-Path $PSScriptRoot 'collect_report.ps1') `
    -RunDirectory $output -CaseId 'V91-A01-A02-SAFE-CORE' `
    -Outcome $outcome -Version $candidateBefore.version `
    -Commit $candidateBefore.commit `
    -Notes 'Low-impact supporting checks from the exact clean candidate source: lab tooling, runtime languages, protocol/port guards, IPv6 wire suites and LiveTV Node regression; complete build gates remain authoritative.'

if (-not $candidateUnchanged) {
    throw 'Candidate package changed while the safe-core suite was executing'
}
if ($failed.Count -gt 0) {
    throw "Safe-core suite failed: $($failed.name -join ', ')"
}
Write-Host "V91 safe-core suite PASS: $output" -ForegroundColor Green
