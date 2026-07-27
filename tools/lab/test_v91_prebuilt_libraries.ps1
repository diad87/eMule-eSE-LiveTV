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

$asanRuntime = @(Get-ChildItem -LiteralPath `
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC' `
    -Recurse -File -Filter 'clang_rt.asan_dynamic-x86_64.dll' `
    -ErrorAction SilentlyContinue | Where-Object {
        $_.DirectoryName -match '\\bin\\Hostx64\\x64$'
    } | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
if ($asanRuntime.Count -ne 1) {
    throw 'The x64 MSVC AddressSanitizer runtime could not be located'
}
$asanRuntimeFile = $asanRuntime[0]
$asanRuntimeDirectory = $asanRuntimeFile.DirectoryName

$definitions = @(
    [ordered]@{
        group = 'libreach'
        directory = 'libreach\build'
        names = @(
            'test_reach_codec.exe',
            'test_reach_facade.exe',
            'test_reach_cascade.exe',
            'test_reach_actuator.exe'
        )
    },
    [ordered]@{
        group = 'libnatmap'
        directory = 'libnatmap\build'
        names = @(
            'test_d0_contracts.exe',
            'test_state_machine.exe',
            'test_mapping_codecs.exe',
            'test_lease_policy.exe',
            'test_nat_chain.exe',
            'test_ownership_ledger.exe'
        )
    },
    [ordered]@{
        group = 'librelaycore-release'
        directory = 'librelaycore\build'
        names = @(
            'test_relay_core.exe',
            'test_krp_control.exe',
            'test_krp_tcp_wire.exe',
            'test_krp_session.exe',
            'test_krp_auth.exe',
            'test_krp_flow.exe',
            'test_kad6_authority_adapter.exe',
            'test_epr_lease.exe',
            'test_krp_p1_gate.exe'
        )
    },
    [ordered]@{
        group = 'librelaycore-asan'
        directory = 'librelaycore\build'
        names = @(
            'test_relay_core_asan.exe',
            'test_krp_control_asan.exe',
            'test_krp_tcp_wire_asan.exe',
            'test_krp_session_asan.exe',
            'test_krp_auth_asan.exe',
            'test_krp_flow_asan.exe',
            'test_kad6_authority_adapter_asan.exe',
            'test_epr_lease_asan.exe',
            'test_krp_p1_gate_asan.exe'
        )
    }
)

$results = [System.Collections.Generic.List[object]]::new()
$originalPath = $env:PATH
try {
    foreach ($definition in $definitions) {
        $workingDirectory = Join-Path $RepoRoot $definition.directory
        $env:PATH = if ($definition.group -eq 'librelaycore-asan') {
            $asanRuntimeDirectory + [IO.Path]::PathSeparator + $originalPath
        } else {
            $originalPath
        }
        foreach ($name in $definition.names) {
            $executable = Join-Path $workingDirectory $name
            if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
                throw "Required prebuilt test executable is missing: $executable"
            }
            $base = [IO.Path]::GetFileNameWithoutExtension($name)
            $logBase = "$($definition.group)-$base"
            $stdout = Join-Path $logs "$logBase.stdout.log"
            $stderr = Join-Path $logs "$logBase.stderr.log"
            $started = [DateTime]::UtcNow
            $process = Start-Process -FilePath $executable `
                -WorkingDirectory $workingDirectory `
                -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
                -WindowStyle Hidden -Wait -PassThru
            $finished = [DateTime]::UtcNow
            $results.Add([pscustomobject][ordered]@{
                group = $definition.group
                name = $name
                sha256 = Get-LabSha256 -Path $executable
                started_at_utc = $started.ToString('o')
                finished_at_utc = $finished.ToString('o')
                duration_seconds = [Math]::Round(
                    ($finished - $started).TotalSeconds, 3)
                exit_code = $process.ExitCode
                stdout = "logs\$logBase.stdout.log"
                stderr = "logs\$logBase.stderr.log"
                verdict = if ($process.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }
            })
        }
    }
} finally {
    $env:PATH = $originalPath
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
$groupResults = @($definitions | ForEach-Object {
    $groupName = $_.group
    $groupTests = @($results | Where-Object group -eq $groupName)
    [pscustomobject][ordered]@{
        name = $groupName
        expected_count = @($_.names).Count
        executed_count = $groupTests.Count
        passed_count = @($groupTests | Where-Object verdict -eq 'PASS').Count
        failed_count = @($groupTests | Where-Object verdict -ne 'PASS').Count
        verdict = if (@($groupTests | Where-Object verdict -ne 'PASS').Count -eq 0) {
            'PASS'
        } else {
            'FAIL'
        }
    }
})
$summary = [ordered]@{
    schema = 'ese.v91.prebuilt-libraries/v1'
    supported_cases = @('V91-A01')
    formal_scope = 'supporting execution only; compiler and linker gates are separate'
    candidate_version = $candidateBefore.version
    candidate_commit = $candidateBefore.commit
    candidate_binary_sha256 = $candidateBefore.emule_sha256
    candidate_unchanged = $candidateUnchanged
    source = [ordered]@{
        before = $sourceBefore
        after = $sourceAfter
        unchanged = $true
    }
    location_constraint = 'fixed library build directories in the exact clean candidate worktree'
    build_provenance_unverified = $true
    asan_runtime = [ordered]@{
        name = $asanRuntimeFile.Name
        sha256 = Get-LabSha256 -Path $asanRuntimeFile.FullName
    }
    generated_at_utc = Get-LabUtcTimestamp
    expected_count = @($definitions | ForEach-Object names).Count
    executed_count = $results.Count
    passed_count = @($results | Where-Object verdict -eq 'PASS').Count
    failed_count = $failed.Count
    verdict = if ($overallPass) { 'PASS' } else { 'FAIL' }
    groups = $groupResults
    tests = @($results)
}
Write-LabJson -Value $summary `
    -Path (Join-Path $evidence 'V91-A01-PREBUILT-LIBRARIES-SUMMARY.json') |
    Out-Null

$outcome = if ($overallPass) { 'PASS' } else { 'FAIL' }
& (Join-Path $PSScriptRoot 'collect_report.ps1') `
    -RunDirectory $output -CaseId 'V91-A01-PREBUILT-LIBRARIES' `
    -Outcome $outcome -Version $candidateBefore.version `
    -Commit $candidateBefore.commit `
    -Notes 'Supporting rerun of worktree-local libreach, libnatmap and librelaycore Release/ASan binaries; compiler and linker gates remain authoritative.'

if (-not $candidateUnchanged) {
    throw 'Candidate package changed while prebuilt library tests were executing'
}
if ($failed.Count -gt 0) {
    throw "Prebuilt library suite failed: $($failed.name -join ', ')"
}
Write-Host "V91 prebuilt library suite PASS: $output" -ForegroundColor Green
