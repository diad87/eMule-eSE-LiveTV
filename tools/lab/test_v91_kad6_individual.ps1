[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Kad6Root,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$CandidateCommit = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$root = (Resolve-Path -LiteralPath $Kad6Root).Path
$build = Join-Path $root 'build'
if (-not (Test-Path -LiteralPath $build -PathType Container)) {
    throw "Kad6 build directory is missing: $build"
}
$output = New-LabDirectory -Path $OutputRoot
$executables = @(Get-ChildItem -LiteralPath $build -Filter 'test_kad6_*.exe' -File |
    Sort-Object Name)
if ($executables.Count -ne 29) {
    throw "Expected 29 Kad6 test executables, found $($executables.Count)."
}

$results = [System.Collections.Generic.List[object]]::new()
foreach ($executable in $executables) {
    $caseRoot = New-LabDirectory -Path (Join-Path $output $executable.BaseName)
    $stdout = Join-Path $caseRoot 'stdout.log'
    $stderr = Join-Path $caseRoot 'stderr.log'
    $started = [DateTime]::UtcNow
    $process = Start-Process -FilePath $executable.FullName -WorkingDirectory $root `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -WindowStyle Hidden -Wait -PassThru
    $finished = [DateTime]::UtcNow
    $results.Add([pscustomobject][ordered]@{
        name = $executable.Name
        executable_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $executable.FullName).Hash.ToLowerInvariant()
        started_at_utc = $started.ToString('o')
        finished_at_utc = $finished.ToString('o')
        duration_seconds = [Math]::Round(($finished - $started).TotalSeconds, 3)
        exit_code = $process.ExitCode
        stdout = "$($executable.BaseName)\stdout.log"
        stderr = "$($executable.BaseName)\stderr.log"
        verdict = if ($process.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }
    })
}

$failures = @($results | Where-Object verdict -ne 'PASS')
$summary = [ordered]@{
    schema = 'ese.v91.kad6-individual/v1'
    generated_at_utc = Get-LabUtcTimestamp
    candidate_commit = $CandidateCommit
    kad6_root = $root
    expected_count = 29
    executed_count = $results.Count
    passed_count = @($results | Where-Object verdict -eq 'PASS').Count
    failed_count = $failures.Count
    verdict = if ($failures.Count -eq 0) { 'PASS' } else { 'FAIL' }
    tests = @($results)
}
Write-LabJson -Value $summary -Path (Join-Path $output 'summary.json') | Out-Null
if ($failures.Count -ne 0) {
    throw "Kad6 individual suite failed: $($failures.name -join ', ')"
}
Write-Host "Kad6 individual suite PASS ($($results.Count)/29): $output" -ForegroundColor Green
