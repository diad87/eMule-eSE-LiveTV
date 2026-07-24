[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('A', 'B', 'R', 'controller')]
    [string]$NodeRole,
    [string]$BaseUrl = 'http://127.0.0.1:4711',
    [string]$Token = '',
    [ValidateRange(1, 604800)][int]$DurationSeconds = 43200,
    [ValidateRange(1, 3600)][int]$IntervalSeconds = 300,
    [ValidateRange(0, 2147483647)][int]$TargetProcessId = 0,
    [ValidateRange(0, 1048576)][int]$MaxWorkingSetGrowthMB = 64,
    [ValidateRange(0, 1048576)][int]$MaxHandleGrowth = 256,
    [string]$OutFile = '',
    [string]$SamplesFile = '',
    [switch]$AllowRemoteApi,
    [switch]$AllowUnavailable,
    [switch]$RequireProcess,
    [switch]$IncludeSensitive
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not $OutFile) {
    $OutFile = Join-Path (Get-Location) ('lab-soak-{0}.json' -f $NodeRole.ToLowerInvariant())
}
if (-not $SamplesFile) {
    $baseName = [IO.Path]::GetFileNameWithoutExtension($OutFile)
    $SamplesFile = Join-Path (Split-Path -Parent (Get-LabFullPath -Path $OutFile)) ($baseName + '.jsonl')
}
$samplesFullPath = Get-LabFullPath -Path $SamplesFile
$null = New-LabDirectory -Path (Split-Path -Parent $samplesFullPath)
if (Test-Path -LiteralPath $samplesFullPath) {
    throw "Samples file already exists; refusing to overwrite it: $samplesFullPath"
}

$encoding = New-Object Text.UTF8Encoding($false)
$started = [DateTime]::UtcNow
$deadline = $started.AddSeconds($DurationSeconds)
$samples = @()
$sampleNumber = 0

do {
    $sampleNumber++
    $processes = @(if ($TargetProcessId -gt 0) {
        Get-LabProcessSnapshot -TargetProcessIds @($TargetProcessId)
    } else {
        Get-LabProcessSnapshot
    })
    if ($RequireProcess -and $processes.Count -eq 0) {
        throw "Required process is unavailable at soak sample $sampleNumber"
    }

    $apiStatus = Invoke-LabApi -BaseUrl $BaseUrl -Path '/api/status' -Token $Token `
        -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable:$AllowUnavailable
    $sample = [ordered]@{
        schema = 'ese.lab.soak-sample/v1'
        sample_number = $sampleNumber
        captured_at_utc = Get-LabUtcTimestamp
        elapsed_seconds = [Math]::Round(([DateTime]::UtcNow - $started).TotalSeconds, 3)
        processes = $processes
        api_available = [bool]$apiStatus.available
        api_data = $apiStatus.data
        api_error = $apiStatus.error
    }
    $safeSample = ConvertTo-LabSanitizedValue -InputObject $sample `
        -RedactAddresses:(-not $IncludeSensitive)
    $samples += ,$safeSample
    $sampleJson = $safeSample | ConvertTo-Json -Depth 32 -Compress
    [IO.File]::AppendAllText($samplesFullPath, $sampleJson + [Environment]::NewLine, $encoding)

    $remainingMilliseconds = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if ($remainingMilliseconds -gt 0) {
        $sleepMilliseconds = [Math]::Min($remainingMilliseconds, $IntervalSeconds * 1000)
        Start-Sleep -Milliseconds $sleepMilliseconds
    }
} while ([DateTime]::UtcNow -lt $deadline)

$processSamples = @($samples | ForEach-Object { @($_.processes) } | Where-Object {
    $TargetProcessId -eq 0 -or $_.process_id -eq $TargetProcessId
})
$firstProcess = $processSamples | Select-Object -First 1
$lastProcess = $processSamples | Select-Object -Last 1
$workingSetGrowth = if ($null -eq $firstProcess -or $null -eq $lastProcess) {
    $null
} else {
    [Int64]$lastProcess.working_set_bytes - [Int64]$firstProcess.working_set_bytes
}
$handleGrowth = if ($null -eq $firstProcess -or $null -eq $lastProcess) {
    $null
} else {
    [int]$lastProcess.handle_count - [int]$firstProcess.handle_count
}
$unavailableSamples = @($samples | Where-Object { -not $_.api_available }).Count
$failures = @()
if ($RequireProcess -and $processSamples.Count -eq 0) { $failures += 'No process samples were captured' }
if ($null -ne $workingSetGrowth -and $workingSetGrowth -gt ($MaxWorkingSetGrowthMB * 1MB)) {
    $failures += "Working-set growth exceeded $MaxWorkingSetGrowthMB MB"
}
if ($null -ne $handleGrowth -and $handleGrowth -gt $MaxHandleGrowth) {
    $failures += "Handle growth exceeded $MaxHandleGrowth"
}
if (-not $AllowUnavailable -and $unavailableSamples -gt 0) {
    $failures += "$unavailableSamples API sample(s) were unavailable"
}

$summary = [ordered]@{
    schema = 'ese.lab.soak-summary/v1'
    node_role = $NodeRole
    started_at_utc = $started.ToString('o')
    finished_at_utc = [DateTime]::UtcNow.ToString('o')
    requested_duration_seconds = $DurationSeconds
    interval_seconds = $IntervalSeconds
    sample_count = $samples.Count
    process_sample_count = $processSamples.Count
    api_unavailable_samples = $unavailableSamples
    working_set_growth_bytes = $workingSetGrowth
    handle_growth = $handleGrowth
    limits = [ordered]@{
        max_working_set_growth_mb = $MaxWorkingSetGrowthMB
        max_handle_growth = $MaxHandleGrowth
    }
    samples_file = Split-Path -Leaf $samplesFullPath
    verdict = if ($failures.Count -eq 0) { 'PASS' } else { 'FAIL' }
    failures = $failures
}
$writtenPath = Write-LabJson -Value $summary -Path $OutFile
if ($failures.Count -gt 0) {
    throw "Soak monitor FAIL: $($failures -join '; ') (report: $writtenPath)"
}
Write-Host "Soak monitor PASS: $writtenPath" -ForegroundColor Green
