<#
.SYNOPSIS
    V92-O01 simple soak sampler (plan section 20, V92-O01; 92-8.3).

.DESCRIPTION
    Samples the running eMule candidate every IntervalSeconds for
    DurationHours: process working set, handles, threads, /api/status and
    /api/reach/status (gate_state, generation, lease per plane). Writes
    samples.jsonl and summary.json into RunDirectory and returns a verdict on
    what it can measure. Orphan-mapping and orphan-process checks stay with
    the operator (see docs/V9.2_O01_SIMPLE_SOAK.md).

    Passive: never starts or stops eMule, never touches the router.
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:4711',
    [string]$Token = '',
    [Parameter(Mandatory = $true)][string]$RunDirectory,
    [ValidateRange(0.05, 168)][double]$DurationHours = 8,
    [ValidateRange(10, 3600)][int]$IntervalSeconds = 300,
    [int]$TargetProcessId = 0,
    [ValidateRange(0, 64)][int]$ExpectedGenerationChanges = 2,
    [ValidateRange(0, 500)][int]$MaxWorkingSetGrowthPercent = 50,
    [ValidateRange(0, 100000)][int]$MaxHandleGrowth = 200,
    [ValidateRange(0, 100)][int]$MinApiAvailabilityPercent = 95,
    [switch]$AllowRemoteApi
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

function Get-Prop {
    param([object]$Object, [Parameter(Mandatory = $true)][string]$Name, [object]$Default = $null)
    if ($null -eq $Object) { return $Default }
    if (@($Object.PSObject.Properties.Name) -contains $Name) { return $Object.$Name }
    return $Default
}

function Get-SoakProcess {
    if ($TargetProcessId -gt 0) {
        return Get-Process -Id $TargetProcessId -ErrorAction SilentlyContinue
    }
    $candidates = @(Get-Process -Name 'emule' -ErrorAction SilentlyContinue)
    if ($candidates.Count -eq 1) { return $candidates[0] }
    if ($candidates.Count -eq 0) { return $null }
    throw "Ambiguous: $($candidates.Count) emule.exe processes; pass -TargetProcessId"
}

$runRoot = Get-LabFullPath -Path $RunDirectory
if (-not (Test-Path -LiteralPath $runRoot)) { New-Item -ItemType Directory -Path $runRoot | Out-Null }
$samplesPath = Join-Path $runRoot 'samples.jsonl'
$summaryPath = Join-Path $runRoot 'summary.json'
if (Test-Path -LiteralPath $samplesPath) { throw "Refusing to append to existing $samplesPath" }
$utf8 = New-Object Text.UTF8Encoding($false)

$first = Get-SoakProcess
if ($null -eq $first) { throw 'No emule.exe process found; start the candidate first' }
$pidLocked = $first.Id
$durationSeconds = [int]($DurationHours * 3600)
$clock = [Diagnostics.Stopwatch]::StartNew()
$samples = [Collections.Generic.List[object]]::new()
$reasons = [Collections.Generic.List[string]]::new()
$exitedEarly = $false

Write-Host "V92-O01 simple soak: pid $pidLocked, $DurationHours h, every $IntervalSeconds s -> $runRoot"

while ($true) {
    $process = Get-SoakProcess
    $elapsed = [int]$clock.Elapsed.TotalSeconds
    if ($null -eq $process -or $process.Id -ne $pidLocked) {
        $exitedEarly = $true
        $reasons.Add("process $pidLocked not running at ${elapsed}s")
        break
    }
    $process.Refresh()
    $reach = Invoke-LabApi -BaseUrl $BaseUrl -Path '/api/reach/status' -Token $Token `
        -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable
    $status = Invoke-LabApi -BaseUrl $BaseUrl -Path '/api/status' -Token $Token `
        -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable
    $reachData = Get-Prop -Object $reach -Name 'data'
    $planes = [ordered]@{}
    $planeSet = Get-Prop -Object $reachData -Name 'planes'
    if ($null -ne $planeSet) {
        foreach ($planeName in @($planeSet.PSObject.Properties.Name)) {
            $plane = $planeSet.$planeName
            $lease = Get-Prop -Object $plane -Name 'lease'
            $planes[$planeName] = [ordered]@{
                gate_state = Get-Prop -Object $plane -Name 'gate_state'
                state = Get-Prop -Object $plane -Name 'state'
                generation = Get-Prop -Object $plane -Name 'generation'
                reason_code = Get-Prop -Object $plane -Name 'reason_code'
                lease_mapper = Get-Prop -Object $lease -Name 'mapper'
                lease_lifetime_seconds = Get-Prop -Object $lease -Name 'lifetime_seconds'
                lease_epoch = Get-Prop -Object $lease -Name 'mapper_epoch'
            }
        }
    }
    $sample = [ordered]@{
        utc = Get-LabUtcTimestamp
        elapsed_seconds = $elapsed
        pid = $process.Id
        working_set_bytes = [int64]$process.WorkingSet64
        private_bytes = [int64]$process.PrivateMemorySize64
        handles = [int]$process.HandleCount
        threads = [int]$process.Threads.Count
        api_status_available = [bool]$status.available
        reach_available = ([bool]$reach.available -and ($null -ne $reachData))
        topology_generation = Get-Prop -Object $reachData -Name 'topology_generation'
        planes = $planes
    }
    $samples.Add([pscustomobject]$sample)
    [IO.File]::AppendAllText($samplesPath, (($sample | ConvertTo-Json -Depth 6 -Compress) + "`n"), $utf8)
    Write-Host ("{0,6}s ws={1,6:N0} MiB handles={2} threads={3} gen={4} reach={5}" -f $elapsed,
        ($sample.working_set_bytes / 1MB), $sample.handles, $sample.threads,
        $sample.topology_generation, $sample.reach_available)
    if ($elapsed -ge $durationSeconds) { break }
    Start-Sleep -Seconds ([Math]::Min($IntervalSeconds, [Math]::Max(1, $durationSeconds - $elapsed)))
}

$count = $samples.Count
$firstSample = $samples[0]
$lastSample = $samples[$count - 1]
$maxWs = ($samples | Measure-Object -Property working_set_bytes -Maximum).Maximum
$wsGrowthPercent = 0
if ($firstSample.working_set_bytes -gt 0) {
    $wsGrowthPercent = [Math]::Round((($lastSample.working_set_bytes - $firstSample.working_set_bytes) * 100.0) / $firstSample.working_set_bytes, 2)
}
$handleGrowth = $lastSample.handles - $firstSample.handles
$generations = [Collections.Generic.List[object]]::new()
$generationChanges = 0
$previousGeneration = $null
$reachAvailableCount = 0
foreach ($sample in $samples) {
    if ($sample.reach_available) { $reachAvailableCount++ }
    $generation = $sample.topology_generation
    if ($null -eq $generation) { continue }
    if ($null -ne $previousGeneration -and $generation -ne $previousGeneration) { $generationChanges++ }
    if ($generations.Count -eq 0 -or $generations[$generations.Count - 1] -ne $generation) { $generations.Add($generation) }
    $previousGeneration = $generation
}
$availabilityPercent = 0
if ($count -gt 0) { $availabilityPercent = [Math]::Round(($reachAvailableCount * 100.0) / $count, 2) }

if ($wsGrowthPercent -gt $MaxWorkingSetGrowthPercent) { $reasons.Add("working set grew $wsGrowthPercent% (limit $MaxWorkingSetGrowthPercent%)") }
if ($handleGrowth -gt $MaxHandleGrowth) { $reasons.Add("handles grew by $handleGrowth (limit $MaxHandleGrowth)") }
if ($generationChanges -gt $ExpectedGenerationChanges) { $reasons.Add("topology_generation changed $generationChanges times (expected <= $ExpectedGenerationChanges)") }
if ($availabilityPercent -lt $MinApiAvailabilityPercent) { $reasons.Add("reach API available in $availabilityPercent% of samples (min $MinApiAvailabilityPercent%)") }
if ($lastSample.elapsed_seconds -lt $durationSeconds) { $reasons.Add("soak stopped at $($lastSample.elapsed_seconds)s of $durationSeconds") }

$verdict = 'FAIL'
if ($reasons.Count -eq 0) { $verdict = 'PASS' }
$summary = [ordered]@{
    schema = 'ese.v92.o01-simple-soak/v1'
    verdict = $verdict
    reasons = @($reasons)
    pid = $pidLocked
    duration_seconds_requested = $durationSeconds
    duration_seconds_measured = $lastSample.elapsed_seconds
    interval_seconds = $IntervalSeconds
    samples = $count
    working_set_first_bytes = $firstSample.working_set_bytes
    working_set_last_bytes = $lastSample.working_set_bytes
    working_set_max_bytes = [int64]$maxWs
    working_set_growth_percent = $wsGrowthPercent
    handles_first = $firstSample.handles
    handles_last = $lastSample.handles
    threads_first = $firstSample.threads
    threads_last = $lastSample.threads
    reach_availability_percent = $availabilityPercent
    topology_generations_seen = @($generations)
    topology_generation_changes = $generationChanges
    process_exited_early = $exitedEarly
    operator_checks = @(
        'UPnP census after natural shutdown: zero owned mappings, foreign entries intact',
        'No emule.exe or ese-server.exe left running after shutdown',
        'Operator interventions (mapping deleted, router restarted) logged with UTC time in operator.txt'
    )
    samples_file = 'samples.jsonl'
}
[IO.File]::WriteAllText($summaryPath, (([pscustomobject]$summary | ConvertTo-Json -Depth 6) + "`n"), $utf8)
Write-Host "Soak $verdict; summary: $summaryPath"
if ($verdict -eq 'PASS') { exit 0 } else { exit 1 }
