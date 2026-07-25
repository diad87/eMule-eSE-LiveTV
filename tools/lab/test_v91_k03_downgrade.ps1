[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CandidatePackage,
    [Parameter(Mandatory = $true)][string]$PreviousPackage,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidateRange(10, 120)][int]$StartupTimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$candidateCommit = '72a5a41ebeec1bd08bff7ed17df27782930d96e3'
$candidate = (Resolve-Path -LiteralPath $CandidatePackage).Path
$previous = (Resolve-Path -LiteralPath $PreviousPackage).Path
$output = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $output) {
    throw "OutputRoot already exists; refusing to mix evidence: $output"
}
$nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')

function Wait-Status {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before API readiness with code $($Process.ExitCode)"
        }
        try {
            return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/status" `
                -TimeoutSec 2
        } catch {
            Start-Sleep -Milliseconds 300
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "eMule API did not become ready on port $Port"
}

function Stop-Gracefully {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)
    $Process.Refresh()
    if ($Process.HasExited) { return $true }
    $closed = $Process.CloseMainWindow()
    if ($closed -and $Process.WaitForExit(15000)) { return $true }
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    $null = $Process.WaitForExit(10000)
    return $false
}

function Get-IniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key
    )
    $current = ''
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            $current = $Matches[1]
            continue
        }
        if ($current -eq $Section -and
            $line -match ('^\s*' + [regex]::Escape($Key) + '\s*=(.*)$')) {
            return $Matches[1].Trim()
        }
    }
    return $null
}

& (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
    -SourcePackage $candidate -OutputRoot $nodes -RunId 'v91-k03-candidate' `
    -PortOffset 18000
$candidateNode = Join-Path $nodes 'v91-k03-candidate-a'
$candidatePreferences = Join-Path $candidateNode 'config\preferences.ini'
Set-LabIniValue -Path $candidatePreferences -Section 'Connection' `
    -Key 'KadNetworkMask' -Value '2'
# Deliberately leave the old boolean unsafe; the candidate must normalize and
# save it as OFF for the downgraded build.
Set-LabIniValue -Path $candidatePreferences -Section 'eMule' `
    -Key 'NetworkKademlia' -Value '1'
Set-LabIniValue -Path $candidatePreferences -Section 'eMule' `
    -Key 'AutoConnect' -Value '1'
Set-LabIniValue -Path $candidatePreferences -Section 'eSE' `
    -Key 'EseNetLabConsent' -Value '1'

$candidateProcess = Start-Process -FilePath (Join-Path $candidateNode 'emule.exe') `
    -ArgumentList @(
        '--portable',
        '--ignoreinstances',
        '--metrics-port=22711',
        '--tcp-port=22662',
        '--udp-port=22672'
    ) -WorkingDirectory $candidateNode -WindowStyle Hidden -PassThru
$candidateStatus = Wait-Status -Port 22711 -Process $candidateProcess
Start-Sleep -Seconds 1
$candidateGraceful = Stop-Gracefully -Process $candidateProcess
$legacyAfterCandidate = Get-IniValue -Path $candidatePreferences `
    -Section 'eMule' -Key 'NetworkKademlia'
$maskAfterCandidate = Get-IniValue -Path $candidatePreferences `
    -Section 'Connection' -Key 'KadNetworkMask'

$previousNode = Join-Path $nodes 'v91-k03-previous'
Copy-Item -LiteralPath $previous -Destination $previousNode -Recurse
$previousConfig = Join-Path $previousNode 'config'
if (Test-Path -LiteralPath $previousConfig) {
    Move-Item -LiteralPath $previousConfig `
        -Destination (Join-Path $previousNode 'config.previous-original')
}
Copy-Item -LiteralPath (Join-Path $candidateNode 'config') `
    -Destination $previousConfig -Recurse
$previousPreferences = Join-Path $previousConfig 'preferences.ini'
$previousProcess = Start-Process -FilePath (Join-Path $previousNode 'emule.exe') `
    -ArgumentList @(
        '--portable',
        '--ignoreinstances',
        '--metrics-port=22911',
        '--tcp-port=22862',
        '--udp-port=22872'
    ) -WorkingDirectory $previousNode -WindowStyle Hidden -PassThru
$previousProfileBefore = Get-IniValue -Path $previousPreferences `
    -Section 'eMule' -Key 'NetworkKademlia'
Start-Sleep -Seconds 15
$previousProcess.Refresh()
$previousStayedRunning = -not $previousProcess.HasExited
$previousTcp = @(
    Get-NetTCPConnection -OwningProcess $previousProcess.Id `
        -ErrorAction SilentlyContinue |
        Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort
)
$previousUdp = @(
    Get-NetUDPEndpoint -OwningProcess $previousProcess.Id `
        -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort
)
$previousGraceful = Stop-Gracefully -Process $previousProcess
$legacyAfterPrevious = Get-IniValue -Path $previousPreferences `
    -Section 'eMule' -Key 'NetworkKademlia'

$pass = $maskAfterCandidate -eq '2' -and
    $legacyAfterCandidate -eq '0' -and
    $previousProfileBefore -eq '0' -and
    $legacyAfterPrevious -eq '0' -and
    $previousStayedRunning

$artifact = [ordered]@{
    schema = 'ese.v91.k03-downgrade/v1'
    case_id = 'V91-K03'
    candidate_commit = $candidateCommit
    captured_at_utc = Get-LabUtcTimestamp
    candidate_binary_sha256 = Get-LabSha256 `
        -Path (Join-Path $candidate 'emule.exe')
    previous_build = [ordered]@{
        build_info_sha256 = Get-LabSha256 `
            -Path (Join-Path $previous 'BUILD_INFO.txt')
        emule_sha256 = Get-LabSha256 -Path (Join-Path $previous 'emule.exe')
    }
    candidate_profile_after_save = [ordered]@{
        kad_network_mask = $maskAfterCandidate
        legacy_network_kademlia = $legacyAfterCandidate
        graceful_close = $candidateGraceful
    }
    previous_runtime = [ordered]@{
        observation_seconds = 15
        stayed_running = $previousStayedRunning
        legacy_network_kademlia_before_start = $previousProfileBefore
        legacy_network_kademlia_after_close = $legacyAfterPrevious
        graceful_close = $previousGraceful
        tcp_sockets = ConvertTo-LabSanitizedValue $previousTcp -RedactAddresses
        udp_endpoints = ConvertTo-LabSanitizedValue $previousUdp -RedactAddresses
    }
    non_gating_diagnostics = [ordered]@{
        candidate_closed_within_15_seconds = $candidateGraceful
        previous_closed_within_15_seconds = $previousGraceful
        note = 'Shutdown latency is covered by V91-C03; V91-K03 gates only downgrade safety and legacy Kad2 non-reactivation.'
    }
    verdict = if ($pass) { 'PASS' } else { 'FAIL' }
}
Write-LabJson -Value $artifact `
    -Path (Join-Path $evidence 'V91-K03-SUMMARY.json') | Out-Null
$outcome = if ($pass) { 'PASS' } else { 'FAIL' }
& (Join-Path $PSScriptRoot 'collect_report.ps1') `
    -RunDirectory $evidence -CaseId 'V91-K03' -Outcome $outcome `
    -Version '9.1.0-beta.1' -Commit $candidateCommit `
    -Notes 'Kad6-only profile saved by the candidate, then opened with the exact eSE 8.1 package copy.'

if (-not $pass) {
    throw 'V91-K03 downgrade gate failed'
}
Write-Host "V91-K03 PASS: $output" -ForegroundColor Green
