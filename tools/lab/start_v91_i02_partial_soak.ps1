[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidateRange(600, 86400)][int]$DurationSeconds = 7200,
    [string]$Commit = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$candidate = Get-LabCandidateInfo -PackagePath $PackagePath -ExpectedCommit $Commit
$candidateCommit = $candidate.commit
$package = $candidate.package_path
$output = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $output) {
    throw "OutputRoot already exists; refusing to mix evidence: $output"
}
$nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
$logs = New-LabDirectory -Path (Join-Path $output 'logs')

function Set-NodePreferences {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][int]$WebPort
    )
    foreach ($entry in ([ordered]@{
        Port = $TcpPort
        UDPPort = $UdpPort
        NetworkKademlia = 0
        AutoConnect = 0
    }).GetEnumerator()) {
        Set-LabIniValue -Path $Path -Section 'eMule' `
            -Key $entry.Key -Value ([string]$entry.Value)
    }
    Set-LabIniValue -Path $Path -Section 'Connection' `
        -Key 'KadNetworkMask' -Value '0'
    Set-LabIniValue -Path $Path -Section 'Connection' `
        -Key 'IPv6Mode' -Value '2'
    Set-LabIniValue -Path $Path -Section 'WebServer' `
        -Key 'Enabled' -Value '1'
    Set-LabIniValue -Path $Path -Section 'WebServer' `
        -Key 'Port' -Value ([string]$WebPort)
    Set-LabIniValue -Path $Path -Section 'WebServer' `
        -Key 'WebUseUPnP' -Value '0'
    foreach ($key in 'EseNetLabConsent',
        'EseNetLabAdvancedConsent', 'EseNetLabContributionConsent') {
        Set-LabIniValue -Path $Path -Section 'eSE' -Key $key -Value '1'
    }
    Set-LabIniValue -Path $Path -Section 'eSE' `
        -Key 'EseNetLabEnabled' -Value '0'
}

function Wait-Api {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
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

function Stop-TestProcess {
    param([AllowNull()][Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try { $Process.Refresh() } catch { return }
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $null = $Process.WaitForExit(10000)
    }
}

& (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
    -SourcePackage $package -OutputRoot $nodes -RunId 'v91-i02-exact' `
    -PortOffset 2000
& (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
    -SourcePackage $package -OutputRoot $nodes -RunId 'v91-i02-exact' `
    -PortOffset 2100
$sourceNode = Join-Path $nodes 'v91-i02-exact-a'
$viewerNode = Join-Path $nodes 'v91-i02-exact-b'
Set-NodePreferences -Path (Join-Path $sourceNode 'config\preferences.ini') `
    -TcpPort 6662 -UdpPort 6672 -WebPort 4811
Set-NodePreferences -Path (Join-Path $viewerNode 'config\preferences.ini') `
    -TcpPort 6762 -UdpPort 6772 -WebPort 4911

$source = $null
$viewer = $null
$monitorProcesses = @()
try {
    $source = Start-Process -FilePath (Join-Path $sourceNode 'emule.exe') `
        -ArgumentList @(
            '--portable', '--ignoreinstances', '--headless',
            '--metrics-port=4811', '--tcp-port=6662', '--udp-port=6672'
        ) -WorkingDirectory $sourceNode -WindowStyle Hidden -PassThru
    $viewer = Start-Process -FilePath (Join-Path $viewerNode 'emule.exe') `
        -ArgumentList @(
            '--portable', '--ignoreinstances', '--headless',
            '--metrics-port=4911', '--tcp-port=6762', '--udp-port=6772'
        ) -WorkingDirectory $viewerNode -WindowStyle Hidden -PassThru
    $sourceStatus = Wait-Api -Port 4811 -Process $source
    $viewerStatus = Wait-Api -Port 4911 -Process $viewer

    $warpAddress = @(
        Get-NetIPAddress -InterfaceAlias 'CloudflareWARP' `
            -AddressFamily IPv6 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -notlike 'fe80:*' -and
                $_.AddressState -eq 'Preferred'
            }
    ) | Select-Object -First 1
    if ($null -eq $warpAddress) {
        throw 'No preferred Cloudflare WARP IPv6 address is available'
    }

    $broadcast = Invoke-RestMethod `
        -Uri 'http://127.0.0.1:4811/api/live/broadcast/start?source=testpattern&title=V91-I02-exact&bitrate=12000' `
        -TimeoutSec 30
    if (-not [bool]$broadcast.success -or -not [bool]$broadcast.ready) {
        throw "12 Mbps test-pattern broadcast did not become ready: $($broadcast | ConvertTo-Json -Compress)"
    }
    $linkText = [string]$broadcast.link
    $keyMatch = [regex]::Match($linkText, '\|live\|([0-9A-Fa-f]{32})\|')
    if (-not $keyMatch.Success) {
        throw "Broadcast response did not contain a stream key: $linkText"
    }
    $streamKey = $keyMatch.Groups[1].Value
    $encodedAddress = [Uri]::EscapeDataString($warpAddress.IPAddress)
    $join = Invoke-RestMethod -Uri (
        'http://127.0.0.1:4911/api/live/direct_join' +
        "?key=$streamKey&ip=$encodedAddress&port=6662&title=V91-I02-exact"
    ) -TimeoutSec 15
    if (-not [bool]$join.success -or -not [bool]$join.dialed) {
        throw "Viewer did not start the direct IPv6 dial: $($join | ConvertTo-Json -Compress)"
    }

    $debug = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $debug = Invoke-RestMethod `
            -Uri 'http://127.0.0.1:4911/api/live/debug' -TimeoutSec 3
        if ([bool]$debug.viewing -and
            [int64]$debug.counters.chunksReceived -gt 0) {
            break
        }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not [bool]$debug.viewing -or
        [int64]$debug.counters.chunksReceived -le 0) {
        throw 'Viewer did not receive a playable chunk within 90 seconds'
    }

    & (Join-Path $PSScriptRoot 'assert_data_route.ps1') `
        -TargetProcessId $viewer.Id -RequiredFamily IPv6 `
        -ExpectedRemotePort 6662 -MinimumConnections 1 `
        -ForbiddenInterfacePattern 'Tailscale' `
        -OutFile (Join-Path $evidence 'route-start.json')

    $monitorSpecs = @(
        [ordered]@{
            name = 'source'
            script = Join-Path $PSScriptRoot 'soak_monitor.ps1'
            args = @(
                '-NodeRole', 'A',
                '-BaseUrl', 'http://127.0.0.1:4811',
                '-TargetProcessId', [string]$source.Id,
                '-DurationSeconds', [string]$DurationSeconds,
                '-IntervalSeconds', '30',
                '-MaxWorkingSetGrowthMB', '192',
                '-MaxHandleGrowth', '512',
                '-OutFile', (Join-Path $evidence 'source-summary.json'),
                '-SamplesFile', (Join-Path $evidence 'source-samples.jsonl')
            )
        },
        [ordered]@{
            name = 'viewer'
            script = Join-Path $PSScriptRoot 'soak_monitor.ps1'
            args = @(
                '-NodeRole', 'B',
                '-BaseUrl', 'http://127.0.0.1:4911',
                '-TargetProcessId', [string]$viewer.Id,
                '-DurationSeconds', [string]$DurationSeconds,
                '-IntervalSeconds', '30',
                '-MaxWorkingSetGrowthMB', '192',
                '-MaxHandleGrowth', '512',
                '-OutFile', (Join-Path $evidence 'viewer-summary.json'),
                '-SamplesFile', (Join-Path $evidence 'viewer-samples.jsonl')
            )
        },
        [ordered]@{
            name = 'live'
            script = Join-Path $PSScriptRoot 'live_ipv6_soak_monitor.ps1'
            args = @(
                '-BaseUrl', 'http://127.0.0.1:4911',
                '-TargetProcessId', [string]$viewer.Id,
                '-ExpectedRemotePort', '6662',
                '-DurationSeconds', [string]$DurationSeconds,
                '-IntervalSeconds', '15',
                '-OutFile', (Join-Path $evidence 'live-summary.json'),
                '-SamplesFile', (Join-Path $evidence 'live-samples.jsonl')
            )
        }
    )
    foreach ($spec in $monitorSpecs) {
        $arguments = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', [string]$spec.script
        ) + $spec.args
        $monitor = Start-Process -FilePath 'powershell.exe' `
            -ArgumentList $arguments -WorkingDirectory $PSScriptRoot `
            -RedirectStandardOutput (Join-Path $logs "$($spec.name).stdout.log") `
            -RedirectStandardError (Join-Path $logs "$($spec.name).stderr.log") `
            -WindowStyle Hidden -PassThru
        $monitorProcesses += [pscustomobject]@{
            name = $spec.name
            process_id = $monitor.Id
        }
    }

    $session = [ordered]@{
        schema = 'ese.v91.i02-partial-session/v1'
        candidate_version = $candidate.version
        candidate_commit = $candidateCommit
        candidate_binary_sha256 = Get-LabSha256 `
            -Path (Join-Path $package 'emule.exe')
        started_at_utc = Get-LabUtcTimestamp
        requested_duration_seconds = $DurationSeconds
        topology = 'same-host Cloudflare WARP loop'
        formal_v91_i02_eligible = $false
        formal_limitation = 'V91-I02 requires T5 with two physical peers or V1/V2; this run is exact-candidate evidence only.'
        source = [ordered]@{
            process_id = $source.Id
            tcp_port = 6662
            web_port = 4811
        }
        viewer = [ordered]@{
            process_id = $viewer.Id
            tcp_port = 6762
            web_port = 4911
        }
        route = [ordered]@{
            family = 'IPv6'
            interface = 'CloudflareWARP'
        }
        initial_chunks_received = [int64]$debug.counters.chunksReceived
        monitors = $monitorProcesses
    }
    Write-LabJson -Value $session `
        -Path (Join-Path $evidence 'session.json') | Out-Null
    Write-Host "Exact-candidate partial V91-I02 soak started: $output" `
        -ForegroundColor Green
} catch {
    foreach ($monitor in $monitorProcesses) {
        Stop-Process -Id $monitor.process_id -Force -ErrorAction SilentlyContinue
    }
    try {
        Invoke-RestMethod -Uri 'http://127.0.0.1:4811/api/live/broadcast/stop' `
            -TimeoutSec 5 | Out-Null
    } catch {}
    Stop-TestProcess -Process $viewer
    Stop-TestProcess -Process $source
    throw
}
