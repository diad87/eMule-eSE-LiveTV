<#
.SYNOPSIS
Starts the exact-candidate V91-I06 LiveTV viewer on an isolated profile.

.DESCRIPTION
Creates a role-B portable profile, disables Kad and automatic network
connection, starts the viewer on the fixed 7062/7072/7111 ports, and joins a
known LiveTV source over the supplied IPv6 endpoint. The helper records
candidate identity, sanitized startup API state, and the initial established
TCP route. It deliberately leaves the successful viewer running for a later
monitor/finalizer and does not adjudicate V91-I06.

.PARAMETER PackagePath
Path to the extracted exact-candidate package.

.PARAMETER RemoteIPv6
Global or ULA IPv6 address of the controlled I06 source.

.PARAMETER RemotePort
TCP port of the controlled I06 source.

.PARAMETER StreamKey
The 32-hex-character LiveTV stream key printed by the source helper.

.PARAMETER Commit
Full 40-character commit expected in the candidate BUILD_INFO.txt.

.PARAMETER OutputRoot
New directory in which the isolated node and startup evidence are written.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$RemoteIPv6,
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)][int]$RemotePort,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{32}$')][string]$StreamKey,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)][string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$tcpPort = 7062
$udpPort = 7072
$webPort = 7111
$runId = 'v91-i06-isolated'
$title = 'V91-I06-ULA-Isolated'

$remoteText = $RemoteIPv6.Trim()
if ($remoteText.StartsWith('[') -and $remoteText.EndsWith(']')) {
    $remoteText = $remoteText.Substring(1, $remoteText.Length - 2)
}
$remoteAddress = $null
if (-not [Net.IPAddress]::TryParse($remoteText, [ref]$remoteAddress) -or
    $remoteAddress.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetworkV6) {
    throw "RemoteIPv6 is not an IPv6 address: $RemoteIPv6"
}
$remoteCanonical = $remoteAddress.ToString().ToLowerInvariant()
$remoteClass = Get-LabAddressClass -Address $remoteCanonical
if ($remoteClass -notin @('ula-v6', 'global-v6')) {
    throw (
        'RemoteIPv6 must be a controlled global or ULA IPv6 address; ' +
        "found $remoteClass"
    )
}

$candidate = Get-LabCandidateInfo -PackagePath $PackagePath `
    -ExpectedCommit $Commit
$package = $candidate.package_path
$output = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $output) {
    throw "OutputRoot already exists; refusing to mix evidence: $output"
}

$nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
$offset = $tcpPort - 4662
if (($udpPort - 4672) -ne $offset -or
    ($webPort - 4711) -ne $offset) {
    throw 'Fixed viewer ports do not share one prepare_node offset'
}

& (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
    -SourcePackage $package -OutputRoot $nodes -RunId $runId `
    -PortOffset $offset

$node = Join-Path $nodes "$runId-b"
$preferences = Join-Path $node 'config\preferences.ini'
foreach ($entry in ([ordered]@{
    NetworkKademlia = '0'
    Autoconnect = '0'
}).GetEnumerator()) {
    Set-LabIniValue -Path $preferences -Section 'eMule' `
        -Key $entry.Key -Value $entry.Value
}
Set-LabIniValue -Path $preferences -Section 'Connection' `
    -Key 'KadNetworkMask' -Value '0'
Set-LabIniValue -Path $preferences -Section 'Connection' `
    -Key 'IPv6Mode' -Value '2'
Set-LabIniValue -Path $preferences -Section 'UPnP' `
    -Key 'EnableUPnP' -Value '0'
Set-LabIniValue -Path $preferences -Section 'WebServer' `
    -Key 'Enabled' -Value '1'
Set-LabIniValue -Path $preferences -Section 'WebServer' `
    -Key 'Port' -Value ([string]$webPort)
Set-LabIniValue -Path $preferences -Section 'WebServer' `
    -Key 'WebUseUPnP' -Value '0'

$viewer = $null
$started = [DateTime]::UtcNow
$streamKeyNormalized = $StreamKey.ToLowerInvariant()
$remoteHash = Get-LabStringSha256 -Value $remoteCanonical
$streamKeyHash = Get-LabStringSha256 -Value $streamKeyNormalized
$machineSeed = '{0}|{1}|{2}' -f $env:COMPUTERNAME,
    [Environment]::OSVersion.VersionString, $env:PROCESSOR_ARCHITECTURE

try {
    $viewer = Start-Process -FilePath (Join-Path $node 'emule.exe') `
        -ArgumentList @(
            '--portable', '--ignoreinstances', '--headless',
            "--metrics-port=$webPort",
            "--tcp-port=$tcpPort",
            "--udp-port=$udpPort"
        ) -WorkingDirectory $node -WindowStyle Hidden -PassThru

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    $status = $null
    do {
        Start-Sleep -Milliseconds 400
        $viewer.Refresh()
        if ($viewer.HasExited) {
            throw "Isolated viewer exited with code $($viewer.ExitCode)"
        }
        try {
            $status = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$webPort/api/status" `
                -TimeoutSec 2
        } catch {}
    } while ($null -eq $status -and [DateTime]::UtcNow -lt $deadline)
    if ($null -eq $status) {
        throw "Isolated viewer API did not become ready on port $webPort"
    }

    $encodedKey = [Uri]::EscapeDataString($streamKeyNormalized)
    $encodedAddress = [Uri]::EscapeDataString($remoteCanonical)
    $encodedTitle = [Uri]::EscapeDataString($title)
    $join = Invoke-RestMethod -Uri (
        "http://127.0.0.1:$webPort/api/live/direct_join" +
        "?key=$encodedKey&ip=$encodedAddress&port=$RemotePort" +
        "&title=$encodedTitle"
    ) -TimeoutSec 15
    if (-not [bool]$join.success -or -not [bool]$join.dialed) {
        $joinText = $join | ConvertTo-Json -Compress
        throw "Viewer did not start the direct IPv6 dial: $joinText"
    }

    $debug = $null
    $routeSnapshot = @()
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $viewer.Refresh()
        if ($viewer.HasExited) {
            throw "Isolated viewer exited with code $($viewer.ExitCode)"
        }
        try {
            $debug = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$webPort/api/live/debug" `
                -TimeoutSec 3
        } catch {
            $debug = $null
        }

        $routeSnapshot = @()
        foreach ($socket in @(
            Get-NetTCPConnection -State Established `
                -OwningProcess $viewer.Id -ErrorAction SilentlyContinue
        )) {
            if ([int]$socket.RemotePort -ne $RemotePort) { continue }
            $socketRemote = $null
            $socketRemoteText = ([string]$socket.RemoteAddress).Split('%')[0]
            if (-not [Net.IPAddress]::TryParse(
                    $socketRemoteText, [ref]$socketRemote) -or
                -not $socketRemote.Equals($remoteAddress)) {
                continue
            }

            $localText = ([string]$socket.LocalAddress).Split('%')[0]
            $adapter = Get-LabInterfaceForAddress -Address $localText
            $adapterText = if ($null -eq $adapter) {
                ''
            } else {
                '{0}|{1}' -f $adapter.name, $adapter.description
            }
            $routeSnapshot += [pscustomobject][ordered]@{
                state = 'ESTABLISHED'
                family = 'IPv6'
                local_address_class = Get-LabAddressClass -Address $localText
                local_address_sha256 = Get-LabStringSha256 -Value (
                    ([Net.IPAddress]::Parse($localText)).ToString().ToLowerInvariant()
                )
                local_port = [int]$socket.LocalPort
                remote_address_class = $remoteClass
                remote_address_sha256 = $remoteHash
                remote_port = [int]$socket.RemotePort
                interface_id = if ($null -eq $adapter) {
                    $null
                } else {
                    Get-LabInterfaceId -Id $adapter.id `
                        -Name $adapter.name -Description $adapter.description
                }
                interface_class = if ($adapterText -match '(?i)Tailscale') {
                    'tailscale-overlay'
                } elseif ($null -eq $adapter) {
                    'unmapped'
                } else {
                    'other'
                }
            }
        }

        if ($null -ne $debug -and [bool]$debug.viewing -and
            [int64]$debug.counters.chunksReceived -gt 0 -and
            $routeSnapshot.Count -gt 0) {
            break
        }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)

    if ($null -eq $debug -or -not [bool]$debug.viewing -or
        [int64]$debug.counters.chunksReceived -le 0) {
        throw 'Viewer did not receive a playable chunk within 90 seconds'
    }
    if ($routeSnapshot.Count -eq 0) {
        throw (
            'Viewer received no attributable established IPv6 socket to ' +
            'the requested controlled endpoint within 90 seconds'
        )
    }

    $safeStatus = ConvertTo-LabSanitizedValue -InputObject $status `
        -RedactAddresses
    $safeDebug = ConvertTo-LabSanitizedValue -InputObject $debug `
        -RedactAddresses
    Write-LabJson -Value $safeStatus `
        -Path (Join-Path $evidence 'status-start.json') | Out-Null
    Write-LabJson -Value $safeDebug `
        -Path (Join-Path $evidence 'live-debug-start.json') | Out-Null

    $routeEvidence = [ordered]@{
        schema = 'ese.v91.i06-isolated-route-start/v1'
        captured_at_utc = Get-LabUtcTimestamp
        process_id = $viewer.Id
        expected = [ordered]@{
            family = 'IPv6'
            remote_address_class = $remoteClass
            remote_address_sha256 = $remoteHash
            remote_port = $RemotePort
        }
        matching_connections = @($routeSnapshot)
        evidence_scope = (
            'Initial TCP route only; UDP and sustained transfer require ' +
            'separate capture/finalization.'
        )
    }
    Write-LabJson -Value $routeEvidence `
        -Path (Join-Path $evidence 'route-start.json') | Out-Null

    $session = [ordered]@{
        schema = 'ese.v91.i06-isolated-viewer/v1'
        case_id = 'V91-I06'
        candidate_version = $candidate.version
        candidate_commit = $candidate.commit
        candidate_dirty = $candidate.dirty
        candidate_binary_sha256 = Get-LabSha256 `
            -Path (Join-Path $package 'emule.exe')
        candidate_ese_server_sha256 = $candidate.ese_server_sha256
        candidate_build_info_sha256 = $candidate.build_info_sha256
        started_at_utc = $started.ToString('o')
        startup_evidence_at_utc = Get-LabUtcTimestamp
        machine_id = (
            Get-LabStringSha256 -Value $machineSeed
        ).Substring(0, 16)
        process_id = $viewer.Id
        node_path = $node
        tcp_port = $tcpPort
        udp_port = $udpPort
        web_port = $webPort
        remote = [ordered]@{
            family = 'IPv6'
            address_class = $remoteClass
            address_sha256 = $remoteHash
            port = $RemotePort
        }
        stream_key_sha256 = $streamKeyHash
        title = $title
        kad_enabled = $false
        auto_connect = $false
        ipv6_mode = 2
        viewing = [bool]$debug.viewing
        initial_chunks_received = [int64]$debug.counters.chunksReceived
        established_route_count = $routeSnapshot.Count
        formal_verdict = $null
        evidence_scope = (
            'Startup evidence only. A separate sustained-transfer monitor ' +
            'and finalizer are required for a formal V91-I06 verdict.'
        )
        evidence = [ordered]@{
            status = 'evidence\status-start.json'
            live_debug = 'evidence\live-debug-start.json'
            route = 'evidence\route-start.json'
        }
    }
    $sessionPath = Write-LabJson -Value $session `
        -Path (Join-Path $evidence 'session.json')

    Write-Host "V91-I06 isolated viewer started: $output" `
        -ForegroundColor Green
    Write-Host "Session: $sessionPath"
    $session | ConvertTo-Json -Depth 8
} catch {
    $failure = [ordered]@{
        schema = 'ese.v91.i06-isolated-viewer-failure/v1'
        case_id = 'V91-I06'
        captured_at_utc = Get-LabUtcTimestamp
        candidate_version = $candidate.version
        candidate_commit = $candidate.commit
        candidate_binary_sha256 = $candidate.emule_sha256
        remote_address_class = $remoteClass
        remote_address_sha256 = $remoteHash
        remote_port = $RemotePort
        process_id = if ($null -eq $viewer) { $null } else { $viewer.Id }
        error = Protect-LabText -Value $_.Exception.Message -RedactAddresses
    }
    Write-LabJson -Value $failure `
        -Path (Join-Path $evidence 'startup-failure.json') | Out-Null
    if ($null -ne $viewer) {
        try {
            $viewer.Refresh()
            if (-not $viewer.HasExited) {
                Stop-Process -Id $viewer.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    throw
}
