<#
.SYNOPSIS
Runs the normative V91-I03 route-selection campaign on two controlled Windows
hosts without changing adapters, routes, DNS, hosts files or firewall state.

.DESCRIPTION
Run one Coordinator role and one Peer role against a shared CoordinationRoot.
The coordinator creates two isolated candidate profiles and tests, in order:

  * IPv6Mode=1 (Auto): an ordinary dual-stack HighID peer must use IPv4.
  * IPv6Mode=2 (Preferred): the same peer must use IPv6.

Each client first receives an IPv4-only explicit source link.  A real IPv4
connection and OP_HelloAnswer then teach that same in-memory peer object the
peer's public IPv6 address and dual-stack capability.  The peer process is
restarted only after a two-host barrier, forcing a subsequent dial.  PASS
requires a new PID-owned Established socket on the expected family, a physical
non-virtual data interface, a matching inbound socket owned by the restarted
peer process, responsive UI/API, and NetLab/Kad/proxy/DNS/third-party-server
isolation.  Each downloader connects only to a nonce-scoped minimal eD2K
server bound to the coordinator's own physical IPv4.  That controlled server
accepts LOGINREQUEST and returns one HighID IDCHANGE solely to keep the
production download scheduler's IsConnected() precondition true.

This harness deliberately has no DNS fixture (V91-D01), no Kad/bootstrap,
no third-party source and no firewall setup. Missing direct native T1/T2
topology or ambiguous evidence is BLOCKED. A policy mismatch after a fully
valid fixture is FAIL. T1 is reported only when both physical prefixes are
equal and IPv6 is on-link; a routed native IPv6 next hop is reported as T2.
#>
[CmdletBinding()]
param(
    [ValidateSet('Coordinator', 'Peer')][string]$Role = 'Coordinator',
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedEmuleSha256,
    [Parameter(Mandatory = $true)][string]$PeerIPv4,
    [Parameter(Mandatory = $true)][string]$PeerLocalIPv4,
    [Parameter(Mandatory = $true)][string]$PeerIPv6,
    [Parameter(Mandatory = $true)][string]$CoordinationRoot,
    [Parameter(Mandatory = $true)][switch]$ControlledPeerAcknowledged,
    [ValidateRange(1024, 65535)][int]$PeerTcpPort = 9462,
    [ValidateRange(1024, 65535)][int]$PeerUdpPort = 9472,
    [ValidateRange(1024, 65535)][int]$PeerWebPort = 9511,
    [ValidateRange(1024, 65535)][int]$AutoTcpPort = 9562,
    [ValidateRange(1024, 65535)][int]$AutoUdpPort = 9572,
    [ValidateRange(1024, 65535)][int]$AutoWebPort = 9611,
    [ValidateRange(1024, 65535)][int]$PreferredTcpPort = 9662,
    [ValidateRange(1024, 65535)][int]$PreferredUdpPort = 9672,
    [ValidateRange(1024, 65535)][int]$PreferredWebPort = 9711,
    [ValidateRange(268435456, 17179869184)]
    [Int64]$FileSizeBytes = 1073741824,
    [ValidateRange(30, 900)][int]$PeerReadyTimeoutSeconds = 300,
    [ValidateRange(60, 3600)][int]$CaseTimeoutSeconds = 2400,
    [ValidateRange(3, 30)][int]$StableObservationSeconds = 5,
    [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunNonce = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'common.ps1')

$caseId = 'V91-I03'
$expectedHash = $ExpectedEmuleSha256.ToLowerInvariant()
$peerUploadCapKiBps = 16
$candidate = Get-LabCandidateInfo -PackagePath $PackagePath `
    -ExpectedCommit $Commit
if ($candidate.emule_sha256 -ne $expectedHash) {
    throw "Candidate hash mismatch: package=$($candidate.emule_sha256) expected=$expectedHash"
}
if (-not $ControlledPeerAcknowledged) {
    throw 'I03 requires two controlled physical Windows hosts'
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'V91-I03 T1/T2 is a Windows-only two-host fixture'
}

function Convert-I03Address {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$Family,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Value.Split('%')[0], [ref]$parsed) -or
        $parsed.AddressFamily -ne $Family -or
        ($Family -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and
            $parsed.IsIPv4MappedToIPv6)) {
        throw "$Name is not an address in the required family: '$Value'"
    }
    return $parsed
}

function Get-I03NormalizedIp {
    param([Parameter(Mandatory = $true)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address.Trim('[', ']').Split('%')[0],
        [ref]$parsed)) {
        return $Address
    }
    if ($parsed.IsIPv4MappedToIPv6) {
        return $parsed.MapToIPv4().ToString()
    }
    return $parsed.ToString()
}

$peerV4Address = Convert-I03Address -Value $PeerIPv4 `
    -Family ([Net.Sockets.AddressFamily]::InterNetwork) -Name 'PeerIPv4'
$peerLocalV4Address = Convert-I03Address -Value $PeerLocalIPv4 `
    -Family ([Net.Sockets.AddressFamily]::InterNetwork) -Name 'PeerLocalIPv4'
$peerV6Address = Convert-I03Address -Value $PeerIPv6 `
    -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) -Name 'PeerIPv6'
$peerV4Text = $peerV4Address.ToString()
$peerLocalV4Text = $peerLocalV4Address.ToString()
$peerV6Text = $peerV6Address.ToString()
if ((Get-LabAddressClass -Address $peerV4Text) -ne 'global-v4') {
    throw 'PeerIPv4 must be the real globally routable HighID endpoint'
}
if ((Get-LabAddressClass -Address $peerV6Text) -ne 'global-v6') {
    throw 'PeerIPv6 must be a native public global IPv6 address'
}
if ((Get-LabAddressClass -Address $peerLocalV4Text) -in @(
    'invalid', 'loopback-v4', 'linklocal-v4', 'special-v4'
)) {
    throw 'PeerLocalIPv4 must be an assigned unicast address on the peer adapter'
}

$allPorts = @(
    $PeerTcpPort, $PeerUdpPort, $PeerWebPort,
    $AutoTcpPort, $AutoUdpPort, $AutoWebPort,
    $PreferredTcpPort, $PreferredUdpPort, $PreferredWebPort
)
if (@($allPorts | Sort-Object -Unique).Count -ne $allPorts.Count) {
    throw 'All peer, Auto and Preferred TCP/UDP/Web ports must be unique'
}

function Test-I03Administrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    } catch {
        return $false
    }
}

function Get-I03MachineId {
    $machineGuid = ''
    try {
        $machineGuid = [string](Get-ItemProperty `
            -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
            -Name MachineGuid -ErrorAction Stop).MachineGuid
    } catch {
        $machineGuid = '{0}|{1}' -f $env:COMPUTERNAME,
            [Environment]::OSVersion.VersionString
    }
    return Get-LabStringSha256 -Value $machineGuid
}

function Get-I03PackageIdentity {
    param([Parameter(Mandatory = $true)][string]$PackagePath)

    $root = Get-LabFullPath -Path $PackagePath
    $entries = [System.Collections.Generic.List[object]]::new()
    $canonical = New-Object Text.StringBuilder
    $totalBytes = 0L
    foreach ($file in @(
        Get-ChildItem -LiteralPath $root -Recurse -File -Force |
            Sort-Object FullName
    )) {
        $relative = $file.FullName.Substring($root.Length).
            TrimStart('\').Replace('\', '/')
        $sha256 = Get-LabSha256 -Path $file.FullName
        $totalBytes += [Int64]$file.Length
        $entries.Add([pscustomobject][ordered]@{
            relative_path = $relative
            bytes = [Int64]$file.Length
            sha256 = $sha256
        })
        $null = $canonical.Append($relative)
        $null = $canonical.Append([char]0)
        $null = $canonical.Append([string][Int64]$file.Length)
        $null = $canonical.Append([char]0)
        $null = $canonical.Append($sha256)
        $null = $canonical.Append("`n")
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-extracted-package-manifest/v1'
        package_directory_name = Split-Path -Leaf $root
        file_count = $entries.Count
        total_bytes = $totalBytes
        manifest_sha256 =
            Get-LabStringSha256 -Value $canonical.ToString()
        files = @($entries)
    }
}

function Add-I03JsonLine {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    Add-Content -LiteralPath $Path `
        -Value ($Value | ConvertTo-Json -Depth 32 -Compress) -Encoding utf8
}

function Wait-I03JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [AllowEmptyString()][string]$StopPath = ''
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($StopPath -and
            (Test-Path -LiteralPath $StopPath -PathType Leaf)) {
            return [pscustomobject]@{
                kind = 'stop'
                value = Get-Content -LiteralPath $StopPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return [pscustomobject]@{
                kind = 'value'
                value = Get-Content -LiteralPath $Path -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Get-I03AdapterEvidence {
    param(
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex `
        -ErrorAction Stop
    $overlayPattern =
        '(?i)tailscale|wireguard|cloudflare|warp|zerotier|openvpn|' +
        'hyper-v|vethernet|loopback|tunnel|tap|vpn'
    $overlayLike = ([string]$adapter.Name) -match $overlayPattern -or
        ([string]$adapter.InterfaceDescription) -match $overlayPattern
    $physical = [bool]$adapter.HardwareInterface -and
        -not [bool]$adapter.Virtual -and -not $overlayLike -and
        [string]$adapter.Status -eq 'Up'
    return [pscustomobject][ordered]@{
        context = $Context
        interface_index = [int]$adapter.InterfaceIndex
        interface_id = Get-LabInterfaceId `
            -Id ([string]$adapter.InterfaceGuid) `
            -Name ([string]$adapter.Name) `
            -Description ([string]$adapter.InterfaceDescription)
        status = [string]$adapter.Status
        hardware_interface = [bool]$adapter.HardwareInterface
        virtual = [bool]$adapter.Virtual
        overlay_like = $overlayLike
        physical_nonvirtual = $physical
    }
}

function Get-I03AssignedAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$Family,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $familyName = if ($Family -eq
        [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
    $item = Get-NetIPAddress -AddressFamily $familyName `
        -ErrorAction SilentlyContinue | Where-Object {
            (Get-I03NormalizedIp -Address ([string]$_.IPAddress)) -eq
                (Get-I03NormalizedIp -Address $Address) -and
            [string]$_.AddressState -eq 'Preferred'
        } | Select-Object -First 1
    if ($null -eq $item) {
        throw "$Context is not a Preferred address assigned on this host"
    }
    $adapter = Get-I03AdapterEvidence `
        -InterfaceIndex ([int]$item.InterfaceIndex) -Context $Context
    return [pscustomobject][ordered]@{
        address = Get-I03NormalizedIp -Address ([string]$item.IPAddress)
        address_class = Get-LabAddressClass -Address ([string]$item.IPAddress)
        interface_index = [int]$item.InterfaceIndex
        prefix_length = [int]$item.PrefixLength
        adapter = $adapter
    }
}

function Get-I03RouteEvidence {
    param([Parameter(Mandatory = $true)][string]$RemoteAddress)

    try {
        $route = Find-NetRoute -RemoteIPAddress $RemoteAddress `
            -ErrorAction Stop | Select-Object -First 1
        if ($null -eq $route) { throw 'Find-NetRoute returned no route' }
        $source = Get-I03NormalizedIp -Address ([string]$route.IPAddress)
        $adapter = Get-I03AdapterEvidence `
            -InterfaceIndex ([int]$route.InterfaceIndex) `
            -Context "route-to-$RemoteAddress"
        return [pscustomobject][ordered]@{
            available = $true
            family = if ($RemoteAddress.Contains(':')) { 'IPv6' } else { 'IPv4' }
            remote_address = Get-I03NormalizedIp -Address $RemoteAddress
            source_address = $source
            source_class = Get-LabAddressClass -Address $source
            interface_index = [int]$route.InterfaceIndex
            next_hop_class = if ([string]$route.NextHop -in @(
                '0.0.0.0', '::'
            )) {
                'on-link'
            } else {
                Get-LabAddressClass -Address ([string]$route.NextHop)
            }
            adapter = $adapter
            error = $null
        }
    } catch {
        return [pscustomobject][ordered]@{
            available = $false
            family = if ($RemoteAddress.Contains(':')) { 'IPv6' } else { 'IPv4' }
            remote_address = Get-I03NormalizedIp -Address $RemoteAddress
            source_address = ''
            source_class = 'invalid'
            interface_index = $null
            next_hop_class = 'unknown'
            adapter = $null
            error = $_.Exception.Message
        }
    }
}

function Test-I03SamePhysicalPrefix {
    param(
        [Parameter(Mandatory = $true)][string]$LeftAddress,
        [Parameter(Mandatory = $true)][int]$LeftPrefixLength,
        [Parameter(Mandatory = $true)][string]$RightAddress,
        [Parameter(Mandatory = $true)][int]$RightPrefixLength
    )

    $left = $null
    $right = $null
    if (-not [Net.IPAddress]::TryParse(
        $LeftAddress.Split('%')[0], [ref]$left) -or
        -not [Net.IPAddress]::TryParse(
            $RightAddress.Split('%')[0], [ref]$right) -or
        $left.AddressFamily -ne $right.AddressFamily -or
        $LeftPrefixLength -ne $RightPrefixLength) {
        return $false
    }
    $leftBytes = $left.GetAddressBytes()
    $rightBytes = $right.GetAddressBytes()
    $maxBits = $leftBytes.Length * 8
    if ($LeftPrefixLength -le 0 -or $LeftPrefixLength -gt $maxBits) {
        return $false
    }
    $wholeBytes = [Math]::Floor($LeftPrefixLength / 8)
    for ($index = 0; $index -lt $wholeBytes; $index++) {
        if ($leftBytes[$index] -ne $rightBytes[$index]) {
            return $false
        }
    }
    $remainingBits = $LeftPrefixLength % 8
    if ($remainingBits -gt 0) {
        $mask = (0xff -shl (8 - $remainingBits)) -band 0xff
        if (($leftBytes[$wholeBytes] -band $mask) -ne
            ($rightBytes[$wholeBytes] -band $mask)) {
            return $false
        }
    }
    return $true
}

function Get-I03TupleKey {
    param(
        [Parameter(Mandatory = $true)][string]$Family,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][int]$LocalPort,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$RemotePort
    )

    return '{0}|{1}|{2}|{3}|{4}' -f $Family,
        (Get-I03NormalizedIp -Address $LocalAddress), $LocalPort,
        (Get-I03NormalizedIp -Address $RemoteAddress), $RemotePort
}

function Get-I03TargetConnections {
    return @(
        Get-NetTCPConnection -RemotePort $PeerTcpPort `
            -ErrorAction SilentlyContinue | Where-Object {
                (Get-I03NormalizedIp -Address ([string]$_.RemoteAddress)) -in
                    @($peerV4Text, $peerV6Text)
            } | ForEach-Object {
                $remote = Get-I03NormalizedIp -Address ([string]$_.RemoteAddress)
                $local = Get-I03NormalizedIp -Address ([string]$_.LocalAddress)
                $family = if ($remote.Contains(':')) { 'IPv6' } else { 'IPv4' }
                [pscustomobject][ordered]@{
                    captured_at_utc = Get-LabUtcTimestamp
                    owning_process = [int]$_.OwningProcess
                    state = [string]$_.State
                    family = $family
                    local_address = $local
                    local_port = [int]$_.LocalPort
                    remote_address = $remote
                    remote_port = [int]$_.RemotePort
                    tuple_key = Get-I03TupleKey -Family $family `
                        -LocalAddress $local -LocalPort ([int]$_.LocalPort) `
                        -RemoteAddress $remote -RemotePort ([int]$_.RemotePort)
                }
            }
    )
}

function Get-I03SocketEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$Connection,
        [Parameter(Mandatory = $true)][int]$ExpectedProcessId
    )

    $assigned = $null
    $adapter = $null
    $currentMatches = @()
    try {
        $familyName = if ([string]$Connection.family -eq 'IPv6') {
            'IPv6'
        } else { 'IPv4' }
        $assigned = Get-NetIPAddress -AddressFamily $familyName `
            -ErrorAction Stop | Where-Object {
                (Get-I03NormalizedIp -Address ([string]$_.IPAddress)) -eq
                    (Get-I03NormalizedIp -Address ([string]$Connection.local_address))
            } | Select-Object -First 1
        if ($null -ne $assigned) {
            $adapter = Get-I03AdapterEvidence `
                -InterfaceIndex ([int]$assigned.InterfaceIndex) `
                -Context 'candidate-established-socket'
        }
        $currentMatches = @(
            Get-NetTCPConnection -State Established `
                -OwningProcess $ExpectedProcessId `
                -LocalPort ([int]$Connection.local_port) `
                -RemotePort ([int]$Connection.remote_port) `
                -ErrorAction SilentlyContinue | Where-Object {
                    (Get-I03NormalizedIp `
                        -Address ([string]$_.LocalAddress)) -eq
                            (Get-I03NormalizedIp -Address `
                                ([string]$Connection.local_address)) -and
                    (Get-I03NormalizedIp `
                        -Address ([string]$_.RemoteAddress)) -eq
                            (Get-I03NormalizedIp -Address `
                                ([string]$Connection.remote_address))
                }
        )
    } catch {}
    return [pscustomobject][ordered]@{
        connection = $Connection
        expected_process_id = $ExpectedProcessId
        pid_matches = [int]$Connection.owning_process -eq $ExpectedProcessId
        current_established_match_count = $currentMatches.Count
        tuple_current_exact = $currentMatches.Count -eq 1
        local_address_assigned = $null -ne $assigned
        local_address_class = Get-LabAddressClass `
            -Address ([string]$Connection.local_address)
        adapter = $adapter
        physical_nonvirtual = $null -ne $adapter -and
            [bool]$adapter.physical_nonvirtual
    }
}

function Open-I03TcpProbe {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port,
        [ValidateRange(1, 30)][int]$TimeoutSeconds = 10
    )

    $client = New-Object Net.Sockets.TcpClient($Address.AddressFamily)
    try {
        if ($Address.AddressFamily -eq
            [Net.Sockets.AddressFamily]::InterNetworkV6) {
            $client.Client.DualMode = $false
        }
        $async = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(
            [TimeSpan]::FromSeconds($TimeoutSeconds)
        )) {
            throw "Timed out connecting to $Address`:$Port"
        }
        $client.EndConnect($async)
        $local = [Net.IPEndPoint]$client.Client.LocalEndPoint
        $remote = [Net.IPEndPoint]$client.Client.RemoteEndPoint
        $localText = Get-I03NormalizedIp -Address $local.Address.ToString()
        $family = if ($Address.AddressFamily -eq
            [Net.Sockets.AddressFamily]::InterNetworkV6) { 'IPv6' } else {
            'IPv4'
        }
        $assigned = Get-I03AssignedAddress -Address $localText `
            -Family $Address.AddressFamily -Context "baseline-$family-source"
        return [pscustomobject][ordered]@{
            client = $client
            evidence = [pscustomobject][ordered]@{
                connected = $true
                connected_at_utc = Get-LabUtcTimestamp
                family = $family
                local_address = $localText
                local_port = [int]$local.Port
                remote_address = Get-I03NormalizedIp `
                    -Address $remote.Address.ToString()
                remote_port = [int]$remote.Port
                adapter = $assigned.adapter
            }
        }
    } catch {
        $client.Dispose()
        throw
    }
}

function Wait-I03Api {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before API readiness (exit $($Process.ExitCode))"
        }
        try {
            $data = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$Port/api/status" -TimeoutSec 2
            return $data
        } catch {
            Start-Sleep -Milliseconds 300
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "API on port $Port did not become ready"
}

function Wait-I03Listener {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [switch]$RequireDualStack
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before listener $Port became ready"
        }
        $listeners = @(
            Get-NetTCPConnection -State Listen -LocalPort $Port `
                -OwningProcess $Process.Id -ErrorAction SilentlyContinue
        )
        if ($listeners.Count -gt 0) {
            $dual = @($listeners | Where-Object {
                (Get-I03NormalizedIp -Address ([string]$_.LocalAddress)) -eq '::'
            }).Count -gt 0
            if (-not $RequireDualStack -or $dual) {
                return [pscustomobject][ordered]@{
                    listeners = $listeners
                    dual_stack = $dual
                }
            }
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($RequireDualStack) {
        throw "A dual-stack [::]:$Port listener did not become ready"
    }
    throw "Listener $Port did not become ready"
}

function Test-I03ApiIsolation {
    param(
        [AllowNull()][object]$Data,
        [switch]$AllowControlledEd2k
    )

    if ($null -eq $Data) { return $false }
    $names = @($Data.PSObject.Properties.Name)
    $ed2kStateValid = if ($AllowControlledEd2k) {
        [bool]$Data.ed2k_connected
    } else {
        -not [bool]$Data.ed2k_connected
    }
    return $names -contains 'netlab_enabled' -and
        $names -contains 'netlab_consent' -and
        $names -contains 'kad_running_mask' -and
        $names -contains 'ed2k_connected' -and
        -not [bool]$Data.netlab_enabled -and
        [string]$Data.netlab_consent -eq 'declined' -and
        [int]$Data.kad_running_mask -eq 0 -and
        $ed2kStateValid
}

function Get-I03ApiProbe {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [switch]$AllowControlledEd2k
    )

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $data = $null
    $errorText = $null
    try {
        $data = Invoke-RestMethod `
            -Uri "http://127.0.0.1:$Port/api/status" -TimeoutSec 2
    } catch {
        $errorText = $_.Exception.Message
    } finally {
        $watch.Stop()
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        available = $null -ne $data
        duration_ms = [Int64]$watch.ElapsedMilliseconds
        isolation_valid = Test-I03ApiIsolation -Data $data `
            -AllowControlledEd2k:$AllowControlledEd2k
        error = $errorText
        data = $data
    }
}

function Initialize-I03UiProbe {
    if ('V91I03UiProbe' -as [type]) { return }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91I03UiProbe {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam,
        uint flags, uint timeout, out IntPtr result);
}
'@
}

function Get-I03UiProbe {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    Initialize-I03UiProbe
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $present = $false
    $responsive = $false
    try {
        $Process.Refresh()
        if (-not $Process.HasExited -and
            $Process.MainWindowHandle -ne [IntPtr]::Zero) {
            $present = $true
            $result = [IntPtr]::Zero
            $sent = [V91I03UiProbe]::SendMessageTimeout(
                $Process.MainWindowHandle, 0x0000,
                [IntPtr]::Zero, [IntPtr]::Zero,
                2, 500, [ref]$result
            )
            $responsive = $sent -ne [IntPtr]::Zero
        }
    } catch {
        $responsive = $false
    } finally {
        $watch.Stop()
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        process_id = $Process.Id
        main_window_present = $present
        message_pump_responsive = $responsive
        duration_ms = [Int64]$watch.ElapsedMilliseconds
    }
}

function Stop-I03OwnedProcess {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [switch]$RequireGraceful
    )

    if ($null -eq $Process) {
        return [pscustomobject]@{
            stopped = $true
            path_owned = $true
            graceful = $true
            process_id = $null
        }
    }
    $actual = Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
    if ($null -eq $actual) {
        return [pscustomobject]@{
            stopped = $true
            path_owned = $true
            graceful = $true
            process_id = $Process.Id
        }
    }
    $actualPath = ''
    try { $actualPath = [IO.Path]::GetFullPath($actual.Path) } catch {}
    $pathOwned = $actualPath -and
        $actualPath -eq [IO.Path]::GetFullPath($ExpectedPath)
    if (-not $pathOwned) {
        return [pscustomobject]@{
            stopped = $false
            path_owned = $false
            graceful = $false
            process_id = $actual.Id
        }
    }

    $graceful = $false
    try {
        $actual.Refresh()
        if ($actual.MainWindowHandle -ne [IntPtr]::Zero) {
            $null = $actual.CloseMainWindow()
            $graceful = $actual.WaitForExit(15000)
        }
        if (-not $graceful -and -not $RequireGraceful) {
            Stop-Process -Id $actual.Id -Force -ErrorAction Stop
            $null = $actual.WaitForExit(10000)
        }
    } catch {}
    $remaining = Get-Process -Id $actual.Id -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        stopped = $null -eq $remaining
        path_owned = $true
        graceful = $graceful
        process_id = $actual.Id
    }
}

function Get-I03UserHashSha256 {
    param([Parameter(Mandatory = $true)][string]$NodePath)

    $path = Join-Path $NodePath 'config\preferences.dat'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Stable peer identity file is missing: $path"
    }
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -lt 17) {
        throw "Stable peer identity file is truncated: $path"
    }
    $identity = New-Object byte[] 16
    [Array]::Copy($bytes, 1, $identity, 0, 16)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash($identity)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-I03Md5Text {
    param([Parameter(Mandatory = $true)][string]$Value)

    $md5 = [Security.Cryptography.MD5]::Create()
    try {
        return ([BitConverter]::ToString(
            $md5.ComputeHash([Text.Encoding]::Unicode.GetBytes($Value))
        )).Replace('-', '')
    } finally {
        $md5.Dispose()
    }
}

function Get-I03ClassicSession {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $encoded = [Uri]::EscapeDataString($Password)
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        try {
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/?w=password&p=$encoded" `
                -UseBasicParsing -TimeoutSec 10
            $match = [regex]::Match($response.Content, 'ses=(\d+)')
            if ($match.Success) { return $match.Groups[1].Value }
        } catch {}
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Classic WebServer login failed on port $Port"
}

function Get-I03SharedLink {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][Int64]$FileBytes
    )

    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    $pattern = 'ed2k://\|file\|' + [regex]::Escape($FileName) +
        '\|' + $FileBytes + '\|([A-Fa-f0-9]{32})' +
        '(?:\|h=[A-Z2-7]{32})?\|/'
    do {
        try {
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/?ses=$Session&w=shared" `
                -UseBasicParsing -TimeoutSec 15
            $match = [regex]::Match($response.Content, $pattern)
            if ($match.Success) {
                return [pscustomobject][ordered]@{
                    link = $match.Value
                    ed2k_hash = $match.Groups[1].Value.ToUpperInvariant()
                }
            }
        } catch {}
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Timed out waiting for the unique I03 fixture to enter the shared list'
}

function Send-I03Ed2kLink {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Link
    )

    if (-not ('V91I03CopyDataTimeout' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91I03CopyDataTimeout {
    [StructLayout(LayoutKind.Sequential)]
    public struct COPYDATASTRUCT {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint msg, IntPtr wParam,
        ref COPYDATASTRUCT lParam, uint flags, uint timeoutMs,
        out UIntPtr result);
}
'@
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $handle = [IntPtr]::Zero
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'Client exited before direct-link injection'
        }
        $handle = $Process.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($handle -eq [IntPtr]::Zero) {
        throw 'Client main window handle was unavailable'
    }

    $pointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Link)
    try {
        $payload = New-Object V91I03CopyDataTimeout+COPYDATASTRUCT
        $payload.dwData = [IntPtr]12000
        $payload.cbData = ($Link.Length + 1) * 2
        $payload.lpData = $pointer
        $nativeResult = [UIntPtr]::Zero
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $sent = [V91I03CopyDataTimeout]::SendMessageTimeout(
            $handle, 0x004A, [IntPtr]::Zero, [ref]$payload,
            0x0003, 10000, [ref]$nativeResult
        )
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $watch.Stop()
        if ($sent -eq [IntPtr]::Zero) {
            throw (
                'WM_COPYDATA delivery timed out or failed after ' +
                "$($watch.ElapsedMilliseconds) ms (Win32=$lastError)"
            )
        }
        if ($nativeResult.ToUInt64() -eq 0) {
            throw 'Candidate rejected the WM_COPYDATA eD2K link'
        }
        return [pscustomobject][ordered]@{
            delivered = $true
            accepted = $true
            duration_ms = [Int64]$watch.ElapsedMilliseconds
            native_result = $nativeResult.ToUInt64()
            timeout_ms = 10000
            flags = 'SMTO_ABORTIFHUNG|SMTO_BLOCK'
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
    }
}

function Get-I03HelloEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ExpectedIPv6
    )

    $highId = 0
    $lowIdLike = 0
    $files = @()
    foreach ($log in @(
        Get-ChildItem -LiteralPath $NodePath -Recurse -File -Filter '*.log' `
            -ErrorAction SilentlyContinue
    )) {
        $lines = @()
        try { $lines = @(Get-Content -LiteralPath $log.FullName) } catch {}
        foreach ($lineObject in $lines) {
            $line = [string]$lineObject
            if ($line -notmatch 'OP_HelloAnswer\s+from\s+([^\s]+)') {
                continue
            }
            $firstToken = $Matches[1].Trim('[', ']', '(', ')')
            $parsed = $null
            if ([Net.IPAddress]::TryParse($firstToken.Split('%')[0],
                [ref]$parsed) -and
                (Get-I03NormalizedIp -Address $parsed.ToString()) -eq
                    $ExpectedIPv6) {
                # HighID DbgGetClientInfo begins with the endpoint. LowID begins
                # with "<id>@<server>" and only mentions IPv6 in parentheses.
                $highId++
            } elseif ($line -match [regex]::Escape($ExpectedIPv6) -and
                $firstToken.Contains('@')) {
                $lowIdLike++
            }
        }
        $files += [pscustomobject][ordered]@{
            relative_path = $log.FullName.Substring(
                [IO.Path]::GetFullPath($NodePath).Length
            ).TrimStart('\')
            bytes = [Int64]$log.Length
            sha256 = Get-LabSha256 -Path $log.FullName
        }
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        expected_ipv6 = $ExpectedIPv6
        highid_hello_answer_count = $highId
        lowid_like_hello_answer_count = $lowIdLike
        learned_public_ipv6_via_hello = $highId -gt 0 -and $lowIdLike -eq 0
        files = $files
    }
}

function Set-I03IsolatedPreferences {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][int]$IPv6Mode,
        [Parameter(Mandatory = $true)][string]$IPv6BindAddress,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$IncomingPath,
        [Parameter(Mandatory = $true)][string]$TempPath,
        [ValidateRange(0, 1024)][int]$MaxUploadKiBps = 0
    )

    $config = Join-Path $NodePath 'config'
    $preferences = Join-Path $config 'preferences.ini'
    $removedIdentityFiles = New-Object 'Collections.Generic.List[string]'
    foreach ($identityName in @(
        'preferences.dat', 'cryptkey.dat', 'clients.met'
    )) {
        $identityPath = Join-Path $config $identityName
        if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
            Remove-Item -LiteralPath $identityPath -Force `
                -ErrorAction Stop
            $removedIdentityFiles.Add($identityName)
        }
    }
    foreach ($entry in ([ordered]@{
        Autoconnect = '0'
        NetworkED2K = '0'
        NetworkKademlia = '0'
        Serverlist = '0'
        UpdateNotifyTestClient = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        VerboseOptions = '1'
        Verbose = '1'
        SaveLogToDisk = '1'
        SaveDebugToDisk = '1'
        DebugClientTCP = '1'
        ConfirmExit = '0'
        CryptLayerRequested = '0'
        CryptLayerRequired = '0'
        CryptLayerSupported = '0'
        IncomingDir = ($IncomingPath + '\')
        TempDir = ($TempPath + '\')
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
    }
    if ($MaxUploadKiBps -gt 0) {
        foreach ($entry in ([ordered]@{
            MaxUpload = [string]$MaxUploadKiBps
            UploadCapacityNew = [string]($MaxUploadKiBps * 2)
            MinUpload = '1'
            USSEnabled = '0'
        }).GetEnumerator()) {
            Set-LabIniValue -Path $preferences -Section 'eMule' `
                -Key $entry.Key -Value $entry.Value
        }
    }
    foreach ($entry in ([ordered]@{
        IPv6Mode = [string]$IPv6Mode
        IPv6BindAddr = $IPv6BindAddress
        KadNetworkMask = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'Connection' `
            -Key $entry.Key -Value $entry.Value
    }
    foreach ($entry in ([ordered]@{
        EseNetLabConsent = '1'
        EseNetLabAdvancedConsent = '1'
        EseNetLabContributionConsent = '1'
        EseNetLabEnabled = '0'
        EseV9Experimental = '0'
        EnableUtpHolePunch = '0'
        EseAutoKeepalive = '0'
        EseKad3Rendezvous = '0'
        EseReachSelector = '0'
        EseHolePunchPortPredict = '0'
        EseEd2kPunch3 = '0'
        EseRelayAccept = '0'
        EseRelayEgress = '0'
        Kad6BetaExitOptIn = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eSE' `
            -Key $entry.Key -Value $entry.Value
    }
    Set-LabIniValue -Path $preferences -Section 'Proxy' `
        -Key 'ProxyEnableProxy' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'UPnP' `
        -Key 'EnableUPnP' -Value '0'
    foreach ($entry in ([ordered]@{
        Enabled = '1'
        Port = [string]$WebPort
        Password = Get-I03Md5Text -Value $Password
        AllowedIPs = '127.0.0.1'
        WebUseUPnP = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'WebServer' `
            -Key $entry.Key -Value $entry.Value
    }
    Set-LabIniValue -Path $preferences -Section 'KRPRelay' `
        -Key 'KrpRelayEnabled' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'KRPRelay' `
        -Key 'KrpRelayKillSwitch' -Value '1'

    # No inherited shared directory may introduce another source. This is an
    # isolated package copy; the candidate package itself is never modified.
    $shares = Join-Path $NodePath 'config\shareddir.dat'
    [IO.File]::WriteAllText($shares, '', (New-Object Text.UTF8Encoding($false)))
    # Route/HELLO evidence must belong to this run, never to a log inherited
    # from the release package copied by prepare_node.ps1.
    foreach ($runtimeLog in @(
        Get-ChildItem -LiteralPath $NodePath -Recurse -File -Filter '*.log' `
            -ErrorAction SilentlyContinue
    )) {
        Remove-Item -LiteralPath $runtimeLog.FullName -Force `
            -ErrorAction Stop
    }
    return [pscustomobject][ordered]@{
        preferences_ini_path = $preferences
        identity_bootstrap = 'fresh isolated profile'
        inherited_identity_files_removed = @($removedIdentityFiles)
        preferences_dat_absent_before_start =
            -not (Test-Path -LiteralPath (
                Join-Path $config 'preferences.dat'
            ))
        cryptkey_dat_absent_before_start =
            -not (Test-Path -LiteralPath (
                Join-Path $config 'cryptkey.dat'
            ))
        max_upload_kib_per_second = $MaxUploadKiBps
        dynamic_upload_disabled = $MaxUploadKiBps -gt 0
    }
}

function Test-I03PortSetFree {
    param([Parameter(Mandatory = $true)][int[]]$Ports)

    foreach ($port in $Ports) {
        if (Get-NetTCPConnection -State Listen -LocalPort $port `
            -ErrorAction SilentlyContinue) {
            throw "TCP port $port is already listening"
        }
        if (Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue) {
            throw "UDP port $port is already in use"
        }
    }
}

function Get-I03PeerDualStackMarker {
    param([Parameter(Mandatory = $true)][string]$NodePath)

    $inbound = 0
    $accepted = 0
    $files = @()
    foreach ($log in @(
        Get-ChildItem -LiteralPath $NodePath -Recurse -File -Filter '*.log' `
            -ErrorAction SilentlyContinue
    )) {
        $content = ''
        try { $content = Get-Content -LiteralPath $log.FullName -Raw } catch {}
        $inbound += @([regex]::Matches(
            $content, '(?i)native IPv6 inbound TCP observed'
        )).Count
        $accepted += @([regex]::Matches(
            $content, '(?i)Accepted native IPv6 client'
        )).Count
        $files += [pscustomobject][ordered]@{
            relative_path = $log.FullName.Substring(
                [IO.Path]::GetFullPath($NodePath).Length
            ).TrimStart('\')
            bytes = [Int64]$log.Length
            sha256 = Get-LabSha256 -Path $log.FullName
        }
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        inbound_reachability_markers = $inbound
        accepted_native_ipv6_markers = $accepted
        dualstack_capability_armed = $inbound -gt 0 -and $accepted -gt 0
        files = $files
    }
}

function Wait-I03Prewarm {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$TempPath,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$SamplesPath
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastPartWrite = $null
    $progress = $false
    $selected = $null
    $hello = $null
    $apiCount = 0
    $apiFailures = 0
    $apiMaxMs = 0L
    $uiCount = 0
    $uiFailures = 0
    $uiMaxMs = 0L
    $otherPid = [System.Collections.Generic.List[object]]::new()
    $otherPidKeys = New-Object `
        'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    $nextHealth = [DateTime]::UtcNow
    $lastSignature = ''
    $sample = 0

    do {
        $Process.Refresh()
        if ($Process.HasExited) { throw 'Client exited during IPv4 prewarm' }
        $connections = @(Get-I03TargetConnections)
        foreach ($other in @($connections | Where-Object {
            [int]$_.owning_process -ne $Process.Id -and
            [string]$_.state -in @('SynSent', 'Established')
        })) {
            $otherKey = '{0}|{1}|{2}' -f $other.owning_process,
                $other.state, $other.tuple_key
            if ($otherPidKeys.Add($otherKey)) {
                $otherPid.Add($other)
            }
        }
        $owned = @($connections | Where-Object {
            [int]$_.owning_process -eq $Process.Id -and
            [string]$_.state -eq 'Established'
        })
        $ownedV4 = @($owned | Where-Object family -eq 'IPv4')
        $ownedV6 = @($owned | Where-Object family -eq 'IPv6')
        if ($ownedV4.Count -eq 1 -and $ownedV6.Count -eq 0) {
            $selected = $ownedV4[0]
        } elseif ($owned.Count -gt 1 -or $ownedV6.Count -gt 0) {
            throw 'Ambiguous or non-IPv4 connection appeared during prewarm'
        } else {
            $selected = $null
        }

        $part = Get-ChildItem -LiteralPath $TempPath -File -Filter '*.part' `
            -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        if ($null -ne $part) {
            if ($null -ne $lastPartWrite -and
                $part.LastWriteTimeUtc -gt $lastPartWrite) {
                $progress = $true
            }
            $lastPartWrite = $part.LastWriteTimeUtc
        }
        $hello = Get-I03HelloEvidence -NodePath $NodePath `
            -ExpectedIPv6 $peerV6Text

        $now = [DateTime]::UtcNow
        $health = $null
        if ($now -ge $nextHealth) {
            $api = Get-I03ApiProbe -Port $WebPort -AllowControlledEd2k
            $ui = Get-I03UiProbe -Process $Process
            $apiCount++
            if (-not $api.available -or -not $api.isolation_valid) {
                $apiFailures++
            }
            $apiMaxMs = [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
            $uiCount++
            if (-not $ui.main_window_present -or
                -not $ui.message_pump_responsive) {
                $uiFailures++
            }
            $uiMaxMs = [Math]::Max($uiMaxMs, [Int64]$ui.duration_ms)
            $health = [ordered]@{ api = $api; ui = $ui }
            $nextHealth = $now.AddSeconds(1)
        }
        $signature = (@($connections | ForEach-Object {
            '{0}:{1}:{2}:{3}' -f $_.owning_process, $_.state,
                $_.family, $_.tuple_key
        }) -join ';')
        if ($signature -ne $lastSignature -or $null -ne $health) {
            Add-I03JsonLine -Path $SamplesPath -Value ([ordered]@{
                schema = 'ese.v91.i03-prewarm-sample/v1'
                sample_number = ++$sample
                captured_at_utc = Get-LabUtcTimestamp
                connections = $connections
                transfer_progress = $progress
                hello = $hello
                health = $health
            })
            $lastSignature = $signature
        }

        if ($null -ne $selected -and $progress -and
            [bool]$hello.learned_public_ipv6_via_hello) {
            Start-Sleep -Milliseconds 500
            break
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)

    $finalConnections = @(Get-I03TargetConnections)
    foreach ($other in @($finalConnections | Where-Object {
        [int]$_.owning_process -ne $Process.Id -and
        [string]$_.state -in @('SynSent', 'Established')
    })) {
        $otherKey = '{0}|{1}|{2}' -f $other.owning_process,
            $other.state, $other.tuple_key
        if ($otherPidKeys.Add($otherKey)) {
            $otherPid.Add($other)
        }
    }
    $finalOwned = @($finalConnections | Where-Object {
        [int]$_.owning_process -eq $Process.Id -and
        [string]$_.state -eq 'Established'
    })
    $finalOwnedV4 = @($finalOwned | Where-Object family -eq 'IPv4')
    $finalOwnedV6 = @($finalOwned | Where-Object family -eq 'IPv6')
    if ($finalOwnedV4.Count -eq 1 -and $finalOwnedV6.Count -eq 0) {
        $selected = $finalOwnedV4[0]
    } else {
        $selected = $null
    }
    $socket = if ($null -ne $selected) {
        Get-I03SocketEvidence -Connection $selected `
            -ExpectedProcessId $Process.Id
    } else { $null }
    return [pscustomobject][ordered]@{
        complete = $null -ne $selected -and $progress -and
            $null -ne $hello -and
            [bool]$hello.learned_public_ipv6_via_hello
        selected_connection = $selected
        socket = $socket
        final_connection_revalidation = [ordered]@{
            captured_at_utc = Get-LabUtcTimestamp
            current_owned_established_count = $finalOwned.Count
            current_ipv4_established_count = $finalOwnedV4.Count
            current_ipv6_established_count = $finalOwnedV6.Count
            selected_tuple_current = $null -ne $selected
        }
        transfer_progress = $progress
        hello = $hello
        other_pid_connection_count = $otherPid.Count
        other_pid_connections = @($otherPid)
        api_probe_count = $apiCount
        api_failure_count = $apiFailures
        api_max_ms = $apiMaxMs
        ui_probe_count = $uiCount
        ui_failure_count = $uiFailures
        ui_max_ms = $uiMaxMs
        health_valid = $apiCount -gt 0 -and $apiFailures -eq 0 -and
            $apiMaxMs -lt 2000 -and $uiCount -gt 0 -and
            $uiFailures -eq 0 -and $uiMaxMs -lt 1000
    }
}

function Wait-I03PostRestartRoute {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][string]$ExpectedFamily,
        [Parameter(Mandatory = $true)][string]$PrewarmTuple,
        [Parameter(Mandatory = $true)][string]$RestartAckPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$ObservationSeconds,
        [Parameter(Mandatory = $true)][string]$SamplesPath
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $prewarmGone = $false
    $prewarmGoneAt = $null
    $selected = $null
    $selectedAt = $null
    $wrongSelected = $null
    $wrongSelectedAt = $null
    $stableSignature = ''
    $stableSince = $null
    $ambiguousSelectionObserved = $false
    $wrongFamily = [System.Collections.Generic.List[object]]::new()
    $wrongFamilyKeys = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    $otherPid = [System.Collections.Generic.List[object]]::new()
    $otherPidKeys = New-Object `
        'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    $restartAck = $null
    $apiCount = 0
    $apiFailures = 0
    $apiMaxMs = 0L
    $uiCount = 0
    $uiFailures = 0
    $uiMaxMs = 0L
    $nextHealth = [DateTime]::UtcNow
    $lastSignature = ''
    $sample = 0

    do {
        $now = [DateTime]::UtcNow
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'Client exited during post-restart route observation'
        }
        if ($null -eq $restartAck -and
            (Test-Path -LiteralPath $RestartAckPath -PathType Leaf)) {
            $restartAck = Get-Content -LiteralPath $RestartAckPath -Raw |
                ConvertFrom-Json -ErrorAction Stop
        }
        $connections = @(Get-I03TargetConnections)
        $prewarmPresent = @($connections | Where-Object {
            [int]$_.owning_process -eq $Process.Id -and
            [string]$_.tuple_key -eq $PrewarmTuple -and
            [string]$_.state -in @('SynSent', 'Established')
        }).Count -gt 0
        if (-not $prewarmPresent -and -not $prewarmGone) {
            $prewarmGone = $true
            $prewarmGoneAt = $now
        }
        foreach ($connection in @($connections | Where-Object {
            [string]$_.state -in @('SynSent', 'Established')
        })) {
            if ([int]$connection.owning_process -ne $Process.Id) {
                $otherKey = '{0}|{1}|{2}' -f
                    $connection.owning_process, $connection.state,
                    $connection.tuple_key
                if ($otherPidKeys.Add($otherKey)) {
                    $otherPid.Add($connection)
                }
                continue
            }
            if (-not $prewarmGone) {
                continue
            }
            if ([string]$connection.family -ne $ExpectedFamily) {
                $wrongKey = '{0}|{1}' -f $connection.state,
                    $connection.tuple_key
                if ($wrongFamilyKeys.Add($wrongKey)) {
                    $wrongFamily.Add($connection)
                }
            }
        }
        $currentEstablished = @(
            if ($prewarmGone) {
                $connections | Where-Object {
                    [int]$_.owning_process -eq $Process.Id -and
                    [string]$_.state -eq 'Established'
                }
            }
        )
        $currentExpected = @($currentEstablished | Where-Object {
            [string]$_.family -eq $ExpectedFamily
        })
        $currentWrong = @($currentEstablished | Where-Object {
            [string]$_.family -ne $ExpectedFamily
        })
        if ($currentExpected.Count -gt 1 -or
            $currentWrong.Count -gt 1 -or
            ($currentExpected.Count -gt 0 -and
                $currentWrong.Count -gt 0)) {
            $ambiguousSelectionObserved = $true
        }
        $currentStableSignature = @(
            $currentEstablished.tuple_key | Sort-Object
        ) -join ';'
        if ($currentStableSignature) {
            if ($currentStableSignature -ne $stableSignature) {
                $stableSignature = $currentStableSignature
                $stableSince = $now
            }
        } else {
            $stableSignature = ''
            $stableSince = $null
        }
        $selected = if ($currentExpected.Count -eq 1) {
            $currentExpected[0]
        } else { $null }
        $wrongSelected = if ($currentWrong.Count -eq 1) {
            $currentWrong[0]
        } else { $null }
        $selectedAt = if ($null -ne $selected) {
            $stableSince
        } else { $null }
        $wrongSelectedAt = if ($null -ne $wrongSelected) {
            $stableSince
        } else { $null }

        $health = $null
        if ($now -ge $nextHealth) {
            $api = Get-I03ApiProbe -Port $WebPort -AllowControlledEd2k
            $ui = Get-I03UiProbe -Process $Process
            $apiCount++
            if (-not $api.available -or -not $api.isolation_valid) {
                $apiFailures++
            }
            $apiMaxMs = [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
            $uiCount++
            if (-not $ui.main_window_present -or
                -not $ui.message_pump_responsive) {
                $uiFailures++
            }
            $uiMaxMs = [Math]::Max($uiMaxMs, [Int64]$ui.duration_ms)
            $health = [ordered]@{ api = $api; ui = $ui }
            $nextHealth = $now.AddSeconds(1)
        }
        $signature = (@($connections | ForEach-Object {
            '{0}:{1}:{2}:{3}' -f $_.owning_process, $_.state,
                $_.family, $_.tuple_key
        }) -join ';')
        if ($signature -ne $lastSignature -or $null -ne $health) {
            Add-I03JsonLine -Path $SamplesPath -Value ([ordered]@{
                schema = 'ese.v91.i03-route-sample/v1'
                sample_number = ++$sample
                captured_at_utc = Get-LabUtcTimestamp
                prewarm_gone = $prewarmGone
                expected_family = $ExpectedFamily
                connections = $connections
                restart_ack_seen = $null -ne $restartAck
                current_established_signature =
                    $currentStableSignature
                current_established_since_utc = if (
                    $null -eq $stableSince
                ) { $null } else { $stableSince.ToString('o') }
                health = $health
            })
            $lastSignature = $signature
        }
        if ($null -ne $stableSince -and $null -ne $restartAck -and
            ($now - $stableSince).TotalSeconds -ge $ObservationSeconds) {
            break
        }
        Start-Sleep -Milliseconds 75
    } while ([DateTime]::UtcNow -lt $deadline)

    $Process.Refresh()
    if ($Process.HasExited) {
        throw 'Client exited during post-restart route observation'
    }
    $finalConnections = @(Get-I03TargetConnections)
    foreach ($other in @($finalConnections | Where-Object {
        [int]$_.owning_process -ne $Process.Id -and
        [string]$_.state -in @('SynSent', 'Established')
    })) {
        $otherKey = '{0}|{1}|{2}' -f $other.owning_process,
            $other.state, $other.tuple_key
        if ($otherPidKeys.Add($otherKey)) {
            $otherPid.Add($other)
        }
    }
    $finalEstablished = @(
        if ($prewarmGone) {
            $finalConnections | Where-Object {
                [int]$_.owning_process -eq $Process.Id -and
                [string]$_.state -eq 'Established'
            }
        }
    )
    $finalExpected = @($finalEstablished | Where-Object {
        [string]$_.family -eq $ExpectedFamily
    })
    $finalWrong = @($finalEstablished | Where-Object {
        [string]$_.family -ne $ExpectedFamily
    })
    $finalSignature = @(
        $finalEstablished.tuple_key | Sort-Object
    ) -join ';'
    $finalMatchesObservedWindow = $finalSignature -and
        $finalSignature -eq $stableSignature
    if ($finalSignature -ne $stableSignature) {
        $stableSignature = $finalSignature
        $stableSince = if ($finalSignature) {
            [DateTime]::UtcNow
        } else { $null }
    }
    if ($finalExpected.Count -gt 1 -or
        $finalWrong.Count -gt 1 -or
        ($finalExpected.Count -gt 0 -and $finalWrong.Count -gt 0)) {
        $ambiguousSelectionObserved = $true
    }
    $selected = if ($finalExpected.Count -eq 1) {
        $finalExpected[0]
    } else { $null }
    $wrongSelected = if ($finalWrong.Count -eq 1) {
        $finalWrong[0]
    } else { $null }
    $selectedAt = if ($null -ne $selected) {
        $stableSince
    } else { $null }
    $wrongSelectedAt = if ($null -ne $wrongSelected) {
        $stableSince
    } else { $null }
    $currentSocketEvidence = @(
        $finalEstablished | ForEach-Object {
            Get-I03SocketEvidence -Connection $_ `
                -ExpectedProcessId $Process.Id
        }
    )
    $socket = if ($null -ne $selected) {
        Get-I03SocketEvidence -Connection $selected `
            -ExpectedProcessId $Process.Id
    } else { $null }
    $wrongSocket = if ($null -ne $wrongSelected) {
        Get-I03SocketEvidence -Connection $wrongSelected `
            -ExpectedProcessId $Process.Id
    } else { $null }
    return [pscustomobject][ordered]@{
        prewarm_tuple = $PrewarmTuple
        prewarm_disappeared = $prewarmGone
        prewarm_disappeared_at_utc = if ($null -eq $prewarmGoneAt) {
            $null
        } else { $prewarmGoneAt.ToString('o') }
        restart_ack = $restartAck
        expected_family = $ExpectedFamily
        selected_connection = $selected
        selected_at_utc = if ($null -eq $selectedAt) {
            $null
        } else { $selectedAt.ToString('o') }
        socket = $socket
        wrong_family_selected_connection = $wrongSelected
        wrong_family_selected_at_utc = if ($null -eq $wrongSelectedAt) {
            $null
        } else { $wrongSelectedAt.ToString('o') }
        wrong_family_socket = $wrongSocket
        current_established_connections = @($finalEstablished)
        current_socket_evidence = @($currentSocketEvidence)
        final_connection_revalidation = [ordered]@{
            captured_at_utc = Get-LabUtcTimestamp
            signature = $finalSignature
            matches_continuous_observation_window =
                [bool]$finalMatchesObservedWindow
            established_count = @($finalEstablished).Count
            expected_family_count = $finalExpected.Count
            wrong_family_count = $finalWrong.Count
        }
        ambiguous_family_selection = $ambiguousSelectionObserved
        wrong_family_observation_count = $wrongFamily.Count
        wrong_family_observations = @($wrongFamily)
        other_pid_connection_count = $otherPid.Count
        other_pid_connections = @($otherPid)
        stable_observation_seconds = if ($null -eq $stableSince -or
            -not $finalSignature) {
            0
        } else {
            [Math]::Round(
                ([DateTime]::UtcNow - $stableSince).TotalSeconds, 3
            )
        }
        api_probe_count = $apiCount
        api_failure_count = $apiFailures
        api_max_ms = $apiMaxMs
        ui_probe_count = $uiCount
        ui_failure_count = $uiFailures
        ui_max_ms = $uiMaxMs
        health_valid = $apiCount -gt 0 -and $apiFailures -eq 0 -and
            $apiMaxMs -lt 2000 -and $uiCount -gt 0 -and
            $uiFailures -eq 0 -and $uiMaxMs -lt 1000
    }
}

function Enable-I03ControlledEd2kProfile {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ServerAddress,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1024, 65535)][int]$ServerPort,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][string]$Policy
    )

    $preferences = Join-Path $NodePath 'config\preferences.ini'
    foreach ($entry in ([ordered]@{
        Autoconnect = '1'
        NetworkED2K = '1'
        NetworkKademlia = '0'
        AutoConnectStaticOnly = '1'
        Reconnect = '1'
        Serverlist = '0'
        UpdateNotifyTestClient = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        FilterBadIPs = '0'
        FilterServersByIP = '0'
        ServerKeepAliveTimeout = '60000'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
    }

    $config = Join-Path $NodePath 'config'
    foreach ($name in @(
        'server.met', 'server_met.old', 'server_met.download',
        'server_met.old.bak'
    )) {
        $path = Join-Path $config $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
    $staticPath = Join-Path $config 'staticservers.dat'
    $line = '{0}:{1},0,eSE-I03-{2}-{3}' -f
        $ServerAddress, $ServerPort, $RunNonce, $Policy
    [IO.File]::WriteAllText(
        $staticPath, ($line + "`r`n"),
        (New-Object Text.UnicodeEncoding($false, $true))
    )
    return [pscustomobject][ordered]@{
        endpoint = "$ServerAddress`:$ServerPort"
        endpoint_scope = 'same-host assigned physical IPv4'
        staticservers_path = $staticPath
        staticservers_sha256 = Get-LabSha256 -Path $staticPath
        preferences_sha256 = Get-LabSha256 -Path $preferences
        network_ed2k = $true
        network_kad = $false
        auto_connect_static_only = $true
        filter_lan_ips = $false
        third_party_server_files_removed = $true
    }
}

function Start-I03ControlledEd2kServer {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedClientAddress,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][string]$Policy
    )

    $listenIp = [Net.IPAddress]::Parse($ListenAddress)
    if ($listenIp.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork -or
        [Net.IPAddress]::IsLoopback($listenIp)) {
        throw 'Controlled eD2K server requires an assigned non-loopback IPv4'
    }
    $listener = New-Object Net.Sockets.TcpListener($listenIp, 0)
    $listener.Server.ExclusiveAddressUse = $true
    $listener.Start(1)
    $port = [int]([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $state = New-Object `
        'Collections.Concurrent.ConcurrentDictionary[string,object]'
    $state['phase'] = 'listening'
    $state['stop_requested'] = $false
    $state['logged_in'] = $false
    $state['reply_sent'] = $false
    $state['error'] = ''
    $state['frames_received'] = 0
    $state['listen_port'] = $port
    $state['high_id'] = [uint32]0x01000001

    $state['listen_address'] = $ListenAddress
    $state['expected_client_address'] = $ExpectedClientAddress

    $serverBody = {
        param(
            $Listener, $State, $ResultPath, $Nonce, $PolicyName,
            $AllowedClientAddress
        )

        function Read-ExactBytes {
            param(
                [Parameter(Mandatory = $true)]
                [Net.Sockets.NetworkStream]$Stream,
                [Parameter(Mandatory = $true)][int]$Count
            )
            $buffer = New-Object byte[] $Count
            $offset = 0
            while ($offset -lt $Count) {
                $read = $Stream.Read($buffer, $offset, $Count - $offset)
                if ($read -le 0) {
                    throw "Controlled server TCP stream closed after $offset/$Count bytes"
                }
                $offset += $read
            }
            return $buffer
        }

        function Send-Ed2kFrame {
            param(
                [Parameter(Mandatory = $true)]
                [Net.Sockets.NetworkStream]$Stream,
                [Parameter(Mandatory = $true)][byte]$Opcode,
                [Parameter(Mandatory = $true)][byte[]]$Payload
            )
            $header = New-Object byte[] 6
            $header[0] = 0xE3
            [Array]::Copy(
                [BitConverter]::GetBytes([uint32]($Payload.Length + 1)),
                0, $header, 1, 4
            )
            $header[5] = $Opcode
            $Stream.Write($header, 0, $header.Length)
            if ($Payload.Length -gt 0) {
                $Stream.Write($Payload, 0, $Payload.Length)
            }
            $Stream.Flush()
        }

        $client = $null
        $stream = $null
        $loginAt = ''
        $stoppedAt = ''
        try {
            $State['phase'] = 'accepting'
            $client = $Listener.AcceptTcpClient()
            $State['client'] = $client
            $remote = [Net.IPEndPoint]$client.Client.RemoteEndPoint
            if ($remote.Address.ToString() -ne $AllowedClientAddress) {
                throw (
                    "Controlled server accepted unexpected client $remote; " +
                    "expected $AllowedClientAddress"
                )
            }
            $State['accepted_remote'] = $remote.ToString()
            $stream = $client.GetStream()
            $stream.ReadTimeout = 30000
            $header = Read-ExactBytes -Stream $stream -Count 6
            $packetLength = [BitConverter]::ToUInt32($header, 1)
            if ($header[0] -ne 0xE3 -or $header[5] -ne 0x01 -or
                $packetLength -lt 23 -or $packetLength -gt 1048576) {
                throw (
                    'Expected OP_EDONKEYPROT:OP_LOGINREQUEST with at least ' +
                    "22 payload bytes; protocol=0x$('{0:X2}' -f $header[0]) " +
                    "opcode=0x$('{0:X2}' -f $header[5]) length=$packetLength"
                )
            }
            $payload = Read-ExactBytes -Stream $stream `
                -Count ([int]$packetLength - 1)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $payloadSha = ([BitConverter]::ToString(
                    $sha.ComputeHash($payload)
                )).Replace('-', '').ToLowerInvariant()
            } finally {
                $sha.Dispose()
            }
            $State['login_protocol'] = [int]$header[0]
            $State['login_opcode'] = [int]$header[5]
            $State['login_payload_bytes'] = $payload.Length
            $State['login_payload_sha256'] = $payloadSha
            $State['login_advertised_tcp_port'] =
                [int][BitConverter]::ToUInt16($payload, 20)
            $loginAt = [DateTime]::UtcNow.ToString('o')

            $idPayload = [BitConverter]::GetBytes([uint32]0x01000001)
            Send-Ed2kFrame -Stream $stream -Opcode 0x40 `
                -Payload $idPayload
            $State['reply_sent'] = $true
            $State['logged_in'] = $true
            $State['phase'] = 'connected'
            $State['login_at_utc'] = $loginAt
            $stream.ReadTimeout = 2000
            $nextStatus = [DateTime]::UtcNow.AddSeconds(10)

            while (-not [bool]$State['stop_requested']) {
                if ($stream.DataAvailable) {
                    $nextHeader = Read-ExactBytes -Stream $stream -Count 6
                    $nextLength = [BitConverter]::ToUInt32($nextHeader, 1)
                    if ($nextLength -lt 1 -or $nextLength -gt 16777216) {
                        throw "Invalid client frame length $nextLength"
                    }
                    $remaining = [int]$nextLength - 1
                    if ($remaining -gt 0) {
                        $null = Read-ExactBytes -Stream $stream `
                            -Count $remaining
                    }
                    $State['frames_received'] =
                        [int]$State['frames_received'] + 1
                    $State['last_client_opcode'] = [int]$nextHeader[5]
                } elseif ([DateTime]::UtcNow -ge $nextStatus) {
                    Send-Ed2kFrame -Stream $stream -Opcode 0x34 `
                        -Payload (New-Object byte[] 8)
                    $State['status_frames_sent'] = if (
                        $State.ContainsKey('status_frames_sent')
                    ) {
                        [int]$State['status_frames_sent'] + 1
                    } else { 1 }
                    $nextStatus = [DateTime]::UtcNow.AddSeconds(10)
                } else {
                    Start-Sleep -Milliseconds 50
                }
            }
        } catch {
            if (-not [bool]$State['stop_requested']) {
                $State['error'] = $_.Exception.Message
                $State['phase'] = 'error'
            }
        } finally {
            $stoppedAt = [DateTime]::UtcNow.ToString('o')
            if ($null -ne $stream) {
                try { $stream.Dispose() } catch {}
            }
            if ($null -ne $client) {
                try { $client.Dispose() } catch {}
            }
            try { $Listener.Stop() } catch {}
            if ([string]$State['phase'] -ne 'error') {
                $State['phase'] = 'stopped'
            }
            $State['stopped_at_utc'] = $stoppedAt
            $result = [ordered]@{
                schema = 'ese.v91.i03-controlled-ed2k-server/v1'
                run_nonce = $Nonce
                policy = $PolicyName
                listen_address = [string]$State['listen_address']
                listen_port = [int]$State['listen_port']
                high_id = [uint32]$State['high_id']
                login_at_utc = $loginAt
                stopped_at_utc = $stoppedAt
                phase = [string]$State['phase']
                logged_in = [bool]$State['logged_in']
                reply_sent = [bool]$State['reply_sent']
                login_protocol = if ($State.ContainsKey('login_protocol')) {
                    [int]$State['login_protocol']
                } else { $null }
                login_opcode = if ($State.ContainsKey('login_opcode')) {
                    [int]$State['login_opcode']
                } else { $null }
                login_payload_bytes = if (
                    $State.ContainsKey('login_payload_bytes')
                ) {
                    [int]$State['login_payload_bytes']
                } else { 0 }
                login_payload_sha256 = if (
                    $State.ContainsKey('login_payload_sha256')
                ) {
                    [string]$State['login_payload_sha256']
                } else { '' }
                login_advertised_tcp_port = if (
                    $State.ContainsKey('login_advertised_tcp_port')
                ) {
                    [int]$State['login_advertised_tcp_port']
                } else { 0 }
                frames_received = [int]$State['frames_received']
                status_frames_sent = if (
                    $State.ContainsKey('status_frames_sent')
                ) {
                    [int]$State['status_frames_sent']
                } else { 0 }
                accepted_remote = if (
                    $State.ContainsKey('accepted_remote')
                ) {
                    [string]$State['accepted_remote']
                } else { '' }
                error = [string]$State['error']
            }
            [IO.File]::WriteAllText(
                $ResultPath,
                ($result | ConvertTo-Json -Depth 16),
                (New-Object Text.UTF8Encoding($false))
            )
        }
    }

    $powershell = [PowerShell]::Create()
    $null = $powershell.AddScript($serverBody.ToString())
    $null = $powershell.AddArgument($listener)
    $null = $powershell.AddArgument($state)
    $null = $powershell.AddArgument($EvidencePath)
    $null = $powershell.AddArgument($RunNonce)
    $null = $powershell.AddArgument($Policy)
    $null = $powershell.AddArgument($ExpectedClientAddress)
    $async = $powershell.BeginInvoke()

    return [pscustomobject][ordered]@{
        listener = $listener
        port = $port
        state = $state
        powershell = $powershell
        async = $async
        evidence_path = $EvidencePath
        started_at_utc = Get-LabUtcTimestamp
    }
}

function Wait-I03ControlledEd2kLogin {
    param(
        [Parameter(Mandatory = $true)][object]$Server,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$ExpectedTcpPort,
        [ValidateRange(5, 120)][int]$TimeoutSeconds = 60
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'Candidate exited before controlled eD2K login'
        }
        if ([string]$Server.state['error']) {
            throw "Controlled eD2K server failed: $($Server.state['error'])"
        }
        if ([bool]$Server.state['logged_in'] -and
            [bool]$Server.state['reply_sent']) {
            $connections = @(
                Get-NetTCPConnection -State Established `
                    -OwningProcess $Process.Id `
                    -RemoteAddress ([string]$Server.state['listen_address']) `
                    -RemotePort $Server.port -ErrorAction SilentlyContinue
            )
            if ($connections.Count -eq 1 -and
                [int]$Server.state['login_protocol'] -eq 0xE3 -and
                [int]$Server.state['login_opcode'] -eq 0x01 -and
                [int]$Server.state['login_payload_bytes'] -ge 22 -and
                [int]$Server.state['login_advertised_tcp_port'] -eq
                    $ExpectedTcpPort) {
                return [pscustomobject][ordered]@{
                    connected = $true
                    server_address =
                        [string]$Server.state['listen_address']
                    server_port = $Server.port
                    client_process_id = $Process.Id
                    client_local_address =
                        Get-I03NormalizedIp -Address `
                            ([string]$connections[0].LocalAddress)
                    client_local_port = [int]$connections[0].LocalPort
                    login_protocol = [int]$Server.state['login_protocol']
                    login_opcode = [int]$Server.state['login_opcode']
                    login_payload_bytes =
                        [int]$Server.state['login_payload_bytes']
                    login_payload_sha256 =
                        [string]$Server.state['login_payload_sha256']
                    advertised_tcp_port =
                        [int]$Server.state['login_advertised_tcp_port']
                    assigned_high_id = [uint32]$Server.state['high_id']
                    endpoint_is_same_host_physical = $true
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Timed out proving the same-host physical-IP controlled eD2K login'
}

function Stop-I03ControlledEd2kServer {
    param([AllowNull()][object]$Server)

    if ($null -eq $Server) {
        return [pscustomobject]@{
            stopped = $true
            error = $null
            evidence = $null
        }
    }
    $errorText = $null
    try {
        $Server.state['stop_requested'] = $true
        if ($Server.state.ContainsKey('client')) {
            try { $Server.state['client'].Close() } catch {}
        }
        try { $Server.listener.Stop() } catch {}
        if (-not $Server.async.AsyncWaitHandle.WaitOne(
            [TimeSpan]::FromSeconds(10)
        )) {
            $Server.powershell.Stop()
        }
        try { $null = $Server.powershell.EndInvoke($Server.async) } catch {
            if (-not [bool]$Server.state['stop_requested']) {
                $errorText = $_.Exception.Message
            }
        }
    } catch {
        $errorText = $_.Exception.Message
    } finally {
        try { $Server.powershell.Dispose() } catch {}
    }
    $evidence = $null
    if (Test-Path -LiteralPath $Server.evidence_path -PathType Leaf) {
        try {
            $evidence = Get-Content -LiteralPath $Server.evidence_path -Raw |
                ConvertFrom-Json -ErrorAction Stop
        } catch {
            if (-not $errorText) { $errorText = $_.Exception.Message }
        }
    }
    return [pscustomobject][ordered]@{
        stopped = $Server.async.IsCompleted -or
            [string]$Server.state['phase'] -in @('stopped', 'error')
        error = $errorText
        evidence = $evidence
    }
}

function Invoke-I03PeerRole {
    if (-not (Test-I03Administrator)) {
        throw 'Peer role requires an elevated PowerShell for complete PID/socket evidence'
    }
    if (-not $RunNonce) {
        throw 'Peer role requires the coordinator-issued RunNonce'
    }
    $nonce = $RunNonce.ToLowerInvariant()
    $outputPath = Get-LabFullPath -Path $OutputRoot
    $packageRootWithSeparator =
        (Get-LabFullPath -Path $candidate.package_path).TrimEnd('\') + '\'
    if (($outputPath.TrimEnd('\') + '\').StartsWith(
        $packageRootWithSeparator,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Peer OutputRoot must not be inside the candidate package'
    }
    if (Test-Path -LiteralPath $outputPath) {
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Peer OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $coordination = Get-LabFullPath -Path (Join-Path `
        (Get-LabFullPath -Path $CoordinationRoot) "v91-i03-$nonce")
    if (($coordination.TrimEnd('\') + '\').StartsWith(
        $packageRootWithSeparator,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Peer CoordinationRoot must not be inside the candidate package'
    }
    if (-not (Test-Path -LiteralPath $coordination -PathType Container)) {
        throw "Peer requires the coordinator run directory: $coordination"
    }
    $entries = @(
        Get-ChildItem -LiteralPath $coordination -Force -ErrorAction Stop
    )
    if ($entries.Count -ne 1 -or $entries[0].Name -ne 'run.json') {
        throw 'Peer coordination directory is not pristine (expected only run.json)'
    }
    $runPath = Join-Path $coordination 'run.json'
    $manifest = Get-Content -LiteralPath $runPath -Raw |
        ConvertFrom-Json -ErrorAction Stop
    if ([string]$manifest.schema -ne 'ese.v91.i03-run/v1' -or
        [string]$manifest.case_id -ne $caseId -or
        [string]$manifest.run_nonce -ne $nonce -or
        [string]$manifest.candidate.commit -ne $candidate.commit -or
        [string]$manifest.candidate.emule_sha256 -ne $expectedHash -or
        [string]$manifest.candidate.ese_server_sha256 -ne
            $candidate.ese_server_sha256 -or
        [string]$manifest.candidate.build_info_sha256 -ne
            $candidate.build_info_sha256 -or
        [string]$manifest.peer.public_ipv4 -ne $peerV4Text -or
        [string]$manifest.peer.local_ipv4 -ne $peerLocalV4Text -or
        [string]$manifest.peer.public_ipv6 -ne $peerV6Text -or
        [int]$manifest.peer.tcp_port -ne $PeerTcpPort -or
        [int]$manifest.peer.udp_port -ne $PeerUdpPort -or
        [int]$manifest.peer.web_port -ne $PeerWebPort -or
        [Int64]$manifest.file_size_bytes -ne $FileSizeBytes) {
        throw 'Peer arguments/package do not exactly match run.json'
    }

    $readyPath = Join-Path $coordination 'peer-ready.json'
    $baselineCommandPath = Join-Path $coordination 'baseline.json'
    $baselineAckPath = Join-Path $coordination 'peer-baseline-ack.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $peerResultPath = Join-Path $coordination 'peer-result.json'
    $source = $null
    $sourceNode = ''
    $sourceExe = ''
    $sourceIdentity = ''
    $currentSourcePid = 0
    $fixture = $null
    $shared = $null
    $peerTopology = $null
    $runtimeFailure = $null
    $cleanupFailures = New-Object 'Collections.Generic.List[string]'
    $barriersCompleted = 0
    $peerStopped = $false
    $candidateUnchanged = $false
    $nodeUnchanged = $false
    $packageIdentityBefore = $null
    $packageIdentityAfter = $null
    $packageManifestUnchanged = $false
    $sourcePassword = 'v91-i03-peer'

    function Start-I03PeerSource {
        $process = $null
        try {
            # Do not use --headless here. The candidate intentionally
            # regenerates its userhash on every headless startup; that would
            # turn each controlled restart into a different peer.
            $process = Start-Process -FilePath $sourceExe `
                -ArgumentList @(
                    '--portable', '--ignoreinstances',
                    "--metrics-port=$PeerWebPort",
                    "--tcp-port=$PeerTcpPort",
                    "--udp-port=$PeerUdpPort"
                ) -WorkingDirectory $sourceNode -PassThru -WindowStyle Hidden
            $listener = Wait-I03Listener -Port $PeerTcpPort `
                -Process $process -RequireDualStack
            $api = Wait-I03Api -Port $PeerWebPort -Process $process
            if (-not (Test-I03ApiIsolation -Data $api)) {
                throw 'Peer API shows NetLab, Kad or server activity'
            }
            if ((Get-LabSha256 -Path $process.Path) -ne $expectedHash) {
                throw 'Started peer process is not the exact candidate'
            }
            return [pscustomobject][ordered]@{
                process = $process
                listener = $listener
                api = $api
            }
        } catch {
            if ($null -ne $process) {
                $stopped = Stop-I03OwnedProcess -Process $process `
                    -ExpectedPath $sourceExe
                if (-not $stopped.stopped) {
                    $cleanupFailures.Add(
                        "partially started peer process $($process.Id) remains"
                    )
                }
            }
            throw
        }
    }

    try {
        $packageIdentityBefore =
            Get-I03PackageIdentity -PackagePath $candidate.package_path
        Write-LabJson -Value $packageIdentityBefore -Path (
            Join-Path $evidence 'package-manifest-before.json'
        ) | Out-Null
        Test-I03PortSetFree -Ports @(
            $PeerTcpPort, $PeerUdpPort, $PeerWebPort
        )
        $localV4 = Get-I03AssignedAddress -Address $peerLocalV4Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
            -Context 'peer-local-ipv4'
        $localV6 = Get-I03AssignedAddress -Address $peerV6Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
            -Context 'peer-public-ipv6'
        if ([int]$localV4.interface_index -ne [int]$localV6.interface_index) {
            throw 'Peer local IPv4 and public IPv6 are not on the same adapter'
        }
        if (-not $localV4.adapter.physical_nonvirtual -or
            -not $localV6.adapter.physical_nonvirtual) {
            throw 'Peer dual-stack addresses are not on an Up physical non-virtual adapter'
        }
        $peerTopology = [ordered]@{
            machine_id_sha256 = Get-I03MachineId
            computer_name_sha256 = Get-LabStringSha256 `
                -Value $env:COMPUTERNAME
            local_ipv4 = $localV4
            public_ipv6 = $localV6
            same_adapter = [int]$localV4.interface_index -eq
                [int]$localV6.interface_index
            public_ipv4_endpoint = $peerV4Text
            public_ipv4_may_be_nat_mapped = $peerV4Text -ne $peerLocalV4Text
        }

        $offset = $PeerTcpPort - 4662
        if (($PeerUdpPort - 4672) -ne $offset -or
            ($PeerWebPort - 4711) -ne $offset) {
            throw 'Peer TCP/UDP/Web ports must share the standard offset'
        }
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
            -SourcePackage $candidate.package_path -OutputRoot $nodes `
            -RunId 'v91-i03-peer' -PortOffset $offset
        $sourceNode = Join-Path $nodes 'v91-i03-peer-a'
        $sourceExe = Join-Path $sourceNode 'emule.exe'
        if ((Get-LabSha256 -Path $sourceExe) -ne $expectedHash) {
            throw 'Prepared peer node is not the exact candidate'
        }
        $incoming = New-LabDirectory `
            -Path (Join-Path $sourceNode 'I03Incoming')
        $temp = New-LabDirectory -Path (Join-Path $sourceNode 'I03Temp')
        $peerIsolation = Set-I03IsolatedPreferences -NodePath $sourceNode `
            -IPv6Mode 1 -IPv6BindAddress '::' `
            -WebPort $PeerWebPort -Password $sourcePassword `
            -IncomingPath $incoming -TempPath $temp `
            -MaxUploadKiBps $peerUploadCapKiBps

        # One clean normal-mode initialization makes preferences.dat and its
        # userhash durable before the campaign. A graceful stop is mandatory.
        $initialized = Start-I03PeerSource
        $source = $initialized.process
        $initStop = Stop-I03OwnedProcess -Process $source `
            -ExpectedPath $sourceExe -RequireGraceful
        if (-not $initStop.stopped -or -not $initStop.graceful) {
            throw 'Peer identity initialization did not stop gracefully'
        }
        $source = $null
        $sourceIdentity = Get-I03UserHashSha256 -NodePath $sourceNode
        if ($sourceIdentity -notmatch '^[0-9a-f]{64}$' -or
            -not $peerIsolation.preferences_dat_absent_before_start -or
            -not $peerIsolation.cryptkey_dat_absent_before_start -or
            [int]$peerIsolation.max_upload_kib_per_second -ne
                $peerUploadCapKiBps -or
            -not [bool]$peerIsolation.dynamic_upload_disabled) {
            throw 'Peer fresh isolated identity bootstrap could not be proved'
        }

        # UploadDiskIOThread deliberately skips compression for .zip. The
        # payload need not be a valid archive; the extension guarantees the
        # wire carries the logical bytes instead of collapsing zero ranges.
        $fileName = "v91-i03-$nonce.zip"
        $filePath = Join-Path $incoming $fileName
        $stream = [IO.File]::Open(
            $filePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
            try {
                $buffer = New-Object byte[] (1MB)
                $rng.GetBytes($buffer)
                $stream.Write($buffer, 0, $buffer.Length)
            } finally {
                $rng.Dispose()
            }
            $stream.SetLength($FileSizeBytes)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        $fixture = [ordered]@{
            name = $fileName
            bytes = $FileSizeBytes
            sha256 = Get-LabSha256 -Path $filePath
            generation = 'nonce filename plus materialized CSPRNG first MiB'
            upload_compression_disabled_by_extension = $true
            peer_max_upload_kib_per_second =
                $peerUploadCapKiBps
        }

        $started = Start-I03PeerSource
        $source = $started.process
        $currentSourcePid = $source.Id
        if ((Get-I03UserHashSha256 -NodePath $sourceNode) -ne
            $sourceIdentity) {
            throw 'Peer userhash changed before the campaign began'
        }
        $session = Get-I03ClassicSession -Port $PeerWebPort `
            -Password $sourcePassword
        $shared = Get-I03SharedLink -Port $PeerWebPort -Session $session `
            -FileName $fileName -FileBytes $FileSizeBytes
        if ([string]$shared.link -match '(?i)\|sources,' -or
            [string]$shared.link -match [regex]::Escape($peerV6Text)) {
            throw 'Base fixture link unexpectedly contains a source endpoint'
        }

        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-peer-ready/v1'
            case_id = $caseId
            run_nonce = $nonce
            ready_at_utc = Get-LabUtcTimestamp
            candidate = [ordered]@{
                commit = $candidate.commit
                emule_sha256 = $expectedHash
                ese_server_sha256 = $candidate.ese_server_sha256
                build_info_sha256 = $candidate.build_info_sha256
                extracted_package_manifest_sha256 =
                    $packageIdentityBefore.manifest_sha256
                extracted_package_file_count =
                    $packageIdentityBefore.file_count
            }
            peer = $peerTopology
            endpoint = [ordered]@{
                public_ipv4 = $peerV4Text
                local_ipv4 = $peerLocalV4Text
                public_ipv6 = $peerV6Text
                tcp_port = $PeerTcpPort
                dual_stack_listener = [bool]$started.listener.dual_stack
                ipv6_bind_preference = '::'
                expected_public_ipv6 = $peerV6Text
            }
            process = [ordered]@{
                id = $source.Id
                executable_sha256 = Get-LabSha256 -Path $source.Path
                headless = $false
                stable_userhash_sha256 = $sourceIdentity
                identity_profile = $peerIsolation
            }
            fixture = $fixture
            ed2k = [ordered]@{
                base_link = $shared.link
                hash = $shared.ed2k_hash
                source_extensions_present = $false
            }
            isolation = [ordered]@{
                dns_used = $false
                kad_enabled = $false
                server_enabled = $false
                netlab_enabled = $false
                web_allowed_ips = '127.0.0.1'
                firewall_modified = $false
            }
        }) -Path $readyPath | Out-Null

        $baselineControl = Wait-I03JsonFile -Path $baselineCommandPath `
            -StopPath $stopPath -TimeoutSeconds $CaseTimeoutSeconds
        if ($null -eq $baselineControl) {
            throw 'Coordinator did not issue baseline or stop'
        }
        if ($baselineControl.kind -eq 'stop') {
            throw 'Coordinator stopped before baseline completed'
        }
        $baselineClockT1 = [DateTime]::UtcNow
        $baseline = $baselineControl.value
        if ([string]$baseline.schema -ne
                'ese.v91.i03-baseline-command/v1' -or
            [string]$baseline.case_id -ne $caseId -or
            [string]$baseline.run_nonce -ne $nonce -or
            [string]$baseline.candidate_commit -ne $candidate.commit -or
            [string]$baseline.candidate_emule_sha256 -ne $expectedHash -or
            [int]$baseline.expected_source_process_id -ne $source.Id -or
            [string]$baseline.clock_t0_utc -notmatch 'Z$') {
            throw 'Peer received an invalid baseline command'
        }
        $baselineDeadline = [DateTime]::UtcNow.AddSeconds(10)
        $baselineInbound = @()
        $baselineInboundV4 = @()
        $baselineInboundV6 = @()
        $dualMarker = $null
        do {
            $baselineInbound = @(
                Get-NetTCPConnection -State Established `
                    -LocalPort $PeerTcpPort -OwningProcess $source.Id `
                    -ErrorAction SilentlyContinue | ForEach-Object {
                        [pscustomobject][ordered]@{
                            owning_process = [int]$_.OwningProcess
                            local_address = Get-I03NormalizedIp `
                                -Address ([string]$_.LocalAddress)
                            local_port = [int]$_.LocalPort
                            remote_address = Get-I03NormalizedIp `
                                -Address ([string]$_.RemoteAddress)
                            remote_port = [int]$_.RemotePort
                        }
                    }
            )
            $baselineInboundV4 = @($baselineInbound | Where-Object {
                $_.local_address -eq $peerLocalV4Text
            })
            $baselineInboundV6 = @($baselineInbound | Where-Object {
                $_.local_address -eq $peerV6Text
            })
            $dualMarker = Get-I03PeerDualStackMarker -NodePath $sourceNode
            if ($baselineInbound.Count -eq 2 -and
                $baselineInboundV4.Count -eq 1 -and
                $baselineInboundV6.Count -eq 1 -and
                $dualMarker.dualstack_capability_armed) {
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $baselineDeadline)
        $peerApi = Get-I03ApiProbe -Port $PeerWebPort
        if ($baselineInbound.Count -ne 2 -or
            $baselineInboundV4.Count -ne 1 -or
            $baselineInboundV6.Count -ne 1 -or
            -not $dualMarker.dualstack_capability_armed -or
            -not $peerApi.available -or -not $peerApi.isolation_valid) {
            throw 'Peer could not prove exact live IPv4+IPv6 baseline sockets and DUALSTACK arming'
        }
        $baselineClockT2 = [DateTime]::UtcNow
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-peer-baseline-ack/v1'
            case_id = $caseId
            run_nonce = $nonce
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            source_process_id = $source.Id
            source_process_emule_sha256 = Get-LabSha256 -Path $source.Path
            source_userhash_sha256 = $sourceIdentity
            clock = [ordered]@{
                t0_coordinator_send_utc =
                    [string]$baseline.clock_t0_utc
                t1_peer_receive_utc = $baselineClockT1.ToString('o')
                t2_peer_send_utc = $baselineClockT2.ToString('o')
            }
            inbound_connections = $baselineInbound
            dualstack_marker = $dualMarker
            api = $peerApi
        }) -Path $baselineAckPath | Out-Null

        foreach ($policy in @(
            [pscustomobject]@{ name = 'auto'; mode = 1; family = 'IPv4' },
            [pscustomobject]@{ name = 'preferred'; mode = 2; family = 'IPv6' }
        )) {
            $rearmPath = Join-Path $coordination `
                "$($policy.name)-rearm.json"
            $rearmAckPath = Join-Path $coordination `
                "peer-$($policy.name)-rearm-ack.json"
            $prewarmPath = Join-Path $coordination `
                "$($policy.name)-prewarm.json"
            $prewarmAckPath = Join-Path $coordination `
                "peer-$($policy.name)-prewarm-ack.json"
            $restartPath = Join-Path $coordination `
                "$($policy.name)-restart.json"
            $restartedPath = Join-Path $coordination `
                "peer-$($policy.name)-restarted.json"
            $donePath = Join-Path $coordination "$($policy.name)-done.json"
            $completePath = Join-Path $coordination `
                "peer-$($policy.name)-complete.json"

            # g_uForkCapsRuntime is process-local and is reset by every peer
            # restart. Require a nonce-scoped native-v6 socket on the CURRENT
            # source PID and a fresh log-marker delta before each prewarm.
            $markerBefore = Get-I03PeerDualStackMarker -NodePath $sourceNode
            $rearmControl = Wait-I03JsonFile -Path $rearmPath `
                -StopPath $stopPath -TimeoutSeconds $CaseTimeoutSeconds
            if ($null -eq $rearmControl -or
                $rearmControl.kind -eq 'stop') {
                throw "Coordinator stopped before $($policy.name) DUALSTACK rearm"
            }
            $rearm = $rearmControl.value
            if ([string]$rearm.schema -ne
                    'ese.v91.i03-rearm-command/v1' -or
                [string]$rearm.case_id -ne $caseId -or
                [string]$rearm.run_nonce -ne $nonce -or
                [string]$rearm.policy -ne $policy.name -or
                [int]$rearm.ipv6_mode -ne $policy.mode -or
                [string]$rearm.candidate_commit -ne $candidate.commit -or
                [string]$rearm.candidate_emule_sha256 -ne $expectedHash -or
                [int]$rearm.expected_source_process_id -ne $source.Id -or
                [string]$rearm.coordinator_local_ipv6 -notmatch ':' -or
                [int]$rearm.coordinator_local_port -le 0) {
                throw "Invalid $($policy.name) DUALSTACK rearm command"
            }
            $rearmInbound = @()
            $markerAfter = $markerBefore
            $inboundDelta = 0
            $acceptedDelta = 0
            $rearmDeadline = [DateTime]::UtcNow.AddSeconds(10)
            do {
                $rearmInbound = @(
                    Get-NetTCPConnection -State Established `
                        -LocalPort $PeerTcpPort -OwningProcess $source.Id `
                        -ErrorAction SilentlyContinue | ForEach-Object {
                            [pscustomobject][ordered]@{
                                owning_process = [int]$_.OwningProcess
                                local_address = Get-I03NormalizedIp `
                                    -Address ([string]$_.LocalAddress)
                                local_port = [int]$_.LocalPort
                                remote_address = Get-I03NormalizedIp `
                                    -Address ([string]$_.RemoteAddress)
                                remote_port = [int]$_.RemotePort
                            }
                        }
                )
                $markerAfter =
                    Get-I03PeerDualStackMarker -NodePath $sourceNode
                $inboundDelta =
                    [int]$markerAfter.inbound_reachability_markers -
                    [int]$markerBefore.inbound_reachability_markers
                $acceptedDelta =
                    [int]$markerAfter.accepted_native_ipv6_markers -
                    [int]$markerBefore.accepted_native_ipv6_markers
                if ($rearmInbound.Count -eq 1 -and
                    $inboundDelta -ge 1 -and $acceptedDelta -ge 1) {
                    break
                }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $rearmDeadline)
            if ($rearmInbound.Count -ne 1 -or
                $rearmInbound[0].local_address -ne $peerV6Text -or
                $rearmInbound[0].remote_address -ne
                    (Get-I03NormalizedIp -Address `
                        ([string]$rearm.coordinator_local_ipv6)) -or
                $rearmInbound[0].remote_port -ne
                    [int]$rearm.coordinator_local_port -or
                $inboundDelta -ne 1 -or $acceptedDelta -ne 1 -or
                (Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                    $sourceIdentity) {
                throw "Peer could not prove current-PID $($policy.name) DUALSTACK rearm"
            }
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i03-peer-rearm-ack/v1'
                case_id = $caseId
                run_nonce = $nonce
                policy = $policy.name
                ipv6_mode = $policy.mode
                candidate_commit = $candidate.commit
                candidate_emule_sha256 = $expectedHash
                source_process_id = $source.Id
                source_process_emule_sha256 =
                    Get-LabSha256 -Path $source.Path
                source_userhash_sha256 = $sourceIdentity
                inbound_connection = $rearmInbound[0]
                marker_before = $markerBefore
                marker_after = $markerAfter
                inbound_marker_delta = $inboundDelta
                accepted_marker_delta = $acceptedDelta
                runtime_dualstack_rearmed = $true
            }) -Path $rearmAckPath | Out-Null

            $prewarmControl = Wait-I03JsonFile -Path $prewarmPath `
                -StopPath $stopPath -TimeoutSeconds $CaseTimeoutSeconds
            if ($null -eq $prewarmControl -or
                $prewarmControl.kind -eq 'stop') {
                throw "Coordinator stopped before $($policy.name) prewarm"
            }
            $prewarm = $prewarmControl.value
            if ([string]$prewarm.schema -ne
                    'ese.v91.i03-prewarm-command/v1' -or
                [string]$prewarm.case_id -ne $caseId -or
                [string]$prewarm.run_nonce -ne $nonce -or
                [string]$prewarm.policy -ne $policy.name -or
                [int]$prewarm.ipv6_mode -ne $policy.mode -or
                [string]$prewarm.expected_family -ne $policy.family -or
                [string]$prewarm.candidate_commit -ne $candidate.commit -or
                [string]$prewarm.candidate_emule_sha256 -ne $expectedHash -or
                [int]$prewarm.expected_source_process_id -ne $source.Id -or
                [int]$prewarm.client_process_id -le 0) {
                throw "Invalid $($policy.name) prewarm command"
            }
            $prewarmInbound = @(
                Get-NetTCPConnection -State Established `
                    -LocalPort $PeerTcpPort -OwningProcess $source.Id `
                    -ErrorAction SilentlyContinue | ForEach-Object {
                        [pscustomobject][ordered]@{
                            owning_process = [int]$_.OwningProcess
                            local_address = Get-I03NormalizedIp `
                                -Address ([string]$_.LocalAddress)
                            local_port = [int]$_.LocalPort
                            remote_address = Get-I03NormalizedIp `
                                -Address ([string]$_.RemoteAddress)
                            remote_port = [int]$_.RemotePort
                        }
                    }
            )
            $peerApi = Get-I03ApiProbe -Port $PeerWebPort
            if ($prewarmInbound.Count -ne 1 -or
                $prewarmInbound[0].local_address -ne $peerLocalV4Text -or
                -not $peerApi.available -or -not $peerApi.isolation_valid -or
                (Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                    $sourceIdentity) {
                throw "Peer could not correlate exact IPv4 $($policy.name) prewarm"
            }
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i03-peer-prewarm-ack/v1'
                case_id = $caseId
                run_nonce = $nonce
                policy = $policy.name
                ipv6_mode = $policy.mode
                candidate_commit = $candidate.commit
                candidate_emule_sha256 = $expectedHash
                source_process_id = $source.Id
                source_process_emule_sha256 = Get-LabSha256 -Path $source.Path
                source_userhash_sha256 = $sourceIdentity
                client_process_id_from_command = [int]$prewarm.client_process_id
                inbound_connection = $prewarmInbound[0]
                api = $peerApi
            }) -Path $prewarmAckPath | Out-Null

            $restartControl = Wait-I03JsonFile -Path $restartPath `
                -StopPath $stopPath -TimeoutSeconds $CaseTimeoutSeconds
            if ($null -eq $restartControl -or
                $restartControl.kind -eq 'stop') {
                throw "Coordinator stopped before $($policy.name) restart"
            }
            $restart = $restartControl.value
            if ([string]$restart.schema -ne
                    'ese.v91.i03-restart-command/v1' -or
                [string]$restart.case_id -ne $caseId -or
                [string]$restart.run_nonce -ne $nonce -or
                [string]$restart.policy -ne $policy.name -or
                [string]$restart.action -ne 'restart-same-peer-source' -or
                [string]$restart.candidate_commit -ne $candidate.commit -or
                [string]$restart.candidate_emule_sha256 -ne $expectedHash -or
                [int]$restart.expected_old_process_id -ne $source.Id) {
                throw "Invalid $($policy.name) restart command"
            }
            $oldPid = $source.Id
            $watch = [Diagnostics.Stopwatch]::StartNew()
            $stopped = Stop-I03OwnedProcess -Process $source `
                -ExpectedPath $sourceExe -RequireGraceful
            if (-not $stopped.stopped -or -not $stopped.graceful) {
                throw "Peer $($policy.name) source did not stop gracefully"
            }
            $source = $null
            if ((Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                $sourceIdentity) {
                throw "Peer identity changed while stopping $($policy.name)"
            }
            Start-Sleep -Milliseconds 250
            $restarted = Start-I03PeerSource
            $source = $restarted.process
            $watch.Stop()
            $currentSourcePid = $source.Id
            if ($source.Id -eq $oldPid -or
                (Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                    $sourceIdentity) {
                throw "Peer $($policy.name) restart changed identity or reused PID"
            }
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i03-peer-restarted/v1'
                case_id = $caseId
                run_nonce = $nonce
                policy = $policy.name
                candidate_commit = $candidate.commit
                candidate_emule_sha256 = $expectedHash
                old_process_id = $oldPid
                process_id = $source.Id
                process_emule_sha256 = Get-LabSha256 -Path $source.Path
                source_userhash_sha256 = $sourceIdentity
                restart_elapsed_ms = [Int64]$watch.ElapsedMilliseconds
                dual_stack_listener = [bool]$restarted.listener.dual_stack
                api_isolation_valid = Test-I03ApiIsolation `
                    -Data $restarted.api
            }) -Path $restartedPath | Out-Null

            $doneControl = Wait-I03JsonFile -Path $donePath `
                -StopPath $stopPath -TimeoutSeconds $CaseTimeoutSeconds
            if ($null -eq $doneControl -or $doneControl.kind -eq 'stop') {
                throw "Coordinator stopped before $($policy.name) completion"
            }
            $done = $doneControl.value
            if ([string]$done.schema -ne
                    'ese.v91.i03-done-command/v1' -or
                [string]$done.case_id -ne $caseId -or
                [string]$done.run_nonce -ne $nonce -or
                [string]$done.policy -ne $policy.name -or
                [int]$done.source_process_id -ne $source.Id -or
                [int]$done.client_process_id -ne
                    [int]$prewarm.client_process_id -or
                [string]$done.candidate_commit -ne $candidate.commit -or
                [string]$done.candidate_emule_sha256 -ne $expectedHash -or
                [int]$done.expected_connection_count -lt 0) {
                throw "Invalid $($policy.name) done command"
            }
            $finalInbound = @(
                Get-NetTCPConnection -State Established `
                    -LocalPort $PeerTcpPort -OwningProcess $source.Id `
                    -ErrorAction SilentlyContinue | ForEach-Object {
                        $localAddress = Get-I03NormalizedIp `
                            -Address ([string]$_.LocalAddress)
                        [pscustomobject][ordered]@{
                            owning_process = [int]$_.OwningProcess
                            family = if ($localAddress.Contains(':')) {
                                'IPv6'
                            } else { 'IPv4' }
                            local_address = $localAddress
                            local_port = [int]$_.LocalPort
                            remote_address = Get-I03NormalizedIp `
                                -Address ([string]$_.RemoteAddress)
                            remote_port = [int]$_.RemotePort
                        }
                    }
            )
            if ([bool]$done.route_observed) {
                $peerFamilies = @(
                    $finalInbound.family | Sort-Object -Unique
                )
                $reportedFamilies = @(
                    $done.observed_families | ForEach-Object {
                        [string]$_
                    } | Sort-Object -Unique
                )
                if ($finalInbound.Count -ne
                        [int]$done.expected_connection_count -or
                    ($peerFamilies -join ',') -ne
                        ($reportedFamilies -join ',')) {
                    throw "Peer could not correlate $($policy.name) final inbound socket"
                }
            } elseif ($finalInbound.Count -ne 0) {
                throw "Peer saw an unreported $($policy.name) final connection"
            }
            $peerApi = Get-I03ApiProbe -Port $PeerWebPort
            if (-not $peerApi.available -or -not $peerApi.isolation_valid -or
                (Get-I03UserHashSha256 -NodePath $sourceNode) -ne
                    $sourceIdentity) {
                throw "Peer $($policy.name) final state is not isolated/exact"
            }
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i03-peer-complete/v1'
                case_id = $caseId
                run_nonce = $nonce
                policy = $policy.name
                candidate_commit = $candidate.commit
                candidate_emule_sha256 = $expectedHash
                source_process_id = $source.Id
                source_process_emule_sha256 = Get-LabSha256 -Path $source.Path
                source_userhash_sha256 = $sourceIdentity
                route_observed = [bool]$done.route_observed
                observed_family = [string]$done.observed_family
                observed_families = @($done.observed_families)
                inbound_connections = $finalInbound
                api = $peerApi
            }) -Path $completePath | Out-Null
            $barriersCompleted++
        }

        $finalStop = Wait-I03JsonFile -Path $stopPath `
            -TimeoutSeconds $CaseTimeoutSeconds
        if ($null -eq $finalStop -or
            [string]$finalStop.value.schema -ne
                'ese.v91.i03-stop-command/v1' -or
            [string]$finalStop.value.case_id -ne $caseId -or
            [string]$finalStop.value.run_nonce -ne $nonce -or
            [string]$finalStop.value.action -ne 'stop-owned-processes' -or
            [string]$finalStop.value.candidate_commit -ne
                $candidate.commit -or
            [string]$finalStop.value.candidate_emule_sha256 -ne
                $expectedHash) {
            throw 'Peer received an invalid final stop command'
        }
    } catch {
        $runtimeFailure = $_.Exception.Message
    } finally {
        if ($null -ne $source) {
            $stopped = Stop-I03OwnedProcess -Process $source `
                -ExpectedPath $sourceExe
            $peerStopped = [bool]$stopped.stopped
            if (-not $stopped.stopped) {
                $cleanupFailures.Add('peer source process remains running')
            }
        } else {
            $peerStopped = $true
        }
        try {
            $after = Get-LabCandidateInfo -PackagePath $PackagePath `
                -ExpectedCommit $Commit
            $packageIdentityAfter =
                Get-I03PackageIdentity -PackagePath $candidate.package_path
            Write-LabJson -Value $packageIdentityAfter -Path (
                Join-Path $evidence 'package-manifest-after.json'
            ) | Out-Null
            $packageManifestUnchanged =
                $null -ne $packageIdentityBefore -and
                $packageIdentityAfter.manifest_sha256 -eq
                    $packageIdentityBefore.manifest_sha256 -and
                $packageIdentityAfter.file_count -eq
                    $packageIdentityBefore.file_count -and
                $packageIdentityAfter.total_bytes -eq
                    $packageIdentityBefore.total_bytes
            $candidateUnchanged =
                $after.emule_sha256 -eq $expectedHash -and
                $after.ese_server_sha256 -eq $candidate.ese_server_sha256 -and
                $after.build_info_sha256 -eq $candidate.build_info_sha256 -and
                $packageManifestUnchanged
        } catch {
            $cleanupFailures.Add(
                "candidate revalidation failed: $($_.Exception.Message)"
            )
        }
        if ($sourceExe -and
            (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
            $nodeUnchanged =
                (Get-LabSha256 -Path $sourceExe) -eq $expectedHash
        }
        if (-not $candidateUnchanged) {
            $cleanupFailures.Add('candidate package changed during peer run')
        }
        if (-not $nodeUnchanged) {
            $cleanupFailures.Add('prepared peer executable changed')
        }
    }

    $peerStatus = if ($null -eq $runtimeFailure -and
        $barriersCompleted -eq 2 -and $peerStopped -and
        $cleanupFailures.Count -eq 0) { 'COMPLETE' } else { 'INCOMPLETE' }
    $peerResult = [ordered]@{
        schema = 'ese.v91.i03-peer-result/v1'
        case_id = $caseId
        run_nonce = $nonce
        generated_at_utc = Get-LabUtcTimestamp
        status = $peerStatus
        candidate_commit = $candidate.commit
        candidate_emule_sha256 = $expectedHash
        source_userhash_sha256 = $sourceIdentity
        barriers_completed = $barriersCompleted
        expected_barriers = 2
        last_source_process_id = $currentSourcePid
        topology = $peerTopology
        fixture = $fixture
        runtime_error = $runtimeFailure
        cleanup = [ordered]@{
            source_process_stopped = $peerStopped
            candidate_package_unchanged = $candidateUnchanged
            extracted_package_manifest_unchanged =
                $packageManifestUnchanged
            prepared_executable_unchanged = $nodeUnchanged
            firewall_modified = $false
            dns_modified = $false
            hosts_modified = $false
            routes_modified = $false
            adapters_modified = $false
            failures = @($cleanupFailures)
            retained_by_design = @('peer OutputRoot profile', 'fixture', 'evidence')
        }
    }
    Write-LabJson -Value $peerResult `
        -Path (Join-Path $evidence 'peer-result.json') | Out-Null
    Write-LabJson -Value $peerResult -Path $peerResultPath | Out-Null
    Write-Host "V91-I03 peer status: $peerStatus" -ForegroundColor $(
        if ($peerStatus -eq 'COMPLETE') { 'Green' } else { 'Yellow' }
    )
    if ($peerStatus -eq 'COMPLETE') { exit 0 }
    exit 2
}

function Invoke-I03CoordinatorRole {
    if (-not (Test-I03Administrator)) {
        throw 'Coordinator role requires an elevated PowerShell for complete PID/socket evidence'
    }
    if (-not $RunNonce) {
        $script:RunNonce = [Guid]::NewGuid().ToString('N')
    }
    $nonce = $RunNonce.ToLowerInvariant()
    $startedAt = [DateTime]::UtcNow
    $outputPath = Get-LabFullPath -Path $OutputRoot
    $packageRootWithSeparator =
        (Get-LabFullPath -Path $candidate.package_path).TrimEnd('\') + '\'
    if (($outputPath.TrimEnd('\') + '\').StartsWith(
        $packageRootWithSeparator,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Coordinator OutputRoot must not be inside the candidate package'
    }
    if (Test-Path -LiteralPath $outputPath) {
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Coordinator OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $summaryPath = Join-Path $evidence 'summary.json'
    $cleanupPath = Join-Path $evidence 'cleanup.json'
    $manualPath = Join-Path $evidence 'MANUAL-PEER-COMMAND.txt'
    $coordination = Get-LabFullPath -Path (Join-Path `
        (Get-LabFullPath -Path $CoordinationRoot) "v91-i03-$nonce")
    if (($coordination.TrimEnd('\') + '\').StartsWith(
        $packageRootWithSeparator,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Coordinator CoordinationRoot must not be inside the candidate package'
    }
    if (Test-Path -LiteralPath $coordination) {
        throw "Coordinator run directory must be fresh/absent: $coordination"
    }
    $null = New-LabDirectory -Path (Split-Path -Parent $coordination)
    $null = New-Item -ItemType Directory -Path $coordination `
        -ErrorAction Stop

    $runPath = Join-Path $coordination 'run.json'
    $readyPath = Join-Path $coordination 'peer-ready.json'
    $baselineCommandPath = Join-Path $coordination 'baseline.json'
    $baselineAckPath = Join-Path $coordination 'peer-baseline-ack.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $peerResultPath = Join-Path $coordination 'peer-result.json'

    $blockedReasons = New-Object 'Collections.Generic.List[string]'
    $productFailures = New-Object 'Collections.Generic.List[string]'
    $cleanupFailures = New-Object 'Collections.Generic.List[string]'
    $caseResults = [System.Collections.Generic.List[object]]::new()
    $preparedBinaries = [System.Collections.Generic.List[object]]::new()
    $profileIdentityHashes =
        New-Object 'Collections.Generic.HashSet[string]' `
            ([StringComparer]::OrdinalIgnoreCase)
    $runtimeFailure = $null
    $peerReady = $null
    $peerResult = $null
    $peerReadyExact = $false
    $peerResultExact = $false
    $peerCleanupExact = $false
    $peerStopWritten = $false
    $baselineProbeV4 = $null
    $baselineProbeV6 = $null
    $baselineEvidence = $null
    $clockEvidence = $null
    $routeV4 = $null
    $routeV6 = $null
    $localV4 = $null
    $localV6 = $null
    $topologyLocalValid = $false
    $topologyT1 = $false
    $topologyT2 = $false
    $topologyValid = $false
    $topologyClass = ''
    $sameIPv4PhysicalPrefix = $false
    $sameIPv6PhysicalPrefix = $false
    $currentPeerPid = 0
    $sourceIdentity = ''
    $activeClient = $null
    $activeClientExe = ''
    $activeServer = $null
    $remoteJob = $null
    $candidateAfter = $null
    $candidateUnchanged = $false
    $packageIdentityBefore = $null
    $packageIdentityAfter = $null
    $packageManifestUnchanged = $false
    $allClientsStopped = $true
    $allControlServersStopped = $true
    $productAdjudication = [ordered]@{
        runtime_failure = $false
        reason = ''
    }

    function Add-I03BlockedReason {
        param([Parameter(Mandatory = $true)][string]$Reason)
        if (-not $blockedReasons.Contains($Reason)) {
            $blockedReasons.Add($Reason)
        }
    }

    function Stop-I03Fixture {
        param([Parameter(Mandatory = $true)][string]$Reason)
        Add-I03BlockedReason -Reason $Reason
        throw "I03_FIXTURE_BLOCKED: $Reason"
    }

    function Stop-I03ProductFailure {
        param([Parameter(Mandatory = $true)][string]$Reason)
        $productFailures.Add($Reason)
        $productAdjudication.runtime_failure = $true
        $productAdjudication.reason = $Reason
        throw "I03_PRODUCT_FAILURE: $Reason"
    }

    function Wait-I03OwnedTupleGone {
        param(
            [Parameter(Mandatory = $true)][int]$ProcessId,
            [Parameter(Mandatory = $true)][string]$TupleKey,
            [ValidateRange(1, 30)][int]$TimeoutSeconds = 10
        )
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            $present = @(
                Get-I03TargetConnections | Where-Object {
                    [int]$_.owning_process -eq $ProcessId -and
                    [string]$_.tuple_key -eq $TupleKey -and
                    [string]$_.state -in @('SynSent', 'Established')
                }
            ).Count -gt 0
            if (-not $present) { return $true }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        return $false
    }

    try {
        $packageIdentityBefore =
            Get-I03PackageIdentity -PackagePath $candidate.package_path
        Write-LabJson -Value $packageIdentityBefore -Path (
            Join-Path $evidence 'package-manifest-before.json'
        ) | Out-Null
        Test-I03PortSetFree -Ports @(
            $AutoTcpPort, $AutoUdpPort, $AutoWebPort,
            $PreferredTcpPort, $PreferredUdpPort, $PreferredWebPort
        )
        $routeV4 = Get-I03RouteEvidence -RemoteAddress $peerV4Text
        $routeV6 = Get-I03RouteEvidence -RemoteAddress $peerV6Text
        if (-not $routeV4.available -or -not $routeV6.available) {
            Stop-I03Fixture `
                -Reason 'Coordinator lacks a real route to both peer families'
        }
        $localV4 = Get-I03AssignedAddress `
            -Address ([string]$routeV4.source_address) `
            -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
            -Context 'coordinator-route-ipv4'
        $localV6 = Get-I03AssignedAddress `
            -Address ([string]$routeV6.source_address) `
            -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
            -Context 'coordinator-route-ipv6'
        $topologyLocalValid =
            [bool]$routeV4.adapter.physical_nonvirtual -and
            [bool]$routeV6.adapter.physical_nonvirtual -and
            [int]$routeV4.interface_index -eq
                [int]$routeV6.interface_index -and
            [int]$routeV4.interface_index -eq
                [int]$localV4.interface_index -and
            [int]$routeV6.interface_index -eq
                [int]$localV6.interface_index -and
            (Get-LabAddressClass -Address `
                ([string]$routeV6.source_address)) -eq 'global-v6'
        if (-not $topologyLocalValid) {
            Stop-I03Fixture -Reason (
                'Coordinator IPv4/IPv6 routes are not on one Up physical ' +
                'non-virtual interface'
            )
        }
        $localMachineId = Get-I03MachineId
        $runManifest = [ordered]@{
            schema = 'ese.v91.i03-run/v1'
            case_id = $caseId
            run_nonce = $nonce
            created_at_utc = Get-LabUtcTimestamp
            candidate = [ordered]@{
                commit = $candidate.commit
                version = $candidate.version
                emule_sha256 = $expectedHash
                ese_server_sha256 = $candidate.ese_server_sha256
                build_info_sha256 = $candidate.build_info_sha256
            }
            peer = [ordered]@{
                public_ipv4 = $peerV4Text
                local_ipv4 = $peerLocalV4Text
                public_ipv6 = $peerV6Text
                tcp_port = $PeerTcpPort
                udp_port = $PeerUdpPort
                web_port = $PeerWebPort
            }
            coordinator = [ordered]@{
                machine_id_sha256 = $localMachineId
                route_ipv4_source = $routeV4.source_address
                route_ipv6_source = $routeV6.source_address
                interface_index = $routeV4.interface_index
            }
            clients = @(
                [ordered]@{
                    policy = 'auto'
                    ipv6_mode = 1
                    expected_family = 'IPv4'
                    tcp_port = $AutoTcpPort
                    udp_port = $AutoUdpPort
                    web_port = $AutoWebPort
                },
                [ordered]@{
                    policy = 'preferred'
                    ipv6_mode = 2
                    expected_family = 'IPv6'
                    tcp_port = $PreferredTcpPort
                    udp_port = $PreferredUdpPort
                    web_port = $PreferredWebPort
                }
            )
            file_size_bytes = $FileSizeBytes
            transfer_backlog_control = [ordered]@{
                peer_max_upload_kib_per_second =
                    $peerUploadCapKiBps
                compression_disabled_extension = '.zip'
                minimum_required_backlog_bytes = 64MB
            }
            scheduler_control = [ordered]@{
                type = 'same-host physical-IP minimal eD2K server'
                dynamic_port_per_case = $true
                literal_address = $routeV4.source_address
                idchange_high_id = [uint32]0x01000001
                dns_used = $false
                third_party_servers = $false
            }
            forbidden_mutations = @(
                'adapters', 'routes', 'DNS', 'hosts file', 'firewall'
            )
        }
        Write-LabJson -Value $runManifest -Path $runPath | Out-Null
        Write-LabJson -Value $runManifest `
            -Path (Join-Path $evidence 'run.json') | Out-Null
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-preflight/v1'
            captured_at_utc = Get-LabUtcTimestamp
            candidate = $candidate
            local_machine_id_sha256 = $localMachineId
            routes = @($routeV4, $routeV6)
            local_addresses = @($localV4, $localV6)
            topology_local_valid = $topologyLocalValid
            existing_emule_processes = @(
                Get-Process -Name emule -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        [pscustomobject][ordered]@{
                            id = $_.Id
                            path_sha256 = try {
                                Get-LabStringSha256 -Value $_.Path
                            } catch { '' }
                        }
                    }
            )
            planned_mutations = @(
                'isolated profile copies',
                'same-host controlled eD2K scheduler server',
                'owned candidate processes',
                'nonce-scoped coordination files'
            )
            forbidden_and_unmodified = @(
                'adapters', 'routes', 'DNS settings/cache', 'hosts file',
                'firewall'
            )
        }) -Path (Join-Path $evidence 'preflight.json') | Out-Null

        $manualCommand = @"
Run this in an elevated PowerShell on the controlled physical peer while the
coordinator waits:

& '$PSCommandPath' ``
  -Role Peer ``
  -PackagePath '<exact-package-on-peer>' ``
  -OutputRoot '<new-empty-peer-output-root>' ``
  -Commit '$($candidate.commit)' ``
  -ExpectedEmuleSha256 '$expectedHash' ``
  -PeerIPv4 '$peerV4Text' ``
  -PeerLocalIPv4 '$peerLocalV4Text' ``
  -PeerIPv6 '$peerV6Text' ``
  -CoordinationRoot '$CoordinationRoot' ``
  -ControlledPeerAcknowledged ``
  -PeerTcpPort $PeerTcpPort -PeerUdpPort $PeerUdpPort ``
  -PeerWebPort $PeerWebPort ``
  -AutoTcpPort $AutoTcpPort -AutoUdpPort $AutoUdpPort ``
  -AutoWebPort $AutoWebPort ``
  -PreferredTcpPort $PreferredTcpPort ``
  -PreferredUdpPort $PreferredUdpPort ``
  -PreferredWebPort $PreferredWebPort ``
  -FileSizeBytes $FileSizeBytes ``
  -PeerReadyTimeoutSeconds $PeerReadyTimeoutSeconds ``
  -CaseTimeoutSeconds $CaseTimeoutSeconds ``
  -StableObservationSeconds $StableObservationSeconds ``
  -RunNonce '$nonce'

The CoordinationRoot must resolve to this same shared directory on both hosts.
No adapter, route, DNS, hosts or firewall change is part of V91-I03.
"@
        Write-LabText -Value $manualCommand -Path $manualPath | Out-Null
        Write-Host $manualCommand -ForegroundColor Yellow

        $readyWait = Wait-I03JsonFile -Path $readyPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $readyWait -or $readyWait.kind -ne 'value') {
            Stop-I03Fixture -Reason (
                "Peer did not publish peer-ready.json within " +
                "$PeerReadyTimeoutSeconds seconds"
            )
        }
        $peerReady = $readyWait.value
        Write-LabJson -Value $peerReady `
            -Path (Join-Path $evidence 'peer-ready.json') | Out-Null
        $peerReadyExact =
            [string]$peerReady.schema -eq
                'ese.v91.i03-peer-ready/v1' -and
            [string]$peerReady.case_id -eq $caseId -and
            [string]$peerReady.run_nonce -eq $nonce -and
            [string]$peerReady.candidate.commit -eq $candidate.commit -and
            [string]$peerReady.candidate.emule_sha256 -eq $expectedHash -and
            [string]$peerReady.candidate.ese_server_sha256 -eq
                $candidate.ese_server_sha256 -and
            [string]$peerReady.candidate.build_info_sha256 -eq
                $candidate.build_info_sha256 -and
            [string]$peerReady.candidate.
                extracted_package_manifest_sha256 -eq
                    $packageIdentityBefore.manifest_sha256 -and
            [int]$peerReady.candidate.extracted_package_file_count -eq
                [int]$packageIdentityBefore.file_count -and
            [string]$peerReady.endpoint.public_ipv4 -eq $peerV4Text -and
            [string]$peerReady.endpoint.local_ipv4 -eq
                $peerLocalV4Text -and
            [string]$peerReady.endpoint.public_ipv6 -eq $peerV6Text -and
            [string]$peerReady.endpoint.expected_public_ipv6 -eq
                $peerV6Text -and
            [string]$peerReady.endpoint.ipv6_bind_preference -eq '::' -and
            [int]$peerReady.endpoint.tcp_port -eq $PeerTcpPort -and
            [bool]$peerReady.endpoint.dual_stack_listener -and
            [int]$peerReady.process.id -gt 0 -and
            [string]$peerReady.process.executable_sha256 -eq
                $expectedHash -and
            -not [bool]$peerReady.process.headless -and
            [string]$peerReady.process.stable_userhash_sha256 -match
                '^[0-9a-f]{64}$' -and
            [string]$peerReady.process.identity_profile.
                identity_bootstrap -eq 'fresh isolated profile' -and
            [bool]$peerReady.process.identity_profile.
                preferences_dat_absent_before_start -and
            [bool]$peerReady.process.identity_profile.
                cryptkey_dat_absent_before_start -and
            [int]$peerReady.process.identity_profile.
                max_upload_kib_per_second -eq $peerUploadCapKiBps -and
            [bool]$peerReady.process.identity_profile.
                dynamic_upload_disabled -and
            [string]$peerReady.fixture.name -eq "v91-i03-$nonce.zip" -and
            [Int64]$peerReady.fixture.bytes -eq $FileSizeBytes -and
            [string]$peerReady.fixture.sha256 -match
                '^[0-9a-fA-F]{64}$' -and
            [bool]$peerReady.fixture.
                upload_compression_disabled_by_extension -and
            [int]$peerReady.fixture.peer_max_upload_kib_per_second -eq
                $peerUploadCapKiBps -and
            [string]$peerReady.ed2k.hash -match '^[0-9A-F]{32}$' -and
            -not [bool]$peerReady.ed2k.source_extensions_present -and
            [string]$peerReady.isolation.web_allowed_ips -eq
                '127.0.0.1' -and
            -not [bool]$peerReady.isolation.kad_enabled -and
            -not [bool]$peerReady.isolation.server_enabled -and
            -not [bool]$peerReady.isolation.netlab_enabled
        if (-not $peerReadyExact) {
            Stop-I03Fixture `
                -Reason 'Peer ready evidence does not identify the exact candidate/run'
        }
        $sourceIdentity =
            [string]$peerReady.process.stable_userhash_sha256
        $null = $profileIdentityHashes.Add($sourceIdentity)
        $currentPeerPid = [int]$peerReady.process.id
        $topologyT1 =
            $topologyLocalValid -and
            [string]$peerReady.peer.machine_id_sha256 -ne
                $localMachineId -and
            [bool]$peerReady.peer.same_adapter -and
            [bool]$peerReady.peer.local_ipv4.adapter.physical_nonvirtual -and
            [bool]$peerReady.peer.public_ipv6.adapter.physical_nonvirtual -and
            [int]$peerReady.peer.local_ipv4.interface_index -eq
                [int]$peerReady.peer.public_ipv6.interface_index -and
            ($sameIPv4PhysicalPrefix = Test-I03SamePhysicalPrefix `
                -LeftAddress ([string]$localV4.address) `
                -LeftPrefixLength ([int]$localV4.prefix_length) `
                -RightAddress ([string]$peerReady.peer.local_ipv4.address) `
                -RightPrefixLength (
                    [int]$peerReady.peer.local_ipv4.prefix_length
                )) -and
            ($sameIPv6PhysicalPrefix = Test-I03SamePhysicalPrefix `
                -LeftAddress ([string]$localV6.address) `
                -LeftPrefixLength ([int]$localV6.prefix_length) `
                -RightAddress (
                    [string]$peerReady.peer.public_ipv6.address
                ) -RightPrefixLength (
                    [int]$peerReady.peer.public_ipv6.prefix_length
                )) -and
            [string]$routeV6.next_hop_class -eq 'on-link'
        $topologyT2 =
            $topologyLocalValid -and
            [string]$peerReady.peer.machine_id_sha256 -ne
                $localMachineId -and
            [bool]$peerReady.peer.same_adapter -and
            [bool]$peerReady.peer.local_ipv4.adapter.physical_nonvirtual -and
            [bool]$peerReady.peer.public_ipv6.adapter.physical_nonvirtual -and
            [int]$peerReady.peer.local_ipv4.interface_index -eq
                [int]$peerReady.peer.public_ipv6.interface_index -and
            -not $topologyT1 -and
            [string]$routeV6.next_hop_class -in @(
                'linklocal-v6', 'ula-v6', 'global-v6'
            )
        $topologyValid = $topologyT1 -or $topologyT2
        $topologyClass = if ($topologyT1) { 'T1' } elseif ($topologyT2) {
            'T2'
        } else { '' }
        if (-not $topologyValid) {
            Stop-I03Fixture -Reason (
                'T1/T2 requires two distinct physical Windows hosts with ' +
                'both families on one physical interface per host, plus an ' +
                'observed on-link prefix match (T1) or routed native IPv6 ' +
                'next hop (T2)'
            )
        }

        $baselineProbeV4 = Open-I03TcpProbe -Address $peerV4Address `
            -Port $PeerTcpPort
        $baselineProbeV6 = Open-I03TcpProbe -Address $peerV6Address `
            -Port $PeerTcpPort
        if (-not $baselineProbeV4.evidence.adapter.physical_nonvirtual -or
            -not $baselineProbeV6.evidence.adapter.physical_nonvirtual -or
            [string]$baselineProbeV4.evidence.local_address -ne
                [string]$routeV4.source_address -or
            [string]$baselineProbeV6.evidence.local_address -ne
                [string]$routeV6.source_address) {
            Stop-I03Fixture `
                -Reason (
                    'Baseline probes did not use the preflight-certified ' +
                    'physical T1/T2 routes'
                )
        }
        $clockT0 = [DateTime]::UtcNow
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-baseline-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            expected_source_process_id = $currentPeerPid
            clock_t0_utc = $clockT0.ToString('o')
            probes = @(
                $baselineProbeV4.evidence,
                $baselineProbeV6.evidence
            )
        }) -Path $baselineCommandPath | Out-Null
        $baselineAckWait = Wait-I03JsonFile -Path $baselineAckPath `
            -StopPath $stopPath -TimeoutSeconds 30
        $clockT3 = [DateTime]::UtcNow
        if ($null -eq $baselineAckWait -or
            $baselineAckWait.kind -ne 'value') {
            Stop-I03Fixture -Reason 'Peer did not acknowledge dual-family baseline'
        }
        $baselineAck = $baselineAckWait.value
        Write-LabJson -Value $baselineAck `
            -Path (Join-Path $evidence 'peer-baseline-ack.json') | Out-Null
        $baselineAckExact =
            [string]$baselineAck.schema -eq
                'ese.v91.i03-peer-baseline-ack/v1' -and
            [string]$baselineAck.case_id -eq $caseId -and
            [string]$baselineAck.run_nonce -eq $nonce -and
            [string]$baselineAck.candidate_commit -eq
                $candidate.commit -and
            [string]$baselineAck.candidate_emule_sha256 -eq
                $expectedHash -and
            [int]$baselineAck.source_process_id -eq $currentPeerPid -and
            [string]$baselineAck.source_process_emule_sha256 -eq
                $expectedHash -and
            [string]$baselineAck.source_userhash_sha256 -eq
                $sourceIdentity -and
            @($baselineAck.inbound_connections).Count -eq 2 -and
            [bool]$baselineAck.dualstack_marker.dualstack_capability_armed -and
            [bool]$baselineAck.api.available -and
            [bool]$baselineAck.api.isolation_valid
        if (-not $baselineAckExact) {
            Stop-I03Fixture -Reason 'Peer baseline acknowledgement is not exact'
        }
        $baselineInboundV4 = @(
            $baselineAck.inbound_connections | Where-Object {
                [string]$_.local_address -eq $peerLocalV4Text -and
                [int]$_.local_port -eq $PeerTcpPort
            }
        )
        $baselineV4InverseExact = $baselineInboundV4.Count -eq 1 -and
            [string]$baselineInboundV4[0].remote_address -eq
                [string]$baselineProbeV4.evidence.local_address -and
            [int]$baselineInboundV4[0].remote_port -eq
                [int]$baselineProbeV4.evidence.local_port
        $baselineInboundV6 = @(
            $baselineAck.inbound_connections | Where-Object {
                [string]$_.local_address -eq $peerV6Text -and
                [int]$_.local_port -eq $PeerTcpPort -and
                [string]$_.remote_address -eq
                    [string]$baselineProbeV6.evidence.local_address -and
                [int]$_.remote_port -eq
                    [int]$baselineProbeV6.evidence.local_port
            }
        )
        if ($baselineInboundV4.Count -ne 1 -or
            $baselineInboundV6.Count -ne 1 -or
            ($peerV4Text -eq $peerLocalV4Text -and
                -not $baselineV4InverseExact)) {
            Stop-I03Fixture -Reason (
                'Baseline tuples do not correlate both hosts'
            )
        }
        try {
            $clockT0Echo = [DateTime]::Parse(
                [string]$baselineAck.clock.t0_coordinator_send_utc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )
            $clockT1 = [DateTime]::Parse(
                [string]$baselineAck.clock.t1_peer_receive_utc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )
            $clockT2 = [DateTime]::Parse(
                [string]$baselineAck.clock.t2_peer_send_utc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )
            $clockDelayMs =
                ($clockT3 - $clockT0).TotalMilliseconds -
                ($clockT2 - $clockT1).TotalMilliseconds
            $clockOffsetMs = (
                ($clockT1 - $clockT0).TotalMilliseconds +
                ($clockT2 - $clockT3).TotalMilliseconds
            ) / 2.0
            $clockUncertaintyMs = [Math]::Max(0.0, $clockDelayMs / 2.0)
            $clockCertified = $clockT0Echo -eq $clockT0 -and
                $clockDelayMs -ge 0 -and
                [Math]::Abs($clockOffsetMs) + $clockUncertaintyMs -le 1000.0
            $clockEvidence = [ordered]@{
                method = 'four-timestamp shared-coordination challenge'
                t0_coordinator_send_utc = $clockT0.ToString('o')
                t1_peer_receive_utc = $clockT1.ToString('o')
                t2_peer_send_utc = $clockT2.ToString('o')
                t3_coordinator_receive_utc = $clockT3.ToString('o')
                round_trip_delay_ms = [Math]::Round($clockDelayMs, 3)
                estimated_offset_ms = [Math]::Round($clockOffsetMs, 3)
                uncertainty_ms = [Math]::Round($clockUncertaintyMs, 3)
                certified_within_1000_ms = $clockCertified
            }
        } catch {
            Stop-I03Fixture -Reason (
                "Clock challenge could not be parsed: $($_.Exception.Message)"
            )
        }
        if (-not $clockEvidence.certified_within_1000_ms) {
            Stop-I03Fixture -Reason (
                'T1 clock difference could not be certified at <= 1 second'
            )
        }
        $baselineEvidence = [ordered]@{
            schema = 'ese.v91.i03-baseline/v1'
            captured_at_utc = Get-LabUtcTimestamp
            coordinator = @(
                $baselineProbeV4.evidence,
                $baselineProbeV6.evidence
            )
            peer_ack = $baselineAck
            ipv6_inverse_tuple_exact = $true
            ipv4_correlation = [ordered]@{
                nat_mapped = $peerV4Text -ne $peerLocalV4Text
                inverse_tuple_exact = $baselineV4InverseExact
                method = if ($peerV4Text -ne $peerLocalV4Text) {
                    'nonce barrier + unique peer PID/local endpoint; remote tuple may be NAT-translated'
                } else { 'exact inverse tuple' }
                peer_observed_remote_address =
                    $baselineInboundV4[0].remote_address
                peer_observed_remote_port =
                    $baselineInboundV4[0].remote_port
            }
            clock = $clockEvidence
        }
        Write-LabJson -Value $baselineEvidence `
            -Path (Join-Path $evidence 'baseline.json') | Out-Null

        $baselineV4Tuple = Get-I03TupleKey -Family 'IPv4' `
            -LocalAddress $baselineProbeV4.evidence.local_address `
            -LocalPort $baselineProbeV4.evidence.local_port `
            -RemoteAddress $baselineProbeV4.evidence.remote_address `
            -RemotePort $baselineProbeV4.evidence.remote_port
        $baselineV6Tuple = Get-I03TupleKey -Family 'IPv6' `
            -LocalAddress $baselineProbeV6.evidence.local_address `
            -LocalPort $baselineProbeV6.evidence.local_port `
            -RemoteAddress $baselineProbeV6.evidence.remote_address `
            -RemotePort $baselineProbeV6.evidence.remote_port
        $baselineProbeV4.client.Dispose()
        $baselineProbeV4 = $null
        $baselineProbeV6.client.Dispose()
        $baselineProbeV6 = $null
        if (-not (Wait-I03OwnedTupleGone -ProcessId $PID `
            -TupleKey $baselineV4Tuple) -or
            -not (Wait-I03OwnedTupleGone -ProcessId $PID `
                -TupleKey $baselineV6Tuple)) {
            Stop-I03Fixture `
                -Reason 'Baseline probes remained active before policy cases'
        }

        foreach ($policy in @(
            [pscustomobject][ordered]@{
                name = 'auto'
                mode = 1
                expected_family = 'IPv4'
                tcp = $AutoTcpPort
                udp = $AutoUdpPort
                web = $AutoWebPort
            },
            [pscustomobject][ordered]@{
                name = 'preferred'
                mode = 2
                expected_family = 'IPv6'
                tcp = $PreferredTcpPort
                udp = $PreferredUdpPort
                web = $PreferredWebPort
            }
        )) {
            $caseStarted = [DateTime]::UtcNow
            $failureCountBefore = $productFailures.Count
            $caseRecord = [ordered]@{
                schema = 'ese.v91.i03-policy-case/v1'
                policy = $policy.name
                ipv6_mode = $policy.mode
                expected_family = $policy.expected_family
                started_at_utc = $caseStarted.ToString('o')
                finished_at_utc = $null
                fixture_valid = $false
                product_match = $false
                client = $null
                controlled_server = $null
                literal_ipv4_source_link_validated = $false
                link_injection = $null
                dualstack_rearm = $null
                prewarm = $null
                backlog_before_restart = $null
                post_restart = $null
                peer_complete = $null
                cleanup = $null
                runtime_error = $null
            }
            $caseRecorded = $false
            $caseNode = ''
            $caseExe = ''
            $caseTemp = ''
            $caseServerStop = $null
            try {
                $offset = $policy.tcp - 4662
                if (($policy.udp - 4672) -ne $offset -or
                    ($policy.web - 4711) -ne $offset) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) ports do not share the standard " +
                        '4662/4672/4711 offset'
                    )
                }
                $serverEvidencePath = Join-Path $evidence `
                    "$($policy.name)-controlled-ed2k-server.json"
                $activeServer = Start-I03ControlledEd2kServer `
                    -EvidencePath $serverEvidencePath `
                    -ListenAddress ([string]$routeV4.source_address) `
                    -ExpectedClientAddress ([string]$routeV4.source_address) `
                    -RunNonce $nonce -Policy $policy.name
                $serverListeners = @(
                    Get-NetTCPConnection -State Listen `
                        -LocalAddress ([string]$routeV4.source_address) `
                        -LocalPort $activeServer.port -OwningProcess $PID `
                        -ErrorAction SilentlyContinue
                )
                if ($serverListeners.Count -ne 1) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) controlled server is not one " +
                        'coordinator-owned physical-IP listener'
                    )
                }

                & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
                    -SourcePackage $candidate.package_path -OutputRoot $nodes `
                    -RunId "v91-i03-$($policy.name)" -PortOffset $offset
                $caseNode = Join-Path $nodes `
                    "v91-i03-$($policy.name)-b"
                $caseExe = Join-Path $caseNode 'emule.exe'
                if ((Get-LabSha256 -Path $caseExe) -ne $expectedHash) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) prepared executable is not the " +
                        'exact candidate'
                    )
                }
                $caseIncoming = New-LabDirectory `
                    -Path (Join-Path $caseNode 'I03Incoming')
                $caseTemp = New-LabDirectory `
                    -Path (Join-Path $caseNode 'I03Temp')
                $casePassword = "v91-i03-$($policy.name)"
                $clientIsolation = Set-I03IsolatedPreferences `
                    -NodePath $caseNode `
                    -IPv6Mode $policy.mode -IPv6BindAddress '::' `
                    -WebPort $policy.web -Password $casePassword `
                    -IncomingPath $caseIncoming -TempPath $caseTemp

                # preferences.dat is saved on graceful shutdown, not merely
                # on startup. Bootstrap a fresh identity while eD2K is still
                # disabled, then reopen that exact profile for the test.
                $activeClientExe = $caseExe
                $activeClient = Start-Process -FilePath $caseExe `
                    -ArgumentList @(
                        '--portable', '--ignoreinstances',
                        "--metrics-port=$($policy.web)",
                        "--tcp-port=$($policy.tcp)",
                        "--udp-port=$($policy.udp)"
                    ) -WorkingDirectory $caseNode -PassThru `
                    -WindowStyle Hidden
                $identityInitListener = Wait-I03Listener `
                    -Port $policy.tcp -Process $activeClient `
                    -RequireDualStack
                $identityInitApi = Wait-I03Api -Port $policy.web `
                    -Process $activeClient
                $identityInitUi =
                    Get-I03UiProbe -Process $activeClient
                if (-not $identityInitListener.dual_stack -or
                    -not (Test-I03ApiIsolation -Data $identityInitApi) -or
                    -not $identityInitUi.main_window_present -or
                    -not $identityInitUi.message_pump_responsive -or
                    (Get-LabSha256 -Path $activeClient.Path) -ne
                        $expectedHash) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) clean identity initialization " +
                        'was not exact and isolated'
                    )
                }
                $identityInitProcessId = $activeClient.Id
                $identityInitStop = Stop-I03OwnedProcess `
                    -Process $activeClient -ExpectedPath $activeClientExe `
                    -RequireGraceful
                if (-not $identityInitStop.stopped -or
                    -not $identityInitStop.graceful) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) fresh identity initialization " +
                        'did not stop gracefully'
                    )
                }
                $activeClient = $null
                try {
                    $clientIdentity =
                        Get-I03UserHashSha256 -NodePath $caseNode
                } catch {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) fresh client identity was not " +
                        "persisted: $($_.Exception.Message)"
                    )
                }
                $identityUnique =
                    $profileIdentityHashes.Add($clientIdentity)
                if ($clientIdentity -notmatch '^[0-9a-f]{64}$' -or
                    -not $identityUnique -or
                    -not $clientIsolation.
                        preferences_dat_absent_before_start -or
                    -not $clientIsolation.
                        cryptkey_dat_absent_before_start) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) client and peer profiles do not " +
                        'have independently bootstrapped identities'
                    )
                }
                $controlProfile = Enable-I03ControlledEd2kProfile `
                    -NodePath $caseNode `
                    -ServerAddress ([string]$routeV4.source_address) `
                    -ServerPort $activeServer.port -RunNonce $nonce `
                    -Policy $policy.name

                # Normal mode is mandatory: it provides the UI liveness probe
                # and does not regenerate the userhash on startup.
                $activeClient = Start-Process -FilePath $caseExe `
                    -ArgumentList @(
                        '--portable', '--ignoreinstances',
                        "--metrics-port=$($policy.web)",
                        "--tcp-port=$($policy.tcp)",
                        "--udp-port=$($policy.udp)"
                    ) -WorkingDirectory $caseNode -PassThru `
                    -WindowStyle Hidden
                $activeClientExe = $caseExe
                $clientListener = Wait-I03Listener -Port $policy.tcp `
                    -Process $activeClient -RequireDualStack
                $null = Wait-I03Api -Port $policy.web `
                    -Process $activeClient
                $serverLogin = Wait-I03ControlledEd2kLogin `
                    -Server $activeServer -Process $activeClient `
                    -ExpectedTcpPort $policy.tcp
                $apiDeadline = [DateTime]::UtcNow.AddSeconds(60)
                $clientApi = $null
                do {
                    $clientApi = Get-I03ApiProbe -Port $policy.web `
                        -AllowControlledEd2k
                    if ($clientApi.available -and
                        $clientApi.isolation_valid) {
                        break
                    }
                    Start-Sleep -Milliseconds 200
                } while ([DateTime]::UtcNow -lt $apiDeadline)
                $clientUi = Get-I03UiProbe -Process $activeClient
                try {
                    $runtimeClientIdentity =
                        Get-I03UserHashSha256 -NodePath $caseNode
                } catch {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) persisted client identity could not " +
                        "be read: $($_.Exception.Message)"
                    )
                }
                if ($runtimeClientIdentity -ne $clientIdentity) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) client identity changed between " +
                        'clean initialization and controlled startup'
                    )
                }
                $serverConnections = @(
                    Get-NetTCPConnection -State Established `
                        -OwningProcess $activeClient.Id `
                        -RemoteAddress ([string]$routeV4.source_address) `
                        -RemotePort $activeServer.port `
                        -ErrorAction SilentlyContinue
                )
                $startupConnections = @(
                    Get-NetTCPConnection -State Established `
                        -OwningProcess $activeClient.Id `
                        -ErrorAction SilentlyContinue
                )
                $unexpectedStartupConnections = @(
                    $startupConnections | Where-Object {
                        $remote = Get-I03NormalizedIp `
                            -Address ([string]$_.RemoteAddress)
                        $isControlServer =
                            $remote -eq
                                [string]$routeV4.source_address -and
                            [int]$_.RemotePort -eq $activeServer.port
                        $isLocalWebProbe =
                            [int]$_.LocalPort -eq $policy.web -and
                            $remote -in @('127.0.0.1', '::1')
                        -not $isControlServer -and -not $isLocalWebProbe
                    }
                )
                if (-not $clientListener.dual_stack -or
                    (Get-LabSha256 -Path $activeClient.Path) -ne
                        $expectedHash -or
                    -not $clientApi.available -or
                    -not $clientApi.isolation_valid -or
                    -not $clientUi.main_window_present -or
                    -not $clientUi.message_pump_responsive -or
                    $serverConnections.Count -ne 1 -or
                    $unexpectedStartupConnections.Count -ne 0 -or
                    -not $serverLogin.endpoint_is_same_host_physical) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) candidate/control-plane startup " +
                        'could not be proved exact and isolated'
                    )
                }
                $clientStartup = [ordered]@{
                    process_id = $activeClient.Id
                    executable_sha256 = Get-LabSha256 `
                        -Path $activeClient.Path
                    source_mode = 'non-headless'
                    ports = [ordered]@{
                        tcp = $policy.tcp
                        udp = $policy.udp
                        web = $policy.web
                    }
                    ipv6_mode = $policy.mode
                    ipv6_bind = '::'
                    dual_stack_listener = $clientListener.dual_stack
                    identity = [ordered]@{
                        initialized_userhash_sha256 = $clientIdentity
                        runtime_userhash_sha256 =
                            $runtimeClientIdentity
                        preserved_across_controlled_startup =
                            $runtimeClientIdentity -eq $clientIdentity
                        source_userhash_sha256 = $sourceIdentity
                        distinct_from_source =
                            $clientIdentity -ne $sourceIdentity
                        distinct_from_all_prior_profiles =
                            $identityUnique
                        initialization = [ordered]@{
                            process_id = $identityInitProcessId
                            source_mode = 'non-headless'
                            ed2k_connected = $false
                            dual_stack_listener =
                                $identityInitListener.dual_stack
                            api_isolation_valid =
                                Test-I03ApiIsolation `
                                    -Data $identityInitApi
                            ui = $identityInitUi
                            graceful_stop =
                                $identityInitStop.graceful
                        }
                        profile = $clientIsolation
                    }
                    api = $clientApi
                    ui = $clientUi
                    profile = $controlProfile
                    web_allowed_ips = '127.0.0.1'
                    isolation_controls = [ordered]@{
                        update_notify = $false
                        serverlist_auto_update = $false
                        add_servers_from_server = $false
                        add_servers_from_client = $false
                        kad = $false
                        netlab = $false
                        proxy = $false
                        literal_control_server_address = $true
                    }
                    controlled_server_login = $serverLogin
                    startup_established_connections = @(
                        $startupConnections | ForEach-Object {
                            [pscustomobject][ordered]@{
                                local_address =
                                    Get-I03NormalizedIp -Address `
                                        ([string]$_.LocalAddress)
                                local_port = [int]$_.LocalPort
                                remote_address =
                                    Get-I03NormalizedIp -Address `
                                        ([string]$_.RemoteAddress)
                                remote_port = [int]$_.RemotePort
                                owning_process = [int]$_.OwningProcess
                            }
                        }
                    )
                    unexpected_startup_connection_count =
                        $unexpectedStartupConnections.Count
                }
                $caseRecord.client = $clientStartup
                $caseRecord.controlled_server = [ordered]@{
                    listen_address = $routeV4.source_address
                    listen_port = $activeServer.port
                    listener_owning_process = $PID
                    listener_exact = $serverListeners.Count -eq 1
                    login = $serverLogin
                    third_party = $false
                    dns_used = $false
                }
                Write-LabJson -Value $clientStartup -Path (
                    Join-Path $evidence `
                        "$($policy.name)-client-startup.json"
                ) | Out-Null

                # Arm the CURRENT peer process. Keep the native-v6 TcpClient
                # open until the peer proves the exact inverse tuple and a
                # one-marker delta for this PID.
                $rearmProbe = Open-I03TcpProbe -Address $peerV6Address `
                    -Port $PeerTcpPort
                $rearmTuple = Get-I03TupleKey -Family 'IPv6' `
                    -LocalAddress $rearmProbe.evidence.local_address `
                    -LocalPort $rearmProbe.evidence.local_port `
                    -RemoteAddress $rearmProbe.evidence.remote_address `
                    -RemotePort $rearmProbe.evidence.remote_port
                $rearmPath = Join-Path $coordination `
                    "$($policy.name)-rearm.json"
                $rearmAckPath = Join-Path $coordination `
                    "peer-$($policy.name)-rearm-ack.json"
                $rearmAck = $null
                try {
                    Write-LabJson -Value ([ordered]@{
                        schema = 'ese.v91.i03-rearm-command/v1'
                        case_id = $caseId
                        run_nonce = $nonce
                        policy = $policy.name
                        ipv6_mode = $policy.mode
                        candidate_commit = $candidate.commit
                        candidate_emule_sha256 = $expectedHash
                        expected_source_process_id = $currentPeerPid
                        coordinator_local_ipv6 =
                            $rearmProbe.evidence.local_address
                        coordinator_local_port =
                            $rearmProbe.evidence.local_port
                        peer_ipv6 = $peerV6Text
                        peer_tcp_port = $PeerTcpPort
                    }) -Path $rearmPath | Out-Null
                    $rearmAckWait = Wait-I03JsonFile `
                        -Path $rearmAckPath -StopPath $stopPath `
                        -TimeoutSeconds 30
                    if ($null -eq $rearmAckWait -or
                        $rearmAckWait.kind -ne 'value') {
                        Stop-I03Fixture -Reason (
                            "Peer did not acknowledge $($policy.name) " +
                            'current-PID DUALSTACK rearm'
                        )
                    }
                    $rearmAck = $rearmAckWait.value
                    Write-LabJson -Value $rearmAck -Path (
                        Join-Path $evidence `
                            "$($policy.name)-peer-rearm-ack.json"
                    ) | Out-Null
                    $rearmExact =
                        [string]$rearmAck.schema -eq
                            'ese.v91.i03-peer-rearm-ack/v1' -and
                        [string]$rearmAck.case_id -eq $caseId -and
                        [string]$rearmAck.run_nonce -eq $nonce -and
                        [string]$rearmAck.policy -eq $policy.name -and
                        [int]$rearmAck.ipv6_mode -eq $policy.mode -and
                        [string]$rearmAck.candidate_commit -eq
                            $candidate.commit -and
                        [string]$rearmAck.candidate_emule_sha256 -eq
                            $expectedHash -and
                        [int]$rearmAck.source_process_id -eq
                            $currentPeerPid -and
                        [string]$rearmAck.source_process_emule_sha256 -eq
                            $expectedHash -and
                        [string]$rearmAck.source_userhash_sha256 -eq
                            $sourceIdentity -and
                        [bool]$rearmAck.runtime_dualstack_rearmed -and
                        [int]$rearmAck.inbound_marker_delta -eq 1 -and
                        [int]$rearmAck.accepted_marker_delta -eq 1 -and
                        [string]$rearmAck.inbound_connection.local_address -eq
                            $peerV6Text -and
                        [int]$rearmAck.inbound_connection.local_port -eq
                            $PeerTcpPort -and
                        [string]$rearmAck.inbound_connection.remote_address -eq
                            [string]$rearmProbe.evidence.local_address -and
                        [int]$rearmAck.inbound_connection.remote_port -eq
                            [int]$rearmProbe.evidence.local_port
                    if (-not $rearmExact) {
                        Stop-I03Fixture -Reason (
                            "$($policy.name) DUALSTACK rearm evidence " +
                            'is not current-PID/exact'
                        )
                    }
                } finally {
                    $rearmProbe.client.Dispose()
                }
                if (-not (Wait-I03OwnedTupleGone -ProcessId $PID `
                    -TupleKey $rearmTuple)) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) rearm probe remained active " +
                        'before prewarm'
                    )
                }
                $caseRecord.dualstack_rearm = [ordered]@{
                    coordinator = $rearmProbe.evidence
                    peer = $rearmAck
                    exact_inverse_tuple = $true
                    current_source_process_id = $currentPeerPid
                }

                $directLink = [string]$peerReady.ed2k.base_link +
                    "|sources,$peerV4Text`:$PeerTcpPort|/"
                if ($directLink -notmatch (
                    '\|sources,' + [regex]::Escape($peerV4Text) + ':' +
                    $PeerTcpPort + '\|/$'
                ) -or $directLink -match
                    ('(?i)\|sources,\[' +
                        [regex]::Escape($peerV6Text))) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) direct source link is not " +
                        'literal-IPv4-only'
                    )
                }
                $caseRecord.literal_ipv4_source_link_validated = $true
                $linkDeliveries =
                    [System.Collections.Generic.List[object]]::new()
                try {
                    $linkDeliveries.Add(
                        (Send-I03Ed2kLink -Process $activeClient `
                            -Link $directLink)
                    )
                    Start-Sleep -Seconds 2
                    $linkDeliveries.Add(
                        (Send-I03Ed2kLink -Process $activeClient `
                            -Link $directLink)
                    )
                } catch {
                    $activeClient.Refresh()
                    Stop-I03ProductFailure -Reason (
                        "$($policy.name) candidate did not accept the " +
                        "bounded eD2K-link injection: " +
                        "$($_.Exception.Message); exited=" +
                        [string]$activeClient.HasExited
                    )
                }
                $caseRecord.link_injection = [ordered]@{
                    bounded = $true
                    attempts = @($linkDeliveries)
                    all_accepted = $linkDeliveries.Count -eq 2 -and
                        @($linkDeliveries | Where-Object {
                            -not [bool]$_.delivered -or
                            -not [bool]$_.accepted
                        }).Count -eq 0
                }
                $prewarmSamples = Join-Path $evidence `
                    "$($policy.name)-prewarm-samples.jsonl"
                try {
                    $prewarm = Wait-I03Prewarm -Process $activeClient `
                        -NodePath $caseNode -TempPath $caseTemp `
                        -WebPort $policy.web `
                        -TimeoutSeconds $CaseTimeoutSeconds `
                        -SamplesPath $prewarmSamples
                } catch {
                    if ($_.Exception.Message -match
                        'Client exited|Ambiguous or non-IPv4 connection') {
                        Stop-I03ProductFailure -Reason (
                            "$($policy.name) candidate failed during " +
                            "IPv4 prewarm: $($_.Exception.Message)"
                        )
                    }
                    throw
                }
                if ([int]$prewarm.other_pid_connection_count -ne 0) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) IPv4 prewarm was contaminated " +
                        'by another local process'
                    )
                }
                $prewarmExact =
                    [bool]$prewarm.complete -and
                    $null -ne $prewarm.selected_connection -and
                    [string]$prewarm.selected_connection.family -eq
                        'IPv4' -and
                    [string]$prewarm.selected_connection.remote_address -eq
                        $peerV4Text -and
                    [int]$prewarm.selected_connection.remote_port -eq
                        $PeerTcpPort -and
                    [int]$prewarm.selected_connection.owning_process -eq
                        $activeClient.Id -and
                    [string]$prewarm.selected_connection.local_address -eq
                        [string]$routeV4.source_address -and
                    [bool]$prewarm.socket.pid_matches -and
                    [bool]$prewarm.socket.tuple_current_exact -and
                    [bool]$prewarm.socket.local_address_assigned -and
                    [bool]$prewarm.socket.physical_nonvirtual -and
                    [bool]$prewarm.transfer_progress -and
                    [bool]$prewarm.hello.learned_public_ipv6_via_hello -and
                    [int]$prewarm.hello.highid_hello_answer_count -gt 0 -and
                    [int]$prewarm.hello.lowid_like_hello_answer_count -eq 0 -and
                    [bool]$prewarm.health_valid
                if (-not $prewarmExact) {
                    Stop-I03ProductFailure -Reason (
                        "$($policy.name) candidate did not establish the " +
                        'IPv4 HighID HELLO/transfer prewarm on the valid ' +
                        'controlled fixture'
                    )
                }
                Write-LabJson -Value $prewarm -Path (
                    Join-Path $evidence "$($policy.name)-prewarm.json"
                ) | Out-Null
                $caseRecord.prewarm = $prewarm

                $prewarmPath = Join-Path $coordination `
                    "$($policy.name)-prewarm.json"
                $prewarmAckPath = Join-Path $coordination `
                    "peer-$($policy.name)-prewarm-ack.json"
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i03-prewarm-command/v1'
                    case_id = $caseId
                    run_nonce = $nonce
                    policy = $policy.name
                    ipv6_mode = $policy.mode
                    expected_family = $policy.expected_family
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $expectedHash
                    expected_source_process_id = $currentPeerPid
                    client_process_id = $activeClient.Id
                    client_tuple = $prewarm.selected_connection
                }) -Path $prewarmPath | Out-Null
                $prewarmAckWait = Wait-I03JsonFile `
                    -Path $prewarmAckPath -StopPath $stopPath `
                    -TimeoutSeconds 30
                if ($null -eq $prewarmAckWait -or
                    $prewarmAckWait.kind -ne 'value') {
                    Stop-I03Fixture -Reason (
                        "Peer did not acknowledge $($policy.name) prewarm"
                    )
                }
                $prewarmAck = $prewarmAckWait.value
                Write-LabJson -Value $prewarmAck -Path (
                    Join-Path $evidence `
                        "$($policy.name)-peer-prewarm-ack.json"
                ) | Out-Null
                $prewarmV4InverseExact =
                    [string]$prewarmAck.inbound_connection.remote_address -eq
                        [string]$prewarm.selected_connection.local_address -and
                    [int]$prewarmAck.inbound_connection.remote_port -eq
                        [int]$prewarm.selected_connection.local_port
                $prewarmAckExact =
                    [string]$prewarmAck.schema -eq
                        'ese.v91.i03-peer-prewarm-ack/v1' -and
                    [string]$prewarmAck.case_id -eq $caseId -and
                    [string]$prewarmAck.run_nonce -eq $nonce -and
                    [string]$prewarmAck.policy -eq $policy.name -and
                    [int]$prewarmAck.ipv6_mode -eq $policy.mode -and
                    [string]$prewarmAck.candidate_commit -eq
                        $candidate.commit -and
                    [string]$prewarmAck.candidate_emule_sha256 -eq
                        $expectedHash -and
                    [int]$prewarmAck.source_process_id -eq
                        $currentPeerPid -and
                    [string]$prewarmAck.source_process_emule_sha256 -eq
                        $expectedHash -and
                    [string]$prewarmAck.source_userhash_sha256 -eq
                        $sourceIdentity -and
                    [int]$prewarmAck.client_process_id_from_command -eq
                        $activeClient.Id -and
                    [string]$prewarmAck.inbound_connection.local_address -eq
                        $peerLocalV4Text -and
                    [int]$prewarmAck.inbound_connection.local_port -eq
                        $PeerTcpPort -and
                    ($peerV4Text -ne $peerLocalV4Text -or
                        $prewarmV4InverseExact) -and
                    [bool]$prewarmAck.api.available -and
                    [bool]$prewarmAck.api.isolation_valid
                if (-not $prewarmAckExact) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) prewarm tuple/peer ack " +
                        'is not exact'
                    )
                }
                $prewarm | Add-Member -NotePropertyName `
                    peer_ipv4_correlation -NotePropertyValue `
                    ([pscustomobject][ordered]@{
                        nat_mapped =
                            $peerV4Text -ne $peerLocalV4Text
                        inverse_tuple_exact = $prewarmV4InverseExact
                        peer_observed_remote_address =
                            $prewarmAck.inbound_connection.remote_address
                        peer_observed_remote_port =
                            $prewarmAck.inbound_connection.remote_port
                    }) -Force
                Write-LabJson -Value $prewarm -Path (
                    Join-Path $evidence "$($policy.name)-prewarm.json"
                ) | Out-Null

                # A completed download has no reason to redial after the peer
                # restart. Prove a large backlog while the exact IPv4 prewarm
                # tuple is still live, before issuing the restart barrier.
                $backlogCapturedAt = [DateTime]::UtcNow
                $caseElapsedSeconds =
                    ($backlogCapturedAt - $caseStarted).TotalSeconds
                $configuredTransferUpperBytes = [Int64][Math]::Ceiling(
                    $peerUploadCapKiBps * 1024.0 *
                        [Math]::Max(0.0, $caseElapsedSeconds) +
                    16MB
                )
                $minimumBacklogBytes = [Int64]$FileSizeBytes -
                    $configuredTransferUpperBytes
                $partFiles = @(
                    Get-ChildItem -LiteralPath $caseTemp -File `
                        -Filter '*.part' -ErrorAction SilentlyContinue
                )
                $partMetFiles = @(
                    Get-ChildItem -LiteralPath $caseTemp -File `
                        -Filter '*.part.met' -ErrorAction SilentlyContinue
                )
                $completedFixturePath = Join-Path $caseIncoming `
                    ([string]$peerReady.fixture.name)
                $currentPrewarmMatches = @(
                    Get-I03TargetConnections | Where-Object {
                        [int]$_.owning_process -eq $activeClient.Id -and
                        [string]$_.state -eq 'Established' -and
                        [string]$_.tuple_key -eq
                            [string]$prewarm.selected_connection.tuple_key
                    }
                )
                $currentPrewarmSocket = if (
                    $currentPrewarmMatches.Count -eq 1
                ) {
                    Get-I03SocketEvidence `
                        -Connection $currentPrewarmMatches[0] `
                        -ExpectedProcessId $activeClient.Id
                } else { $null }
                $backlogValid =
                    [IO.Path]::GetExtension(
                        [string]$peerReady.fixture.name
                    ).ToLowerInvariant() -eq '.zip' -and
                    [bool]$peerReady.fixture.
                        upload_compression_disabled_by_extension -and
                    [int]$peerReady.fixture.
                        peer_max_upload_kib_per_second -eq
                            $peerUploadCapKiBps -and
                    $partFiles.Count -eq 1 -and
                    $partMetFiles.Count -ge 1 -and
                    -not (Test-Path -LiteralPath $completedFixturePath `
                        -PathType Leaf) -and
                    $minimumBacklogBytes -ge 64MB -and
                    $currentPrewarmMatches.Count -eq 1 -and
                    [bool]$currentPrewarmSocket.tuple_current_exact -and
                    [bool]$currentPrewarmSocket.physical_nonvirtual
                $backlogEvidence = [ordered]@{
                    schema = 'ese.v91.i03-backlog-before-restart/v1'
                    policy = $policy.name
                    captured_at_utc = $backlogCapturedAt.ToString('o')
                    fixture_name = $peerReady.fixture.name
                    fixture_bytes = [Int64]$FileSizeBytes
                    compression_disabled_extension = '.zip'
                    peer_max_upload_kib_per_second =
                        $peerUploadCapKiBps
                    case_elapsed_seconds =
                        [Math]::Round($caseElapsedSeconds, 3)
                    startup_burst_allowance_bytes = 16MB
                    configured_transfer_upper_bound_bytes =
                        $configuredTransferUpperBytes
                    minimum_backlog_bytes = $minimumBacklogBytes
                    part_file_count = $partFiles.Count
                    part_met_file_count = $partMetFiles.Count
                    part_files = @($partFiles | ForEach-Object {
                        [pscustomobject][ordered]@{
                            name = $_.Name
                            bytes = [Int64]$_.Length
                            last_write_utc =
                                $_.LastWriteTimeUtc.ToString('o')
                        }
                    })
                    completed_fixture_present =
                        Test-Path -LiteralPath $completedFixturePath `
                            -PathType Leaf
                    prewarm_tuple_current =
                        $currentPrewarmMatches.Count -eq 1
                    prewarm_tuple_revalidation =
                        $currentPrewarmSocket
                    valid = $backlogValid
                }
                $caseRecord.backlog_before_restart = $backlogEvidence
                Write-LabJson -Value $backlogEvidence -Path (
                    Join-Path $evidence `
                        "$($policy.name)-backlog-before-restart.json"
                ) | Out-Null
                if (-not $backlogValid) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) transfer backlog was not proved " +
                        'immediately before peer restart'
                    )
                }

                $oldPeerPid = $currentPeerPid
                $restartPath = Join-Path $coordination `
                    "$($policy.name)-restart.json"
                $restartedPath = Join-Path $coordination `
                    "peer-$($policy.name)-restarted.json"
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i03-restart-command/v1'
                    case_id = $caseId
                    run_nonce = $nonce
                    policy = $policy.name
                    action = 'restart-same-peer-source'
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $expectedHash
                    expected_old_process_id = $oldPeerPid
                    source_userhash_sha256 = $sourceIdentity
                }) -Path $restartPath | Out-Null
                $routeSamples = Join-Path $evidence `
                    "$($policy.name)-post-restart-samples.jsonl"
                try {
                    $routeObservation = Wait-I03PostRestartRoute `
                        -Process $activeClient -WebPort $policy.web `
                        -ExpectedFamily $policy.expected_family `
                        -PrewarmTuple `
                            ([string]$prewarm.selected_connection.tuple_key) `
                        -RestartAckPath $restartedPath `
                        -TimeoutSeconds $CaseTimeoutSeconds `
                        -ObservationSeconds $StableObservationSeconds `
                        -SamplesPath $routeSamples
                } catch {
                    if ($_.Exception.Message -match
                        'Client exited during post-restart') {
                        Stop-I03ProductFailure -Reason (
                            "$($policy.name) candidate exited during " +
                            "post-restart route selection: " +
                            $_.Exception.Message
                        )
                    }
                    throw
                }
                $restartAck = $routeObservation.restart_ack
                $restartAckExact =
                    $null -ne $restartAck -and
                    [string]$restartAck.schema -eq
                        'ese.v91.i03-peer-restarted/v1' -and
                    [string]$restartAck.case_id -eq $caseId -and
                    [string]$restartAck.run_nonce -eq $nonce -and
                    [string]$restartAck.policy -eq $policy.name -and
                    [string]$restartAck.candidate_commit -eq
                        $candidate.commit -and
                    [string]$restartAck.candidate_emule_sha256 -eq
                        $expectedHash -and
                    [int]$restartAck.old_process_id -eq $oldPeerPid -and
                    [int]$restartAck.process_id -gt 0 -and
                    [int]$restartAck.process_id -ne $oldPeerPid -and
                    [string]$restartAck.process_emule_sha256 -eq
                        $expectedHash -and
                    [string]$restartAck.source_userhash_sha256 -eq
                        $sourceIdentity -and
                    [bool]$restartAck.dual_stack_listener -and
                    [bool]$restartAck.api_isolation_valid
                if (-not $restartAckExact) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) same-identity peer restart " +
                        'was not proved'
                    )
                }
                $currentPeerPid = [int]$restartAck.process_id

                $observedConnections = @(
                    $routeObservation.current_established_connections
                )
                $observedSockets = @(
                    $routeObservation.current_socket_evidence
                )
                if (-not $routeObservation.prewarm_disappeared -or
                    $routeObservation.other_pid_connection_count -ne 0) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) route observation was " +
                        'contaminated or did not cross the restart boundary'
                    )
                }
                if (-not $routeObservation.health_valid) {
                    $productFailures.Add(
                        "$($policy.name): UI/API liveness failed during route observation"
                    )
                }
                $socketEvidenceValid =
                    $observedSockets.Count -eq
                        $observedConnections.Count
                $socketPairCount = [Math]::Min(
                    $observedSockets.Count,
                    $observedConnections.Count
                )
                for ($socketIndex = 0;
                    $socketIndex -lt $socketPairCount;
                    $socketIndex++) {
                    $connection = $observedConnections[$socketIndex]
                    $socket = $observedSockets[$socketIndex]
                    $expectedAddress = if (
                        [string]$connection.family -eq 'IPv6'
                    ) { $peerV6Text } else { $peerV4Text }
                    $expectedLocal = if (
                        [string]$connection.family -eq 'IPv6'
                    ) {
                        [string]$routeV6.source_address
                    } else {
                        [string]$routeV4.source_address
                    }
                    if ([int]$connection.owning_process -ne
                            $activeClient.Id -or
                        [string]$connection.remote_address -ne
                            $expectedAddress -or
                        [int]$connection.remote_port -ne $PeerTcpPort -or
                        [string]$connection.local_address -ne
                            $expectedLocal -or
                        -not [bool]$socket.pid_matches -or
                        -not [bool]$socket.tuple_current_exact -or
                        -not [bool]$socket.local_address_assigned -or
                        -not [bool]$socket.physical_nonvirtual) {
                        $socketEvidenceValid = $false
                    }
                }
                if (-not $socketEvidenceValid) {
                    $productFailures.Add(
                        "$($policy.name): selected route was not the exact candidate-owned physical socket"
                    )
                }
                if ($observedConnections.Count -gt 0 -and
                    [double]$routeObservation.stable_observation_seconds -lt
                        $StableObservationSeconds) {
                    $productFailures.Add(
                        "$($policy.name): route did not remain stable for " +
                        "$StableObservationSeconds seconds"
                    )
                }

                $observedFamilies = @(
                    $observedConnections.family | Sort-Object -Unique
                )
                $productMatch = $observedConnections.Count -eq 1 -and
                    [string]$observedConnections[0].family -eq
                        $policy.expected_family -and
                    -not [bool]$routeObservation.ambiguous_family_selection -and
                    [int]$routeObservation.
                        wrong_family_observation_count -eq 0 -and
                    $socketEvidenceValid -and
                    [bool]$routeObservation.health_valid -and
                    ($observedConnections.Count -eq 0 -or
                        [double]$routeObservation.stable_observation_seconds -ge
                            $StableObservationSeconds)
                if ($observedConnections.Count -eq 0) {
                    $productFailures.Add(
                        "$($policy.name): no post-restart route was established"
                    )
                } elseif ($observedConnections.Count -ne 1 -or
                    [string]$observedConnections[0].family -ne
                        $policy.expected_family -or
                    [bool]$routeObservation.ambiguous_family_selection -or
                    [int]$routeObservation.
                        wrong_family_observation_count -ne 0) {
                    $productFailures.Add(
                        "$($policy.name): expected $($policy.expected_family), " +
                        "observed $($observedFamilies -join '+')"
                    )
                }

                $donePath = Join-Path $coordination `
                    "$($policy.name)-done.json"
                $completePath = Join-Path $coordination `
                    "peer-$($policy.name)-complete.json"
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i03-done-command/v1'
                    case_id = $caseId
                    run_nonce = $nonce
                    policy = $policy.name
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $expectedHash
                    source_process_id = $currentPeerPid
                    client_process_id = $activeClient.Id
                    route_observed = $observedConnections.Count -gt 0
                    observed_family = if (
                        $observedFamilies.Count -eq 1
                    ) {
                        [string]$observedFamilies[0]
                    } else { $observedFamilies -join '+' }
                    observed_families = $observedFamilies
                    expected_connection_count =
                        $observedConnections.Count
                    observed_connections = $observedConnections
                }) -Path $donePath | Out-Null
                $completeWait = Wait-I03JsonFile -Path $completePath `
                    -StopPath $stopPath -TimeoutSeconds 30
                if ($null -eq $completeWait -or
                    $completeWait.kind -ne 'value') {
                    Stop-I03Fixture -Reason (
                        "Peer did not complete $($policy.name) barrier"
                    )
                }
                $peerComplete = $completeWait.value
                Write-LabJson -Value $peerComplete -Path (
                    Join-Path $evidence `
                        "$($policy.name)-peer-complete.json"
                ) | Out-Null
                $completeFamilies = @(
                    $peerComplete.observed_families |
                        ForEach-Object { [string]$_ } |
                        Sort-Object -Unique
                )
                $peerCompleteExact =
                    [string]$peerComplete.schema -eq
                        'ese.v91.i03-peer-complete/v1' -and
                    [string]$peerComplete.case_id -eq $caseId -and
                    [string]$peerComplete.run_nonce -eq $nonce -and
                    [string]$peerComplete.policy -eq $policy.name -and
                    [string]$peerComplete.candidate_commit -eq
                        $candidate.commit -and
                    [string]$peerComplete.candidate_emule_sha256 -eq
                        $expectedHash -and
                    [int]$peerComplete.source_process_id -eq
                        $currentPeerPid -and
                    [string]$peerComplete.source_process_emule_sha256 -eq
                        $expectedHash -and
                    [string]$peerComplete.source_userhash_sha256 -eq
                        $sourceIdentity -and
                    [bool]$peerComplete.route_observed -eq
                        ($observedConnections.Count -gt 0) -and
                    ($completeFamilies -join ',') -eq
                        ($observedFamilies -join ',') -and
                    @($peerComplete.inbound_connections).Count -eq
                        $observedConnections.Count -and
                    [bool]$peerComplete.api.available -and
                    [bool]$peerComplete.api.isolation_valid
                if (-not $peerCompleteExact) {
                    Stop-I03Fixture -Reason (
                        "$($policy.name) final peer barrier is not exact"
                    )
                }
                foreach ($outbound in $observedConnections) {
                    $inverse = @(
                        $peerComplete.inbound_connections |
                            Where-Object {
                                $expectedPeerLocal = if (
                                    [string]$outbound.family -eq 'IPv4'
                                ) {
                                    $peerLocalV4Text
                                } else {
                                    [string]$outbound.remote_address
                                }
                                $remoteTupleExact =
                                    [string]$_.remote_address -eq
                                        [string]$outbound.local_address -and
                                    [int]$_.remote_port -eq
                                        [int]$outbound.local_port
                                $natTranslated = [string]$outbound.family -eq
                                    'IPv4' -and
                                    $peerV4Text -ne $peerLocalV4Text
                                [string]$_.family -eq
                                    [string]$outbound.family -and
                                [string]$_.local_address -eq
                                    $expectedPeerLocal -and
                                [int]$_.local_port -eq
                                    [int]$outbound.remote_port -and
                                ($natTranslated -or $remoteTupleExact) -and
                                [int]$_.owning_process -eq
                                    $currentPeerPid
                            }
                    )
                    if ($inverse.Count -ne 1) {
                        Stop-I03Fixture -Reason (
                            "$($policy.name) final route lacks a unique " +
                            'correlated peer tuple'
                        )
                    }
                }
                $routeObservation | Add-Member -NotePropertyName `
                    observed_connections -NotePropertyValue `
                    $observedConnections -Force
                $routeObservation | Add-Member -NotePropertyName `
                    observed_families -NotePropertyValue `
                    $observedFamilies -Force
                $routeObservation | Add-Member -NotePropertyName `
                    product_match -NotePropertyValue $productMatch -Force
                $routeObservation | Add-Member -NotePropertyName `
                    ipv4_nat_correlation -NotePropertyValue `
                    ([pscustomobject][ordered]@{
                        nat_mapped =
                            $peerV4Text -ne $peerLocalV4Text
                        peer_observed_ipv4 = @(
                            $peerComplete.inbound_connections |
                                Where-Object family -eq 'IPv4'
                        )
                    }) -Force
                Write-LabJson -Value $routeObservation -Path (
                    Join-Path $evidence `
                        "$($policy.name)-post-restart.json"
                ) | Out-Null
                $caseRecord.post_restart = $routeObservation
                $caseRecord.peer_complete = $peerComplete
                $caseRecord.fixture_valid = $true
                $caseRecord.product_match = $productMatch
            } catch {
                $caseRecord.runtime_error = $_.Exception.Message
                throw
            } finally {
                $clientStopped = $true
                # Mark the server stop as expected before the candidate closes
                # its control-plane socket, otherwise EOF can be misclassified
                # as a fixture-server failure.
                if ($null -ne $activeServer) {
                    $caseServerStop =
                        Stop-I03ControlledEd2kServer `
                            -Server $activeServer
                    if (-not $caseServerStop.stopped -or
                        $caseServerStop.error) {
                        $allControlServersStopped = $false
                        $cleanupFailures.Add(
                            "$($policy.name) controlled server cleanup failed: " +
                            [string]$caseServerStop.error
                        )
                    }
                    if ($null -eq $caseServerStop.evidence -or
                        -not [bool]$caseServerStop.evidence.logged_in -or
                        -not [bool]$caseServerStop.evidence.reply_sent -or
                        [string]$caseServerStop.evidence.error) {
                        $cleanupFailures.Add(
                            "$($policy.name) controlled server evidence is incomplete"
                        )
                    }
                }
                if ($null -ne $activeClient) {
                    $clientStop = Stop-I03OwnedProcess `
                        -Process $activeClient -ExpectedPath $activeClientExe
                    $clientStopped = [bool]$clientStop.stopped
                    if (-not $clientStopped) {
                        $allClientsStopped = $false
                        $cleanupFailures.Add(
                            "$($policy.name) client process remains running"
                        )
                    }
                }
                $clientHashAfter = if ($caseExe -and
                    (Test-Path -LiteralPath $caseExe -PathType Leaf)) {
                    Get-LabSha256 -Path $caseExe
                } else { '' }
                if ($clientHashAfter -and
                    $clientHashAfter -ne $expectedHash) {
                    $cleanupFailures.Add(
                        "$($policy.name) prepared executable changed"
                    )
                }
                if ($caseExe) {
                    $preparedBinaries.Add([pscustomobject][ordered]@{
                        policy = $policy.name
                        path = $caseExe
                        expected_sha256 = $expectedHash
                        after_sha256 = $clientHashAfter
                        unchanged = $clientHashAfter -eq $expectedHash
                    })
                }
                $caseRecord.cleanup = [ordered]@{
                    client_stopped = $clientStopped
                    client_executable_sha256_after = $clientHashAfter
                    controlled_server_stopped = if (
                        $null -eq $caseServerStop
                    ) { $true } else { [bool]$caseServerStop.stopped }
                    controlled_server_evidence = if (
                        $null -eq $caseServerStop
                    ) { $null } else { $caseServerStop.evidence }
                }
                $caseRecord.finished_at_utc =
                    [DateTime]::UtcNow.ToString('o')
                if (-not $caseRecorded) {
                    $caseResults.Add([pscustomobject]$caseRecord)
                    $caseRecorded = $true
                }
                $activeClient = $null
                $activeClientExe = ''
                $activeServer = $null
            }
            if ($productFailures.Count -gt $failureCountBefore) {
                $caseRecord.product_match = $false
            }
        }

        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i03-stop-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            action = 'stop-owned-processes'
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            expected_last_source_process_id = $currentPeerPid
        }) -Path $stopPath | Out-Null
        $peerStopWritten = $true
        $peerResultWait = Wait-I03JsonFile -Path $peerResultPath `
            -TimeoutSeconds 30
        if ($null -eq $peerResultWait -or
            $peerResultWait.kind -ne 'value') {
            Stop-I03Fixture `
                -Reason 'Peer did not publish its final cleanup result'
        }
        $peerResult = $peerResultWait.value
    } catch {
        $runtimeFailure = $_.Exception.Message
    } finally {
        if ($null -ne $baselineProbeV4) {
            try { $baselineProbeV4.client.Dispose() } catch {}
            $baselineProbeV4 = $null
        }
        if ($null -ne $baselineProbeV6) {
            try { $baselineProbeV6.client.Dispose() } catch {}
            $baselineProbeV6 = $null
        }
        if ($null -ne $activeServer) {
            $serverStop = Stop-I03ControlledEd2kServer `
                -Server $activeServer
            if (-not $serverStop.stopped -or $serverStop.error) {
                $allControlServersStopped = $false
                $cleanupFailures.Add(
                    'active controlled server remained after outer cleanup'
                )
            }
            $activeServer = $null
        }
        if ($null -ne $activeClient) {
            $clientStop = Stop-I03OwnedProcess -Process $activeClient `
                -ExpectedPath $activeClientExe
            if (-not $clientStop.stopped) {
                $allClientsStopped = $false
                $cleanupFailures.Add(
                    'active client process remained after outer cleanup'
                )
            }
            $activeClient = $null
        }
        if (-not $peerStopWritten) {
            try {
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i03-stop-command/v1'
                    case_id = $caseId
                    run_nonce = $nonce
                    action = 'stop-owned-processes'
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $expectedHash
                    expected_last_source_process_id = $currentPeerPid
                }) -Path $stopPath | Out-Null
                $peerStopWritten = $true
            } catch {
                $cleanupFailures.Add(
                    "Could not publish peer stop: $($_.Exception.Message)"
                )
            }
        }
        if ($null -eq $peerResult -and $null -ne $peerReady) {
            try {
                $latePeerResult = Wait-I03JsonFile `
                    -Path $peerResultPath -TimeoutSeconds 30
                if ($null -ne $latePeerResult -and
                    $latePeerResult.kind -eq 'value') {
                    $peerResult = $latePeerResult.value
                }
            } catch {
                $cleanupFailures.Add(
                    "Peer result wait failed: $($_.Exception.Message)"
                )
            }
        }
        if ($null -ne $peerResult) {
            try {
                Write-LabJson -Value $peerResult -Path (
                    Join-Path $evidence 'peer-result.json'
                ) | Out-Null
            } catch {
                $cleanupFailures.Add(
                    "Peer result copy failed: $($_.Exception.Message)"
                )
            }
        }
        try {
            $candidateAfter = Get-LabCandidateInfo `
                -PackagePath $PackagePath -ExpectedCommit $Commit
            $packageIdentityAfter =
                Get-I03PackageIdentity -PackagePath $candidate.package_path
            Write-LabJson -Value $packageIdentityAfter -Path (
                Join-Path $evidence 'package-manifest-after.json'
            ) | Out-Null
            $packageManifestUnchanged =
                $null -ne $packageIdentityBefore -and
                $packageIdentityAfter.manifest_sha256 -eq
                    $packageIdentityBefore.manifest_sha256 -and
                $packageIdentityAfter.file_count -eq
                    $packageIdentityBefore.file_count -and
                $packageIdentityAfter.total_bytes -eq
                    $packageIdentityBefore.total_bytes
            $candidateUnchanged =
                $candidateAfter.emule_sha256 -eq $expectedHash -and
                $candidateAfter.ese_server_sha256 -eq
                    $candidate.ese_server_sha256 -and
                $candidateAfter.build_info_sha256 -eq
                    $candidate.build_info_sha256 -and
                $packageManifestUnchanged
        } catch {
            $cleanupFailures.Add(
                "Candidate revalidation failed: $($_.Exception.Message)"
            )
        }
        if (-not $candidateUnchanged) {
            $cleanupFailures.Add(
                'Candidate package changed during V91-I03'
            )
        }
    }

    if ($null -ne $peerResult) {
        try {
            $peerCleanupExact =
                [string]$peerResult.schema -eq
                    'ese.v91.i03-peer-result/v1' -and
                [string]$peerResult.case_id -eq $caseId -and
                [string]$peerResult.run_nonce -eq $nonce -and
                [string]$peerResult.candidate_commit -eq
                    $candidate.commit -and
                [string]$peerResult.candidate_emule_sha256 -eq
                    $expectedHash -and
                [string]$peerResult.source_userhash_sha256 -eq
                    $sourceIdentity -and
                [bool]$peerResult.cleanup.source_process_stopped -and
                [bool]$peerResult.cleanup.candidate_package_unchanged -and
                [bool]$peerResult.cleanup.
                    extracted_package_manifest_unchanged -and
                [bool]$peerResult.cleanup.prepared_executable_unchanged -and
                @($peerResult.cleanup.failures).Count -eq 0
            $peerResultExact = $peerCleanupExact -and
                [string]$peerResult.status -eq 'COMPLETE' -and
                [int]$peerResult.barriers_completed -eq 2 -and
                [int]$peerResult.expected_barriers -eq 2
        } catch {
            $peerResultExact = $false
            $peerCleanupExact = $false
            $cleanupFailures.Add(
                "Peer result validation failed: $($_.Exception.Message)"
            )
        }
    }
    if (-not $peerResultExact -and -not (
        [bool]$productAdjudication.runtime_failure -and
        $peerCleanupExact
    )) {
        Add-I03BlockedReason `
            -Reason 'Peer completion/cleanup evidence is not exact'
    }
    if ($null -ne $runtimeFailure -and
        -not $runtimeFailure.StartsWith('I03_FIXTURE_BLOCKED:') -and
        -not $runtimeFailure.StartsWith('I03_PRODUCT_FAILURE:')) {
        Add-I03BlockedReason `
            -Reason "Harness/runtime error: $runtimeFailure"
    }
    if ($cleanupFailures.Count -gt 0) {
        Add-I03BlockedReason `
            -Reason 'Transactional owned-process/server cleanup was incomplete'
    }
    $caseFixtureValid = $caseResults.Count -eq 2 -and
        @($caseResults | Where-Object {
            -not [bool]$_.fixture_valid
        }).Count -eq 0
    $productRuntimeFixtureValid =
        [bool]$productAdjudication.runtime_failure -and
        $caseResults.Count -ge 1 -and
        $null -ne $caseResults[$caseResults.Count - 1].client -and
        $null -ne $caseResults[$caseResults.Count - 1].
            controlled_server -and
        $null -ne $caseResults[$caseResults.Count - 1].
            dualstack_rearm
    if (-not $caseFixtureValid -and
        -not $productRuntimeFixtureValid -and
        $blockedReasons.Count -eq 0) {
        Add-I03BlockedReason `
            -Reason 'Both Auto and Preferred fixtures did not complete'
    }
    $preparedBinariesAllValid =
        $preparedBinaries.Count -ge 1 -and
        @($preparedBinaries | Where-Object {
            -not [bool]$_.unchanged
        }).Count -eq 0
    $preparedBinariesValid = $preparedBinariesAllValid -and (
        $preparedBinaries.Count -eq 2 -or
        $productRuntimeFixtureValid
    )
    if (-not $preparedBinariesValid) {
        Add-I03BlockedReason `
            -Reason 'Prepared candidate binary revalidation is incomplete'
    }
    $cleanupComplete = $allClientsStopped -and
        $allControlServersStopped -and
        ($peerResultExact -or
            ($productRuntimeFixtureValid -and $peerCleanupExact)) -and
        $candidateUnchanged -and $preparedBinariesValid -and
        $cleanupFailures.Count -eq 0
    $cleanup = [ordered]@{
        schema = 'ese.v91.i03-cleanup/v1'
        captured_at_utc = Get-LabUtcTimestamp
        all_candidate_clients_stopped = $allClientsStopped
        all_controlled_servers_stopped = $allControlServersStopped
        peer_stop_command_written = $peerStopWritten
        peer_cleanup_exact = $peerCleanupExact
        peer_full_completion_exact = $peerResultExact
        candidate_package_unchanged = $candidateUnchanged
        extracted_package_manifest_unchanged =
            $packageManifestUnchanged
        prepared_binaries = @($preparedBinaries)
        adapters_modified = $false
        routes_modified = $false
        dns_modified = $false
        hosts_modified = $false
        firewall_modified = $false
        retained_by_design = @(
            'coordinator OutputRoot profiles',
            'peer OutputRoot profile',
            'fixture files',
            'evidence',
            'nonce-scoped coordination records'
        )
        complete = $cleanupComplete
        failures = @($cleanupFailures)
    }
    Write-LabJson -Value $cleanup -Path $cleanupPath | Out-Null

    $clockValid = $null -ne $clockEvidence -and
        [bool]$clockEvidence.certified_within_1000_ms
    $adjudicationFixtureValid = $peerReadyExact -and $topologyValid -and
        $null -ne $baselineEvidence -and $clockValid -and
        ($caseFixtureValid -or $productRuntimeFixtureValid) -and
        ($peerResultExact -or
            ($productRuntimeFixtureValid -and $peerCleanupExact)) -and
        $candidateUnchanged -and $cleanupComplete
    $fullFixtureValid = $adjudicationFixtureValid -and
        $caseFixtureValid -and $peerResultExact
    $formalStatus = if (-not $adjudicationFixtureValid -or
        $blockedReasons.Count -gt 0) {
        'BLOCKED'
    } elseif ($productFailures.Count -gt 0) {
        'FAIL'
    } elseif ($fullFixtureValid) {
        'PASS'
    } else { 'BLOCKED' }
    $controlledLoginValidated = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            $null -eq $_.controlled_server -or
            -not [bool]$_.controlled_server.login.connected
        }).Count -eq 0
    $literalIPv4SourceValidated = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            -not [bool]$_.literal_ipv4_source_link_validated
        }).Count -eq 0
    $dnsIsolationConfigured = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            $null -eq $_.client -or
            [bool]$_.client.isolation_controls.update_notify -or
            [bool]$_.client.isolation_controls.serverlist_auto_update -or
            [bool]$_.client.isolation_controls.add_servers_from_server -or
            [bool]$_.client.isolation_controls.add_servers_from_client -or
            -not [bool]$_.client.isolation_controls.
                literal_control_server_address
        }).Count -eq 0
    $helloLearnedInCompletedCases = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            $null -eq $_.prewarm -or
            -not [bool]$_.prewarm.hello.
                learned_public_ipv6_via_hello
        }).Count -eq 0
    $rearmProvedInCompletedCases = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            $null -eq $_.dualstack_rearm -or
            -not [bool]$_.dualstack_rearm.peer.
                runtime_dualstack_rearmed
        }).Count -eq 0
    $backlogProvedInCompletedCases = $caseResults.Count -gt 0 -and
        @($caseResults | Where-Object {
            $null -eq $_.backlog_before_restart -or
            -not [bool]$_.backlog_before_restart.valid
        }).Count -eq 0
    $finishedAt = [DateTime]::UtcNow
    $summary = [ordered]@{
        schema = 'ese.v91.i03-route-selection/v1'
        case_id = $caseId
        formal_status = $formalStatus
        candidate = [ordered]@{
            commit = $candidate.commit
            version = $candidate.version
            expected_emule_sha256 = $expectedHash
            package_emule_sha256_before = $candidate.emule_sha256
            package_emule_sha256_after = if ($null -eq $candidateAfter) {
                ''
            } else { $candidateAfter.emule_sha256 }
            ese_server_sha256 = $candidate.ese_server_sha256
            build_info_sha256 = $candidate.build_info_sha256
            extracted_package_manifest_before = if (
                $null -eq $packageIdentityBefore
            ) { $null } else {
                [ordered]@{
                    sha256 = $packageIdentityBefore.manifest_sha256
                    file_count = $packageIdentityBefore.file_count
                    total_bytes = $packageIdentityBefore.total_bytes
                }
            }
            extracted_package_manifest_after = if (
                $null -eq $packageIdentityAfter
            ) { $null } else {
                [ordered]@{
                    sha256 = $packageIdentityAfter.manifest_sha256
                    file_count = $packageIdentityAfter.file_count
                    total_bytes = $packageIdentityAfter.total_bytes
                }
            }
            extracted_package_manifest_unchanged =
                $packageManifestUnchanged
            unchanged = $candidateUnchanged
            prepared_binaries = @($preparedBinaries)
        }
        run = [ordered]@{
            nonce = $nonce
            started_at_utc = $startedAt.ToString('o')
            finished_at_utc = $finishedAt.ToString('o')
            elapsed_seconds = [Math]::Round(
                ($finishedAt - $startedAt).TotalSeconds, 3
            )
            coordination_directory_name =
                Split-Path -Leaf $coordination
        }
        topology = [ordered]@{
            required = 'T1/T2 direct native'
            observed_class = $topologyClass
            proved = $topologyValid
            t1_proved = $topologyT1
            t2_proved = $topologyT2
            same_ipv4_physical_prefix = $sameIPv4PhysicalPrefix
            same_ipv6_physical_prefix = $sameIPv6PhysicalPrefix
            local_machine_id_sha256 = if (
                Get-Variable -Name localMachineId `
                    -ErrorAction SilentlyContinue
            ) { $localMachineId } else { '' }
            peer_machine_id_sha256 = if ($null -eq $peerReady) {
                ''
            } else { [string]$peerReady.peer.machine_id_sha256 }
            ipv4_route = $routeV4
            ipv6_route = $routeV6
            clocks = $clockEvidence
        }
        isolation = [ordered]@{
            netlab_enabled = $false
            kad_enabled = $false
            third_party_ed2k_servers = $false
            controlled_ed2k_scheduler = [ordered]@{
                type = 'same-host physical-IP minimal server'
                address = if ($null -eq $routeV4) {
                    ''
                } else { [string]$routeV4.source_address }
                OP_LOGINREQUEST_validated =
                    $controlledLoginValidated
                OP_IDCHANGE_high_id = [uint32]0x01000001
                static_only = $true
            }
            dns_dependency = $false
            dns_third_party_controls_configured =
                $dnsIsolationConfigured
            web_allowed_ips = '127.0.0.1'
            firewall_modified = $false
            adapters_modified = $false
            routes_modified = $false
            hosts_modified = $false
        }
        fixture = [ordered]@{
            valid_for_adjudication = $adjudicationFixtureValid
            full_two_policy_fixture_valid = $fullFixtureValid
            exact_peer_ready = $peerReadyExact
            exact_peer_result = $peerResultExact
            source_userhash_sha256 = $sourceIdentity
            same_peer_identity_across_restarts =
                $peerResultExact -and
                [string]$peerResult.source_userhash_sha256 -eq
                    $sourceIdentity
            literal_ipv4_source_only =
                $literalIPv4SourceValidated
            public_ipv6_learned_by_highid_hello =
                $helloLearnedInCompletedCases
            current_pid_dualstack_rearm_per_case =
                $rearmProvedInCompletedCases
            incomplete_transfer_backlog_before_restart =
                $backlogProvedInCompletedCases
            baseline = $baselineEvidence
        }
        policies = @($caseResults)
        product_failures = @($productFailures)
        blocked_reasons = @(
            $blockedReasons | Select-Object -Unique
        )
        runtime_error = $runtimeFailure
        cleanup = $cleanup
        evidence = [ordered]@{
            run = 'evidence\run.json'
            preflight = 'evidence\preflight.json'
            peer_ready = 'evidence\peer-ready.json'
            baseline = 'evidence\baseline.json'
            peer_result = 'evidence\peer-result.json'
            cleanup = 'evidence\cleanup.json'
            package_manifest_before =
                'evidence\package-manifest-before.json'
            package_manifest_after =
                'evidence\package-manifest-after.json'
            manual_peer_command =
                'evidence\MANUAL-PEER-COMMAND.txt'
            auto = [ordered]@{
                startup = 'evidence\auto-client-startup.json'
                rearm = 'evidence\auto-peer-rearm-ack.json'
                prewarm = 'evidence\auto-prewarm.json'
                backlog_before_restart =
                    'evidence\auto-backlog-before-restart.json'
                post_restart =
                    'evidence\auto-post-restart.json'
                peer_complete =
                    'evidence\auto-peer-complete.json'
                controlled_server =
                    'evidence\auto-controlled-ed2k-server.json'
            }
            preferred = [ordered]@{
                startup =
                    'evidence\preferred-client-startup.json'
                rearm =
                    'evidence\preferred-peer-rearm-ack.json'
                prewarm = 'evidence\preferred-prewarm.json'
                backlog_before_restart =
                    'evidence\preferred-backlog-before-restart.json'
                post_restart =
                    'evidence\preferred-post-restart.json'
                peer_complete =
                    'evidence\preferred-peer-complete.json'
                controlled_server =
                    'evidence\preferred-controlled-ed2k-server.json'
            }
        }
    }
    Write-LabJson -Value $summary -Path $summaryPath | Out-Null

    if ($formalStatus -eq 'FAIL') {
        throw (
            'V91-I03 FAIL: ' +
            (@($productFailures) -join '; ') +
            ". Evidence: $summaryPath"
        )
    }
    if ($formalStatus -eq 'BLOCKED') {
        throw (
            'V91-I03 BLOCKED: ' +
            (@($summary.blocked_reasons) -join '; ') +
            ". Evidence: $summaryPath"
        )
    }
    Write-Host "V91-I03 PASS on exact candidate/$topologyClass`: $output" `
        -ForegroundColor Green
}

if ($Role -eq 'Peer') {
    Invoke-I03PeerRole
} else {
    Invoke-I03CoordinatorRole
}
