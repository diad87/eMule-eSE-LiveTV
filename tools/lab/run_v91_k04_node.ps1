[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$request = Get-Content -LiteralPath $JobRequestPath -Raw |
    ConvertFrom-Json
$jobRoot = Split-Path -Parent $JobRequestPath
$jobId = Split-Path -Leaf $jobRoot
$dataRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$resultPath = Join-Path $jobRoot 'k04-result.json'
$nodePath = Join-Path $jobRoot 'node'
$evidencePath = Join-Path $jobRoot 'evidence'
$process = $null
$addressCreated = $false
$ruleNames = [Collections.Generic.List[string]]::new()
$hostsMarker = "# eSE-V91-K04-$jobId"
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsLineAdded = $false
$finalStatus = 'ERROR'
$failure = ''
$pktmonStarted = $false
$pktmonEtl = Join-Path $evidencePath 'kad6-capture.etl'
$pktmonPcap = Join-Path $evidencePath 'kad6-capture.pcapng'
$pktmonText = Join-Path $evidencePath 'kad6-capture.txt'
$pktmonLog = Join-Path $evidencePath 'pktmon.log'
$progressPath = Join-Path $jobRoot 'progress.json'
$postResult = $null
$secondaryProcess = $null
$secondaryAddressCreated = $false
$secondaryNodePath = Join-Path $jobRoot 'node-secondary'
$guardProcess = $null
$guardAddressCreated = $false
$guardNodePath = Join-Path $jobRoot 'node-guard'
$i01ExternalRoot = ''

function Write-K04Json {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $temporary = $Path + '.new'
    $Value | ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Write-K04Progress {
    param(
        [Parameter(Mandatory = $true)][string]$Phase,
        [AllowNull()]$Detail = $null
    )
    Write-K04Json -Path $progressPath -Value ([ordered]@{
        schema = 'ese.v91.k04-progress/v1'
        phase = $Phase
        detail = $Detail
        updated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    })
}

function Set-K04IniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key,
        [AllowEmptyString()][string]$Value
    )
    $lines = [Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        foreach ($line in Get-Content -LiteralPath $Path) {
            $lines.Add([string]$line)
        }
    }
    $sectionStart = -1
    $sectionEnd = $lines.Count
    for ($i = 0; $i -lt $lines.Count; ++$i) {
        if ($lines[$i] -match '^\s*\[(.+)\]\s*$') {
            if ($sectionStart -ge 0) {
                $sectionEnd = $i
                break
            }
            if ($Matches[1] -ieq $Section) {
                $sectionStart = $i
            }
        }
    }
    if ($sectionStart -lt 0) {
        if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -ne '') {
            $lines.Add('')
        }
        $lines.Add("[$Section]")
        $lines.Add("$Key=$Value")
    } else {
        $found = $false
        for ($i = $sectionStart + 1; $i -lt $sectionEnd; ++$i) {
            if ($lines[$i] -match ('^\s*' + [regex]::Escape($Key) + '\s*=')) {
                $lines[$i] = "$Key=$Value"
                $found = $true
                break
            }
        }
        if (-not $found) {
            $lines.Insert($sectionEnd, "$Key=$Value")
        }
    }
    [IO.File]::WriteAllLines(
        $Path, $lines, (New-Object Text.UTF8Encoding($false)))
}

function Get-K04Md5 {
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

function Get-K04Status {
    param([Parameter(Mandatory = $true)][int]$Port)
    Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/status" `
        -TimeoutSec 2
}

function Wait-K04Api {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutSeconds = 60
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 300
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "El candidato termino con codigo $($Process.ExitCode)."
        }
        try {
            return Get-K04Status -Port $Port
        } catch {}
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "La API $Port no quedo disponible."
}

function Start-K04Kad {
    param([Parameter(Mandatory = $true)][int]$Port)
    # Starting/stopping Kad is marshalled synchronously onto eMule's GUI
    # thread.  During that transition the native WebServer may close the
    # control connection after accepting it.  The observable state, not the
    # HTTP response body, is the authoritative acknowledgement.
    try {
        Invoke-RestMethod -Uri (
            "http://127.0.0.1:$Port/api/network/connect?ed2k=0&kad=1"
        ) -TimeoutSec 10 | Out-Null
    } catch {}
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 200
        try {
            $status = Get-K04Status -Port $Port
            if ([bool]$status.kad6_running) {
                return $status
            }
        } catch {}
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'Kad6 no arranco.'
}

function Stop-K04Kad {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session
    )
    try {
        Invoke-WebRequest -UseBasicParsing -Uri (
            "http://127.0.0.1:$Port/?ses=$Session&w=kad&c=disconnect"
        ) -TimeoutSec 10 | Out-Null
    } catch {}
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250
        try {
            $status = Get-K04Status -Port $Port
            if (-not [bool]$status.kad6_running) {
                return
            }
        } catch {}
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'Kad6 no se detuvo para persistir la tabla.'
}

function Get-K04WebSession {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Password
    )
    $encoded = [Uri]::EscapeDataString($Password)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri (
                "http://127.0.0.1:$Port/?w=password&p=$encoded"
            ) -TimeoutSec 10
            $match = [regex]::Match($response.Content, 'ses=(\d+)')
            if ($match.Success) {
                return $match.Groups[1].Value
            }
        } catch {}
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'No se pudo obtener sesion WebServer administrativa.'
}

function Invoke-K04Bootstrap {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$PeerPort
    )
    $uri = (
        "http://127.0.0.1:$Port/?ses=$Session&w=kad&bootstrap=1" +
        "&ip=$([Uri]::EscapeDataString($HostName))&port=$PeerPort"
    )
    Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 10 |
        Out-Null
}

function Stop-K04Process {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [int]$Port = 0,
        [string]$Session = ''
    )
    if ($null -eq $Process) { return }
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            if ($Port -gt 0 -and -not [string]::IsNullOrWhiteSpace($Session)) {
                try {
                    Invoke-WebRequest -UseBasicParsing -Uri (
                        "http://127.0.0.1:$Port/?ses=$Session&w=close"
                    ) -TimeoutSec 10 | Out-Null
                } catch {}
                if ($Process.WaitForExit(30000)) {
                    return
                }
            }
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            $Process.WaitForExit(10000) | Out-Null
        }
    } catch {}
}

function Remove-K04HostsLine {
    if (-not $script:hostsLineAdded) { return }
    $lines = @(Get-Content -LiteralPath $script:hostsPath |
        Where-Object { $_ -cnotmatch [regex]::Escape($script:hostsMarker) })
    [IO.File]::WriteAllLines(
        $script:hostsPath, $lines,
        (New-Object Text.ASCIIEncoding))
    $script:hostsLineAdded = $false
}

function Get-I02SocketEvidence {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$PeerIPv6,
        [string]$PeerIPv4 = '',
        [Parameter(Mandatory = $true)][int]$LocalTcpPort,
        [Parameter(Mandatory = $true)][int]$PeerTcpPort,
        [Parameter(Mandatory = $true)][string]$Role
    )
    $connections = @(
        Get-NetTCPConnection -OwningProcess $ProcessId `
            -State Established -ErrorAction SilentlyContinue
    )
    $peer = @($connections | Where-Object {
        $remote = ([string]$_.RemoteAddress).Split('%')[0]
        $remote -ieq $PeerIPv6 -and (
            ($Role -ceq 'source' -and [int]$_.LocalPort -eq $LocalTcpPort) -or
            ($Role -ceq 'viewer' -and [int]$_.RemotePort -eq $PeerTcpPort)
        )
    })
    $unexpectedV4 = @($connections | Where-Object {
        $remote = [string]$_.RemoteAddress
        $remote -notmatch ':' -and $remote -notmatch '^127\.' -and
        ([string]::IsNullOrWhiteSpace($PeerIPv4) -or
            $remote -ine $PeerIPv4)
    })
    $peerV4 = @($connections | Where-Object {
        -not [string]::IsNullOrWhiteSpace($PeerIPv4) -and
        [string]$_.RemoteAddress -ieq $PeerIPv4 -and (
            ($Role -ceq 'source' -and [int]$_.LocalPort -eq $LocalTcpPort) -or
            ($Role -ceq 'viewer' -and [int]$_.RemotePort -eq $PeerTcpPort)
        )
    })
    [ordered]@{
        peer_ipv6 = $peer.Count
        peer_ipv4 = $peerV4.Count
        unexpected_ipv4 = $unexpectedV4.Count
        peer_ipv6_tuples = @($peer | ForEach-Object {
            [ordered]@{
                local_address = [string]$_.LocalAddress
                local_port = [int]$_.LocalPort
                remote_address = [string]$_.RemoteAddress
                remote_port = [int]$_.RemotePort
                owning_process = [int]$_.OwningProcess
            }
        })
        peer_ipv4_tuples = @($peerV4 | ForEach-Object {
            [ordered]@{
                local_address = [string]$_.LocalAddress
                local_port = [int]$_.LocalPort
                remote_address = [string]$_.RemoteAddress
                remote_port = [int]$_.RemotePort
                owning_process = [int]$_.OwningProcess
            }
        })
    }
}

function Get-O01RouteEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$PeerIPv6,
        [Parameter(Mandatory = $true)][string]$PeerIPv4,
        [Parameter(Mandatory = $true)][int]$ExpectedInterfaceIndex
    )
    $adapter = Get-NetAdapter -InterfaceIndex $ExpectedInterfaceIndex `
        -ErrorAction Stop
    $result = [ordered]@{
        interface_index = $ExpectedInterfaceIndex
        interface_alias = [string]$adapter.InterfaceAlias
        interface_guid = [string]$adapter.InterfaceGuid
    }
    foreach ($family in @(
        [ordered]@{ name = 'ipv6'; remote = $PeerIPv6 },
        [ordered]@{ name = 'ipv4'; remote = $PeerIPv4 }
    )) {
        $selection = @(Find-NetRoute -RemoteIPAddress $family.remote `
            -ErrorAction Stop)
        $route = @($selection | Where-Object {
            $null -ne $_.PSObject.Properties['DestinationPrefix']
        }) | Select-Object -First 1
        $source = @($selection | Where-Object {
            $null -ne $_.PSObject.Properties['IPAddress']
        }) | Select-Object -First 1
        if ($null -eq $route -or $null -eq $source -or
            [int]$route.InterfaceIndex -ne $ExpectedInterfaceIndex) {
            throw "O01 route $($family.name) did not use the physical NIC."
        }
        $result[$family.name] = [ordered]@{
            remote_address = [string]$family.remote
            source_address = [string]$source.IPAddress
            destination_prefix = [string]$route.DestinationPrefix
            next_hop = [string]$route.NextHop
            interface_index = [int]$route.InterfaceIndex
            interface_metric = [int]$route.InterfaceMetric
            route_metric = [int]$route.RouteMetric
        }
    }
    return $result
}

function Get-I02HlsEvidence {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$StreamKey
    )
    $playlistOk = $false
    $segmentOk = $false
    $segmentBytes = 0L
    $playlistPath = Join-Path $env:TEMP 'eMule_RTMP\stream.m3u8'
    if ($Role -ceq 'viewer') {
        $playlistPath = Join-Path $env:TEMP (
            "eMule_RTMP\$StreamKey\stream.m3u8")
    }
    try {
        $playlistText = Get-Content -LiteralPath $playlistPath -Raw `
            -ErrorAction Stop
        $playlistOk = $playlistText -match '#EXTM3U'
        $segment = [regex]::Match(
            $playlistText, '(?m)^([^#\r\n]+\.ts)\s*$')
        if ($segment.Success) {
            $segmentPath = Join-Path (Split-Path -Parent $playlistPath) `
                $segment.Groups[1].Value
            $segmentBytes = [Int64](
                Get-Item -LiteralPath $segmentPath -ErrorAction Stop).Length
            $segmentOk = $segmentBytes -gt 0
        }
    } catch {}
    [ordered]@{
        playlist_ok = $playlistOk
        segment_ok = $segmentOk
        segment_bytes = $segmentBytes
    }
}

function Invoke-K01DirectJoin {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$PeerIPv6,
        [Parameter(Mandatory = $true)][int]$PeerTcpPort,
        [Parameter(Mandatory = $true)][string]$Title
    )
    $join = Invoke-RestMethod -Uri (
        "http://127.0.0.1:$Port/api/live/direct_join" +
        "?key=$Key&ip=$([Uri]::EscapeDataString($PeerIPv6))" +
        "&port=$PeerTcpPort&title=$([Uri]::EscapeDataString($Title))"
    ) -TimeoutSec 15
    if (-not [bool]$join.success -or -not [bool]$join.dialed) {
        throw "No se pudo iniciar direct_join hacia [$PeerIPv6]:$PeerTcpPort."
    }
}

function Wait-K01Peers {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][object[]]$Targets,
        [int]$TimeoutSeconds = 120
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        foreach ($target in $Targets) {
            try {
                Invoke-K01DirectJoin -Port $Port `
                    -Key ([string]$target.key) `
                    -PeerIPv6 ([string]$target.ipv6) `
                    -PeerTcpPort ([int]$target.port) `
                    -Title ([string]$target.title)
            } catch {}
        }
        Start-Sleep -Seconds 2
        try {
            $peers = Invoke-RestMethod -Uri (
                "http://127.0.0.1:$Port/api/live/privacy/peers"
            ) -TimeoutSec 5
            if ([int]$peers.authenticatedTunnelCapable -ge 2) {
                return $peers
            }
        } catch {}
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "El nodo Web $Port no obtuvo dos peers eSE autenticables."
}

function Wait-K01PeerAddress {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$PeerIPv6,
        [int]$MinimumAuthenticated = 1,
        [int]$TimeoutSeconds = 60
    )
    $expected = [Net.IPAddress]::Parse($PeerIPv6).ToString()
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 1
        try {
            $peers = Invoke-RestMethod -Uri (
                "http://127.0.0.1:$Port/api/live/privacy/peers"
            ) -TimeoutSec 5
            $matching = @($peers.peers | Where-Object {
                [bool]$_.authReady -and
                [Net.IPAddress]::Parse([string]$_.address).ToString() -ceq
                    $expected
            })
            if ($matching.Count -gt 0 -and
                [int]$peers.authenticatedTunnelCapable -ge
                    $MinimumAuthenticated) {
                return $peers
            }
        } catch {}
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "El nodo Web $Port no autentico el peer [$PeerIPv6]."
}

function New-K01Circuit {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutSeconds = 150
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastReason = 'not_started'
    do {
        $build = $null
        try {
            $build = Invoke-RestMethod -Uri (
                "http://127.0.0.1:$Port/api/live/privacy/test_circuit?hops=2"
            ) -TimeoutSec 10
        } catch {
            $lastReason = $_.Exception.Message
        }
        if ($null -eq $build -or -not [bool]$build.ok) {
            if ($null -ne $build) { $lastReason = [string]$build.reason }
            Start-Sleep -Seconds 1
            continue
        }
        $circuitId = ([string]$build.circuit_id).ToUpperInvariant()
        $retryBuild = $false
        do {
            Start-Sleep -Seconds 1
            $snapshot = Invoke-RestMethod -Uri (
                "http://127.0.0.1:$Port/api/live/privacy/circuits"
            ) -TimeoutSec 5
            Write-K04Json -Path (
                Join-Path $script:jobRoot 'k01-circuit-last.json') `
                -Value $snapshot
            $selected = @($snapshot.circuits | Where-Object {
                ([string]$_.circ_id).ToUpperInvariant() -ceq $circuitId
            })
            Write-K04Progress -Phase 'k01_circuit_handshake' `
                -Detail ([ordered]@{
                    port = $Port
                    circuit_id = $circuitId
                    selected = $selected
                })
            $active = @($selected | Where-Object {
                [string]$_.role -ceq 'Originator' -and
                [string]$_.state -ceq 'Active' -and
                [int]$_.hop_count -ge 2 -and
                [bool]$_.auth_ok
            })
            if ($active.Count -gt 0) {
                return [ordered]@{
                    build = $build
                    active = $active[0]
                    snapshot = $snapshot
                }
            }
            if ($selected.Count -gt 0 -and
                [string]$selected[0].state -ceq 'Destroyed') {
                $lastReason = [string]$selected[0].abort_reason
                $retryBuild = $true
                break
            }
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        if ($retryBuild) { Start-Sleep -Seconds 1 }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw (
        "El circuito K01 de $Port no llego a Active autenticado con 2 hops: " +
        $lastReason)
}

function Get-K01Hardening {
    param([Parameter(Mandatory = $true)][int]$Port)
    Invoke-RestMethod -Uri (
        "http://127.0.0.1:$Port/api/live/privacy/kad6/hardening"
    ) -TimeoutSec 5
}

function Get-I08ByteHash {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Invoke-I08EchoFixture {
    param(
        [Parameter(Mandatory = $true)][string]$LocalIPv6,
        [Parameter(Mandatory = $true)][string]$PeerIPv6,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][scriptblock]$SignalReady,
        [int]$TimeoutSeconds = 120
    )
    $localAddress = [Net.IPAddress]::Parse($LocalIPv6)
    $peerAddress = [Net.IPAddress]::Parse($PeerIPv6)
    if ($localAddress.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetworkV6 -or
        $peerAddress.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetworkV6) {
        throw 'I08 requiere literales IPv6 nativos.'
    }
    $listener = [Net.Sockets.TcpListener]::new($localAddress, $TcpPort)
    $udp = [Net.Sockets.UdpClient]::new(
        [Net.IPEndPoint]::new($localAddress, $UdpPort))
    $tcpClient = $null
    try {
        $listener.Start(1)
        $accept = $listener.BeginAcceptTcpClient($null, $null)
        $udpRemote = [Net.IPEndPoint]::new([Net.IPAddress]::IPv6Any, 0)
        $receive = $udp.BeginReceive($null, $null)
        & $SignalReady

        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            if ($accept.IsCompleted) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        if (-not $accept.IsCompleted) {
            throw 'Timeout esperando el eco TCP I08.'
        }

        $tcpClient = $listener.EndAcceptTcpClient($accept)
        $tcpClient.ReceiveTimeout = 10000
        $tcpClient.SendTimeout = 10000
        $stream = $tcpClient.GetStream()
        $buffer = New-Object byte[] 512
        $memory = [IO.MemoryStream]::new()
        try {
            do {
                $read = $stream.Read($buffer, 0, $buffer.Length)
                if ($read -gt 0) {
                    $memory.Write($buffer, 0, $read)
                }
            } while ($read -gt 0)
            $tcpBytes = $memory.ToArray()
            $stream.Write($tcpBytes, 0, $tcpBytes.Length)
            $stream.Flush()
        } finally {
            $memory.Dispose()
        }

        do {
            if ($receive.IsCompleted) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        if (-not $receive.IsCompleted) {
            throw 'Timeout esperando el eco UDP I08.'
        }
        $udpBytes = $udp.EndReceive($receive, [ref]$udpRemote)
        $null = $udp.Send(
            $udpBytes, $udpBytes.Length, $udpRemote)
        $tcpRemote = [Net.IPEndPoint]$tcpClient.Client.RemoteEndPoint
        $tcpLocal = [Net.IPEndPoint]$tcpClient.Client.LocalEndPoint
        $udpLocal = [Net.IPEndPoint]$udp.Client.LocalEndPoint
        $tcpText = [Text.Encoding]::ASCII.GetString($tcpBytes)
        $udpText = [Text.Encoding]::ASCII.GetString($udpBytes)
        $payloadMatch = [regex]::Match(
            $tcpText,
            '^ese-v91-i08-v1:([0-9a-f]{32})\|target=([0-9a-fA-F:]+)$')
        $payloadTarget = $null
        if ($payloadMatch.Success) {
            try {
                $payloadTarget = [Net.IPAddress]::Parse(
                    $payloadMatch.Groups[2].Value)
            } catch {}
        }
        $tuplePass = (
            $tcpRemote.Address.Equals($peerAddress) -and
            $udpRemote.Address.Equals($peerAddress) -and
            $tcpLocal.Address.Equals($localAddress) -and
            $udpLocal.Address.Equals($localAddress) -and
            $tcpLocal.Port -eq $TcpPort -and
            $udpLocal.Port -eq $UdpPort)
        $payloadPass = (
            $tcpText -ceq $udpText -and
            $payloadMatch.Success -and
            $payloadMatch.Groups[1].Value -ceq $Nonce -and
            $null -ne $payloadTarget -and
            $payloadTarget.Equals($localAddress) -and
            (Get-I08ByteHash -Bytes $tcpBytes) -ceq
                (Get-I08ByteHash -Bytes $udpBytes))
        if (-not $tuplePass -or -not $payloadPass) {
            throw 'La evidencia independiente I08 no coincide.'
        }
        [ordered]@{
            schema = 'ese.v91.i08-echo-fixture/v1'
            status = 'PASS'
            nonce = $Nonce
            expected_payload = $tcpText
            tcp = [ordered]@{
                local_address = $tcpLocal.Address.ToString()
                local_address_hex = (
                    [BitConverter]::ToString(
                        $tcpLocal.Address.GetAddressBytes())
                ).Replace('-', '').ToLowerInvariant()
                local_port = $tcpLocal.Port
                remote_address = $tcpRemote.Address.ToString()
                remote_port = $tcpRemote.Port
                bytes = $tcpBytes.Length
                sha256 = Get-I08ByteHash -Bytes $tcpBytes
            }
            udp = [ordered]@{
                local_address = $udpLocal.Address.ToString()
                local_address_hex = (
                    [BitConverter]::ToString(
                        $udpLocal.Address.GetAddressBytes())
                ).Replace('-', '').ToLowerInvariant()
                local_port = $udpLocal.Port
                remote_address = $udpRemote.Address.ToString()
                remote_port = $udpRemote.Port
                bytes = $udpBytes.Length
                sha256 = Get-I08ByteHash -Bytes $udpBytes
            }
        }
    } finally {
        if ($null -ne $tcpClient) {
            $tcpClient.Dispose()
        }
        $listener.Stop()
        $udp.Dispose()
    }
}

function Get-I01SharedLink {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][Int64]$FileBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedEd2k,
        [int]$TimeoutSeconds = 900
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $pattern = 'ed2k://\|file\|' + [regex]::Escape($FileName) +
        '\|' + [string]$FileBytes + '\|([A-Fa-f0-9]{32})' +
        '(?:\|h=[A-Z2-7]{32})?\|/'
    do {
        try {
            $response = Invoke-WebRequest -Uri (
                "http://127.0.0.1:$Port/?ses=$Session&w=shared"
            ) -UseBasicParsing -TimeoutSec 15
            $match = [regex]::Match([string]$response.Content, $pattern)
            if ($match.Success) {
                $ed2k = $match.Groups[1].Value.ToUpperInvariant()
                if ($ed2k -cne $ExpectedEd2k.ToUpperInvariant()) {
                    throw 'El ED2K local de la fixture I01 no coincide.'
                }
                return [ordered]@{
                    link = $match.Value
                    ed2k = $ed2k
                }
            }
        } catch {
            if ($_.Exception.Message -like '*ED2K local*') { throw }
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'Timeout esperando la fixture I01 en la lista local de compartidos.'
}

function Send-I01Ed2kLink {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Link
    )
    if (-not ('EseV91I01CopyData' -as [type])) {
        Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class EseV91I01CopyData {
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    public struct COPYDATASTRUCT {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }
    [DllImport("user32.dll", SetLastError=true)]
    private static extern bool EnumWindows(
        EnumWindowsProc callback, IntPtr lParam);
    [DllImport("user32.dll", SetLastError=true)]
    private static extern uint GetWindowThreadProcessId(
        IntPtr hWnd, out uint processId);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint msg, IntPtr wParam,
        ref COPYDATASTRUCT lParam, uint flags, uint timeoutMs,
        out UIntPtr result);

    public static IntPtr[] FindTopLevelWindows(uint expectedProcessId) {
        List<IntPtr> found = new List<IntPtr>();
        EnumWindows(delegate(IntPtr hWnd, IntPtr lParam) {
            uint owner;
            GetWindowThreadProcessId(hWnd, out owner);
            if (owner == expectedProcessId) {
                found.Add(hWnd);
            }
            return true;
        }, IntPtr.Zero);
        return found.ToArray();
    }
}
'@
    }
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    $handles = @()
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'El downloader I01 termino antes de inyectar el enlace.'
        }
        $handles = @()
        if ($Process.MainWindowHandle -ne [IntPtr]::Zero) {
            $handles += $Process.MainWindowHandle
        }
        foreach ($candidateHandle in @(
                [EseV91I01CopyData]::FindTopLevelWindows(
                    [uint32]$Process.Id))) {
            if ($handles -notcontains $candidateHandle) {
                $handles += $candidateHandle
            }
        }
        if ($handles.Count -gt 0) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($handles.Count -eq 0) {
        throw 'El downloader I01 no expuso su ventana para WM_COPYDATA.'
    }
    $pointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Link)
    try {
        $payload = New-Object EseV91I01CopyData+COPYDATASTRUCT
        $payload.dwData = [IntPtr]12000
        $payload.cbData = ($Link.Length + 1) * 2
        $payload.lpData = $pointer
        $acceptedResult = [UInt64]0
        foreach ($handle in $handles) {
            $nativeResult = [UIntPtr]::Zero
            $sent = [EseV91I01CopyData]::SendMessageTimeout(
                $handle, 0x004A, [IntPtr]::Zero, [ref]$payload,
                0x0003, 10000, [ref]$nativeResult)
            if ($sent -ne [IntPtr]::Zero -and
                $nativeResult.ToUInt64() -ne 0) {
                $acceptedResult = $nativeResult.ToUInt64()
                break
            }
        }
        if ($acceptedResult -eq 0) {
            throw 'El candidato rechazo o bloqueo WM_COPYDATA I01.'
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
    }
}

try {
    Write-K04Progress -Phase 'setup_started'
    $baseNode = if (
        $null -ne $request.PSObject.Properties['base_node_path'] -and
        -not [string]::IsNullOrWhiteSpace([string]$request.base_node_path)
    ) {
        [IO.Path]::GetFullPath([string]$request.base_node_path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $dataRoot (
            [string]$request.base_node_relative).Replace('/', '\')))
    }
    $localIPv6 = [string]$request.local_ipv6
    $peerIPv6 = [string]$request.peer_ipv6
    $localIPv4 = if (
        $null -ne $request.PSObject.Properties['local_ipv4']
    ) { [string]$request.local_ipv4 } else { '' }
    $peerIPv4 = if (
        $null -ne $request.PSObject.Properties['peer_ipv4']
    ) { [string]$request.peer_ipv4 } else { '' }
    $interfaceIndex = [int]$request.interface_index
    $interfaceAlias = [string]$request.interface_alias
    $tcpPort = [int]$request.tcp_port
    $udpPort = [int]$request.udp_port
    $webPort = [int]$request.web_port
    $peerUdpPort = [int]$request.peer_udp_port
    $role = [string]$request.role
    $postAction = if (
        $null -ne $request.PSObject.Properties['post_action']
    ) { [string]$request.post_action } else { '' }
    $postDuration = if (
        $null -ne $request.PSObject.Properties['duration_seconds']
    ) { [int]$request.duration_seconds } else { 0 }
    $peerTcpPort = if (
        $null -ne $request.PSObject.Properties['peer_tcp_port']
    ) { [int]$request.peer_tcp_port } else { 0 }
    $i02ControlPort = if (
        $null -ne $request.PSObject.Properties['control_port']
    ) { [int]$request.control_port } else { 0 }
    $i08TcpPort = if (
        $null -ne $request.PSObject.Properties['echo_tcp_port']
    ) { [int]$request.echo_tcp_port } else { 0 }
    $i08UdpPort = if (
        $null -ne $request.PSObject.Properties['echo_udp_port']
    ) { [int]$request.echo_udp_port } else { 0 }
    $i08Nonce = if (
        $null -ne $request.PSObject.Properties['nonce']
    ) { ([string]$request.nonce).ToLowerInvariant() } else { '' }
    $i01FixturePath = if (
        $null -ne $request.PSObject.Properties['fixture_path']
    ) { [string]$request.fixture_path } else { '' }
    $i01FixtureName = if (
        $null -ne $request.PSObject.Properties['fixture_name']
    ) { [string]$request.fixture_name } else {
        'v91-i05-canonical-4294967296.bin'
    }
    $i01FixtureBytes = if (
        $null -ne $request.PSObject.Properties['fixture_bytes']
    ) { [Int64]$request.fixture_bytes } else { 4294967296L }
    $i01FixtureSha256 = if (
        $null -ne $request.PSObject.Properties['fixture_sha256']
    ) { ([string]$request.fixture_sha256).ToLowerInvariant() } else {
        '1016d6f63ae1649a879a7c0de30865ed132deb37b1c3b2bc9ca004c88feee26c'
    }
    $i01FixtureEd2k = if (
        $null -ne $request.PSObject.Properties['fixture_ed2k']
    ) { ([string]$request.fixture_ed2k).ToUpperInvariant() } else {
        '796A95E75DF8E78D54A57CDEA1FEDE84'
    }
    $secondaryIPv6 = if (
        $null -ne $request.PSObject.Properties['secondary_ipv6']
    ) { [string]$request.secondary_ipv6 } else { '' }
    $secondaryTcpPort = if (
        $null -ne $request.PSObject.Properties['secondary_tcp_port']
    ) { [int]$request.secondary_tcp_port } else { 0 }
    $secondaryUdpPort = if (
        $null -ne $request.PSObject.Properties['secondary_udp_port']
    ) { [int]$request.secondary_udp_port } else { 0 }
    $secondaryWebPort = if (
        $null -ne $request.PSObject.Properties['secondary_web_port']
    ) { [int]$request.secondary_web_port } else { 0 }
    $guardIPv6 = if (
        $null -ne $request.PSObject.Properties['guard_ipv6']
    ) { [string]$request.guard_ipv6 } else { '' }
    $guardTcpPort = if (
        $null -ne $request.PSObject.Properties['guard_tcp_port']
    ) { [int]$request.guard_tcp_port } else { 0 }
    $guardUdpPort = if (
        $null -ne $request.PSObject.Properties['guard_udp_port']
    ) { [int]$request.guard_udp_port } else { 0 }
    $guardWebPort = if (
        $null -ne $request.PSObject.Properties['guard_web_port']
    ) { [int]$request.guard_web_port } else { 0 }
    $expectedHash = ([string]$request.exe_sha256).ToLowerInvariant()
    $bootstrapHost = "v91-k04-peer-$jobId.invalid"
    $password = [Guid]::NewGuid().ToString('N')

    if (-not (Test-Path -LiteralPath (
            Join-Path $baseNode 'emule.exe') -PathType Leaf)) {
        throw "Nodo base ausente: $baseNode"
    }
    New-Item -ItemType Directory -Path $nodePath -Force | Out-Null
    New-Item -ItemType Directory -Path $evidencePath -Force | Out-Null
    Get-ChildItem -LiteralPath $baseNode -Force |
        Where-Object Name -NotIn @('Incoming', 'Temp') |
        Copy-Item -Destination $nodePath -Recurse -Force
    New-Item -ItemType Directory -Path (Join-Path $nodePath 'Incoming') `
        -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $nodePath 'Temp') `
        -Force | Out-Null
    if ($postAction -ceq 'k01-source') {
        $earlyFixture = Join-Path $nodePath (
            'Incoming\V91-K01-KAD6-SOURCE.bin')
        $earlyBytes = New-Object byte[] 65536
        for ($i = 0; $i -lt $earlyBytes.Length; ++$i) {
            $earlyBytes[$i] = [byte](($i * 31 + 17) % 251)
        }
        [IO.File]::WriteAllBytes($earlyFixture, $earlyBytes)
    }
    if ($postAction -ceq 'i01-source' -or
        $postAction -ceq 'o01-source') {
        if ([string]::IsNullOrWhiteSpace($i01FixturePath) -or
            -not (Test-Path -LiteralPath $i01FixturePath -PathType Leaf)) {
            throw 'La fixture canonica I01 no existe en H1.'
        }
        $fixtureItem = Get-Item -LiteralPath $i01FixturePath
        if ([Int64]$fixtureItem.Length -ne $i01FixtureBytes) {
            throw 'La fixture canonica I01 tiene un tamano incorrecto.'
        }
        $fixtureHash = (Get-FileHash -LiteralPath $fixtureItem.FullName `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($fixtureHash -cne $i01FixtureSha256) {
            throw 'La fixture canonica I01 tiene un SHA-256 incorrecto.'
        }
        $i01ExternalRoot = Join-Path $fixtureItem.Directory.FullName (
            "v91-$($postAction.Substring(0, 3))-$jobId")
        $i01Incoming = Join-Path $i01ExternalRoot 'Incoming'
        $i01Temp = Join-Path $i01ExternalRoot 'Temp'
        New-Item -ItemType Directory -Path $i01Incoming,$i01Temp `
            -Force | Out-Null
        $sourceFixture = Join-Path $i01Incoming $i01FixtureName
        $hardlink = New-Item -ItemType HardLink -Path $sourceFixture `
            -Target $fixtureItem.FullName -ErrorAction Stop
        if ([Int64]$hardlink.Length -ne $i01FixtureBytes) {
            throw 'El hardlink de la fixture I01 tiene un tamano incorrecto.'
        }
        Write-K04Progress -Phase 'i01_fixture_ready' -Detail ([ordered]@{
            bytes = $i01FixtureBytes
            sha256 = $fixtureHash
            ed2k = $i01FixtureEd2k
        })
    }

    $emulePath = Join-Path $nodePath 'emule.exe'
    $candidateOverride = ''
    if ($null -ne $request.PSObject.Properties['candidate_exe_path'] -and
        -not [string]::IsNullOrWhiteSpace(
            [string]$request.candidate_exe_path)) {
        $candidateOverride = [IO.Path]::GetFullPath(
            [string]$request.candidate_exe_path)
    } elseif (
        $null -ne $request.PSObject.Properties['candidate_exe_relative'] -and
        -not [string]::IsNullOrWhiteSpace(
            [string]$request.candidate_exe_relative)) {
        $candidateOverride = [IO.Path]::GetFullPath((Join-Path $dataRoot (
            [string]$request.candidate_exe_relative).Replace('/', '\')))
    }
    if ($candidateOverride) {
        if (-not (Test-Path -LiteralPath $candidateOverride -PathType Leaf)) {
            throw "Candidato alternativo ausente: $candidateOverride"
        }
        Copy-Item -LiteralPath $candidateOverride -Destination $emulePath `
            -Force
    }
    Unblock-File -LiteralPath $emulePath -ErrorAction SilentlyContinue
    $actualHash = (Get-FileHash -LiteralPath $emulePath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $expectedHash) {
        throw 'El SHA-256 del candidato no coincide.'
    }
    Write-K04Progress -Phase 'candidate_ready' -Detail ([ordered]@{
        sha256 = $actualHash
        bytes = [Int64](Get-Item -LiteralPath $emulePath).Length
    })
    $preferences = Join-Path $nodePath 'config\preferences.ini'
    $nodesPath = Join-Path $nodePath 'config\nodes_v6.dat'
    foreach ($staleName in @(
        'AC_BootstrapIPs.dat', 'AC_SearchStrings.dat',
        'AC_ServerMetURLs.dat', 'cancelled.met', 'clients.met',
        'clients.met.bak', 'cryptkey.dat', 'emfriends.met', 'known.met',
        'node_identity.dat', 'nodes.dat', 'preferences.dat', 'server.met',
        'server_met.old',
        'sharedfiles.dat', 'StoredSearches.met'
    )) {
        Remove-Item -LiteralPath (
            Join-Path $nodePath "config\$staleName") -Force `
            -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath (
            Join-Path $nodePath 'config\preferences.dat')) {
        throw 'El perfil temporal conserva preferences.dat heredado.'
    }
    [IO.File]::WriteAllText(
        $preferences, '', (New-Object Text.UTF8Encoding($false)))
    Remove-Item -LiteralPath $nodesPath -Force -ErrorAction SilentlyContinue
    foreach ($entry in @(
        @('eMule', 'AppVersion', '0.70b x64 - eSE 9.1.0-rc.3'),
        # An empty legacy IPv4 bind is required for the TCP listener to create
        # its explicitly configured dual-stack IPv6 socket.
        @('eMule', 'BindAddr', ''),
        @('eMule', 'Port', [string]$tcpPort),
        @('eMule', 'UDPPort', [string]$udpPort),
        @('eMule', 'NetworkKademlia', '0'),
        @('eMule', 'NetworkED2K', '0'),
        @('eMule', 'AutoConnect', '0'),
        @('eMule', 'SaveLogToDisk', '1'),
        @('eMule', 'SaveDebugToDisk', '1'),
        @('eMule', 'VerboseOptions', '1'),
        @('eMule', 'Verbose', '1'),
        @('eMule', 'FullVerbose', '1'),
        # The frozen candidate's classic bootstrap dispatcher is gated on
        # Kad2 being active even when the supplied hostname resolves only to
        # IPv6.  Use Both solely to create the controlled seed, then persist
        # nodes_v6.dat and switch to Kad6-only before the restart under test.
        @('Connection', 'KadNetworkMask', '3'),
        @('Connection', 'NetworkED2K', '0'),
        @('Connection', 'IPv6Mode', '2'),
        @('Connection', 'IPv6BindAddr', $localIPv6),
        @('WebServer', 'Enabled', '1'),
        @('WebServer', 'Port', [string]$webPort),
        @('WebServer', 'WebUseUPnP', '0'),
        @('WebServer', 'Password', (Get-K04Md5 -Value $password)),
        @('WebServer', 'AllowAdminHiLevelFunc', '1'),
        @('eSE', 'Kad6PublicExitOptIn', '0'),
        @('eSE', 'Kad6BetaExitOptIn', '0')
    )) {
        Set-K04IniValue -Path $preferences -Section $entry[0] `
            -Key $entry[1] -Value $entry[2]
    }
    if ($postAction -like 'i01-*' -or $postAction -like 'o01-*') {
        $incoming = if ($postAction -ceq 'i01-source' -or
            $postAction -ceq 'o01-source') {
            Join-Path $i01ExternalRoot 'Incoming'
        } else {
            Join-Path $nodePath 'Incoming'
        }
        $temp = if ($postAction -ceq 'i01-source' -or
            $postAction -ceq 'o01-source') {
            Join-Path $i01ExternalRoot 'Temp'
        } else {
            Join-Path $nodePath 'Temp'
        }
        Set-K04IniValue -Path $preferences -Section 'eMule' `
            -Key 'IncomingDir' -Value ($incoming + '\')
        Set-K04IniValue -Path $preferences -Section 'eMule' `
            -Key 'TempDir' -Value ($temp + '\')
        Set-K04IniValue -Path $preferences -Section 'eMule' `
            -Key 'FilterBadIPs' -Value '0'
        Set-K04IniValue -Path $preferences -Section 'eMule' `
            -Key 'ConfirmExit' -Value '0'
        # The freshly-created laboratory profile otherwise inherits eMule's
        # conservative 80 KiB/s upload default.  I01 validates a canonical
        # 4 GiB transfer, so keep the transport uncapped and let the physical
        # link be the limiting factor.
        Set-K04IniValue -Path $preferences -Section 'eMule' `
            -Key 'MaxUpload' -Value '-1'
        Set-K04IniValue -Path $preferences -Section 'eMule' `
            -Key 'MaxDownload' -Value '-1'
        Set-K04IniValue -Path $preferences -Section 'eMule' `
            -Key 'UploadCapacityNew' -Value '100000'
        Set-K04IniValue -Path $preferences -Section 'eMule' `
            -Key 'DownloadCapacity' -Value '100000'
        Set-K04IniValue -Path $preferences -Section 'UPnP' `
            -Key 'EnableUPnP' -Value '0'
    }
    if ($postAction -like 'i01-*' -or $postAction -like 'i02-*' -or
        $postAction -like 'o01-*' -or
        $postAction -like 'k01-*' -or
        $postAction -like 'i08-*') {
        foreach ($key in @(
            'EseNetLabConsent',
            'EseNetLabAdvancedConsent',
            'EseNetLabContributionConsent'
        )) {
            Set-K04IniValue -Path $preferences -Section 'eSE' `
                -Key $key -Value '2'
        }
        Set-K04IniValue -Path $preferences -Section 'eSE' `
            -Key 'EseNetLabEnabled' -Value '1'
        if ($postAction -like 'k01-*') {
            Set-K04IniValue -Path $preferences -Section 'eSE' `
                -Key 'EseV9Experimental' -Value '1'
            Set-K04IniValue -Path $preferences -Section 'eSE' `
                -Key 'Kad6BetaExitOptIn' -Value '1'
        }
    }
    if ($postAction -like 'o01-*') {
        Set-K04IniValue -Path $preferences -Section 'Connection' `
            -Key 'KadNetworkMask' -Value '2'
        Set-K04IniValue -Path $preferences -Section 'Connection' `
            -Key 'IPv6BindAddr' -Value '::'
    }

    $existingAddress = Get-NetIPAddress -InterfaceIndex $interfaceIndex `
        -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object IPAddress -EQ $localIPv6
    if ($null -eq $existingAddress) {
        New-NetIPAddress -InterfaceIndex $interfaceIndex `
            -IPAddress $localIPv6 -PrefixLength 64 `
            -AddressFamily IPv6 -Type Unicast | Out-Null
        $addressCreated = $true
    }
    if ($postAction -like 'o01-*') {
        $physicalIPv4 = @(
            Get-NetIPAddress -InterfaceIndex $interfaceIndex `
                -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object {
                    [string]$_.IPAddress -eq $localIPv4 -and
                    [string]$_.AddressState -ne 'Duplicate'
                }
        )
        if ($physicalIPv4.Count -ne 1) {
            throw "O01 no encontro $localIPv4 en la NIC fisica fijada."
        }
    }
    $allowRule = "eSE-V91-K04-allow-$jobId"
    $allowUdpRemotes = @("$peerIPv6/128")
    if ($postAction -like 'k01-*') {
        $allowUdpRemotes += "$secondaryIPv6/128"
        if (-not [string]::IsNullOrWhiteSpace($guardIPv6)) {
            $allowUdpRemotes += "$guardIPv6/128"
        }
    }
    New-NetFirewallRule -Name $allowRule -DisplayName $allowRule `
        -Direction Inbound -Action Allow -Protocol UDP `
        -LocalPort $udpPort -LocalAddress "$localIPv6/128" `
        -RemoteAddress $allowUdpRemotes -InterfaceAlias $interfaceAlias `
        -Program $emulePath | Out-Null
    $ruleNames.Add($allowRule)
    if ($postAction -ceq 'i02-source' -or
        $postAction -ceq 'o01-source') {
        $allowLiveRule = "eSE-V91-I02-live-$jobId"
        New-NetFirewallRule -Name $allowLiveRule `
            -DisplayName $allowLiveRule -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort $tcpPort `
            -LocalAddress "$localIPv6/128" `
            -RemoteAddress "$peerIPv6/128" `
            -InterfaceAlias $interfaceAlias -Program $emulePath | Out-Null
        $ruleNames.Add($allowLiveRule)
        $allowControlRule = "eSE-V91-I02-control-$jobId"
        New-NetFirewallRule -Name $allowControlRule `
            -DisplayName $allowControlRule -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort $i02ControlPort `
            -LocalAddress "$localIPv6/128" `
            -RemoteAddress "$peerIPv6/128" `
            -InterfaceAlias $interfaceAlias | Out-Null
        $ruleNames.Add($allowControlRule)
    }
    if ($postAction -ceq 'o01-source') {
        if ($localIPv4 -notmatch '^\d{1,3}(?:\.\d{1,3}){3}$' -or
            $peerIPv4 -notmatch '^\d{1,3}(?:\.\d{1,3}){3}$') {
            throw 'O01 requiere las direcciones IPv4 fisicas fijadas.'
        }
        $allowO01V4 = "eSE-V91-O01-ipv4-$jobId"
        New-NetFirewallRule -Name $allowO01V4 `
            -DisplayName $allowO01V4 -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort $tcpPort `
            -LocalAddress $localIPv4 -RemoteAddress $peerIPv4 `
            -InterfaceAlias $interfaceAlias -Program $emulePath | Out-Null
        $ruleNames.Add($allowO01V4)
    }
    if ($postAction -ceq 'i08-server') {
        if ($i08TcpPort -lt 1024 -or $i08TcpPort -gt 65535 -or
            $i08UdpPort -lt 1024 -or $i08UdpPort -gt 65535 -or
            $i02ControlPort -lt 1024 -or $i02ControlPort -gt 65535 -or
            $i08Nonce -notmatch '^[0-9a-f]{32}$') {
            throw 'Parametros I08 no validos.'
        }
        foreach ($entry in @(
            [ordered]@{ suffix = 'tcp'; protocol = 'TCP'; port = $i08TcpPort },
            [ordered]@{ suffix = 'udp'; protocol = 'UDP'; port = $i08UdpPort },
            [ordered]@{ suffix = 'control'; protocol = 'TCP'; port = $i02ControlPort }
        )) {
            $allowI08 = "eSE-V91-I08-$($entry.suffix)-$jobId"
            New-NetFirewallRule -Name $allowI08 `
                -DisplayName $allowI08 -Direction Inbound `
                -Action Allow -Protocol ([string]$entry.protocol) `
                -LocalPort ([int]$entry.port) `
                -LocalAddress "$localIPv6/128" `
                -RemoteAddress "$peerIPv6/128" `
                -InterfaceAlias $interfaceAlias | Out-Null
            $ruleNames.Add($allowI08)
        }
    }
    if ($postAction -like 'i01-*') {
        if ($peerTcpPort -lt 1024 -or $peerTcpPort -gt 65535 -or
            $i02ControlPort -lt 1024 -or $i02ControlPort -gt 65535) {
            throw 'Parametros I01 no validos.'
        }
        $allowI01Tcp = "eSE-V91-I01-tcp-$jobId"
        New-NetFirewallRule -Name $allowI01Tcp `
            -DisplayName $allowI01Tcp -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort $tcpPort `
            -LocalAddress "$localIPv6/128" `
            -RemoteAddress "$peerIPv6/128" `
            -InterfaceAlias $interfaceAlias -Program $emulePath | Out-Null
        $ruleNames.Add($allowI01Tcp)
        if ($postAction -ceq 'i01-source') {
            $allowI01Control = "eSE-V91-I01-control-$jobId"
            New-NetFirewallRule -Name $allowI01Control `
                -DisplayName $allowI01Control -Direction Inbound `
                -Action Allow -Protocol TCP -LocalPort $i02ControlPort `
                -LocalAddress "$localIPv6/128" `
                -RemoteAddress "$peerIPv6/128" `
                -InterfaceAlias $interfaceAlias | Out-Null
            $ruleNames.Add($allowI01Control)
        }
        foreach ($direction in @('Inbound', 'Outbound')) {
            $blockI01V4 = "eSE-V91-I01-v4-$($direction.ToLower())-$jobId"
            New-NetFirewallRule -Name $blockI01V4 `
                -DisplayName $blockI01V4 -Direction $direction `
                -Action Block -Protocol Any -RemoteAddress '0.0.0.0/0' `
                -Program $emulePath | Out-Null
            $ruleNames.Add($blockI01V4)
        }
    }
    if ($postAction -like 'k01-*') {
        if ([string]::IsNullOrWhiteSpace($secondaryIPv6) -or
            $secondaryTcpPort -le 0 -or $i02ControlPort -le 0) {
            throw 'K01 requiere el tercer nodo y el canal de control.'
        }
        $k01PeerAddresses = @("$peerIPv6/128", "$secondaryIPv6/128")
        if (-not [string]::IsNullOrWhiteSpace($guardIPv6)) {
            $k01PeerAddresses += "$guardIPv6/128"
        }
        $allowK01Tcp = "eSE-V91-K01-tcp-$jobId"
        New-NetFirewallRule -Name $allowK01Tcp `
            -DisplayName $allowK01Tcp -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort $tcpPort `
            -LocalAddress "$localIPv6/128" `
            -RemoteAddress $k01PeerAddresses `
            -InterfaceAlias $interfaceAlias -Program $emulePath | Out-Null
        $ruleNames.Add($allowK01Tcp)
        if ($postAction -ceq 'k01-source') {
            $allowK01Control = "eSE-V91-K01-control-$jobId"
            New-NetFirewallRule -Name $allowK01Control `
                -DisplayName $allowK01Control -Direction Inbound `
                -Action Allow -Protocol TCP -LocalPort $i02ControlPort `
                -LocalAddress "$localIPv6/128" `
                -RemoteAddress "$peerIPv6/128" `
                -InterfaceAlias $interfaceAlias | Out-Null
            $ruleNames.Add($allowK01Control)
        }
    }
    # Keep the temporary Kad2 bootstrap gate from contacting the public IPv4
    # network.  With nodes.dat removed, the only usable seed is the controlled
    # IPv6 ULA peer supplied below.
    $blockV4In = "eSE-V91-K04-block-v4-in-$jobId"
    $blockV4Out = "eSE-V91-K04-block-v4-out-$jobId"
    New-NetFirewallRule -Name $blockV4In -DisplayName $blockV4In `
        -Direction Inbound -Action Block -Protocol UDP `
        -LocalPort $udpPort -RemoteAddress '0.0.0.0/0' `
        -Program $emulePath | Out-Null
    $ruleNames.Add($blockV4In)
    New-NetFirewallRule -Name $blockV4Out -DisplayName $blockV4Out `
        -Direction Outbound -Action Block -Protocol UDP `
        -LocalPort $udpPort -RemoteAddress '0.0.0.0/0' `
        -Program $emulePath | Out-Null
    $ruleNames.Add($blockV4Out)

    if ($role -ceq 'bootstrap') {
        Add-Content -LiteralPath $hostsPath `
            -Value "`r`n$peerIPv6`t$bootstrapHost`t$hostsMarker" `
            -Encoding ASCII
        $hostsLineAdded = $true
    }
    Write-K04Progress -Phase 'network_ready'

    $captureEnabled = (
        $null -eq $request.PSObject.Properties['capture_enabled'] -or
        [bool]$request.capture_enabled)
    if ($captureEnabled) {
      try {
        $pktmonOutput = [Collections.Generic.List[string]]::new()
        foreach ($line in @(& pktmon.exe filter remove 2>&1)) {
            $pktmonOutput.Add([string]$line)
        }
        foreach ($line in @(& pktmon.exe filter add K04-UDP `
                -t UDP -p $udpPort 2>&1)) {
            $pktmonOutput.Add([string]$line)
        }
        if ($postAction -like 'i01-*') {
            foreach ($line in @(& pktmon.exe filter add I01-TCP `
                    -t TCP -p $tcpPort 2>&1)) {
                $pktmonOutput.Add([string]$line)
            }
        }
        foreach ($line in @(& pktmon.exe start --capture --pkt-size 0 `
                --file-name $pktmonEtl 2>&1)) {
            $pktmonOutput.Add([string]$line)
        }
        if ($LASTEXITCODE -eq 0) {
            $pktmonStarted = $true
        }
        [IO.File]::WriteAllLines(
            $pktmonLog, $pktmonOutput,
            (New-Object Text.UTF8Encoding($false)))
      } catch {
        [IO.File]::WriteAllText(
            $pktmonLog, $_.Exception.Message,
            (New-Object Text.UTF8Encoding($false)))
      }
    }
    Write-K04Progress -Phase 'capture_ready' -Detail ([ordered]@{
        enabled = [bool]$captureEnabled
        started = [bool]$pktmonStarted
    })

    $arguments = @(
        '--portable', '--ignoreinstances', '--headless',
        "--metrics-port=$webPort", "--tcp-port=$tcpPort",
        "--udp-port=$udpPort"
    )
    Write-K04Progress -Phase 'process_starting'
    $process = Start-Process -FilePath $emulePath `
        -ArgumentList $arguments -WorkingDirectory $nodePath `
        -WindowStyle Hidden -PassThru
    Write-K04Progress -Phase 'process_started' -Detail ([ordered]@{
        pid = [int]$process.Id
    })
    $startup = Wait-K04Api -Process $process -Port $webPort
    Write-K04Progress -Phase 'api_ready'
    $session = Get-K04WebSession -Port $webPort -Password $password
    $startup = Start-K04Kad -Port $webPort
    Write-K04Progress -Phase 'kad_started'

    if ($postAction -like 'o01-*') {
        $sample = Get-K04Status -Port $webPort
        if ([bool]$sample.kad2_running -or
            -not [bool]$sample.kad6_running -or
            [int]$sample.kad_running_mask -ne 2) {
            throw 'O01 no arranco exclusivamente con Kad6.'
        }
        $firstSamples = [Collections.Generic.List[object]]::new()
        $firstSamples.Add([ordered]@{
            at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            verified = [int]$sample.kad6_verified_contacts
            running = [bool]$sample.kad6_running
            configured_mask = [int]$sample.kad_configured_mask
            running_mask = [int]$sample.kad_running_mask
        })
        $nodesItem = [pscustomobject]@{ Length = 0L }
        $nodesHash = ''
        $postRestartEvidence = [ordered]@{
            skipped_for_o01 = $true
            verified = [int]$sample.kad6_verified_contacts
            configured_mask = [int]$sample.kad_configured_mask
            running_mask = [int]$sample.kad_running_mask
        }
        $fresh = $sample
        $freshSamples = [Collections.Generic.List[object]]::new()
        $freshSamples.Add($firstSamples[0])
        Write-K04Progress -Phase 'o01_dual_stack_ready' `
            -Detail ([ordered]@{
                pid = [int]$process.Id
                local_address = '::'
                tcp_port = $tcpPort
                ipv6_only = $false
                k04_persistence_preamble_skipped = $true
                functional_verification_pending = $true
            })
    } else {
    $firstSamples = [Collections.Generic.List[object]]::new()
    $verifyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
    do {
        if ($role -ceq 'bootstrap') {
            Invoke-K04Bootstrap -Port $webPort -Session $session `
                -HostName $bootstrapHost -PeerPort $peerUdpPort
        }
        Start-Sleep -Seconds 2
        $sample = Get-K04Status -Port $webPort
        $firstSamples.Add([ordered]@{
            at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            verified = [int]$sample.kad6_verified_contacts
            running = [bool]$sample.kad6_running
            configured_mask = [int]$sample.kad_configured_mask
            running_mask = [int]$sample.kad_running_mask
        })
        Write-K04Progress -Phase 'initial_verification' -Detail (
            $firstSamples[$firstSamples.Count - 1])
        if ([int]$sample.kad6_verified_contacts -gt 0) { break }
    } while ([DateTimeOffset]::UtcNow -lt $verifyDeadline)
    if ([int]$sample.kad6_verified_contacts -le 0) {
        throw 'No se obtuvo contacto Kad6 verificado antes del reinicio.'
    }
    Write-K04Progress -Phase 'initial_verified' -Detail ([ordered]@{
        verified = [int]$sample.kad6_verified_contacts
    })
    Start-Sleep -Seconds 5
    Stop-K04Kad -Port $webPort -Session $session
    Start-Sleep -Seconds 1
    if (-not (Test-Path -LiteralPath $nodesPath -PathType Leaf)) {
        throw 'nodes_v6.dat no se persistio.'
    }
    $nodesItem = Get-Item -LiteralPath $nodesPath
    if ($nodesItem.Length -le 16) {
        throw 'nodes_v6.dat no contiene contactos.'
    }
    $nodesHash = (Get-FileHash -LiteralPath $nodesPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    Copy-Item -LiteralPath $nodesPath -Destination (
        Join-Path $evidencePath 'nodes_v6-before-restart.dat') -Force
    Write-K04Progress -Phase 'contacts_persisted' -Detail ([ordered]@{
        bytes = [Int64]$nodesItem.Length
        sha256 = $nodesHash
    })
    Stop-K04Process -Process $process -Port $webPort -Session $session
    $process = $null
    $preferencesDat = Join-Path $nodePath 'config\preferences.dat'
    if (-not (Test-Path -LiteralPath $preferencesDat -PathType Leaf)) {
        throw 'El cierre limpio no persistio preferences.dat.'
    }
    Write-K04Progress -Phase 'identity_persisted' -Detail ([ordered]@{
        preferences_dat_bytes =
            [Int64](Get-Item -LiteralPath $preferencesDat).Length
    })
    Set-K04IniValue -Path $preferences -Section 'Connection' `
        -Key 'KadNetworkMask' -Value '2'

    $blockIn = "eSE-V91-K04-block-in-$jobId"
    $blockOut = "eSE-V91-K04-block-out-$jobId"
    New-NetFirewallRule -Name $blockIn -DisplayName $blockIn `
        -Direction Inbound -Action Block -Protocol UDP `
        -LocalPort $udpPort -LocalAddress "$localIPv6/128" `
        -RemoteAddress "$peerIPv6/128" -InterfaceAlias $interfaceAlias `
        -Program $emulePath | Out-Null
    $ruleNames.Add($blockIn)
    New-NetFirewallRule -Name $blockOut -DisplayName $blockOut `
        -Direction Outbound -Action Block -Protocol UDP `
        -LocalPort $udpPort -LocalAddress "$localIPv6/128" `
        -RemotePort $peerUdpPort -RemoteAddress "$peerIPv6/128" `
        -InterfaceAlias $interfaceAlias -Program $emulePath | Out-Null
    $ruleNames.Add($blockOut)

    $process = Start-Process -FilePath $emulePath `
        -ArgumentList $arguments -WorkingDirectory $nodePath `
        -WindowStyle Hidden -PassThru
    $null = Wait-K04Api -Process $process -Port $webPort
    $postRestart = Start-K04Kad -Port $webPort
    if ([int]$postRestart.kad_configured_mask -ne 2 -or
        [int]$postRestart.kad_running_mask -ne 2 -or
        [bool]$postRestart.kad2_running -or
        -not [bool]$postRestart.kad6_running) {
        throw 'El reinicio no quedo exclusivamente en Kad6.'
    }
    if ([int]$postRestart.kad6_verified_contacts -ne 0) {
        throw 'El reinicio heredo confianza Kad6 verificada.'
    }
    $postRestartEvidence = [ordered]@{
        at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        verified = [int]$postRestart.kad6_verified_contacts
        configured_mask = [int]$postRestart.kad_configured_mask
        running_mask = [int]$postRestart.kad_running_mask
        kad2_running = [bool]$postRestart.kad2_running
        kad6_running = [bool]$postRestart.kad6_running
        nodes_bytes = [Int64]$nodesItem.Length
        nodes_sha256 = $nodesHash
    }
    Write-K04Progress -Phase 'restart_isolated' -Detail $postRestartEvidence
    Remove-NetFirewallRule -Name $blockIn -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -Name $blockOut -ErrorAction SilentlyContinue
    if ($null -ne (Get-NetFirewallRule -Name $blockIn `
            -ErrorAction SilentlyContinue) -or
        $null -ne (Get-NetFirewallRule -Name $blockOut `
            -ErrorAction SilentlyContinue)) {
        throw 'El aislamiento Kad6 no se pudo retirar.'
    }
    $ruleNames.Remove($blockIn) | Out-Null
    $ruleNames.Remove($blockOut) | Out-Null
    Write-K04Progress -Phase 'firewall_released'

    $freshSamples = [Collections.Generic.List[object]]::new()
    $freshDeadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
    do {
        Start-Sleep -Seconds 1
        $fresh = Get-K04Status -Port $webPort
        $freshSamples.Add([ordered]@{
            at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            verified = [int]$fresh.kad6_verified_contacts
            running = [bool]$fresh.kad6_running
        })
        if ([int]$fresh.kad6_verified_contacts -gt 0) { break }
    } while ([DateTimeOffset]::UtcNow -lt $freshDeadline)
    if ([int]$fresh.kad6_verified_contacts -le 0) {
        throw 'El contacto persistido no se re-verifico dentro del limite.'
    }
    Write-K04Progress -Phase 'reverified' -Detail ([ordered]@{
        verified = [int]$fresh.kad6_verified_contacts
    })

    if ($postAction -like 'o01-*') {
        Write-K04Progress -Phase 'o01_dual_stack_restarting'
        $dualSession = Get-K04WebSession -Port $webPort `
            -Password $password
        Stop-K04Process -Process $process -Port $webPort `
            -Session $dualSession
        $process = $null
        Set-K04IniValue -Path $preferences -Section 'Connection' `
            -Key 'IPv6BindAddr' -Value '::'
        $process = Start-Process -FilePath $emulePath `
            -ArgumentList $arguments -WorkingDirectory $nodePath `
            -WindowStyle Hidden -PassThru
        $null = Wait-K04Api -Process $process -Port $webPort
        $dualStatus = Start-K04Kad -Port $webPort
        if (-not [bool]$dualStatus.kad6_running -or
            [bool]$dualStatus.kad2_running) {
            throw 'O01 no reinicio exclusivamente con Kad6.'
        }
        $dualListener = @(
            Get-NetTCPConnection -OwningProcess $process.Id `
                -State Listen -ErrorAction SilentlyContinue |
                Where-Object {
                    [int]$_.LocalPort -eq $tcpPort
                }
        )
        Write-K04Progress -Phase 'o01_dual_stack_ready' `
            -Detail ([ordered]@{
                pid = [int]$process.Id
                local_address = '::'
                tcp_port = $tcpPort
                ipv6_only = $false
                net_tcp_listener_rows = $dualListener.Count
                functional_verification_pending = $true
            })
    }
    }

    if ($postAction -like 'i01-*') {
        $i01Role = if ($postAction -ceq 'i01-source') {
            'source'
        } elseif ($postAction -ceq 'i01-downloader') {
            'downloader'
        } else {
            throw "Accion posterior desconocida: $postAction"
        }
        if ($postDuration -lt 300 -or $peerTcpPort -le 0 -or
            $i02ControlPort -le 0 -or
            $i01FixtureBytes -ne 4294967296L -or
            $i01FixtureSha256 -notmatch '^[0-9a-f]{64}$' -or
            $i01FixtureEd2k -notmatch '^[0-9A-F]{32}$') {
            throw 'El contrato I01 no es valido.'
        }
        $i01Started = [DateTimeOffset]::UtcNow
        $ownedTcpListeners = @(
            Get-NetTCPConnection -OwningProcess $process.Id `
                -State Listen -ErrorAction SilentlyContinue |
                Where-Object {
                    [int]$_.LocalPort -eq $tcpPort -and
                    ([string]$_.LocalAddress).Contains(':')
                }
        )
        if ($ownedTcpListeners.Count -lt 1) {
            throw 'El candidato I01 no expone listener peer IPv6.'
        }

        if ($i01Role -ceq 'source') {
            Write-K04Progress -Phase 'i01_source_hashing'
            $i01Session = Get-K04WebSession -Port $webPort `
                -Password $password
            $shared = Get-I01SharedLink -Port $webPort `
                -Session $i01Session -FileName $i01FixtureName `
                -FileBytes $i01FixtureBytes `
                -ExpectedEd2k $i01FixtureEd2k
            $directLink = [string]$shared.link +
                "|sources,[$localIPv6]:$tcpPort|/"
            $listener = [Net.Sockets.TcpListener]::new(
                [Net.IPAddress]::Parse($localIPv6), $i02ControlPort)
            $controlClient = $null
            try {
                $listener.Start(1)
                Write-K04Progress -Phase 'i01_source_ready' `
                    -Detail ([ordered]@{
                        bytes = $i01FixtureBytes
                        sha256 = $i01FixtureSha256
                        ed2k = $i01FixtureEd2k
                        control_port = $i02ControlPort
                    })
                $accept = $listener.BeginAcceptTcpClient($null, $null)
                $acceptDeadline = [DateTimeOffset]::UtcNow.AddSeconds(900)
                do {
                    if ($accept.IsCompleted) { break }
                    Start-Sleep -Milliseconds 200
                } while ([DateTimeOffset]::UtcNow -lt $acceptDeadline)
                if (-not $accept.IsCompleted) {
                    throw 'Timeout esperando al downloader I01.'
                }
                $controlClient = $listener.EndAcceptTcpClient($accept)
                $controlClient.ReceiveTimeout = [Math]::Min(
                    [int]::MaxValue, ($postDuration + 300) * 1000)
                $stream = $controlClient.GetStream()
                $writer = [IO.StreamWriter]::new(
                    $stream, [Text.UTF8Encoding]::new($false))
                $writer.AutoFlush = $true
                $reader = [IO.StreamReader]::new(
                    $stream, [Text.UTF8Encoding]::new($false))
                $ready = [ordered]@{
                    schema = 'ese.v91.i01-ready/v1'
                    source_ipv6 = $localIPv6
                    source_tcp_port = $tcpPort
                    candidate_sha256 = $actualHash
                    fixture = [ordered]@{
                        name = $i01FixtureName
                        bytes = $i01FixtureBytes
                        sha256 = $i01FixtureSha256
                        ed2k = $i01FixtureEd2k
                    }
                    direct_link = $directLink
                }
                $writer.WriteLine(($ready | ConvertTo-Json -Depth 6 `
                    -Compress))
                Write-K04Progress -Phase 'i01_source_serving'
                $ackLine = $reader.ReadLine()
                if ([string]::IsNullOrWhiteSpace($ackLine)) {
                    throw 'El downloader I01 cerro el control sin resultado.'
                }
                $ack = $ackLine | ConvertFrom-Json
                if ([string]$ack.schema -cne 'ese.v91.i01-ack/v1' -or
                    [string]$ack.status -cne 'PASS' -or
                    [Int64]$ack.fixture.bytes -ne $i01FixtureBytes -or
                    [string]$ack.fixture.sha256 -cne $i01FixtureSha256 -or
                    [string]$ack.fixture.ed2k -cne $i01FixtureEd2k -or
                    -not [bool]$ack.transport.ipv6_peer_observed -or
                    [bool]$ack.transport.ipv4_peer_observed) {
                    throw 'El resultado remoto I01 no satisface el contrato.'
                }
                $postResult = [ordered]@{
                    schema = 'ese.v91.i01-node-result/v1'
                    case_id = 'V91-I01'
                    status = 'PASS'
                    role = $i01Role
                    started_at_utc = $i01Started.ToString('o')
                    completed_at_utc =
                        [DateTimeOffset]::UtcNow.ToString('o')
                    candidate_sha256 = $actualHash
                    fixture = [ordered]@{
                        name = $i01FixtureName
                        bytes = $i01FixtureBytes
                        sha256 = $i01FixtureSha256
                        ed2k = $i01FixtureEd2k
                        local_ed2k = [string]$shared.ed2k
                    }
                    transport = [ordered]@{
                        family = 'IPv6'
                        source_ipv6 = $localIPv6
                        downloader_ipv6 = $peerIPv6
                        source_tcp_port = $tcpPort
                        ipv4_blocked_by_owned_firewall = $true
                        physical_interface = $interfaceAlias
                    }
                    remote = $ack
                }
            } finally {
                if ($null -ne $controlClient) {
                    $controlClient.Dispose()
                }
                $listener.Stop()
            }
        } else {
            Write-K04Progress -Phase 'i01_downloader_waiting'
            $controlClient = $null
            $readyLine = ''
            $connectDeadline = [DateTimeOffset]::UtcNow.AddSeconds(900)
            do {
                try {
                    $controlClient = [Net.Sockets.TcpClient]::new(
                        [Net.Sockets.AddressFamily]::InterNetworkV6)
                    $connect = $controlClient.BeginConnect(
                        $peerIPv6, $i02ControlPort, $null, $null)
                    if ($connect.AsyncWaitHandle.WaitOne(2000)) {
                        $controlClient.EndConnect($connect)
                        $controlClient.ReceiveTimeout = 30000
                        $stream = $controlClient.GetStream()
                        $reader = [IO.StreamReader]::new(
                            $stream, [Text.UTF8Encoding]::new($false))
                        $writer = [IO.StreamWriter]::new(
                            $stream, [Text.UTF8Encoding]::new($false))
                        $writer.AutoFlush = $true
                        $readyLine = [string]$reader.ReadLine()
                    }
                } catch {
                    $readyLine = ''
                    if ($null -ne $controlClient) {
                        $controlClient.Dispose()
                    }
                    $controlClient = $null
                }
                if (-not [string]::IsNullOrWhiteSpace($readyLine)) {
                    break
                }
                if ($null -ne $controlClient) {
                    $controlClient.Dispose()
                }
                $controlClient = $null
                Start-Sleep -Seconds 1
            } while ([DateTimeOffset]::UtcNow -lt $connectDeadline)
            if ([string]::IsNullOrWhiteSpace($readyLine) -or
                $null -eq $controlClient) {
                throw 'El origen I01 no anuncio READY.'
            }
            try {
                $ready = $readyLine | ConvertFrom-Json
                $link = [string]$ready.direct_link
                $expectedLinkSuffix =
                    "|sources,[$peerIPv6]:$peerTcpPort|/"
                if ([string]$ready.schema -cne 'ese.v91.i01-ready/v1' -or
                    [string]$ready.source_ipv6 -cne $peerIPv6 -or
                    [int]$ready.source_tcp_port -ne $peerTcpPort -or
                    [string]$ready.candidate_sha256 -cne $actualHash -or
                    [string]$ready.fixture.name -cne $i01FixtureName -or
                    [Int64]$ready.fixture.bytes -ne $i01FixtureBytes -or
                    [string]$ready.fixture.sha256 -cne
                        $i01FixtureSha256 -or
                    [string]$ready.fixture.ed2k -cne $i01FixtureEd2k -or
                    -not $link.EndsWith(
                        $expectedLinkSuffix,
                        [StringComparison]::Ordinal)) {
                    throw 'El READY I01 no coincide con la topologia fijada.'
                }
                Write-K04Progress -Phase 'i01_downloader_injecting'
                Send-I01Ed2kLink -Process $process -Link $link
                Start-Sleep -Seconds 3
                Send-I01Ed2kLink -Process $process -Link $link
                Start-Sleep -Seconds 5
                $sourceResolutions = Invoke-RestMethod -Uri (
                    "http://127.0.0.1:$webPort" +
                    '/api/debug/source-resolutions?after=0'
                ) -TimeoutSec 10
                $liveLog = Invoke-RestMethod -Uri (
                    "http://127.0.0.1:$webPort/api/live/log?n=200"
                ) -TimeoutSec 10
                Write-K04Json -Path (
                    Join-Path $evidencePath 'i01-source-resolutions.json'
                ) -Value $sourceResolutions
                Write-K04Json -Path (
                    Join-Path $evidencePath 'i01-live-log.json'
                ) -Value $liveLog
                Write-K04Progress -Phase 'i01_downloader_route_observed' `
                    -Detail ([ordered]@{
                        source_resolutions = $sourceResolutions
                        live_log_tail = @($liveLog.items |
                            Select-Object -Last 12)
                    })

                $destination = Join-Path (
                    Join-Path $nodePath 'Incoming') $i01FixtureName
                $deadline = [DateTimeOffset]::UtcNow.AddSeconds(
                    $postDuration)
                $sawIPv6 = $false
                $sawIPv4 = $false
                $lastProgress = [DateTimeOffset]::MinValue
                do {
                    $process.Refresh()
                    if ($process.HasExited) {
                        throw 'El downloader I01 termino durante la descarga.'
                    }
                    $connections = @(
                        Get-NetTCPConnection -OwningProcess $process.Id `
                            -ErrorAction SilentlyContinue |
                            Where-Object {
                                [int]$_.RemotePort -eq $peerTcpPort
                            }
                    )
                    if (@($connections | Where-Object {
                            ([string]$_.RemoteAddress).Contains(':') -and
                            [Net.IPAddress]::Parse(
                                [string]$_.RemoteAddress).Equals(
                                    [Net.IPAddress]::Parse($peerIPv6))
                        }).Count -gt 0) {
                        $sawIPv6 = $true
                    }
                    if (@($connections | Where-Object {
                            -not ([string]$_.RemoteAddress).Contains(':')
                        }).Count -gt 0) {
                        $sawIPv4 = $true
                    }
                    if (Test-Path -LiteralPath $destination -PathType Leaf) {
                        if ([Int64](Get-Item -LiteralPath $destination).Length `
                                -eq $i01FixtureBytes) {
                            break
                        }
                    }
                    if (([DateTimeOffset]::UtcNow - $lastProgress).
                            TotalSeconds -ge 15) {
                        $partFiles = @(
                            Get-ChildItem -LiteralPath (
                                Join-Path $nodePath 'Temp') `
                                -Filter '*.part' -File `
                                -ErrorAction SilentlyContinue
                        )
                        Write-K04Progress `
                            -Phase 'i01_downloader_transferring' `
                            -Detail ([ordered]@{
                                ipv6_peer_observed = $sawIPv6
                                ipv4_peer_observed = $sawIPv4
                                part_file_count = $partFiles.Count
                                remaining_seconds = [Math]::Max(
                                    0, [Math]::Round(
                                        ($deadline -
                                            [DateTimeOffset]::UtcNow).
                                            TotalSeconds))
                            })
                        $lastProgress = [DateTimeOffset]::UtcNow
                    }
                    Start-Sleep -Seconds 2
                } while ([DateTimeOffset]::UtcNow -lt $deadline)
                if (-not (Test-Path -LiteralPath $destination `
                            -PathType Leaf)) {
                    throw 'Timeout: I01 no produjo el fichero de destino.'
                }
                $destinationItem = Get-Item -LiteralPath $destination
                if ([Int64]$destinationItem.Length -ne $i01FixtureBytes) {
                    throw 'El fichero de destino I01 tiene tamano incorrecto.'
                }
                Write-K04Progress -Phase 'i01_downloader_hashing'
                $destinationHash = (
                    Get-FileHash -LiteralPath $destination `
                        -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($destinationHash -cne $i01FixtureSha256) {
                    throw 'El SHA-256 del destino I01 no coincide.'
                }
                $i01Session = Get-K04WebSession -Port $webPort `
                    -Password $password
                $destinationShared = Get-I01SharedLink -Port $webPort `
                    -Session $i01Session -FileName $i01FixtureName `
                    -FileBytes $i01FixtureBytes `
                    -ExpectedEd2k $i01FixtureEd2k
                $finalApi = Get-K04Status -Port $webPort
                if (-not $sawIPv6 -or $sawIPv4) {
                    throw 'La atribucion de sockets I01 no es IPv6-only.'
                }
                $ack = [ordered]@{
                    schema = 'ese.v91.i01-ack/v1'
                    status = 'PASS'
                    candidate_sha256 = $actualHash
                    fixture = [ordered]@{
                        name = $i01FixtureName
                        bytes = [Int64]$destinationItem.Length
                        sha256 = $destinationHash
                        ed2k = [string]$destinationShared.ed2k
                    }
                    transport = [ordered]@{
                        family = 'IPv6'
                        source_ipv6 = $peerIPv6
                        downloader_ipv6 = $localIPv6
                        source_tcp_port = $peerTcpPort
                        ipv6_peer_observed = $sawIPv6
                        ipv4_peer_observed = $sawIPv4
                        ipv4_blocked_by_owned_firewall = $true
                        physical_interface = $interfaceAlias
                    }
                    api_responsive = ($null -ne $finalApi)
                }
                $writer.WriteLine(($ack | ConvertTo-Json -Depth 6 `
                    -Compress))
                $postResult = [ordered]@{
                    schema = 'ese.v91.i01-node-result/v1'
                    case_id = 'V91-I01'
                    status = 'PASS'
                    role = $i01Role
                    started_at_utc = $i01Started.ToString('o')
                    completed_at_utc =
                        [DateTimeOffset]::UtcNow.ToString('o')
                    candidate_sha256 = $actualHash
                    fixture = $ack.fixture
                    transport = $ack.transport
                    api_responsive = $ack.api_responsive
                }
            } finally {
                $controlClient.Dispose()
            }
        }
        Write-K04Json -Path (Join-Path $jobRoot 'i01-result.json') `
            -Value $postResult
        Write-K04Progress -Phase "i01_${i01Role}_complete"
    }

    if ($postAction -like 'i02-*' -or $postAction -like 'o01-*') {
        if ($postDuration -lt 60 -or $peerTcpPort -le 0 -or
            $i02ControlPort -le 0) {
            throw 'La accion de soak requiere duracion, peer TCP y control TCP.'
        }
        $isO01 = $postAction -like 'o01-*'
        $i02Role = if ($postAction -ceq 'i02-source' -or
            $postAction -ceq 'o01-source') {
            'source'
        } elseif ($postAction -ceq 'i02-viewer' -or
            $postAction -ceq 'o01-viewer') {
            'viewer'
        } else {
            throw "Accion posterior desconocida: $postAction"
        }
        if ($isO01 -and (
            $localIPv4 -notmatch '^\d{1,3}(?:\.\d{1,3}){3}$' -or
            $peerIPv4 -notmatch '^\d{1,3}(?:\.\d{1,3}){3}$' -or
            $i01FixtureBytes -ne 4294967296L -or
            $i01FixtureSha256 -notmatch '^[0-9a-f]{64}$' -or
            $i01FixtureEd2k -notmatch '^[0-9A-F]{32}$')) {
            throw 'La accion O01 requiere IPv4 y fixture canonica fijadas.'
        }
        $streamKey = ''
        $o01DirectLink = ''
        $o01SourceEd2k = ''
        $i02Started = [DateTimeOffset]::UtcNow
        if ($i02Role -ceq 'source') {
            Write-K04Progress -Phase $(
                if ($isO01) { 'o01_broadcast_starting' }
                else { 'i02_broadcast_starting' })
            if ($isO01) {
                $o01Session = Get-K04WebSession -Port $webPort `
                    -Password $password
                $o01Shared = Get-I01SharedLink -Port $webPort `
                    -Session $o01Session -FileName $i01FixtureName `
                    -FileBytes $i01FixtureBytes `
                    -ExpectedEd2k $i01FixtureEd2k
                $o01SourceEd2k = [string]$o01Shared.ed2k
                $o01DirectLink = [string]$o01Shared.link +
                    "|sources,$localIPv4`:$tcpPort|/"
            }
            $broadcast = Invoke-RestMethod -Uri (
                "http://127.0.0.1:$webPort/api/live/broadcast/start" +
                "?source=testpattern&title=$(
                    if ($isO01) { 'V91-O01-T1' } else { 'V91-I02-T5' }
                )&bitrate=12000"
            ) -TimeoutSec 30
            $keyMatch = [regex]::Match(
                [string]$broadcast.link, '\|live\|([0-9A-Fa-f]{32})\|')
            if (-not [bool]$broadcast.success -or
                -not [bool]$broadcast.ready -or
                -not $keyMatch.Success) {
                throw 'La emision I02 a 12 Mbps no quedo preparada.'
            }
            $streamKey = $keyMatch.Groups[1].Value.ToLowerInvariant()
            Write-K04Json -Path (Join-Path $jobRoot 'i02-ready.json') `
                -Value ([ordered]@{
                    schema = 'ese.v91.i02-source-ready/v1'
                    stream_key = $streamKey
                    tcp_port = $tcpPort
                    ipv6 = $localIPv6
                    ready_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                })
            Write-K04Progress -Phase $(
                if ($isO01) { 'o01_source_ready' }
                else { 'i02_source_ready' }) -Detail ([ordered]@{
                tcp_port = $tcpPort
            })
            $listener = [Net.Sockets.TcpListener]::new(
                [Net.IPAddress]::Parse($localIPv6), $i02ControlPort)
            try {
                $listener.Server.DualMode = $false
                $listener.Start(1)
                Write-K04Progress -Phase 'i02_control_listening' `
                    -Detail ([ordered]@{ port = $i02ControlPort })
                $accept = $listener.BeginAcceptTcpClient($null, $null)
                if (-not $accept.AsyncWaitHandle.WaitOne(180000)) {
                    throw 'El viewer no recogio el stream key I02.'
                }
                $controlClient = $listener.EndAcceptTcpClient($accept)
                try {
                    $writer = [IO.StreamWriter]::new(
                        $controlClient.GetStream(),
                        [Text.UTF8Encoding]::new($false))
                    try {
                        $writer.WriteLine((([ordered]@{
                            stream_key = $streamKey
                            source_ipv6 = $localIPv6
                            source_tcp_port = $tcpPort
                            source_ipv4 = if ($isO01) {
                                $localIPv4
                            } else { $null }
                            fixture_link = if ($isO01) {
                                $o01DirectLink
                            } else { $null }
                            fixture_name = if ($isO01) {
                                $i01FixtureName
                            } else { $null }
                            fixture_bytes = if ($isO01) {
                                $i01FixtureBytes
                            } else { $null }
                            fixture_sha256 = if ($isO01) {
                                $i01FixtureSha256
                            } else { $null }
                            fixture_ed2k = if ($isO01) {
                                $i01FixtureEd2k
                            } else { $null }
                        }) | ConvertTo-Json -Compress))
                        $writer.Flush()
                    } finally {
                        $writer.Dispose()
                    }
                } finally {
                    $controlClient.Dispose()
                }
            } finally {
                $listener.Stop()
            }
        } else {
            Write-K04Progress -Phase 'i02_waiting_control' `
                -Detail ([ordered]@{ port = $i02ControlPort })
            $controlDeadline = [DateTimeOffset]::UtcNow.AddSeconds(180)
            $controlLine = ''
            do {
                $controlClient = [Net.Sockets.TcpClient]::new(
                    [Net.Sockets.AddressFamily]::InterNetworkV6)
                try {
                    $connect = $controlClient.BeginConnect(
                        $peerIPv6, $i02ControlPort, $null, $null)
                    if ($connect.AsyncWaitHandle.WaitOne(2000)) {
                        $controlClient.EndConnect($connect)
                        $reader = [IO.StreamReader]::new(
                            $controlClient.GetStream(),
                            [Text.UTF8Encoding]::new($false))
                        try {
                            $controlLine = [string]$reader.ReadLine()
                        } finally {
                            $reader.Dispose()
                        }
                    }
                } catch {
                    $controlLine = ''
                } finally {
                    $controlClient.Dispose()
                }
                if (-not [string]::IsNullOrWhiteSpace($controlLine)) {
                    break
                }
                Start-Sleep -Milliseconds 500
            } while ([DateTimeOffset]::UtcNow -lt $controlDeadline)
            if ([string]::IsNullOrWhiteSpace($controlLine)) {
                throw 'No llego el stream key I02 del coordinador.'
            }
            $control = $controlLine | ConvertFrom-Json
            $streamKey = ([string]$control.stream_key).ToLowerInvariant()
            if ($streamKey -notmatch '^[0-9a-f]{32}$' -or
                [string]$control.source_ipv6 -cne $peerIPv6 -or
                [int]$control.source_tcp_port -ne $peerTcpPort) {
                throw 'El control I02 no coincide con la topologia fijada.'
            }
            if ($isO01) {
                $o01DirectLink = [string]$control.fixture_link
                if ([string]$control.source_ipv4 -cne $peerIPv4 -or
                    [string]$control.fixture_name -cne $i01FixtureName -or
                    [Int64]$control.fixture_bytes -ne $i01FixtureBytes -or
                    [string]$control.fixture_sha256 -cne
                        $i01FixtureSha256 -or
                    [string]$control.fixture_ed2k -cne $i01FixtureEd2k -or
                    $o01DirectLink -notmatch (
                        '\|sources,' + [regex]::Escape($peerIPv4) +
                        ':' + [string]$peerTcpPort + '\|/$')) {
                    throw 'El control O01 no coincide con la fixture T1 fijada.'
                }
            }
            Write-K04Progress -Phase $(
                if ($isO01) { 'o01_join_starting' }
                else { 'i02_join_starting' })
            $join = Invoke-RestMethod -Uri (
                "http://127.0.0.1:$webPort/api/live/direct_join" +
                "?key=$streamKey" +
                "&ip=$([Uri]::EscapeDataString($peerIPv6))" +
                "&port=$peerTcpPort&title=$(
                    if ($isO01) { 'V91-O01-T1' } else { 'V91-I02-T5' })"
            ) -TimeoutSec 20
            if (-not [bool]$join.success -or -not [bool]$join.dialed) {
                throw 'El viewer I02 no inicio el dial IPv6 directo.'
            }
            Write-K04Progress -Phase $(
                if ($isO01) { 'o01_viewer_joined' }
                else { 'i02_viewer_joined' })
        }

        if ($isO01) {
            $warmupSeconds = 120
            $warmupStarted = [DateTimeOffset]::UtcNow
            $warmupDeadline = $warmupStarted.AddSeconds($warmupSeconds)
            do {
                $process.Refresh()
                if ($process.HasExited) {
                    throw 'El candidato termino durante el warm-up O01.'
                }
                if ($i02Role -ceq 'viewer') {
                    $warmAlive = Invoke-RestMethod -Uri (
                        "http://127.0.0.1:$webPort/api/live/player-alive" +
                        "?key=$streamKey"
                    ) -TimeoutSec 5
                    if (-not [bool]$warmAlive.success) {
                        throw 'El heartbeat fue rechazado durante warm-up O01.'
                    }
                }
                $warmDebug = Invoke-RestMethod -Uri (
                    "http://127.0.0.1:$webPort/api/live/debug"
                ) -TimeoutSec 5
                $warmActive = if ($i02Role -ceq 'source') {
                    [bool]$warmDebug.broadcasting
                } else { [bool]$warmDebug.viewing }
                $warmHls = Get-I02HlsEvidence -Port $webPort `
                    -Role $i02Role -StreamKey $streamKey
                if (-not $warmActive) {
                    throw 'LiveTV dejo de estar activo durante warm-up O01.'
                }
                Write-K04Progress -Phase "o01_${i02Role}_warmup" `
                    -Detail ([ordered]@{
                        elapsed_seconds = [int](
                            [DateTimeOffset]::UtcNow -
                            $warmupStarted).TotalSeconds
                        target_seconds = $warmupSeconds
                        playlist_ok = [bool]$warmHls.playlist_ok
                        segment_ok = [bool]$warmHls.segment_ok
                    })
                if ([DateTimeOffset]::UtcNow -lt $warmupDeadline) {
                    Start-Sleep -Seconds 10
                }
            } while ([DateTimeOffset]::UtcNow -lt $warmupDeadline)
            if ($i02Role -ceq 'viewer') {
                Write-K04Progress -Phase 'o01_ipv4_transfer_injecting'
                Send-I01Ed2kLink -Process $process -Link $o01DirectLink
            }
            $i02Started = [DateTimeOffset]::UtcNow
        }
        $o01RouteInitial = if ($isO01) {
            Get-O01RouteEvidence -PeerIPv6 $peerIPv6 `
                -PeerIPv4 $peerIPv4 `
                -ExpectedInterfaceIndex $interfaceIndex
        } else { $null }
        $firstIPv6Tuple = $null
        $lastIPv6Tuple = $null
        $firstIPv4Tuple = $null
        $lastIPv4Tuple = $null
        $samples = [Collections.Generic.List[object]]::new()
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($postDuration)
        $peerRouteSeen = $false
        $playlistSeen = $false
        $segmentSeen = $false
        $initialChunks = -1L
        $finalChunks = -1L
        $initialDuplicates = -1L
        $finalDuplicates = -1L
        $initialWorkingSet = -1L
        $maxWorkingSet = -1L
        $initialHandles = -1
        $maxHandles = -1
        $o01IPv4PeerSeen = $false
        $o01FixtureCompleted = $false
        $o01Destination = if ($isO01 -and $i02Role -ceq 'viewer') {
            Join-Path (Join-Path $nodePath 'Incoming') $i01FixtureName
        } else { '' }
        do {
            $process.Refresh()
            if ($process.HasExited) {
                throw "El candidato I02 termino con codigo $($process.ExitCode)."
            }
            if ($i02Role -ceq 'viewer') {
                # The real watch page relays this heartbeat while it consumes
                # HLS. The lab validates HLS files directly, so mirror that
                # user activity or the 60-second ghost-viewer watchdog would
                # intentionally close an otherwise healthy stream.
                $alive = Invoke-RestMethod -Uri (
                    "http://127.0.0.1:$webPort/api/live/player-alive" +
                    "?key=$streamKey"
                ) -TimeoutSec $(if ($isO01) { 15 } else { 5 })
                if (-not [bool]$alive.success) {
                    throw 'El heartbeat del reproductor I02 fue rechazado.'
                }
            }
            $debug = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$webPort/api/live/debug" `
                -TimeoutSec $(if ($isO01) { 15 } else { 5 })
            $chunks = if (
                $null -ne $debug.PSObject.Properties['counters'] -and
                $null -ne $debug.counters.PSObject.Properties['chunksReceived']
            ) { [Int64]$debug.counters.chunksReceived } elseif (
                $null -ne $debug.PSObject.Properties['chunks'] -and
                $null -ne $debug.chunks.PSObject.Properties['count']
            ) { [Int64]$debug.chunks.count } else { 0L }
            if ($initialChunks -lt 0) { $initialChunks = $chunks }
            $finalChunks = $chunks
            $duplicates = if (
                $null -ne $debug.PSObject.Properties['counters'] -and
                $null -ne $debug.counters.PSObject.Properties[
                    'duplicateChunksReceived']
            ) { [Int64]$debug.counters.duplicateChunksReceived } else { 0L }
            if ($initialDuplicates -lt 0) {
                $initialDuplicates = $duplicates
            }
            $finalDuplicates = $duplicates
            $socketEvidence = Get-I02SocketEvidence `
                -ProcessId $process.Id -PeerIPv6 $peerIPv6 `
                -PeerIPv4 $(if ($isO01) { $peerIPv4 } else { '' }) `
                -LocalTcpPort $tcpPort -PeerTcpPort $peerTcpPort `
                -Role $i02Role
            if ([int]$socketEvidence.unexpected_ipv4 -ne 0) {
                throw 'I02 observo un socket peer IPv4 del candidato.'
            }
            if ([int]$socketEvidence.peer_ipv6 -gt 0) {
                $peerRouteSeen = $true
                $lastIPv6Tuple = $socketEvidence.peer_ipv6_tuples[0]
                if ($null -eq $firstIPv6Tuple) {
                    $firstIPv6Tuple = $lastIPv6Tuple
                }
            }
            if ($isO01 -and [int]$socketEvidence.peer_ipv4 -gt 0) {
                $o01IPv4PeerSeen = $true
                $lastIPv4Tuple = $socketEvidence.peer_ipv4_tuples[0]
                if ($null -eq $firstIPv4Tuple) {
                    $firstIPv4Tuple = $lastIPv4Tuple
                }
            }
            if ($isO01 -and $i02Role -ceq 'viewer' -and
                (Test-Path -LiteralPath $o01Destination -PathType Leaf) -and
                [Int64](Get-Item -LiteralPath $o01Destination).Length -eq
                    $i01FixtureBytes) {
                $o01FixtureCompleted = $true
            }
            $hls = Get-I02HlsEvidence -Port $webPort -Role $i02Role `
                -StreamKey $streamKey
            if ([bool]$hls.playlist_ok) { $playlistSeen = $true }
            if ([bool]$hls.segment_ok) { $segmentSeen = $true }
            $active = if ($i02Role -ceq 'source') {
                [bool]$debug.broadcasting
            } else {
                [bool]$debug.viewing
            }
            if (-not $active) {
                throw "I02 dejo de estar activo en el rol $i02Role."
            }
            $process.Refresh()
            if ($initialWorkingSet -lt 0) {
                $initialWorkingSet = [Int64]$process.WorkingSet64
                $initialHandles = [int]$process.HandleCount
            }
            $maxWorkingSet = [Math]::Max(
                $maxWorkingSet, [Int64]$process.WorkingSet64)
            $maxHandles = [Math]::Max(
                $maxHandles, [int]$process.HandleCount)
            $samples.Add([ordered]@{
                at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                active = $active
                chunks = $chunks
                duplicate_chunks = $duplicates
                peer_ipv6 = [int]$socketEvidence.peer_ipv6
                peer_ipv4 = [int]$socketEvidence.peer_ipv4
                unexpected_ipv4 = [int]$socketEvidence.unexpected_ipv4
                playlist_ok = [bool]$hls.playlist_ok
                segment_ok = [bool]$hls.segment_ok
                working_set = [Int64]$process.WorkingSet64
                handles = [int]$process.HandleCount
            })
            Write-K04Progress -Phase "$(
                if ($isO01) { 'o01' } else { 'i02' }
            )_${i02Role}_soak" `
                -Detail ([ordered]@{
                    elapsed_seconds = [int](
                        [DateTimeOffset]::UtcNow - $i02Started).TotalSeconds
                    target_seconds = $postDuration
                    samples = $samples.Count
                    peer_route_seen = $peerRouteSeen
                    playlist_seen = $playlistSeen
                    segment_seen = $segmentSeen
                    ipv4_transfer_seen = $o01IPv4PeerSeen
                    fixture_completed = $o01FixtureCompleted
                })
            if ([DateTimeOffset]::UtcNow -lt $deadline) {
                Start-Sleep -Seconds 15
            }
        } while ([DateTimeOffset]::UtcNow -lt $deadline)

        $o01DestinationHash = ''
        $o01DestinationEd2k = ''
        if ($isO01 -and $i02Role -ceq 'viewer') {
            if (-not $o01FixtureCompleted) {
                throw 'O01 no completo la fixture IPv4 dentro del soak.'
            }
            Write-K04Progress -Phase 'o01_fixture_hashing'
            $o01DestinationHash = (
                Get-FileHash -LiteralPath $o01Destination -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            $o01Session = Get-K04WebSession -Port $webPort `
                -Password $password
            $o01DestinationShared = Get-I01SharedLink -Port $webPort `
                -Session $o01Session -FileName $i01FixtureName `
                -FileBytes $i01FixtureBytes `
                -ExpectedEd2k $i01FixtureEd2k -TimeoutSeconds 300
            $o01DestinationEd2k = [string]$o01DestinationShared.ed2k
        }
        $receivedDelta = $finalChunks - $initialChunks
        $duplicateDelta = $finalDuplicates - $initialDuplicates
        $duplicateRatio = if ($receivedDelta -gt 0) {
            [double]$duplicateDelta / [double]$receivedDelta
        } else { 0.0 }
        $initialRatio = if ($initialChunks -gt 0) {
            [double]$initialDuplicates / [double]$initialChunks
        } else { 0.0 }
        $finalRatio = if ($finalChunks -gt 0) {
            [double]$finalDuplicates / [double]$finalChunks
        } else { 0.0 }
        $ratioDrift = $finalRatio - $initialRatio
        $maxSampleGapSeconds = 0.0
        $countersMonotonic = $true
        for ($sampleIndex = 1; $sampleIndex -lt $samples.Count;
            ++$sampleIndex) {
            $gap = (
                [DateTimeOffset]::Parse(
                    [string]$samples[$sampleIndex].at_utc) -
                [DateTimeOffset]::Parse(
                    [string]$samples[$sampleIndex - 1].at_utc)
            ).TotalSeconds
            $maxSampleGapSeconds = [Math]::Max(
                $maxSampleGapSeconds, $gap)
            if ([Int64]$samples[$sampleIndex].chunks -lt
                    [Int64]$samples[$sampleIndex - 1].chunks -or
                [Int64]$samples[$sampleIndex].duplicate_chunks -lt
                    [Int64]$samples[$sampleIndex - 1].duplicate_chunks) {
                $countersMonotonic = $false
            }
        }
        $sampleSpanSeconds = if ($samples.Count -ge 2) {
            (
                [DateTimeOffset]::Parse(
                    [string]$samples[$samples.Count - 1].at_utc) -
                [DateTimeOffset]::Parse(
                    [string]$samples[0].at_utc)
            ).TotalSeconds
        } else { 0.0 }
        $o01RouteFinal = if ($isO01) {
            Get-O01RouteEvidence -PeerIPv6 $peerIPv6 `
                -PeerIPv4 $peerIPv4 `
                -ExpectedInterfaceIndex $interfaceIndex
        } else { $null }
        $process.Refresh()
        $finalWorkingSet = [Int64]$process.WorkingSet64
        $finalHandles = [int]$process.HandleCount
        $workingSetGrowth = $finalWorkingSet - $initialWorkingSet
        $handleGrowth = $finalHandles - $initialHandles
        $peakWorkingSetGrowth = $maxWorkingSet - $initialWorkingSet
        $peakHandleGrowth = $maxHandles - $initialHandles
        $commonPass = (
            $peerRouteSeen -and $playlistSeen -and $segmentSeen -and
            ($i02Role -cne 'viewer' -or $finalChunks -gt $initialChunks)
        )
        $o01Pass = (
            $commonPass -and $o01IPv4PeerSeen -and
            $workingSetGrowth -le 268435456L -and
            $handleGrowth -le 1024 -and
            $samples.Count -ge 2 -and
            $maxSampleGapSeconds -le 30.0 -and
            $sampleSpanSeconds -ge ($postDuration - 30) -and
            $countersMonotonic -and
            $null -ne $firstIPv6Tuple -and
            $null -ne $lastIPv6Tuple -and
            $null -ne $firstIPv4Tuple -and
            $null -ne $lastIPv4Tuple -and
            [string]$o01RouteInitial.interface_guid -ceq
                [string]$o01RouteFinal.interface_guid -and
            ($i02Role -cne 'viewer' -or (
                $o01FixtureCompleted -and
                $o01DestinationHash -ceq $i01FixtureSha256 -and
                $o01DestinationEd2k -ceq $i01FixtureEd2k -and
                $duplicateDelta -ge 0 -and
                $duplicateRatio -le 0.25 -and
                $ratioDrift -le 0.05))
        )
        $nodeStatus = if ($isO01) {
            if (-not $o01Pass) { 'FAIL' }
            elseif ($postDuration -ge 43200) { 'PASS' }
            else { 'PREFLIGHT_PASS' }
        } elseif ($commonPass) { 'PASS' } else { 'FAIL' }
        $postResult = [ordered]@{
            schema = if ($isO01) {
                'ese.v91.o01-node-result/v1'
            } else { 'ese.v91.i02-node-result/v1' }
            case_id = if ($isO01) { 'V91-O01' } else { 'V91-I02' }
            status = $nodeStatus
            role = $i02Role
            started_at_utc = $i02Started.ToString('o')
            completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            requested_duration_seconds = $postDuration
            candidate_sha256 = $actualHash
            stream_key_sha256 = (
                [BitConverter]::ToString(
                    [Security.Cryptography.SHA256]::Create().ComputeHash(
                        [Text.Encoding]::ASCII.GetBytes($streamKey))
                ).Replace('-', '').ToLowerInvariant()
            )
            initial_chunks = $initialChunks
            final_chunks = $finalChunks
            initial_duplicate_chunks = $initialDuplicates
            final_duplicate_chunks = $finalDuplicates
            duplicate_delta_ratio = $duplicateRatio
            cumulative_ratio_drift = $ratioDrift
            peer_route_seen = $peerRouteSeen
            ipv4_peer_seen = $o01IPv4PeerSeen
            playlist_seen = $playlistSeen
            segment_seen = $segmentSeen
            resource_growth = [ordered]@{
                working_set_bytes = $workingSetGrowth
                handles = $handleGrowth
                peak_working_set_bytes = $peakWorkingSetGrowth
                peak_handles = $peakHandleGrowth
            }
            sampling = if ($isO01) {
                [ordered]@{
                    count = $samples.Count
                    maximum_gap_seconds = $maxSampleGapSeconds
                    span_seconds = $sampleSpanSeconds
                    counters_monotonic = $countersMonotonic
                }
            } else { $null }
            routes = if ($isO01) {
                [ordered]@{
                    initial = $o01RouteInitial
                    final = $o01RouteFinal
                }
            } else { $null }
            peer_tuples = if ($isO01) {
                [ordered]@{
                    first_ipv6 = $firstIPv6Tuple
                    last_ipv6 = $lastIPv6Tuple
                    first_ipv4 = $firstIPv4Tuple
                    last_ipv4 = $lastIPv4Tuple
                }
            } else { $null }
            fixture = if ($isO01) {
                [ordered]@{
                    name = $i01FixtureName
                    bytes = $i01FixtureBytes
                    sha256 = $i01FixtureSha256
                    ed2k = $i01FixtureEd2k
                    local_sha256 = if ($i02Role -ceq 'viewer') {
                        $o01DestinationHash
                    } else { $i01FixtureSha256 }
                    local_ed2k = if ($i02Role -ceq 'viewer') {
                        $o01DestinationEd2k
                    } else { $o01SourceEd2k }
                    transport_family = 'IPv4'
                    source_ipv4 = if ($i02Role -ceq 'source') {
                        $localIPv4
                    } else { $peerIPv4 }
                }
            } else { $null }
            live_transport = if ($isO01) {
                [ordered]@{
                    family = 'IPv6'
                    source_ipv6 = if ($i02Role -ceq 'source') {
                        $localIPv6
                    } else { $peerIPv6 }
                    ipv6_peer_seen = $peerRouteSeen
                }
            } else { $null }
            samples = $samples
        }
        Write-K04Json -Path (Join-Path $jobRoot $(
            if ($isO01) { 'o01-result.json' } else { 'i02-result.json' })) `
            -Value $postResult
        if ([string]$postResult.status -notin @('PASS', 'PREFLIGHT_PASS')) {
            throw 'El soak no acredito transporte, integridad o estabilidad.'
        }
        Write-K04Progress -Phase "$(
            if ($isO01) { 'o01' } else { 'i02' }
        )_${i02Role}_complete"
        if ($i02Role -ceq 'source') {
            Start-Sleep -Seconds 45
        }
    }

    if ($postAction -like 'i08-*') {
        $i08Role = if ($postAction -ceq 'i08-server') {
            'echo_fixture'
        } elseif ($postAction -ceq 'i08-client') {
            'client'
        } else {
            throw "Accion posterior desconocida: $postAction"
        }
        if ($i08TcpPort -lt 1024 -or $i08TcpPort -gt 65535 -or
            $i08UdpPort -lt 1024 -or $i08UdpPort -gt 65535 -or
            $i02ControlPort -lt 1024 -or $i02ControlPort -gt 65535 -or
            $i08Nonce -notmatch '^[0-9a-f]{32}$') {
            throw 'La accion I08 requiere puertos y nonce fijados.'
        }
        $i08Started = [DateTimeOffset]::UtcNow
        if ($i08Role -ceq 'echo_fixture') {
            Write-K04Progress -Phase 'i08_echo_listening' `
                -Detail ([ordered]@{
                    tcp_port = $i08TcpPort
                    udp_port = $i08UdpPort
                    control_port = $i02ControlPort
                })
            $signalReady = {
                $controlListener = [Net.Sockets.TcpListener]::new(
                    [Net.IPAddress]::Parse($localIPv6), $i02ControlPort)
                $controlClient = $null
                try {
                    $controlListener.Start(1)
                    $acceptControl = $controlListener.BeginAcceptTcpClient(
                        $null, $null)
                    if (-not $acceptControl.AsyncWaitHandle.WaitOne(180000)) {
                        throw 'Timeout esperando al cliente de control I08.'
                    }
                    $controlClient = $controlListener.EndAcceptTcpClient(
                        $acceptControl)
                    $writer = [IO.StreamWriter]::new(
                        $controlClient.GetStream(),
                        [Text.UTF8Encoding]::new($false))
                    try {
                        $writer.WriteLine((([ordered]@{
                            schema = 'ese.v91.i08-ready/v1'
                            nonce = $i08Nonce
                            target_ipv6 = $localIPv6
                            tcp_port = $i08TcpPort
                            udp_port = $i08UdpPort
                        }) | ConvertTo-Json -Compress))
                        $writer.Flush()
                    } finally {
                        $writer.Dispose()
                    }
                } finally {
                    if ($null -ne $controlClient) {
                        $controlClient.Dispose()
                    }
                    $controlListener.Stop()
                }
            }
            $fixture = Invoke-I08EchoFixture -LocalIPv6 $localIPv6 `
                -PeerIPv6 $peerIPv6 -TcpPort $i08TcpPort `
                -UdpPort $i08UdpPort -Nonce $i08Nonce `
                -SignalReady $signalReady -TimeoutSeconds 120
            $postResult = [ordered]@{
                schema = 'ese.v91.i08-node-result/v1'
                case_id = 'V91-I08'
                status = 'PASS'
                role = $i08Role
                started_at_utc = $i08Started.ToString('o')
                completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                candidate_sha256 = $actualHash
                fixture = $fixture
            }
        } else {
            Write-K04Progress -Phase 'i08_waiting_fixture'
            $controlDeadline = [DateTimeOffset]::UtcNow.AddSeconds(180)
            $readyLine = ''
            do {
                $controlClient = $null
                try {
                    $controlClient = [Net.Sockets.TcpClient]::new(
                        [Net.Sockets.AddressFamily]::InterNetworkV6)
                    $connect = $controlClient.BeginConnect(
                        $peerIPv6, $i02ControlPort, $null, $null)
                    if ($connect.AsyncWaitHandle.WaitOne(2000)) {
                        $controlClient.EndConnect($connect)
                        $reader = [IO.StreamReader]::new(
                            $controlClient.GetStream(),
                            [Text.UTF8Encoding]::new($false))
                        try {
                            $readyLine = [string]$reader.ReadLine()
                        } finally {
                            $reader.Dispose()
                        }
                    }
                } catch {
                    $readyLine = ''
                } finally {
                    if ($null -ne $controlClient) {
                        $controlClient.Dispose()
                    }
                }
                if (-not [string]::IsNullOrWhiteSpace($readyLine)) {
                    break
                }
                Start-Sleep -Milliseconds 500
            } while ([DateTimeOffset]::UtcNow -lt $controlDeadline)
            if ([string]::IsNullOrWhiteSpace($readyLine)) {
                throw 'El fixture I08 no anuncio READY.'
            }
            $ready = $readyLine | ConvertFrom-Json
            if ([string]$ready.schema -cne 'ese.v91.i08-ready/v1' -or
                [string]$ready.nonce -cne $i08Nonce -or
                [string]$ready.target_ipv6 -cne $peerIPv6 -or
                [int]$ready.tcp_port -ne $i08TcpPort -or
                [int]$ready.udp_port -ne $i08UdpPort) {
                throw 'El READY I08 no coincide con el contrato.'
            }
            Write-K04Progress -Phase 'i08_client_action'
            $uri = (
                "http://127.0.0.1:$webPort/api/ese/netlab/ipv6_echo" +
                "?target=$([Uri]::EscapeDataString($peerIPv6))" +
                "&tcp_port=$i08TcpPort&udp_port=$i08UdpPort" +
                "&nonce=$i08Nonce&timeout_ms=8000")
            $action = Invoke-RestMethod -Uri $uri -TimeoutSec 25
            $actionTargetMatches = $false
            try {
                $actionTargetMatches = (
                    [Net.IPAddress]::Parse([string]$action.target).Equals(
                        [Net.IPAddress]::Parse($peerIPv6)))
            } catch {}
            if (-not [bool]$action.success -or
                [string]$action.schema -cne
                    'ese.v91.i08-client-action/v1' -or
                -not $actionTargetMatches -or
                [string]$action.nonce -cne $i08Nonce -or
                [int]$action.tcp_port -ne $i08TcpPort -or
                [int]$action.udp_port -ne $i08UdpPort -or
                [int]$action.tcp.error -ne 0 -or
                [int]$action.udp.error -ne 0 -or
                [int]$action.tcp.bytes -le 0 -or
                [int]$action.tcp.bytes -ne [int]$action.udp.bytes) {
                throw 'La accion real del cliente I08 no paso TCP+UDP.'
            }
            $postResult = [ordered]@{
                schema = 'ese.v91.i08-node-result/v1'
                case_id = 'V91-I08'
                status = 'PASS'
                role = $i08Role
                started_at_utc = $i08Started.ToString('o')
                completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                candidate_sha256 = $actualHash
                ready = $ready
                client_action = $action
            }
        }
        Write-K04Json -Path (Join-Path $jobRoot 'i08-result.json') `
            -Value $postResult
        Write-K04Progress -Phase "i08_${i08Role}_complete"
    }

    if ($postAction -like 'k01-*') {
        $k01Role = if ($postAction -ceq 'k01-source') {
            'source'
        } elseif ($postAction -ceq 'k01-requester') {
            'requester'
        } else {
            throw "Accion posterior desconocida: $postAction"
        }
        if ($peerTcpPort -le 0 -or $secondaryTcpPort -le 0 -or
            $i02ControlPort -le 0) {
            throw 'La accion K01 requiere los puertos TCP fijados.'
        }
        $k01Started = [DateTimeOffset]::UtcNow
        $session = Get-K04WebSession -Port $webPort -Password $password
        $secondarySession = ''
        $guardSession = ''
        $secondaryPeers = $null

        if ($k01Role -ceq 'source') {
            if ($secondaryUdpPort -le 0 -or $secondaryWebPort -le 0 -or
                [string]::IsNullOrWhiteSpace($guardIPv6) -or
                $guardTcpPort -le 0 -or $guardUdpPort -le 0 -or
                $guardWebPort -le 0) {
                throw (
                    'El source K01 requiere los puertos del relay y del guard.')
            }
            Write-K04Progress -Phase 'k01_relay_preparing'
            foreach ($secondaryDirectory in @(
                $secondaryNodePath,
                (Join-Path $secondaryNodePath 'config'),
                (Join-Path $secondaryNodePath 'Incoming'),
                (Join-Path $secondaryNodePath 'Temp')
            )) {
                New-Item -ItemType Directory -Path $secondaryDirectory -Force |
                    Out-Null
            }
            # K01's third node is a protocol-only relay. Copying the complete
            # portable package also copied FFmpeg, FFprobe and ese-server
            # (over 500 MB), consuming most of the peer/circuit timeout before
            # the relay could listen. The native Web API only needs the
            # candidate executable and its template.
            foreach ($templateRelative in @(
                'eMule.tmpl', 'config\eMule.tmpl'
            )) {
                $templateSource = Join-Path $baseNode $templateRelative
                if (Test-Path -LiteralPath $templateSource -PathType Leaf) {
                    $templateTarget = Join-Path $secondaryNodePath (
                        $templateRelative)
                    Copy-Item -LiteralPath $templateSource `
                        -Destination $templateTarget -Force
                }
            }
            $secondaryEmule = Join-Path $secondaryNodePath 'emule.exe'
            Copy-Item -LiteralPath $emulePath -Destination $secondaryEmule `
                -Force
            Unblock-File -LiteralPath $secondaryEmule `
                -ErrorAction SilentlyContinue
            foreach ($staleName in @(
                'AC_BootstrapIPs.dat', 'AC_SearchStrings.dat',
                'AC_ServerMetURLs.dat', 'cancelled.met', 'clients.met',
                'clients.met.bak', 'cryptkey.dat', 'emfriends.met',
                'known.met', 'node_identity.dat', 'nodes.dat',
                'nodes_v6.dat',
                'preferences.dat', 'server.met', 'server_met.old',
                'sharedfiles.dat', 'StoredSearches.met'
            )) {
                Remove-Item -LiteralPath (
                    Join-Path $secondaryNodePath "config\$staleName") `
                    -Force -ErrorAction SilentlyContinue
            }
            $secondaryPreferences = Join-Path $secondaryNodePath (
                'config\preferences.ini')
            [IO.File]::WriteAllText(
                $secondaryPreferences, '',
                (New-Object Text.UTF8Encoding($false)))
            $secondaryPassword = [Guid]::NewGuid().ToString('N')
            foreach ($entry in @(
                @('eMule', 'AppVersion', '0.70b x64 - eSE 9.1.0-rc.3'),
                @('eMule', 'BindAddr', ''),
                @('eMule', 'Port', [string]$secondaryTcpPort),
                @('eMule', 'UDPPort', [string]$secondaryUdpPort),
                @('eMule', 'NetworkKademlia', '0'),
                @('eMule', 'NetworkED2K', '0'),
                @('eMule', 'AutoConnect', '0'),
                @('eMule', 'SaveLogToDisk', '1'),
                @('eMule', 'SaveDebugToDisk', '1'),
                @('eMule', 'VerboseOptions', '1'),
                @('eMule', 'Verbose', '1'),
                @('eMule', 'FullVerbose', '1'),
                @('Connection', 'KadNetworkMask', '2'),
                @('Connection', 'NetworkED2K', '0'),
                @('Connection', 'IPv6Mode', '2'),
                @('Connection', 'IPv6BindAddr', $secondaryIPv6),
                @('WebServer', 'Enabled', '1'),
                @('WebServer', 'Port', [string]$secondaryWebPort),
                @('WebServer', 'WebUseUPnP', '0'),
                @('WebServer', 'Password',
                    (Get-K04Md5 -Value $secondaryPassword)),
                @('WebServer', 'AllowAdminHiLevelFunc', '1'),
                @('eSE', 'Kad6PublicExitOptIn', '0'),
                @('eSE', 'Kad6BetaExitOptIn', '1'),
                @('eSE', 'EseNetLabConsent', '2'),
                @('eSE', 'EseNetLabAdvancedConsent', '2'),
                @('eSE', 'EseNetLabContributionConsent', '2'),
                @('eSE', 'EseNetLabEnabled', '1'),
                @('eSE', 'EseV9Experimental', '1')
            )) {
                Set-K04IniValue -Path $secondaryPreferences `
                    -Section $entry[0] -Key $entry[1] -Value $entry[2]
            }

            $existingSecondaryAddress = Get-NetIPAddress `
                -InterfaceIndex $interfaceIndex -AddressFamily IPv6 `
                -ErrorAction SilentlyContinue |
                Where-Object IPAddress -EQ $secondaryIPv6
            if ($null -eq $existingSecondaryAddress) {
                New-NetIPAddress -InterfaceIndex $interfaceIndex `
                    -IPAddress $secondaryIPv6 -PrefixLength 64 `
                    -AddressFamily IPv6 -Type Unicast | Out-Null
                $secondaryAddressCreated = $true
            }
            $relayUdpRule = "eSE-V91-K01-relay-udp-$jobId"
            New-NetFirewallRule -Name $relayUdpRule `
                -DisplayName $relayUdpRule -Direction Inbound `
                -Action Allow -Protocol UDP -LocalPort $secondaryUdpPort `
                -LocalAddress "$secondaryIPv6/128" `
                -RemoteAddress @("$localIPv6/128", "$peerIPv6/128") `
                -InterfaceAlias $interfaceAlias `
                -Program $secondaryEmule | Out-Null
            $ruleNames.Add($relayUdpRule)
            $relayTcpRule = "eSE-V91-K01-relay-tcp-$jobId"
            New-NetFirewallRule -Name $relayTcpRule `
                -DisplayName $relayTcpRule -Direction Inbound `
                -Action Allow -Protocol TCP -LocalPort $secondaryTcpPort `
                -LocalAddress "$secondaryIPv6/128" `
                -RemoteAddress @("$peerIPv6/128", "$localIPv6/128") `
                -InterfaceAlias $interfaceAlias `
                -Program $secondaryEmule | Out-Null
            $ruleNames.Add($relayTcpRule)
            foreach ($direction in @('Inbound', 'Outbound')) {
                $relayV4Rule = (
                    "eSE-V91-K01-relay-v4-$($direction.ToLower())-$jobId")
                New-NetFirewallRule -Name $relayV4Rule `
                    -DisplayName $relayV4Rule -Direction $direction `
                    -Action Block -Protocol UDP `
                    -LocalPort $secondaryUdpPort `
                    -RemoteAddress '0.0.0.0/0' `
                    -Program $secondaryEmule | Out-Null
                $ruleNames.Add($relayV4Rule)
            }

            $secondaryArguments = @(
                '--portable', '--ignoreinstances', '--headless',
                "--metrics-port=$secondaryWebPort",
                "--tcp-port=$secondaryTcpPort",
                "--udp-port=$secondaryUdpPort"
            )
            $secondaryProcess = Start-Process -FilePath $secondaryEmule `
                -ArgumentList $secondaryArguments `
                -WorkingDirectory $secondaryNodePath `
                -WindowStyle Hidden -PassThru
            $null = Wait-K04Api -Process $secondaryProcess `
                -Port $secondaryWebPort
            $secondarySession = Get-K04WebSession `
                -Port $secondaryWebPort -Password $secondaryPassword
            $secondaryStatus = Start-K04Kad -Port $secondaryWebPort
            if ([int]$secondaryStatus.kad_configured_mask -ne 2 -or
                [int]$secondaryStatus.kad_running_mask -ne 2 -or
                [bool]$secondaryStatus.kad2_running -or
                -not [bool]$secondaryStatus.kad6_running) {
                throw 'El relay K01 no arranco exclusivamente en Kad6.'
            }
            # A relay selected as the source's exit can become the native
            # publisher/custodian. Require the deterministic nodes_v6.dat seed
            # copied above to re-verify before circuit use; otherwise a locally
            # stored record at a zero-contact exit is valid but undiscoverable
            # from the requester's independently selected exit.
            $relayKadDeadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
            do {
                Invoke-K04Bootstrap -Port $secondaryWebPort `
                    -Session $secondarySession -HostName $localIPv6 `
                    -PeerPort $udpPort
                Invoke-K04Bootstrap -Port $webPort `
                    -Session $session -HostName $secondaryIPv6 `
                    -PeerPort $secondaryUdpPort
                Start-Sleep -Seconds 1
                $secondaryStatus = Get-K04Status -Port $secondaryWebPort
                Write-K04Progress -Phase 'k01_relay_kad6_verifying' `
                    -Detail ([ordered]@{
                        verified = [int](
                            $secondaryStatus.kad6_verified_contacts)
                    })
            } while (
                [int]$secondaryStatus.kad6_verified_contacts -le 0 -and
                [DateTimeOffset]::UtcNow -lt $relayKadDeadline
            )
            if ([int]$secondaryStatus.kad6_verified_contacts -le 0) {
                throw 'El relay K01 no verifico ningun contacto Kad6.'
            }
            Invoke-K01DirectJoin -Port $secondaryWebPort `
                -Key '44444444444444444444444444444444' `
                -PeerIPv6 $localIPv6 -PeerTcpPort $tcpPort `
                -Title 'K01-relay-bootstrap-source'
            $relayBootstrapPeers = Wait-K01PeerAddress `
                -Port $secondaryWebPort -PeerIPv6 $localIPv6 `
                -MinimumAuthenticated 1 -TimeoutSeconds 60
            $secondaryStatus = Get-K04Status -Port $secondaryWebPort
            Write-K04Progress -Phase 'k01_relay_ready' -Detail ([ordered]@{
                ipv6 = $secondaryIPv6
                tcp_port = $secondaryTcpPort
                verified = [int]$secondaryStatus.kad6_verified_contacts
                authenticated = [int](
                    $relayBootstrapPeers.authenticatedTunnelCapable)
            })

            # K6 economy admission requires a quota issuer outside the two-hop
            # private path. Prepare one distinct identity now, but do not
            # connect it until the source circuit has frozen its two hops.
            Write-K04Progress -Phase 'k01_guard_preparing'
            foreach ($guardDirectory in @(
                $guardNodePath,
                (Join-Path $guardNodePath 'config'),
                (Join-Path $guardNodePath 'Incoming'),
                (Join-Path $guardNodePath 'Temp')
            )) {
                New-Item -ItemType Directory -Path $guardDirectory -Force |
                    Out-Null
            }
            foreach ($templateRelative in @(
                'eMule.tmpl', 'config\eMule.tmpl'
            )) {
                $templateSource = Join-Path $baseNode $templateRelative
                if (Test-Path -LiteralPath $templateSource -PathType Leaf) {
                    Copy-Item -LiteralPath $templateSource -Destination (
                        Join-Path $guardNodePath $templateRelative) -Force
                }
            }
            $guardEmule = Join-Path $guardNodePath 'emule.exe'
            Copy-Item -LiteralPath $emulePath -Destination $guardEmule -Force
            Unblock-File -LiteralPath $guardEmule `
                -ErrorAction SilentlyContinue
            $guardPreferences = Join-Path $guardNodePath (
                'config\preferences.ini')
            [IO.File]::WriteAllText(
                $guardPreferences, '',
                (New-Object Text.UTF8Encoding($false)))
            Copy-Item -LiteralPath $nodesPath -Destination (
                Join-Path $guardNodePath 'config\nodes_v6.dat') -Force
            $guardPassword = [Guid]::NewGuid().ToString('N')
            foreach ($entry in @(
                @('eMule', 'AppVersion', '0.70b x64 - eSE 9.1.0-rc.3'),
                @('eMule', 'BindAddr', ''),
                @('eMule', 'Port', [string]$guardTcpPort),
                @('eMule', 'UDPPort', [string]$guardUdpPort),
                @('eMule', 'NetworkKademlia', '0'),
                @('eMule', 'NetworkED2K', '0'),
                @('eMule', 'AutoConnect', '0'),
                @('eMule', 'SaveLogToDisk', '1'),
                @('eMule', 'SaveDebugToDisk', '1'),
                @('eMule', 'VerboseOptions', '1'),
                @('eMule', 'Verbose', '1'),
                @('eMule', 'FullVerbose', '1'),
                @('Connection', 'KadNetworkMask', '2'),
                @('Connection', 'NetworkED2K', '0'),
                @('Connection', 'IPv6Mode', '2'),
                @('Connection', 'IPv6BindAddr', $guardIPv6),
                @('WebServer', 'Enabled', '1'),
                @('WebServer', 'Port', [string]$guardWebPort),
                @('WebServer', 'WebUseUPnP', '0'),
                @('WebServer', 'Password', (Get-K04Md5 -Value $guardPassword)),
                @('WebServer', 'AllowAdminHiLevelFunc', '1'),
                @('eSE', 'Kad6PublicExitOptIn', '0'),
                @('eSE', 'Kad6BetaExitOptIn', '1'),
                @('eSE', 'EseNetLabConsent', '2'),
                @('eSE', 'EseNetLabAdvancedConsent', '2'),
                @('eSE', 'EseNetLabContributionConsent', '2'),
                @('eSE', 'EseNetLabEnabled', '1'),
                @('eSE', 'EseV9Experimental', '1')
            )) {
                Set-K04IniValue -Path $guardPreferences `
                    -Section $entry[0] -Key $entry[1] -Value $entry[2]
            }
            $existingGuardAddress = Get-NetIPAddress `
                -InterfaceIndex $interfaceIndex -AddressFamily IPv6 `
                -ErrorAction SilentlyContinue |
                Where-Object IPAddress -EQ $guardIPv6
            if ($null -eq $existingGuardAddress) {
                New-NetIPAddress -InterfaceIndex $interfaceIndex `
                    -IPAddress $guardIPv6 -PrefixLength 64 `
                    -AddressFamily IPv6 -Type Unicast | Out-Null
                $guardAddressCreated = $true
            }
            $guardTcpRule = "eSE-V91-K01-guard-tcp-$jobId"
            New-NetFirewallRule -Name $guardTcpRule `
                -DisplayName $guardTcpRule -Direction Inbound `
                -Action Allow -Protocol TCP -LocalPort $guardTcpPort `
                -LocalAddress "$guardIPv6/128" `
                -RemoteAddress @("$localIPv6/128", "$peerIPv6/128") `
                -InterfaceAlias $interfaceAlias -Program $guardEmule |
                Out-Null
            $ruleNames.Add($guardTcpRule)
            $guardUdpRule = "eSE-V91-K01-guard-udp-$jobId"
            New-NetFirewallRule -Name $guardUdpRule `
                -DisplayName $guardUdpRule -Direction Inbound `
                -Action Allow -Protocol UDP -LocalPort $guardUdpPort `
                -LocalAddress "$guardIPv6/128" `
                -RemoteAddress @(
                    "$localIPv6/128", "$peerIPv6/128",
                    "$secondaryIPv6/128") `
                -InterfaceAlias $interfaceAlias -Program $guardEmule |
                Out-Null
            $ruleNames.Add($guardUdpRule)
            foreach ($direction in @('Inbound', 'Outbound')) {
                $guardV4Rule = (
                    "eSE-V91-K01-guard-v4-$($direction.ToLower())-$jobId")
                New-NetFirewallRule -Name $guardV4Rule `
                    -DisplayName $guardV4Rule -Direction $direction `
                    -Action Block -Protocol UDP -LocalPort $guardUdpPort `
                    -RemoteAddress '0.0.0.0/0' -Program $guardEmule |
                    Out-Null
                $ruleNames.Add($guardV4Rule)
            }
            $guardProcess = Start-Process -FilePath $guardEmule `
                -ArgumentList @(
                    '--portable', '--ignoreinstances', '--headless',
                    "--metrics-port=$guardWebPort",
                    "--tcp-port=$guardTcpPort",
                    "--udp-port=$guardUdpPort"
                ) -WorkingDirectory $guardNodePath `
                -WindowStyle Hidden -PassThru
            $null = Wait-K04Api -Process $guardProcess -Port $guardWebPort
            $guardSession = Get-K04WebSession `
                -Port $guardWebPort -Password $guardPassword
            $guardStatus = Start-K04Kad -Port $guardWebPort
            if ([int]$guardStatus.kad_configured_mask -ne 2 -or
                [int]$guardStatus.kad_running_mask -ne 2 -or
                [bool]$guardStatus.kad2_running -or
                -not [bool]$guardStatus.kad6_running) {
                throw 'El guard K01 no arranco exclusivamente en Kad6.'
            }
            Write-K04Progress -Phase 'k01_guard_ready' -Detail ([ordered]@{
                ipv6 = $guardIPv6
                tcp_port = $guardTcpPort
            })

            $secondaryTargets = @(
                [pscustomobject]@{
                    key = '44444444444444444444444444444444'
                    ipv6 = $localIPv6
                    port = $tcpPort
                    title = 'K01-relay-to-source'
                },
                [pscustomobject]@{
                    key = '33333333333333333333333333333333'
                    ipv6 = $peerIPv6
                    port = $peerTcpPort
                    title = 'K01-relay-to-requester'
                }
            )
            foreach ($target in $secondaryTargets) {
                try {
                    Invoke-K01DirectJoin -Port $secondaryWebPort `
                        -Key $target.key -PeerIPv6 $target.ipv6 `
                        -PeerTcpPort $target.port -Title $target.title
                } catch {}
            }
        }

        $primaryTargets = if ($k01Role -ceq 'source') {
            @(
                [pscustomobject]@{
                    key = '11111111111111111111111111111111'
                    ipv6 = $peerIPv6
                    port = $peerTcpPort
                    title = 'K01-source-to-requester'
                },
                [pscustomobject]@{
                    key = '22222222222222222222222222222222'
                    ipv6 = $secondaryIPv6
                    port = $secondaryTcpPort
                    title = 'K01-source-to-relay'
                }
            )
        } else {
            @(
                [pscustomobject]@{
                    key = '66666666666666666666666666666666'
                    ipv6 = $secondaryIPv6
                    port = $secondaryTcpPort
                    title = 'K01-requester-to-relay'
                },
                [pscustomobject]@{
                    key = '55555555555555555555555555555555'
                    ipv6 = $peerIPv6
                    port = $peerTcpPort
                    title = 'K01-requester-to-source'
                }
            )
        }
        Write-K04Progress -Phase "k01_${k01Role}_peering"
        $primaryPeers = Wait-K01Peers -Port $webPort `
            -Targets $primaryTargets -TimeoutSeconds 180
        if ($k01Role -ceq 'source') {
            $secondaryPeers = Wait-K01Peers -Port $secondaryWebPort `
                -Targets $secondaryTargets -TimeoutSeconds 180
        }
        Write-K04Progress -Phase "k01_${k01Role}_circuit_building" `
            -Detail ([ordered]@{
                fork_peers = [int]$primaryPeers.forkTunnelingCapable
            })
        $circuit = New-K01Circuit -Port $webPort -TimeoutSeconds 180
        Write-K04Progress -Phase "k01_${k01Role}_circuit_active" `
            -Detail $circuit.active

        $guardSourcePeers = $null
        if ($k01Role -ceq 'source') {
            # The economy exit must know the independent issuer before it
            # verifies the quota presentation. Authenticate the guard with the
            # requester first; the source's private circuit is already frozen,
            # so this peer cannot be selected into its two-hop data path.
            Invoke-K01DirectJoin -Port $guardWebPort `
                -Key '88888888888888888888888888888888' `
                -PeerIPv6 $peerIPv6 -PeerTcpPort $peerTcpPort `
                -Title 'K01-quota-guard-pretrust-requester'
            $null = Wait-K01PeerAddress -Port $guardWebPort `
                -PeerIPv6 $peerIPv6 -MinimumAuthenticated 1 `
                -TimeoutSeconds 90
            Invoke-K01DirectJoin -Port $guardWebPort `
                -Key '99999999999999999999999999999999' `
                -PeerIPv6 $secondaryIPv6 -PeerTcpPort $secondaryTcpPort `
                -Title 'K01-quota-guard-pretrust-relay'
            $null = Wait-K01PeerAddress -Port $guardWebPort `
                -PeerIPv6 $secondaryIPv6 -MinimumAuthenticated 2 `
                -TimeoutSeconds 90
            Write-K04Progress -Phase 'k01_guard_pretrusted_by_requester' `
                -Detail ([ordered]@{
                    guard_ipv6 = $guardIPv6
                    requester_ipv6 = $peerIPv6
                    relay_ipv6 = $secondaryIPv6
                })
            Invoke-K01DirectJoin -Port $guardWebPort `
                -Key '77777777777777777777777777777777' `
                -PeerIPv6 $localIPv6 -PeerTcpPort $tcpPort `
                -Title 'K01-quota-guard-to-source'
            $guardSourcePeers = Wait-K01PeerAddress -Port $webPort `
                -PeerIPv6 $guardIPv6 -MinimumAuthenticated 3 `
                -TimeoutSeconds 90
            Write-K04Progress -Phase 'k01_guard_attached_to_source' `
                -Detail ([ordered]@{
                    authenticated = [int](
                        $guardSourcePeers.authenticatedTunnelCapable)
                    guard_ipv6 = $guardIPv6
                })
        }

        $hardeningBefore = Get-K01Hardening -Port $webPort
        $fixtureName = 'V91-K01-KAD6-SOURCE.bin'
        $link = ''
        $remoteEvidence = $null
        if ($k01Role -ceq 'source') {
            $fixturePath = Join-Path $nodePath "Incoming\$fixtureName"
            if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
                throw 'La fixture K01 preparada al arranque desaparecio.'
            }
            $fixtureHash = (Get-FileHash -LiteralPath $fixturePath `
                -Algorithm SHA256).Hash.ToLowerInvariant()
            Invoke-WebRequest -UseBasicParsing -Uri (
                "http://127.0.0.1:$webPort/" +
                "?ses=$session&w=shared&reload=true"
            ) -TimeoutSec 15 | Out-Null
            $publishDeadline = [DateTimeOffset]::UtcNow.AddSeconds(300)
            do {
                Start-Sleep -Seconds 2
                $shared = Invoke-WebRequest -UseBasicParsing -Uri (
                    "http://127.0.0.1:$webPort/?ses=$session&w=shared"
                ) -TimeoutSec 10
                $decoded = [Net.WebUtility]::HtmlDecode($shared.Content)
                $match = [regex]::Match(
                    $decoded,
                    'ed2k://\|file\|V91-K01-KAD6-SOURCE\.bin\|' +
                    '\d+\|[0-9A-Fa-f]{32}\|/')
                if ($match.Success) {
                    $link = $match.Value
                }
                if ([string]::IsNullOrWhiteSpace($link)) {
                    $knownPath = Join-Path $nodePath 'config\known.met'
                    if (Test-Path -LiteralPath $knownPath -PathType Leaf) {
                        $knownBytes = [IO.File]::ReadAllBytes($knownPath)
                        if ($knownBytes.Length -ge 25 -and
                            $knownBytes[0] -eq 0x0F -and
                            [BitConverter]::ToUInt32($knownBytes, 1) -eq 1) {
                            $ed2kHash = (
                                [BitConverter]::ToString(
                                    $knownBytes[9..24])
                            ).Replace('-', '')
                            $link = (
                                "ed2k://|file|$fixtureName|" +
                                "$((Get-Item -LiteralPath $fixturePath).Length)|" +
                                "$ed2kHash|/"
                            )
                        }
                    }
                }
                $hardeningNow = Get-K01Hardening -Port $webPort
                if (-not [string]::IsNullOrWhiteSpace($link) -and
                    [Int64]$hardeningNow.source_pipeline.advertised -gt
                        [Int64]$hardeningBefore.source_pipeline.advertised) {
                    break
                }
                Write-K04Progress -Phase 'k01_source_publishing' `
                    -Detail ([ordered]@{
                        link_ready = -not [string]::IsNullOrWhiteSpace($link)
                        advertised = [Int64](
                            $hardeningNow.source_pipeline.advertised)
                        advertised_before = [Int64](
                            $hardeningBefore.source_pipeline.advertised)
                    })
            } while ([DateTimeOffset]::UtcNow -lt $publishDeadline)
            if ([string]::IsNullOrWhiteSpace($link) -or
                [Int64]$hardeningNow.source_pipeline.advertised -le
                    [Int64]$hardeningBefore.source_pipeline.advertised) {
                throw 'K01 no acredito la publicacion nativa Kad6 del source.'
            }
            Write-K04Progress -Phase 'k01_source_advertised' `
                -Detail ([ordered]@{
                    advertised = [Int64](
                        $hardeningNow.source_pipeline.advertised)
                    fixture_sha256 = $fixtureHash
                })

            # Refresh the already authenticated guard/requester relationship
            # before lookup; the source no longer needs a fresh quota grant.
            Invoke-K01DirectJoin -Port $guardWebPort `
                -Key '88888888888888888888888888888888' `
                -PeerIPv6 $peerIPv6 -PeerTcpPort $peerTcpPort `
                -Title 'K01-quota-guard-to-requester'
            $guardRequesterPeers = Wait-K01PeerAddress -Port $guardWebPort `
                -PeerIPv6 $peerIPv6 -MinimumAuthenticated 1 `
                -TimeoutSeconds 90
            Write-K04Progress -Phase 'k01_guard_handed_to_requester' `
                -Detail ([ordered]@{
                    guard_ipv6 = $guardIPv6
                    requester_ipv6 = $peerIPv6
                })

            $listener = [Net.Sockets.TcpListener]::new(
                [Net.IPAddress]::Parse($localIPv6), $i02ControlPort)
            try {
                $listener.Server.DualMode = $false
                $listener.Start(1)
                $accept = $listener.BeginAcceptTcpClient($null, $null)
                if (-not $accept.AsyncWaitHandle.WaitOne(300000)) {
                    throw 'El requester K01 no recogio el enlace de prueba.'
                }
                $controlClient = $listener.EndAcceptTcpClient($accept)
                try {
                    $stream = $controlClient.GetStream()
                    $stream.ReadTimeout = 360000
                    $writer = [IO.StreamWriter]::new(
                        $stream, [Text.UTF8Encoding]::new($false),
                        1024, $true)
                    $reader = [IO.StreamReader]::new(
                        $stream, [Text.UTF8Encoding]::new($false),
                        $false, 1024, $true)
                    try {
                        $writer.WriteLine((([ordered]@{
                            link = $link
                            fixture_sha256 = $fixtureHash
                            advertised = [Int64](
                                $hardeningNow.source_pipeline.advertised)
                        }) | ConvertTo-Json -Compress))
                        $writer.Flush()
                        $ackLine = [string]$reader.ReadLine()
                        if ([string]::IsNullOrWhiteSpace($ackLine)) {
                            throw 'El requester K01 cerro el control sin ACK.'
                        }
                        $remoteEvidence = $ackLine | ConvertFrom-Json
                    } finally {
                        $reader.Dispose()
                        $writer.Dispose()
                    }
                } finally {
                    $controlClient.Dispose()
                }
            } finally {
                $listener.Stop()
            }
            if ([string]$remoteEvidence.status -cne 'PASS' -or
                [Int64]$remoteEvidence.recovered_after -le
                    [Int64]$remoteEvidence.recovered_before) {
                throw 'El ACK K01 no acredita recuperacion de fuente.'
            }
            $hardeningAfter = Get-K01Hardening -Port $webPort
        } else {
            Write-K04Progress -Phase 'k01_requester_waiting_source'
            $controlDeadline = [DateTimeOffset]::UtcNow.AddSeconds(300)
            $controlLine = ''
            $controlClient = $null
            $reader = $null
            $writer = $null
            do {
                $controlClient = [Net.Sockets.TcpClient]::new(
                    [Net.Sockets.AddressFamily]::InterNetworkV6)
                try {
                    $connect = $controlClient.BeginConnect(
                        $peerIPv6, $i02ControlPort, $null, $null)
                    if ($connect.AsyncWaitHandle.WaitOne(2000)) {
                        $controlClient.EndConnect($connect)
                        $stream = $controlClient.GetStream()
                        $stream.ReadTimeout = 300000
                        $reader = [IO.StreamReader]::new(
                            $stream, [Text.UTF8Encoding]::new($false),
                            $false, 1024, $true)
                        $writer = [IO.StreamWriter]::new(
                            $stream, [Text.UTF8Encoding]::new($false),
                            1024, $true)
                        $controlLine = [string]$reader.ReadLine()
                        if (-not [string]::IsNullOrWhiteSpace($controlLine)) {
                            break
                        }
                    }
                } catch {
                    if ($null -ne $controlClient) {
                        $controlClient.Dispose()
                    }
                    $controlClient = $null
                    $controlLine = ''
                }
                if ($null -ne $controlClient) {
                    $controlClient.Dispose()
                    $controlClient = $null
                }
                Start-Sleep -Milliseconds 500
            } while ([DateTimeOffset]::UtcNow -lt $controlDeadline)
            if ([string]::IsNullOrWhiteSpace($controlLine)) {
                throw 'No llego el enlace K01 del source.'
            }
            try {
                $control = $controlLine | ConvertFrom-Json
                $link = [string]$control.link
                if ($link -notmatch (
                    '^ed2k://\|file\|V91-K01-KAD6-SOURCE\.bin\|' +
                    '\d+\|[0-9A-Fa-f]{32}\|/$')) {
                    throw 'El enlace K01 recibido no es valido.'
                }
                $hardeningBefore = Get-K01Hardening -Port $webPort
                Invoke-WebRequest -UseBasicParsing -Uri (
                    "http://127.0.0.1:$webPort/?ses=$session" +
                    "&w=transfer&ed2k=$([Uri]::EscapeDataString($link))"
                ) -TimeoutSec 20 | Out-Null
                $recoverDeadline = [DateTimeOffset]::UtcNow.AddSeconds(360)
                do {
                    Start-Sleep -Seconds 2
                    $hardeningAfter = Get-K01Hardening -Port $webPort
                    Write-K04Progress -Phase 'k01_requester_searching' `
                        -Detail ([ordered]@{
                            recovered = [Int64](
                                $hardeningAfter.source_pipeline.recovered)
                            recovered_before = [Int64](
                                $hardeningBefore.source_pipeline.recovered)
                        })
                    if ([Int64]$hardeningAfter.source_pipeline.recovered -gt
                        [Int64]$hardeningBefore.source_pipeline.recovered) {
                        break
                    }
                } while ([DateTimeOffset]::UtcNow -lt $recoverDeadline)
                if ([Int64]$hardeningAfter.source_pipeline.recovered -le
                    [Int64]$hardeningBefore.source_pipeline.recovered) {
                    throw 'K01 no materializo la fuente encontrada por Kad6.'
                }
                $remoteEvidence = [ordered]@{
                    status = 'PASS'
                    recovered_before = [Int64](
                        $hardeningBefore.source_pipeline.recovered)
                    recovered_after = [Int64](
                        $hardeningAfter.source_pipeline.recovered)
                }
                $writer.WriteLine(($remoteEvidence | ConvertTo-Json -Compress))
                $writer.Flush()
            } finally {
                if ($null -ne $reader) { $reader.Dispose() }
                if ($null -ne $writer) { $writer.Dispose() }
                if ($null -ne $controlClient) {
                    $controlClient.Dispose()
                }
            }
        }

        $statusAfter = Get-K04Status -Port $webPort
        if ([bool]$statusAfter.kad2_running -or
            [int]$statusAfter.kad_running_mask -ne 2) {
            throw 'K01 dejo de estar exclusivamente en Kad6.'
        }
        $postResult = [ordered]@{
            schema = 'ese.v91.k01-node-result/v1'
            case_id = 'V91-K01'
            status = 'PASS'
            role = $k01Role
            started_at_utc = $k01Started.ToString('o')
            completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            candidate_sha256 = $actualHash
            kad_configured_mask = [int]$statusAfter.kad_configured_mask
            kad_running_mask = [int]$statusAfter.kad_running_mask
            kad2_running = [bool]$statusAfter.kad2_running
            kad6_running = [bool]$statusAfter.kad6_running
            peers = $primaryPeers
            secondary_peers = $secondaryPeers
            circuit = $circuit
            hardening_before = $hardeningBefore
            hardening_after = $hardeningAfter
            link_sha256 = (
                [BitConverter]::ToString(
                    [Security.Cryptography.SHA256]::Create().ComputeHash(
                        [Text.Encoding]::UTF8.GetBytes($link))
                ).Replace('-', '').ToLowerInvariant()
            )
            remote_evidence = $remoteEvidence
        }
        Write-K04Json -Path (Join-Path $jobRoot 'k01-result.json') `
            -Value $postResult
        Write-K04Progress -Phase "k01_${k01Role}_complete"
    }

    $finalStatus = 'PASS'
    $result = [ordered]@{
        schema = 'ese.v91.k04-node-result/v1'
        case_id = 'V91-K04'
        status = $finalStatus
        role = $role
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        candidate = [ordered]@{
            exe_sha256 = $actualHash
            ipv6 = $localIPv6
            interface_index = $interfaceIndex
            interface_alias = $interfaceAlias
            udp_port = $udpPort
        }
        before_restart = [ordered]@{
            verified = [int]$sample.kad6_verified_contacts
            samples = $firstSamples
            nodes_bytes = [Int64]$nodesItem.Length
            nodes_sha256 = $nodesHash
        }
        after_restart_blocked = $postRestartEvidence
        after_fresh_reverification = [ordered]@{
            verified = [int]$fresh.kad6_verified_contacts
            samples = $freshSamples
        }
        post_action = $postResult
    }
    Write-K04Json -Value $result -Path $resultPath
    # Keep the verified peer reachable briefly after writing its own result.
    # Otherwise the faster node can close eMule while the other node is still
    # completing the same post-restart HELLO, creating a harness-only race.
    Write-K04Progress -Phase 'peer_grace'
    Start-Sleep -Seconds 20
    $result | ConvertTo-Json -Depth 12
} catch {
    $failure = $_.Exception.Message
    $finalStatus = 'FAIL'
    $result = [ordered]@{
        schema = 'ese.v91.k04-node-result/v1'
        case_id = 'V91-K04'
        status = $finalStatus
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        failure = $failure
    }
    Write-K04Json -Value $result -Path $resultPath
    $result | ConvertTo-Json -Depth 8
    exit 1
} finally {
    if ($null -ne $guardProcess) {
        Stop-K04Process -Process $guardProcess
    }
    if ($null -ne $secondaryProcess) {
        Stop-K04Process -Process $secondaryProcess
    }
    if ($null -ne $process) {
        Stop-K04Process -Process $process
    }
    Remove-K04HostsLine
    foreach ($ruleName in @($ruleNames)) {
        Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    }
    if ($addressCreated) {
        Remove-NetIPAddress -InterfaceIndex ([int]$request.interface_index) `
            -IPAddress ([string]$request.local_ipv6) -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    if ($secondaryAddressCreated) {
        Remove-NetIPAddress -InterfaceIndex ([int]$request.interface_index) `
            -IPAddress ([string]$request.secondary_ipv6) -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    if ($guardAddressCreated) {
        Remove-NetIPAddress -InterfaceIndex ([int]$request.interface_index) `
            -IPAddress ([string]$request.guard_ipv6) -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    if (-not [string]::IsNullOrWhiteSpace($i01ExternalRoot)) {
        Remove-Item -LiteralPath (
            Join-Path $i01ExternalRoot "Incoming\$i01FixtureName") `
            -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $i01ExternalRoot 'Incoming') `
            -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $i01ExternalRoot 'Temp') `
            -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $i01ExternalRoot `
            -Force -ErrorAction SilentlyContinue
    }
    if ($pktmonStarted) {
        try { & pktmon.exe stop 2>&1 | Out-Null } catch {}
        try {
            & pktmon.exe etl2pcap $pktmonEtl --out $pktmonPcap 2>&1 |
                Out-Null
        } catch {}
        try {
            & pktmon.exe etl2txt $pktmonEtl --out $pktmonText 2>&1 |
                Out-Null
        } catch {}
    }
}
