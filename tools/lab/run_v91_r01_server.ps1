[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$request = Get-Content -LiteralPath $JobRequestPath -Raw | ConvertFrom-Json
$root = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$readyPath = Join-Path $root 'server-ready.json'
$resultPath = Join-Path $root 'server-result.json'
$stopPath = Join-Path $root 'stop-server.flag'
$serverListener = $null
$probeListener = $null
$activeClient = $null
$activeFrames = [Collections.Generic.List[object]]::new()
$initial = $null
$mobile = $null
$probe = $null
$initialDisconnectedAt = $null
$failure = ''
$phase = 'initializing'
$interfaceEvidence = $null
$serverListenerStopped = $false
$probeListenerStopped = $false
$cleanupErrors = [Collections.Generic.List[string]]::new()

function Write-R01JsonAtomic {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $temporary = $Path + '.new'
    [IO.File]::WriteAllText(
        $temporary, ($Value | ConvertTo-Json -Depth 12),
        [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Read-R01ExactBytes {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][int]$Count
    )
    $buffer = New-Object byte[] $Count
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) {
            throw "Controlled eD2K stream closed after $offset/$Count bytes."
        }
        $offset += $read
    }
    return $buffer
}

function Convert-R01BytesToHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Read-R01WireFrame {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    $header = Read-R01ExactBytes -Stream $Stream -Count 6
    $packetLength = [BitConverter]::ToUInt32($header, 1)
    if ($packetLength -lt 1 -or $packetLength -gt 1048576) {
        throw "Invalid controlled eD2K frame length: $packetLength."
    }
    $payload = Read-R01ExactBytes -Stream $Stream `
        -Count ([int]$packetLength - 1)
    return [pscustomobject][ordered]@{
        protocol = [int]$header[0]
        opcode = [int]$header[5]
        packet_length = [int]$packetLength
        payload = [byte[]]$payload
    }
}

function Send-R01IdChange {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)
    [byte[]]$payload = [BitConverter]::GetBytes([uint32]0x01000001)
    [byte[]]$header = New-Object byte[] 6
    $header[0] = 0xE3
    [Array]::Copy([BitConverter]::GetBytes([uint32]($payload.Length + 1)),
        0, $header, 1, 4)
    $header[5] = 0x40
    $Stream.Write($header, 0, $header.Length)
    $Stream.Write($payload, 0, $payload.Length)
    $Stream.Flush()
}

function Receive-R01Login {
    param(
        [Parameter(Mandatory = $true)][Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory = $true)][string]$Session
    )
    $Client.ReceiveTimeout = 30000
    $Client.SendTimeout = 30000
    $stream = $Client.GetStream()
    $frame = Read-R01WireFrame -Stream $stream
    if ($frame.protocol -ne 0xE3 -or $frame.opcode -ne 0x01 -or
        $frame.packet_length -lt 23) {
        throw (
            'Expected classic OP_LOGINREQUEST; protocol=0x{0:X2}, ' +
            'opcode=0x{1:X2}, packet_length={2}.' -f
            $frame.protocol, $frame.opcode, $frame.packet_length)
    }
    [byte[]]$payload = $frame.payload
    [byte[]]$userHashBytes = New-Object byte[] 16
    [Array]::Copy($payload, 0, $userHashBytes, 0, 16)
    $remote = [Net.IPEndPoint]$Client.Client.RemoteEndPoint
    $local = [Net.IPEndPoint]$Client.Client.LocalEndPoint
    $observation = [pscustomobject][ordered]@{
        session = $Session
        accepted_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        remote_address = $remote.Address.ToString()
        remote_port = $remote.Port
        local_address = $local.Address.ToString()
        local_port = $local.Port
        protocol = [int]$frame.protocol
        opcode = [int]$frame.opcode
        payload_bytes = $payload.Length
        user_hash_sha256 = ''
        advertised_tcp_port = [int][BitConverter]::ToUInt16($payload, 20)
        idchange_high_id = [uint32]0x01000001
        idchange_sent = $false
        post_login_frames = @()
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $observation.user_hash_sha256 = Convert-R01BytesToHex -Bytes (
            $sha.ComputeHash($userHashBytes))
    } finally { $sha.Dispose() }
    if ($observation.advertised_tcp_port -ne
        [int]$script:request.expected_tcp_port) {
        throw (
            "R01 $Session login advertised TCP port " +
            "$($observation.advertised_tcp_port), expected " +
            "$($script:request.expected_tcp_port).")
    }
    Send-R01IdChange -Stream $stream
    $observation.idchange_sent = $true
    return $observation
}

function Drain-R01ClientFrames {
    param(
        [Parameter(Mandatory = $true)][Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory = $true)]
        [Collections.Generic.List[object]]$Frames
    )

    while ($Client.Client.Poll(1000,
            [Net.Sockets.SelectMode]::SelectRead)) {
        if ($Client.Client.Available -eq 0) {
            return $true
        }
        $Client.ReceiveTimeout = 3000
        $frame = Read-R01WireFrame -Stream $Client.GetStream()
        if ($frame.protocol -notin @(0xE3, 0xC5, 0xD4)) {
            throw ('Unexpected post-login eD2K protocol 0x{0:X2}.' -f
                $frame.protocol)
        }
        $Frames.Add([pscustomobject][ordered]@{
                received_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                protocol = [int]$frame.protocol
                opcode = [int]$frame.opcode
                payload_bytes = ([byte[]]$frame.payload).Length
            })
    }
    return $false
}

function Test-R01ClientClosed {
    param(
        [Parameter(Mandatory = $true)][Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory = $true)]
        [Collections.Generic.List[object]]$Frames
    )
    return Drain-R01ClientFrames -Client $Client -Frames $Frames
}

function Receive-R01Probe {
    param([Parameter(Mandatory = $true)][Net.Sockets.TcpClient]$Client)
    try {
        $Client.ReceiveTimeout = 15000
        $Client.SendTimeout = 15000
        $stream = $Client.GetStream()
        $reader = New-Object IO.StreamReader(
            $stream, (New-Object Text.UTF8Encoding($false)),
            $false, 1024, $true)
        $writer = New-Object IO.StreamWriter(
            $stream, (New-Object Text.UTF8Encoding($false)), 1024, $true)
        $writer.NewLine = "`n"
        $line = $reader.ReadLine()
        if ($line -cne [string]$script:request.nonce) {
            throw 'Topology probe nonce mismatch.'
        }
        $writer.WriteLine($line)
        $writer.Flush()
        $remote = [Net.IPEndPoint]$Client.Client.RemoteEndPoint
        $local = [Net.IPEndPoint]$Client.Client.LocalEndPoint
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.r01-server-probe/v1'
            status = 'PASS'
            accepted_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            remote_address = $remote.Address.ToString()
            remote_port = $remote.Port
            local_address = $local.Address.ToString()
            local_port = $local.Port
            nonce_sha256 = ''
        }
    } finally { $Client.Dispose() }
}

$required = @('nonce', 'listen_address', 'server_port', 'probe_port',
    'expected_tcp_port', 'timeout_seconds')
foreach ($name in $required) {
    if ($null -eq $request.PSObject.Properties[$name]) {
        throw "Missing R01 controlled-server property: $name"
    }
}

try {
    $listenIp = [Net.IPAddress]::Parse([string]$request.listen_address)
    if ($listenIp.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork -or
        [Net.IPAddress]::IsLoopback($listenIp)) {
        throw 'Controlled server requires an assigned non-loopback IPv4.'
    }
    $assigned = @(Get-NetIPAddress -IPAddress $listenIp.ToString() `
            -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
                $_.AddressState -notin @('Invalid', 'Duplicate')
            })
    if ($assigned.Count -ne 1) {
        throw 'Controlled server IPv4 is not uniquely assigned on this host.'
    }
    $adapter = Get-NetAdapter -InterfaceIndex $assigned[0].InterfaceIndex `
        -ErrorAction Stop
    if (-not $adapter.HardwareInterface -or $adapter.Virtual -or
        [string]$adapter.Status -cne 'Up') {
        throw 'Controlled server IPv4 is not on an active physical NIC.'
    }
    $interfaceEvidence = [pscustomobject][ordered]@{
        interface_index = [int]$adapter.ifIndex
        interface_guid = [string]$adapter.InterfaceGuid
        interface_alias = [string]$adapter.Name
        interface_description = [string]$adapter.InterfaceDescription
        hardware_interface = [bool]$adapter.HardwareInterface
        virtual = [bool]$adapter.Virtual
        status = [string]$adapter.Status
        address = $listenIp.ToString()
        overlay = $false
    }
    $serverListener = New-Object Net.Sockets.TcpListener(
        $listenIp, [int]$request.server_port)
    $probeListener = New-Object Net.Sockets.TcpListener(
        $listenIp, [int]$request.probe_port)
    $serverListener.Server.ExclusiveAddressUse = $true
    $probeListener.Server.ExclusiveAddressUse = $true
    $serverListener.Start(4)
    $probeListener.Start(2)
    $phase = 'listening'
    Write-R01JsonAtomic -Path $readyPath -Value ([ordered]@{
            schema = 'ese.v91.r01-server-ready/v1'
            status = 'READY'
            ready_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            listen_address = [string]$request.listen_address
            server_port = [int]$request.server_port
            probe_port = [int]$request.probe_port
        })

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(
        [int]$request.timeout_seconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if ($phase -ceq 'pass_ready') {
            if (Test-Path -LiteralPath $stopPath) {
                $phase = 'pass'
                break
            }
            Start-Sleep -Milliseconds 50
            continue
        }
        if ($probeListener.Pending()) {
            $phase = 'topology_probe'
            $probe = Receive-R01Probe -Client $probeListener.AcceptTcpClient()
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $probe.nonce_sha256 = Convert-R01BytesToHex -Bytes (
                    $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(
                            [string]$request.nonce)))
            } finally { $sha.Dispose() }
        }

        if ($null -eq $activeClient -and $serverListener.Pending()) {
            $activeClient = $serverListener.AcceptTcpClient()
            $activeFrames = [Collections.Generic.List[object]]::new()
            if ($null -eq $initial) {
                $phase = 'initial_login'
                $initial = Receive-R01Login -Client $activeClient `
                    -Session 'home-lan'
            } elseif ($null -ne $initialDisconnectedAt -and
                $null -eq $mobile) {
                $phase = 'mobile_login'
                $mobile = Receive-R01Login -Client $activeClient `
                    -Session 'mobile-hotspot'
            } else {
                $activeClient.Dispose()
                $activeClient = $null
                throw 'Unexpected concurrent or duplicate eD2K session.'
            }
        }

        if ($null -ne $activeClient -and
            (Test-R01ClientClosed -Client $activeClient `
                    -Frames $activeFrames)) {
            if ($null -ne $mobile) {
                $mobile.post_login_frames = @($activeFrames)
            } elseif ($null -ne $initial) {
                $initial.post_login_frames = @($activeFrames)
            }
            $activeClient.Dispose()
            $activeClient = $null
            if ($null -eq $initialDisconnectedAt -and $null -ne $initial) {
                $initialDisconnectedAt = [DateTimeOffset]::UtcNow
                $phase = 'waiting_mobile_login'
            } elseif ($null -ne $mobile) {
                $phase = 'mobile_disconnected'
            }
        }

        $complete = $null -ne $initial -and $null -ne $mobile -and
            $null -ne $probe -and $null -ne $initialDisconnectedAt -and
            [string]$initial.user_hash_sha256 -ceq
                [string]$mobile.user_hash_sha256 -and
            [string]$initial.remote_address -cne [string]$mobile.remote_address
        if ($complete -and $null -eq $activeClient) {
            # Preserve both listeners until the controller has deleted and
            # re-read the two exact UPnP mappings.
            $phase = 'pass_ready'
        }
        if (Test-Path -LiteralPath $stopPath) {
            if ($phase -ceq 'pass_ready') {
                $phase = 'pass'
                break
            }
            throw 'Controller stopped the server before both sessions completed.'
        }
        Start-Sleep -Milliseconds 50
    }
    if ($phase -ne 'pass') {
        throw "Controlled server timed out in phase '$phase'."
    }
} catch {
    $failure = $_.Exception.Message
    $phase = 'failed'
} finally {
    if ($null -ne $activeClient) {
        if ($null -ne $mobile) {
            $mobile.post_login_frames = @($activeFrames)
        } elseif ($null -ne $initial) {
            $initial.post_login_frames = @($activeFrames)
        }
        try { $activeClient.Dispose() } catch {
            $cleanupErrors.Add("active_client: $($_.Exception.Message)")
        }
    }
    if ($null -ne $serverListener) {
        try {
            $serverListener.Stop()
            $serverListenerStopped = $true
        } catch {
            $cleanupErrors.Add("server_listener: $($_.Exception.Message)")
        }
    } else {
        $serverListenerStopped = $true
    }
    if ($null -ne $probeListener) {
        try {
            $probeListener.Stop()
            $probeListenerStopped = $true
        } catch {
            $cleanupErrors.Add("probe_listener: $($_.Exception.Message)")
        }
    } else {
        $probeListenerStopped = $true
    }
}

$sameIdentity = $null -ne $initial -and $null -ne $mobile -and
    [string]$initial.user_hash_sha256 -ceq [string]$mobile.user_hash_sha256
$differentRemote = $null -ne $initial -and $null -ne $mobile -and
    [string]$initial.remote_address -cne [string]$mobile.remote_address
$probeRemoteChanged = $null -ne $initial -and $null -ne $probe -and
    [string]$probe.remote_address -cne [string]$initial.remote_address
$fixtureValidForProduct = $null -ne $initial -and
    [bool]$initial.idchange_sent -and $null -ne $probe -and
    [string]$probe.status -ceq 'PASS' -and
    $probeRemoteChanged -and
    $null -ne $initialDisconnectedAt -and $null -ne $interfaceEvidence -and
    [bool]$interfaceEvidence.hardware_interface -and
    -not [bool]$interfaceEvidence.virtual
$status = if ($phase -eq 'pass' -and $sameIdentity -and $differentRemote -and
    $null -ne $probe -and $probe.status -ceq 'PASS' -and
    $serverListenerStopped -and $probeListenerStopped -and
    $cleanupErrors.Count -eq 0) {
    'SERVER_PASS'
} else { 'SERVER_BLOCKED' }

Write-R01JsonAtomic -Path $resultPath -Value ([ordered]@{
        schema = 'ese.v91.r01-controlled-server/v1'
        case_id = 'V91-R01'
        nonce = [string]$request.nonce
        status = $status
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        failure = $failure
        listen_address = [string]$request.listen_address
        interface = $interfaceEvidence
        server_port = [int]$request.server_port
        probe_port = [int]$request.probe_port
        initial = $initial
        initial_disconnected_at_utc = if (
            $null -ne $initialDisconnectedAt) {
            $initialDisconnectedAt.ToString('o')
        } else { $null }
        mobile = $mobile
        topology_probe = $probe
        same_client_identity = $sameIdentity
        different_observed_remote = $differentRemote
        probe_remote_changed_from_initial = $probeRemoteChanged
        fixture_valid_for_product_adjudication = $fixtureValidForProduct
        cleanup = [ordered]@{
            server_listener_stopped = $serverListenerStopped
            probe_listener_stopped = $probeListenerStopped
            errors = @($cleanupErrors)
        }
    })
if ($status -cne 'SERVER_PASS') { exit 2 }
exit 0
