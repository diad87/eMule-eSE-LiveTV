[CmdletBinding()]
param(
    [ValidateSet('Coordinator', 'Peer')][string]$Role = 'Coordinator',
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedEmuleSha256,
    [string]$PeerHostname = '',
    [Parameter(Mandatory = $true)][string]$PeerIPv4,
    [string]$PeerLocalIPv4 = '',
    [Parameter(Mandatory = $true)][string]$PeerIPv6,
    [string]$CoordinatorIPv4 = '',
    [string]$CoordinatorIPv6 = '',
    [Parameter(Mandatory = $true)][string]$CoordinationRoot,
    [Parameter(Mandatory = $true)][switch]$ControlledPeerAcknowledged,
    [ValidateRange(1024, 65535)][int]$PeerTcpPort = 9462,
    [ValidateRange(1024, 65535)][int]$PeerUdpPort = 9472,
    [ValidateRange(1024, 65535)][int]$PeerWebPort = 9511,
    [ValidateRange(1024, 65535)][int]$ClientTcpPort = 9562,
    [ValidateRange(1024, 65535)][int]$ClientUdpPort = 9572,
    [ValidateRange(1024, 65535)][int]$ClientWebPort = 9611,
    [ValidateRange(67108864, 17179869184)]
    [Int64]$FileSizeBytes = 1073741824,
    [ValidateRange(30, 900)][int]$PeerReadyTimeoutSeconds = 300,
    [ValidateRange(30, 3600)][int]$ScenarioTimeoutSeconds = 2700,
    [ValidateRange(4, 10)][int]$FallbackLimitSeconds = 10,
    [ValidateSet('Manual', 'PowerShellRemoting')]
    [string]$PeerControlMode = 'Manual',
    [string]$PeerComputerName = '',
    [Management.Automation.PSCredential]$PeerCredential,
    [string]$RemoteScriptPath = '',
    [string]$RemotePackagePath = '',
    [string]$RemoteOutputRoot = '',
    [string]$RemoteCoordinationRoot = '',
    [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunNonce = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'common.ps1')

$caseId = 'V91-I04'
$expectedHash = $ExpectedEmuleSha256.ToLowerInvariant()
$candidate = Get-LabCandidateInfo -PackagePath $PackagePath `
    -ExpectedCommit $Commit
if ($candidate.emule_sha256 -ne $expectedHash) {
    throw "Candidate hash mismatch: package=$($candidate.emule_sha256) expected=$expectedHash"
}
if (-not $ControlledPeerAcknowledged) {
    throw 'I04 may only target a peer controlled by, or explicitly authorized for, the operator'
}

$canonicalHostname = $PeerHostname.Trim().TrimEnd('.').ToLowerInvariant()
if ($canonicalHostname -and (
    [Uri]::CheckHostName($canonicalHostname) -ne [UriHostNameType]::Dns -or
    $canonicalHostname.IndexOfAny([char[]]'|,[]:') -ge 0
)) {
    throw "Optional PeerHostname is not a valid DNS name: '$PeerHostname'"
}

$peerV4Address = $null
if (-not [Net.IPAddress]::TryParse($PeerIPv4, [ref]$peerV4Address) -or
    $peerV4Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw "PeerIPv4 is not an IPv4 address: '$PeerIPv4'"
}
$peerLocalV4Value = if ([string]::IsNullOrWhiteSpace($PeerLocalIPv4)) {
    $PeerIPv4
} else { $PeerLocalIPv4 }
$peerLocalV4Address = $null
if (-not [Net.IPAddress]::TryParse(
    $peerLocalV4Value, [ref]$peerLocalV4Address) -or
    $peerLocalV4Address.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork) {
    throw "PeerLocalIPv4 is not an IPv4 address: '$peerLocalV4Value'"
}
$peerV6Address = $null
if (-not [Net.IPAddress]::TryParse($PeerIPv6.Split('%')[0],
    [ref]$peerV6Address) -or
    $peerV6Address.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetworkV6 -or
    $peerV6Address.IsIPv4MappedToIPv6) {
    throw "PeerIPv6 is not a native IPv6 address: '$PeerIPv6'"
}
$peerV4Text = $peerV4Address.ToString()
$peerLocalV4Text = $peerLocalV4Address.ToString()
$peerV6Text = $peerV6Address.ToString()
if ((Get-LabAddressClass -Address $peerV4Text) -ne 'global-v4') {
    throw 'PeerIPv4 must be the real globally routable HighID endpoint'
}
if ((Get-LabAddressClass -Address $peerLocalV4Text) -in @(
    'invalid', 'loopback-v4', 'linklocal-v4', 'special-v4'
)) {
    throw 'PeerLocalIPv4 must be an assigned unicast address on the peer adapter'
}
$expectedFallbackDelayMs = 3000
$captureTimingToleranceMs = 250
$socketClockCoherenceToleranceMs = 50
$minimumSilentWindowMs = $expectedFallbackDelayMs - $captureTimingToleranceMs
$schedulerReconnectFloorSeconds = 1205
$fileBSizeBytes = 67108864
$overlayPattern =
    '(?i)tailscale|wireguard|cloudflare|warp|zerotier|openvpn|' +
    'hyper-v|vethernet|loopback|tunnel|tap|vpn|hamachi'

$uniquePorts = @(
    $PeerTcpPort, $PeerUdpPort, $PeerWebPort,
    $ClientTcpPort, $ClientUdpPort, $ClientWebPort
) | Sort-Object -Unique
if ($uniquePorts.Count -ne 6) {
    throw 'All peer/client TCP, UDP and Web ports must be unique'
}

function Get-I04MachineId {
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

function Test-I04Administrator {
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

function Get-I04NormalizedIp {
    param([Parameter(Mandatory = $true)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address.Split('%')[0], [ref]$parsed)) {
        return $Address
    }
    if ($parsed.IsIPv4MappedToIPv6) {
        return $parsed.MapToIPv4().ToString()
    }
    return $parsed.ToString()
}

function Get-I04EpochMilliseconds {
    param(
        [Parameter(Mandatory = $true)][DateTimeOffset]$Timestamp
    )

    # ToUnixTimeMilliseconds truncates the sub-millisecond part. Packet
    # timestamps are fractional milliseconds, so truncation could classify a
    # packet emitted just before a barrier as post-barrier.
    $unixEpochTicks = ([DateTimeOffset]'1970-01-01T00:00:00Z').UtcTicks
    return [double]($Timestamp.UtcTicks - $unixEpochTicks) /
        [double][TimeSpan]::TicksPerMillisecond
}

function Add-I04JsonLine {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $line = $Value | ConvertTo-Json -Depth 24 -Compress
    Add-Content -LiteralPath $Path -Value $line -Encoding utf8
}

function Add-I04Journal {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Mutation,
        [Parameter(Mandatory = $true)][string]$State,
        [AllowEmptyString()][string]$Detail = ''
    )

    Add-I04JsonLine -Path $Path -Value ([ordered]@{
        schema = 'ese.v91.i04-mutation-journal/v1'
        captured_at_utc = Get-LabUtcTimestamp
        mutation = $Mutation
        state = $State
        detail = $Detail
    })
}

function Add-I04RollbackJournal {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Mutation,
        [Parameter(Mandatory = $true)][string]$State,
        [AllowEmptyString()][string]$Detail = '',
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$CleanupFailures
    )

    # Rollback must never depend on writing evidence. A full/detached evidence
    # volume is a cleanup failure, but it must not prevent the remaining
    # process/firewall/filter rollback from running.
    try {
        Add-I04Journal -Path $Path -Mutation $Mutation -State $State `
            -Detail $Detail
    } catch {
        $CleanupFailures.Add(
            "rollback journal write failed for '$Mutation': $($_.Exception.Message)"
        )
    }
}

function Get-I04IniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key
    )

    $inSection = $false
    $value = $null
    foreach ($lineValue in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $line = [string]$lineValue
        if ($line -match '^\s*\[(?<section>[^\]]+)\]\s*$') {
            $inSection = $Matches.section -ieq $Section
            continue
        }
        if ($inSection -and
            $line -match ('^\s*' + [regex]::Escape($Key) +
                '\s*=\s*(?<value>.*?)\s*$')) {
            $value = [string]$Matches.value
        }
    }
    return $value
}

function Get-I04PersistedUserHash {
    param([Parameter(Mandatory = $true)][string]$NodePath)

    $path = Join-Path $NodePath 'config\preferences.dat'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Peer identity file does not exist: $path"
    }
    $bytes = [IO.File]::ReadAllBytes($path)
    # Preferences_Ext_Struct is packed: uint8 version followed immediately by
    # uchar userhash[16]. This is the exact identity loaded by non-headless
    # startup before the TCP listener is created.
    if ($bytes.Length -lt 17) {
        throw "Peer identity file is truncated: $path"
    }
    $hashBytes = New-Object byte[] 16
    [Array]::Copy($bytes, 1, $hashBytes, 0, 16)
    $hash = ([BitConverter]::ToString($hashBytes)).Replace('-', '')
    if ($hash -notmatch '^[0-9A-F]{32}$' -or
        $hash -eq ('0' * 32) -or $hashBytes[5] -ne 14 -or
        $hashBytes[14] -ne 111) {
        throw "Peer preferences.dat does not contain a valid eMule user hash"
    }
    return [pscustomobject][ordered]@{
        path = $path
        file_sha256 = Get-LabSha256 -Path $path
        format_version = [int]$bytes[0]
        user_hash = $hash
        user_hash_offset = 1
        source_mode = 'non-headless persisted preferences.dat identity'
    }
}

function Set-I04IsolatedPreferences {
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
            Remove-Item -LiteralPath $identityPath -Force -ErrorAction Stop
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
        LogA4AF = '1'
        A4AFSaveCpu = '0'
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
        Kad6PublicExitOptIn = '0'
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
        Password = Get-I04Md5Text -Value $Password
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

    foreach ($serverFile in @(
        'server.met', 'server_met.old', 'server_met.download',
        'server_met.old.bak', 'staticservers.dat'
    )) {
        $serverPath = Join-Path $config $serverFile
        if (Test-Path -LiteralPath $serverPath -PathType Leaf) {
            Remove-Item -LiteralPath $serverPath -Force -ErrorAction Stop
        }
    }
    $shares = Join-Path $config 'shareddir.dat'
    [IO.File]::WriteAllText(
        $shares, '', (New-Object Text.UTF8Encoding($false))
    )
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

function New-I04FixtureFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Int64]$Bytes,
        [Parameter(Mandatory = $true)][string]$Seed
    )

    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        # Seed the first MiB and extend sparsely.  The eD2K and SHA-256
        # identities are therefore unique without making fixture creation slow.
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $written = 0
            $counter = 0
            while ($written -lt [Math]::Min(1MB, $Bytes)) {
                $block = $sha.ComputeHash(
                    [Text.Encoding]::UTF8.GetBytes(
                        "$Seed|$counter"
                    )
                )
                $wanted = [Math]::Min(
                    $block.Length,
                    [Math]::Min(1MB, $Bytes) - $written
                )
                $stream.Write($block, 0, $wanted)
                $written += $wanted
                $counter++
            }
        } finally {
            $sha.Dispose()
        }
        $stream.SetLength($Bytes)
    } finally {
        $stream.Dispose()
    }
    return [pscustomobject][ordered]@{
        name = [IO.Path]::GetFileName($Path)
        bytes = $Bytes
        sha256 = Get-LabSha256 -Path $Path
        seed_sha256 = Get-LabStringSha256 -Value $Seed
    }
}

function Wait-I04File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return Get-Content -LiteralPath $Path -Raw |
                ConvertFrom-Json -ErrorAction Stop
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Wait-I04PeerControl {
    param(
        [Parameter(Mandatory = $true)][string]$ArmPath,
        [Parameter(Mandatory = $true)][string]$StopPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        # Stop wins if both files appear while the peer is polling. This lets
        # the coordinator abort a bad fixture without arming any firewall rule.
        if (Test-Path -LiteralPath $StopPath -PathType Leaf) {
            return [pscustomobject]@{
                kind = 'stop'
                data = Get-Content -LiteralPath $StopPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        if (Test-Path -LiteralPath $ArmPath -PathType Leaf) {
            return [pscustomobject]@{
                kind = 'arm'
                data = Get-Content -LiteralPath $ArmPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Wait-I04RestartControl {
    param(
        [Parameter(Mandatory = $true)][string]$RestartPath,
        [Parameter(Mandatory = $true)][string]$StopPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $StopPath -PathType Leaf) {
            return [pscustomobject]@{
                kind = 'stop'
                data = Get-Content -LiteralPath $StopPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        if (Test-Path -LiteralPath $RestartPath -PathType Leaf) {
            return [pscustomobject]@{
                kind = 'restart'
                data = Get-Content -LiteralPath $RestartPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Wait-I04StopWhileProcessAlive {
    param(
        [Parameter(Mandatory = $true)][string]$StopPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $StopPath -PathType Leaf) {
            return Get-Content -LiteralPath $StopPath -Raw |
                ConvertFrom-Json -ErrorAction Stop
        }
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "Peer source PID $($Process.Id) exited before coordinator stop"
        }
        $actualPath = ''
        try { $actualPath = [IO.Path]::GetFullPath($Process.Path) } catch {}
        if ($actualPath -ne [IO.Path]::GetFullPath($ExpectedPath)) {
            throw "Peer source PID $($Process.Id) no longer has the owned path"
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Convert-I04RequiredAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$AddressFamily,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $address = $null
    if ([string]::IsNullOrWhiteSpace($Value) -or
        -not [Net.IPAddress]::TryParse($Value.Split('%')[0], [ref]$address) -or
        $address.AddressFamily -ne $AddressFamily -or
        ($AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and
            $address.IsIPv4MappedToIPv6)) {
        throw "$Name is not an address in the required family: '$Value'"
    }
    return $address
}

function Get-I04TupleKey {
    param(
        [Parameter(Mandatory = $true)][string]$Family,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][int]$LocalPort,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$RemotePort
    )

    return '{0}|{1}|{2}|{3}|{4}' -f $Family,
        (Get-I04NormalizedIp -Address $LocalAddress), $LocalPort,
        (Get-I04NormalizedIp -Address $RemoteAddress), $RemotePort
}

function Get-I04TargetConnections {
    param(
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][int]$Port
    )

    return @(
        Get-NetTCPConnection -RemotePort $Port `
            -ErrorAction SilentlyContinue | Where-Object {
            @($IPv4, $IPv6) -contains
                (Get-I04NormalizedIp -Address $_.RemoteAddress)
        } | ForEach-Object {
            $remote = Get-I04NormalizedIp -Address $_.RemoteAddress
            $local = Get-I04NormalizedIp -Address $_.LocalAddress
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
                tuple_key = Get-I04TupleKey -Family $family `
                    -LocalAddress $local -LocalPort ([int]$_.LocalPort) `
                    -RemoteAddress $remote -RemotePort ([int]$_.RemotePort)
            }
        }
    )
}

function Wait-I04Api {
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
            return Invoke-RestMethod `
                -Uri "http://127.0.0.1:$Port/api/status" `
                -TimeoutSec 2
        } catch {
            Start-Sleep -Milliseconds 400
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "API on port $Port did not become ready"
}

function Wait-I04Listener {
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
            if (-not $RequireDualStack -or @(
                $listeners | Where-Object {
                    (Get-I04NormalizedIp -Address $_.LocalAddress) -eq '::'
                }
            ).Count -gt 0) {
                return $listeners
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($RequireDualStack) {
        throw "A dual-stack [::]:$Port listener did not become ready"
    }
    throw "Listener $Port did not become ready"
}

function Stop-I04OwnedProcess {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [switch]$ForceImmediate,
        [switch]$RequireGraceful
    )

    if ($ForceImmediate -and $RequireGraceful) {
        throw 'ForceImmediate and RequireGraceful are mutually exclusive'
    }
    if ($null -eq $Process) { return $true }
    $actual = Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
    if ($null -eq $actual) { return $true }
    $actualPath = ''
    try { $actualPath = [IO.Path]::GetFullPath($actual.Path) } catch { return $false }
    if ($actualPath -ne [IO.Path]::GetFullPath($ExpectedPath)) {
        return $false
    }
    try {
        if ($ForceImmediate) {
            Stop-Process -Id $actual.Id -Force -ErrorAction Stop
            return $actual.WaitForExit(10000)
        }
        if ($actual.MainWindowHandle -ne [IntPtr]::Zero) {
            $null = $actual.CloseMainWindow()
            if ($actual.WaitForExit(10000)) { return $true }
        }
        if ($RequireGraceful) { return $false }
        Stop-Process -Id $actual.Id -Force -ErrorAction Stop
        return $actual.WaitForExit(10000)
    } catch {
        return $false
    }
}

function Get-I04Md5Text {
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

function Get-I04ClassicSession {
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

function Get-I04SharedLink {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][Int64]$FileBytes
    )

    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        $response = Invoke-WebRequest `
            -Uri "http://127.0.0.1:$Port/?ses=$Session&w=shared" `
            -UseBasicParsing -TimeoutSec 15
        $pattern = 'ed2k://\|file\|' + [regex]::Escape($FileName) +
            '\|' + $FileBytes +
            '\|([A-Fa-f0-9]{32})(?:\|h=[A-Z2-7]{32})?\|/'
        $match = [regex]::Match($response.Content, $pattern)
        if ($match.Success) {
            return [pscustomobject][ordered]@{
                link = $match.Value
                ed2k_hash = $match.Groups[1].Value.ToUpperInvariant()
            }
        }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for '$FileName' to enter the shared list"
}

function Get-I04TransferSnapshot {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{32}$')][string]$FileHash
    )

    $response = Invoke-WebRequest `
        -Uri "http://127.0.0.1:$Port/?ses=$Session&w=transfer" `
        -UseBasicParsing -TimeoutSec 15
    $content = [string]$response.Content
    $hash = $FileHash.ToUpperInvariant()
    $anchor = $content.IndexOf(
        $hash, [StringComparison]::OrdinalIgnoreCase
    )
    if ($anchor -lt 0) {
        return [pscustomobject][ordered]@{
            captured_at_utc = Get-LabUtcTimestamp
            found = $false
            file_hash = $hash
            state = ''
            size_text = ''
            transferred_text = ''
            transferred_nonzero = $false
            source_active = $null
            source_total = $null
            source_transferring = $null
            row_sha256 = ''
        }
    }

    $rowStart = $content.LastIndexOf(
        '<tr', $anchor, [StringComparison]::OrdinalIgnoreCase
    )
    if ($rowStart -lt 0) { $rowStart = [Math]::Max(0, $anchor - 2048) }
    $nextAnchor = $content.IndexOf(
        'downmenu(event', $anchor + $hash.Length,
        [StringComparison]::OrdinalIgnoreCase
    )
    $rowEnd = if ($nextAnchor -gt $rowStart) {
        $nextAnchor
    } else {
        [Math]::Min($content.Length, $anchor + 8192)
    }
    $row = $content.Substring($rowStart, $rowEnd - $rowStart)
    $stateMatch = [regex]::Match(
        $row,
        "(?is)downmenu\(event,'[^']*','[^']*','[^']*'," +
            "'(?<state>[^']*)'[^)]*" + [regex]::Escape($hash)
    )
    $progressMatch = [regex]::Match(
        $row,
        '(?is)' + [regex]::Escape($hash) +
            '.*?</td>\s*</tr>\s*</table>\s*</td>\s*' +
            '<td[^>]*>(?<size>.*?)</td>\s*' +
            '<td[^>]*>(?<transferred>.*?)</td>'
    )
    $sourceMatch = [regex]::Match(
        $row,
        '(?is)(?<active>\d+)\s*(?:&nbsp;|\s)*\/' +
            '\s*(?:&nbsp;|\s)*(?<total>\d+)\s*' +
            '(?:&nbsp;|\s)*\((?<transferring>\d+)\)'
    )
    $strip = {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        $plain = [regex]::Replace($Value, '<[^>]+>', '')
        return [Net.WebUtility]::HtmlDecode($plain).Trim()
    }
    $sizeText = if ($progressMatch.Success) {
        & $strip $progressMatch.Groups['size'].Value
    } else { '' }
    $transferredText = if ($progressMatch.Success) {
        & $strip $progressMatch.Groups['transferred'].Value
    } else { '' }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        found = $true
        file_hash = $hash
        state = if ($stateMatch.Success) {
            $stateMatch.Groups['state'].Value.ToLowerInvariant()
        } elseif ($row -match '(?i)down-line-(stopped|paused|downloading|waiting)') {
            $Matches[1].ToLowerInvariant()
        } else { '' }
        size_text = $sizeText
        transferred_text = $transferredText
        transferred_nonzero = $transferredText -notin @('', '-') -and
            $transferredText -match '[1-9]'
        source_active = if ($sourceMatch.Success) {
            [int]$sourceMatch.Groups['active'].Value
        } else { $null }
        source_total = if ($sourceMatch.Success) {
            [int]$sourceMatch.Groups['total'].Value
        } else { $null }
        source_transferring = if ($sourceMatch.Success) {
            [int]$sourceMatch.Groups['transferring'].Value
        } else { $null }
        row_sha256 = Get-LabStringSha256 -Value $row
    }
}

function Invoke-I04DownloadOperation {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)]
        [ValidateSet('stop', 'pause', 'resume')][string]$Operation,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{32}$')][string]$FileHash,
        [AllowNull()][object]$PreparedBoundary = $null
    )

    if ($null -eq $PreparedBoundary) {
        $before = [DateTimeOffset]::UtcNow
        $beforeEpochMs = Get-I04EpochMilliseconds -Timestamp $before
        $beforeQpc = [Diagnostics.Stopwatch]::GetTimestamp()
    } else {
        if ([string]$PreparedBoundary.operation -ne $Operation -or
            [string]$PreparedBoundary.file_hash -ne
                $FileHash.ToUpperInvariant() -or
            [double]$PreparedBoundary.boundary_before_request_epoch_ms -le 0 -or
            [Int64]$PreparedBoundary.boundary_before_request_qpc -le 0 -or
            [Int64]$PreparedBoundary.qpc_frequency -ne
                [Diagnostics.Stopwatch]::Frequency) {
            throw 'Prepared Classic Web operation boundary is invalid'
        }
        $before = [DateTimeOffset]::Parse(
            [string]$PreparedBoundary.boundary_before_request_utc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        $beforeEpochMs =
            [double]$PreparedBoundary.boundary_before_request_epoch_ms
        $beforeQpc =
            [Int64]$PreparedBoundary.boundary_before_request_qpc
    }
    $response = Invoke-WebRequest -Uri (
        "http://127.0.0.1:$Port/?ses=$Session&w=transfer" +
        "&op=$Operation&file=$($FileHash.ToUpperInvariant())"
    ) -UseBasicParsing -TimeoutSec 15
    $afterQpc = [Diagnostics.Stopwatch]::GetTimestamp()
    $after = [DateTimeOffset]::UtcNow
    return [pscustomobject][ordered]@{
        operation = $Operation
        file_hash = $FileHash.ToUpperInvariant()
        boundary_before_request_utc = $before.ToString('o')
        boundary_before_request_epoch_ms = $beforeEpochMs
        boundary_before_request_qpc = $beforeQpc
        response_completed_utc = $after.ToString('o')
        response_completed_epoch_ms =
            Get-I04EpochMilliseconds -Timestamp $after
        response_completed_qpc = $afterQpc
        qpc_frequency = [Diagnostics.Stopwatch]::Frequency
        request_completed = $true
        request_error = $null
        http_status = [int]$response.StatusCode
        response_sha256 = Get-LabStringSha256 -Value (
            [string]$response.Content
        )
    }
}

function Send-I04Ed2kLink {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Link
    )

    if (-not ('V91I04CopyData' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91I04CopyData {
    [StructLayout(LayoutKind.Sequential)]
    public struct COPYDATASTRUCT {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint Msg, IntPtr wParam, ref COPYDATASTRUCT lParam,
        uint flags, uint timeoutMilliseconds, out IntPtr result);
}
'@
    }

    $handle = [IntPtr]::Zero
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $Process.Refresh()
        if ($Process.HasExited) { throw 'Downloader exited before link injection' }
        $handle = $Process.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($handle -eq [IntPtr]::Zero) {
        throw 'Downloader main window handle was not available'
    }

    $pointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Link)
    try {
        $payload = New-Object V91I04CopyData+COPYDATASTRUCT
        $payload.dwData = [IntPtr]12000
        $payload.cbData = ($Link.Length + 1) * 2
        $payload.lpData = $pointer
        $messageResult = [IntPtr]::Zero
        $sent = [V91I04CopyData]::SendMessageTimeout(
            $handle, 0x004A, [IntPtr]::Zero, [ref]$payload,
            0x0003, 5000, [ref]$messageResult
        )
        if ($sent -eq [IntPtr]::Zero) {
            $win32 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "Timed out or failed injecting the eD2K link (Win32=$win32)"
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
    }
}

function Test-I04TcpEndpoint {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port,
        [ValidateRange(100, 10000)][int]$TimeoutMilliseconds = 3000
    )

    $startedAt = [DateTimeOffset]::UtcNow
    $startedEpochMs = Get-I04EpochMilliseconds -Timestamp $startedAt
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $socket = New-Object Net.Sockets.TcpClient($Address.AddressFamily)
    $connected = $false
    $timedOut = $false
    $errorText = $null
    $localAddress = $null
    $localPort = $null
    try {
        $task = $socket.ConnectAsync($Address, $Port)
        $completed = [Threading.Tasks.Task]::WaitAny(
            [Threading.Tasks.Task[]]@($task), $TimeoutMilliseconds
        )
        if ($completed -lt 0) {
            $timedOut = $true
        } elseif ($task.IsFaulted) {
            $errorText = $task.Exception.GetBaseException().Message
        } elseif ($task.IsCanceled) {
            $errorText = 'connection task canceled'
        } else {
            $connected = $socket.Connected
            if ($connected -and $null -ne $socket.Client.LocalEndPoint) {
                $localAddress = Get-I04NormalizedIp -Address (
                    [string]$socket.Client.LocalEndPoint.Address
                )
                $localPort = [int]$socket.Client.LocalEndPoint.Port
            }
        }
    } catch {
        $errorText = $_.Exception.GetBaseException().Message
    } finally {
        $watch.Stop()
        $socket.Dispose()
    }
    $finishedAt = [DateTimeOffset]::UtcNow
    return [pscustomobject][ordered]@{
        started_at_utc = $startedAt.ToString('o')
        finished_at_utc = $finishedAt.ToString('o')
        started_epoch_ms = $startedEpochMs
        finished_epoch_ms = Get-I04EpochMilliseconds -Timestamp $finishedAt
        address = $Address.ToString()
        family = if ($Address.AddressFamily -eq
            [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
        port = $Port
        connected = $connected
        timed_out = $timedOut
        duration_ms = $watch.ElapsedMilliseconds
        local_address = $localAddress
        local_port = $localPort
        error = $errorText
    }
}

function Initialize-I04UiProbe {
    if ('V91I04UiProbe' -as [type]) { return }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91I04UiProbe {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam,
        uint flags, uint timeout, out IntPtr result);
}
'@
}

function Get-I04UiProbe {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    Initialize-I04UiProbe
    $Process.Refresh()
    $handle = $Process.MainWindowHandle
    $present = $handle -ne [IntPtr]::Zero
    $responsive = $false
    $duration = 0L
    if ($present) {
        $result = [IntPtr]::Zero
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $sent = [V91I04UiProbe]::SendMessageTimeout(
            $handle, 0, [IntPtr]::Zero, [IntPtr]::Zero,
            2, 500, [ref]$result
        )
        $watch.Stop()
        $duration = $watch.ElapsedMilliseconds
        $responsive = $sent -ne [IntPtr]::Zero
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        process_id = $Process.Id
        main_window_present = $present
        message_pump_responsive = $responsive
        probe_duration_ms = $duration
    }
}

function Get-I04ApiProbe {
    param([Parameter(Mandatory = $true)][int]$Port)

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $available = $false
    $statusAvailable = $false
    $v9Available = $false
    $errorText = $null
    $status = $null
    $v9 = $null
    try {
        $status = Invoke-RestMethod `
            -Uri "http://127.0.0.1:$Port/api/status" `
            -TimeoutSec 2
        $statusAvailable = $true
        $v9 = Invoke-RestMethod `
            -Uri "http://127.0.0.1:$Port/api/ese/v9" `
            -TimeoutSec 2
        $v9Available = $true
        $available = $statusAvailable -and $v9Available
    } catch {
        $errorText = $_.Exception.Message
    } finally {
        $watch.Stop()
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        available = $available
        status_available = $statusAvailable
        v9_available = $v9Available
        duration_ms = $watch.ElapsedMilliseconds
        error = $errorText
        user_hash = if ($null -eq $status) {
            ''
        } else { [string]$status.user_hash }
        ed2k_connected = $null -ne $status -and
            [bool]$status.ed2k_connected
        kad_running_mask = if ($null -eq $status) {
            $null
        } else { [Int64]$status.kad_running_mask }
        kad2_running = $null -ne $status -and [bool]$status.kad2_running
        kad6_running = $null -ne $status -and [bool]$status.kad6_running
        netlab_consent = if ($null -eq $status) {
            ''
        } else { [string]$status.netlab_consent }
        netlab_advanced_consent = if ($null -eq $status) {
            ''
        } else { [string]$status.netlab_advanced_consent }
        netlab_contribution_consent = if ($null -eq $status) {
            ''
        } else { [string]$status.netlab_contribution_consent }
        netlab_enabled = $null -ne $status -and
            [bool]$status.netlab_enabled
        utp_hole_punch_enabled = $null -ne $status -and
            [bool]$status.utp_hole_punch_enabled
        connecting_client_count = if ($null -eq $status -or
            $null -eq $status.connecting_client_count) {
            $null
        } else { [Int64]$status.connecting_client_count }
        connecting_client_adds = if ($null -eq $status -or
            $null -eq $status.connecting_client_adds) {
            $null
        } else { [Int64]$status.connecting_client_adds }
        connecting_client_high_water = if ($null -eq $status -or
            $null -eq $status.connecting_client_high_water) {
            $null
        } else { [Int64]$status.connecting_client_high_water }
        connecting_client_duplicate_adds = if ($null -eq $status -or
            $null -eq $status.connecting_client_duplicate_adds) {
            $null
        } else { [Int64]$status.connecting_client_duplicate_adds }
        v9 = $v9
    }
}

function Test-I04ApiIsolation {
    param(
        [Parameter(Mandatory = $true)][object]$Data,
        [Parameter(Mandatory = $true)][bool]$RequireEd2k
    )

    if (-not [bool]$Data.available -or
        [string]$Data.user_hash -notmatch '^[0-9A-Fa-f]{32}$' -or
        [bool]$Data.ed2k_connected -ne $RequireEd2k -or
        [Int64]$Data.kad_running_mask -ne 0 -or
        [bool]$Data.kad2_running -or [bool]$Data.kad6_running -or
        [string]$Data.netlab_consent -eq 'accepted' -or
        [string]$Data.netlab_advanced_consent -eq 'accepted' -or
        [string]$Data.netlab_contribution_consent -eq 'accepted' -or
        [bool]$Data.netlab_enabled -or
        [bool]$Data.utp_hole_punch_enabled) {
        return $false
    }
    $v9 = $Data.v9
    if ($null -eq $v9 -or -not [bool]$v9.success -or
        [bool]$v9.netlab.enabled -or
        [bool]$v9.netlab.capability_advertised -or
        [bool]$v9.netlab.staged.selector -or
        [bool]$v9.netlab.staged.port_predict -or
        [bool]$v9.netlab.staged.ed2k_punch3 -or
        [bool]$v9.netlab.staged.kad3_rendezvous -or
        [bool]$v9.netlab.independent.relay_accept -or
        [bool]$v9.netlab.independent.relay_egress -or
        [bool]$v9.netlab.independent.krp -or
        [bool]$v9.netlab.independent.kad6_beta_exit -or
        [bool]$v9.netlab.independent.kad6_stable_public_exit -or
        [bool]$v9.netlab.keepalive_running -or
        [bool]$v9.v9.experimental -or
        [bool]$v9.v9.port_predict -or
        [bool]$v9.v9.ed2k_punch3 -or
        [bool]$v9.v9.kad3_rendezvous -or
        [bool]$v9.v9.keepalive_running -or
        [bool]$v9.v9.hole_punch_master) {
        return $false
    }
    return $true
}

function Get-I04ProductLogCounts {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$PeerIPv4,
        [Parameter(Mandatory = $true)][string]$PeerIPv6,
        [Parameter(Mandatory = $true)][int]$PeerPort,
        [string]$FileAName = '',
        [string]$FileBName = ''
    )

    $fallback = 0
    $boundedFallback = 0
    $hello = 0
    $helloAnswer = 0
    $a4afSwap = 0
    $ambiguous = 0
    $files = @()
    $v4 = [regex]::Escape($PeerIPv4)
    $v6 = [regex]::Escape($PeerIPv6)
    $port = [regex]::Escape([string]$PeerPort)
    # DebugSend(client) and IPv6Fallback deliberately render
    # DbgGetClientInfo(), whose native endpoint contains the authoritative
    # address but no TCP port.  The isolated profile, exact PID/socket
    # correlation and PCAP provide the port attribution; requiring a textual
    # ":port" here would reject every genuine product marker.
    $exactTarget = '(?i)(?:' + $v4 + '|\[?' + $v6 + '\]?)'
    $possiblyRelevant = '(?i)(?<!\d)' + $port + '(?!\d)'
    foreach ($log in @(
        Get-ChildItem -LiteralPath $NodePath -Recurse -File -Filter '*.log' `
            -ErrorAction SilentlyContinue
    )) {
        $lines = @()
        try { $lines = @(Get-Content -LiteralPath $log.FullName) } catch {}
        foreach ($lineValue in $lines) {
            $line = [string]$lineValue
            $isFallback = $line -match
                'IPv6 connect failed \([^\r\n]+retrying [^\r\n]+ over IPv4'
            $isBounded = $line -match
                'IPv6 connect failed \([^\r\n]*bounded blackhole timeout'
            $isHello = $line -match '>>>\s+OP_Hello\s+to\s+'
            $isHelloAnswer = $line -match
                '<<<\s+OP_HelloAnswer\s+from\s+'
            $isA4afSwap = $FileAName -and $FileBName -and
                $line -match '(?i)ooo Swapped source ' -and
                $line -match [regex]::Escape($FileAName) -and
                $line -match [regex]::Escape($FileBName)
            if (-not (
                $isFallback -or $isBounded -or $isHello -or
                $isHelloAnswer -or $isA4afSwap
            )) { continue }
            if ($line -match $exactTarget) {
                if ($isFallback) { $fallback++ }
                if ($isBounded) { $boundedFallback++ }
                if ($isHello) { $hello++ }
                if ($isHelloAnswer) { $helloAnswer++ }
                if ($isA4afSwap) { $a4afSwap++ }
            } elseif ($line -match $possiblyRelevant) {
                # A marker carrying only the target port cannot be attributed
                # to the peer address and is deliberately ambiguous.
                $ambiguous++
            }
        }
        $files += [pscustomobject][ordered]@{
            relative_path = $log.FullName.Substring(
                [IO.Path]::GetFullPath($NodePath).Length
            ).TrimStart('\')
            bytes = $log.Length
            sha256 = Get-LabSha256 -Path $log.FullName
        }
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        fallback_count = $fallback
        bounded_fallback_count = $boundedFallback
        hello_send_count = $hello
        hello_answer_receive_count = $helloAnswer
        a4af_swap_a_to_b_count = $a4afSwap
        ambiguous_target_marker_count = $ambiguous
        target = [ordered]@{
            ipv4 = $PeerIPv4
            ipv6 = $PeerIPv6
            tcp_port = $PeerPort
            file_a_name = $FileAName
            file_b_name = $FileBName
        }
        files = $files
    }
}

function Enable-I04ControlledEd2kProfile {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ServerAddress,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1024, 65535)][int]$ServerPort,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][string]$OwnerRole
    )

    $serverIp = [Net.IPAddress]::Parse($ServerAddress)
    if ($serverIp.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork -or
        [Net.IPAddress]::IsLoopback($serverIp)) {
        throw 'Controlled eD2K profile requires a non-loopback IPv4 server'
    }
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
        'server_met.old.bak', 'staticservers.dat'
    )) {
        $path = Join-Path $config $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
    $staticPath = Join-Path $config 'staticservers.dat'
    $line = '{0}:{1},0,eSE-I04-{2}-{3}' -f
        $ServerAddress, $ServerPort, $RunNonce, $OwnerRole
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

function Start-I04ControlledEd2kServer {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedClientAddress,
        [Parameter(Mandatory = $true)][string]$HighIdAddress,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][string]$OwnerRole,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[object]]$OwnerInventory
    )

    $listenIp = [Net.IPAddress]::Parse($ListenAddress)
    $expectedClientIp = [Net.IPAddress]::Parse($ExpectedClientAddress)
    $highIdIp = [Net.IPAddress]::Parse($HighIdAddress)
    foreach ($validatedIp in @($listenIp, $expectedClientIp, $highIdIp)) {
        if ($validatedIp.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
            [Net.IPAddress]::IsLoopback($validatedIp)) {
            throw 'Controlled eD2K server addresses must be non-loopback IPv4'
        }
    }
    $highIdBytes = $highIdIp.GetAddressBytes()
    $highIdNumeric = [BitConverter]::ToUInt32($highIdBytes, 0)
    if ($highIdNumeric -lt 0x01000000) {
        throw "Controlled server ID derived from $HighIdAddress is LowID"
    }

    # Publish an ownership record before the first external mutation.  The
    # caller can therefore retry cleanup even when construction throws before
    # this function can return its normal server handle.
    $owner = [pscustomobject][ordered]@{
        owner_id = '{0}|{1}|{2}' -f $RunNonce, $OwnerRole, $EvidencePath
        owner_role = $OwnerRole
        evidence_path = $EvidencePath
        started_at_utc = Get-LabUtcTimestamp
        listener = $null
        port = $null
        state = $null
        powershell = $null
        async = $null
        construction_complete = $false
        construction_error = ''
        construction_rollback = $null
        cleanup_attempt_count = 0
        cleanup_complete = $false
        cleanup_result = $null
    }
    $OwnerInventory.Add($owner)

    try {
        $listener = New-Object Net.Sockets.TcpListener($listenIp, 0)
        $owner.listener = $listener
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start(4)
        $port = [int]([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $owner.port = $port
        $state = New-Object `
            'Collections.Concurrent.ConcurrentDictionary[string,object]'
        $owner.state = $state
        $logins = New-Object 'Collections.Concurrent.ConcurrentQueue[object]'
        $state['phase'] = 'listening'
        $state['stop_requested'] = $false
        $state['error'] = ''
        $state['listen_port'] = $port
        $state['listen_address'] = $ListenAddress
        $state['expected_client_address'] = $ExpectedClientAddress
        $state['high_id_address'] = $HighIdAddress
        $state['high_id_numeric'] = [uint32]$highIdNumeric
        $state['login_count'] = 0
        $state['logins'] = $logins

    $serverBody = {
        param(
            $Listener, $State, $ResultPath, $Nonce, $RoleName,
            $AllowedClientAddress, [byte[]]$AssignedIdBytes
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
                    throw (
                        "Controlled server stream closed after " +
                        "$offset/$Count bytes"
                    )
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

        $stoppedAt = ''
        try {
            while (-not [bool]$State['stop_requested']) {
                $client = $null
                $stream = $null
                try {
                    $State['phase'] = 'accepting'
                    $client = $Listener.AcceptTcpClient()
                    if ([bool]$State['stop_requested']) { break }
                    $State['client'] = $client
                    $remote = [Net.IPEndPoint]$client.Client.RemoteEndPoint
                    if ($remote.Address.ToString() -ne
                        $AllowedClientAddress) {
                        throw (
                            "Controlled server accepted unexpected client " +
                            "$remote; expected $AllowedClientAddress"
                        )
                    }
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 30000
                    $header = Read-ExactBytes -Stream $stream -Count 6
                    $packetLength = [BitConverter]::ToUInt32($header, 1)
                    if ($header[0] -ne 0xE3 -or
                        $header[5] -ne 0x01 -or
                        $packetLength -lt 23 -or
                        $packetLength -gt 1048576) {
                        throw (
                            'Expected OP_EDONKEYPROT:OP_LOGINREQUEST; ' +
                            "protocol=0x$('{0:X2}' -f $header[0]) " +
                            "opcode=0x$('{0:X2}' -f $header[5]) " +
                            "length=$packetLength"
                        )
                    }
                    $payload = Read-ExactBytes -Stream $stream `
                        -Count ([int]$packetLength - 1)
                    $hashBytes = New-Object byte[] 16
                    [Array]::Copy($payload, 0, $hashBytes, 0, 16)
                    $userHash = ([BitConverter]::ToString(
                        $hashBytes
                    )).Replace('-', '')
                    if ($userHash -eq ('0' * 32) -or
                        $hashBytes[5] -ne 14 -or
                        $hashBytes[14] -ne 111) {
                        throw 'LOGINREQUEST contains an invalid eMule user hash'
                    }
                    $sha = [Security.Cryptography.SHA256]::Create()
                    try {
                        $payloadSha = ([BitConverter]::ToString(
                            $sha.ComputeHash($payload)
                        )).Replace('-', '').ToLowerInvariant()
                    } finally {
                        $sha.Dispose()
                    }
                    $advertisedPort =
                        [int][BitConverter]::ToUInt16($payload, 20)
                    Send-Ed2kFrame -Stream $stream -Opcode 0x40 `
                        -Payload $AssignedIdBytes
                    $loginIndex = [int]$State['login_count'] + 1
                    $loginAt = [DateTime]::UtcNow.ToString('o')
                    $login = [pscustomobject][ordered]@{
                        index = $loginIndex
                        login_at_utc = $loginAt
                        accepted_remote = $remote.ToString()
                        protocol = [int]$header[0]
                        opcode = [int]$header[5]
                        payload_bytes = $payload.Length
                        payload_sha256 = $payloadSha
                        user_hash = $userHash
                        advertised_tcp_port = $advertisedPort
                    }
                    $State['logins'].Enqueue($login)
                    $State['login_count'] = $loginIndex
                    $State['latest_user_hash'] = $userHash
                    $State['latest_advertised_tcp_port'] = $advertisedPort
                    $State['latest_client_remote'] = $remote.ToString()
                    $State['reply_sent'] = $true
                    $State['phase'] = 'connected'
                    $stream.ReadTimeout = 2000
                    $nextStatus = [DateTime]::UtcNow.AddSeconds(10)
                    while (-not [bool]$State['stop_requested']) {
                        if ($client.Client.Poll(
                            1000,
                            [Net.Sockets.SelectMode]::SelectRead
                        ) -and $client.Client.Available -eq 0) {
                            break
                        }
                        if ($stream.DataAvailable) {
                            $nextHeader =
                                Read-ExactBytes -Stream $stream -Count 6
                            $nextLength =
                                [BitConverter]::ToUInt32($nextHeader, 1)
                            if ($nextLength -lt 1 -or
                                $nextLength -gt 16777216) {
                                throw "Invalid client frame length $nextLength"
                            }
                            $remaining = [int]$nextLength - 1
                            if ($remaining -gt 0) {
                                $null = Read-ExactBytes -Stream $stream `
                                    -Count $remaining
                            }
                        } elseif ([DateTime]::UtcNow -ge $nextStatus) {
                            Send-Ed2kFrame -Stream $stream -Opcode 0x34 `
                                -Payload (New-Object byte[] 8)
                            $nextStatus =
                                [DateTime]::UtcNow.AddSeconds(10)
                        } else {
                            Start-Sleep -Milliseconds 25
                        }
                    }
                } finally {
                    if ($null -ne $stream) {
                        try { $stream.Dispose() } catch {}
                    }
                    if ($null -ne $client) {
                        try { $client.Dispose() } catch {}
                    }
                    $removedClient = $null
                    $null = $State.TryRemove(
                        'client', [ref]$removedClient
                    )
                }
            }
        } catch {
            if (-not [bool]$State['stop_requested']) {
                $State['error'] = $_.Exception.Message
                $State['phase'] = 'error'
            }
        } finally {
            $stoppedAt = [DateTime]::UtcNow.ToString('o')
            try { $Listener.Stop() } catch {}
            if ([string]$State['phase'] -ne 'error') {
                $State['phase'] = 'stopped'
            }
            $State['stopped_at_utc'] = $stoppedAt
            $result = [ordered]@{
                schema = 'ese.v91.i04-controlled-ed2k-server/v1'
                run_nonce = $Nonce
                owner_role = $RoleName
                listen_address = [string]$State['listen_address']
                listen_port = [int]$State['listen_port']
                high_id_address = [string]$State['high_id_address']
                high_id_numeric = [uint32]$State['high_id_numeric']
                stopped_at_utc = $stoppedAt
                phase = [string]$State['phase']
                login_count = [int]$State['login_count']
                login_events = @($State['logins'].ToArray())
                error = [string]$State['error']
            }
            [IO.File]::WriteAllText(
                $ResultPath,
                ($result | ConvertTo-Json -Depth 24),
                (New-Object Text.UTF8Encoding($false))
            )
        }
    }

        $powershell = [PowerShell]::Create()
        $owner.powershell = $powershell
        $null = $powershell.AddScript($serverBody.ToString())
        $null = $powershell.AddArgument($listener)
        $null = $powershell.AddArgument($state)
        $null = $powershell.AddArgument($EvidencePath)
        $null = $powershell.AddArgument($RunNonce)
        $null = $powershell.AddArgument($OwnerRole)
        $null = $powershell.AddArgument($ExpectedClientAddress)
        $null = $powershell.AddArgument($highIdBytes)
        $async = $powershell.BeginInvoke()
        $owner.async = $async
        $owner.construction_complete = $true
        return $owner
    } catch {
        $constructionFailure = $_
        $owner.construction_error = $_.Exception.Message
        try {
            $owner.construction_rollback =
                Stop-I04ControlledEd2kServer -Server $owner
        } catch {
            $owner.construction_rollback = [pscustomobject][ordered]@{
                stopped = $false
                error = $_.Exception.Message
                evidence = $null
            }
        }
        throw $constructionFailure
    }
}

function Wait-I04ControlledEd2kLogin {
    param(
        [Parameter(Mandatory = $true)][object]$Server,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$ExpectedTcpPort,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 16)][int]$MinimumLoginCount,
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
        $loginCount = [int]$Server.state['login_count']
        if ($loginCount -ge $MinimumLoginCount -and
            [bool]$Server.state['reply_sent']) {
            $connections = @(
                Get-NetTCPConnection -State Established `
                    -OwningProcess $Process.Id `
                    -RemoteAddress (
                        [string]$Server.state['listen_address']
                    ) -RemotePort $Server.port -ErrorAction SilentlyContinue
            )
            if ($connections.Count -eq 1 -and
                [int]$Server.state['latest_advertised_tcp_port'] -eq
                    $ExpectedTcpPort) {
                return [pscustomobject][ordered]@{
                    connected = $true
                    login_count = $loginCount
                    server_address =
                        [string]$Server.state['listen_address']
                    server_port = $Server.port
                    client_process_id = $Process.Id
                    client_local_address =
                        Get-I04NormalizedIp -Address `
                            ([string]$connections[0].LocalAddress)
                    client_local_port = [int]$connections[0].LocalPort
                    runtime_user_hash =
                        [string]$Server.state['latest_user_hash']
                    advertised_tcp_port =
                        [int]$Server.state['latest_advertised_tcp_port']
                    assigned_high_id_address =
                        [string]$Server.state['high_id_address']
                    assigned_high_id_numeric =
                        [uint32]$Server.state['high_id_numeric']
                    endpoint_is_same_host_physical = $true
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw (
        'Timed out proving the same-host physical-IP controlled eD2K ' +
        "login #$MinimumLoginCount"
    )
}

function Stop-I04ControlledEd2kServer {
    param([AllowNull()][object]$Server)

    if ($null -eq $Server) {
        return [pscustomobject][ordered]@{
            stopped = $true
            error = $null
            evidence = $null
            owner_id = ''
            construction_complete = $false
            listener_stopped = $true
            powershell_stopped = $true
        }
    }

    $properties = @($Server.PSObject.Properties.Name)
    if ('cleanup_complete' -in $properties -and
        [bool]$Server.cleanup_complete -and
        'cleanup_result' -in $properties -and
        $null -ne $Server.cleanup_result) {
        return $Server.cleanup_result
    }
    if ('cleanup_attempt_count' -in $properties) {
        $Server.cleanup_attempt_count =
            [int]$Server.cleanup_attempt_count + 1
    }

    $errors = New-Object 'Collections.Generic.List[string]'
    $state = if ('state' -in $properties) { $Server.state } else { $null }
    $listener = if ('listener' -in $properties) {
        $Server.listener
    } else { $null }
    $powershell = if ('powershell' -in $properties) {
        $Server.powershell
    } else { $null }
    $async = if ('async' -in $properties) { $Server.async } else { $null }
    $listenerStopped = $null -eq $listener
    $powershellStopped = $null -eq $powershell

    if ($null -ne $state) {
        try {
            $state['stop_requested'] = $true
            if ($state.ContainsKey('client') -and
                $null -ne $state['client']) {
                try { $state['client'].Close() } catch {
                    $errors.Add(
                        "controlled server client close failed: " +
                        $_.Exception.Message
                    )
                }
            }
        } catch {
            $errors.Add(
                "controlled server state stop failed: " +
                $_.Exception.Message
            )
        }
    }
    if ($null -ne $listener) {
        try {
            $listener.Stop()
            $listenerStopped = $true
        } catch {
            $errors.Add(
                "controlled server listener stop failed: " +
                $_.Exception.Message
            )
        }
    }
    if ($null -ne $powershell) {
        try {
            if ($null -ne $async) {
                $completed = $async.AsyncWaitHandle.WaitOne(
                    [TimeSpan]::FromSeconds(10)
                )
                if (-not $completed) {
                    $powershell.Stop()
                    $completed = $async.AsyncWaitHandle.WaitOne(
                        [TimeSpan]::FromSeconds(2)
                    )
                }
                try {
                    $null = $powershell.EndInvoke($async)
                } catch {
                    $stopRequested = $null -ne $state -and
                        [bool]$state['stop_requested']
                    if (-not $stopRequested) {
                        $errors.Add(
                            "controlled server EndInvoke failed: " +
                            $_.Exception.Message
                        )
                    }
                }
                $powershellStopped = $completed -or $async.IsCompleted
                if (-not $powershellStopped) {
                    $errors.Add(
                        'controlled server runspace did not stop within 12 seconds'
                    )
                }
            } else {
                # Construction failed after PowerShell::Create but before
                # BeginInvoke.  Disposing this unstarted owner is sufficient.
                try { $powershell.Stop() } catch {}
                $powershellStopped = $true
            }
        } catch {
            $errors.Add(
                "controlled server runspace stop failed: " +
                $_.Exception.Message
            )
        } finally {
            try {
                $powershell.Dispose()
            } catch {
                $errors.Add(
                    "controlled server runspace dispose failed: " +
                    $_.Exception.Message
                )
            }
        }
    }

    $evidence = $null
    $evidencePath = if ('evidence_path' -in $properties) {
        [string]$Server.evidence_path
    } else { '' }
    if ($evidencePath -and
        (Test-Path -LiteralPath $evidencePath -PathType Leaf)) {
        try {
            $evidence = Get-Content -LiteralPath $evidencePath -Raw |
                ConvertFrom-Json -ErrorAction Stop
        } catch {
            $errors.Add(
                "controlled server evidence parse failed: " +
                $_.Exception.Message
            )
        }
    }

    $errorText = @($errors.ToArray() | Select-Object -Unique) -join '; '
    $result = [pscustomobject][ordered]@{
        stopped = $listenerStopped -and $powershellStopped -and
            -not $errorText
        error = if ($errorText) { $errorText } else { $null }
        evidence = $evidence
        owner_id = if ('owner_id' -in $properties) {
            [string]$Server.owner_id
        } else { '' }
        construction_complete =
            'construction_complete' -in $properties -and
            [bool]$Server.construction_complete
        listener_stopped = $listenerStopped
        powershell_stopped = $powershellStopped
    }
    if ('cleanup_complete' -in $properties) {
        $Server.cleanup_complete = [bool]$result.stopped
    }
    if ('cleanup_result' -in $properties) {
        $Server.cleanup_result = $result
    }
    return $result
}

function Stop-I04ControlledEd2kServerInventory {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[object]]$OwnerInventory,
        [AllowNull()][object]$PrimaryServer = $null
    )

    $owners = New-Object 'Collections.Generic.List[object]'
    $seen = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::Ordinal)
    foreach ($owner in $OwnerInventory.ToArray()) {
        if ($null -eq $owner) { continue }
        $key = if ($owner.PSObject.Properties.Name -contains 'owner_id') {
            [string]$owner.owner_id
        } else { [Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($owner) }
        if ($seen.Add($key)) { $owners.Add($owner) }
    }
    if ($null -ne $PrimaryServer) {
        $key = if ($PrimaryServer.PSObject.Properties.Name -contains
            'owner_id') {
            [string]$PrimaryServer.owner_id
        } else {
            [string][Runtime.CompilerServices.RuntimeHelpers]::GetHashCode(
                $PrimaryServer
            )
        }
        if ($seen.Add($key)) { $owners.Add($PrimaryServer) }
    }

    $results = New-Object 'Collections.Generic.List[object]'
    foreach ($owner in $owners.ToArray()) {
        $results.Add((Stop-I04ControlledEd2kServer -Server $owner))
    }
    $failures = @($results.ToArray() | Where-Object {
        -not [bool]$_.stopped -or [string]$_.error
    })
    return [pscustomobject][ordered]@{
        stopped = $failures.Count -eq 0
        error = if ($failures.Count -eq 0) {
            $null
        } else {
            @($failures | ForEach-Object {
                if ([string]$_.error) {
                    '{0}: {1}' -f $_.owner_id, $_.error
                } else { '{0}: not stopped' -f $_.owner_id }
            }) -join '; '
        }
        evidence = if ($results.Count -eq 1) {
            $results[0].evidence
        } else {
            @($results.ToArray() | ForEach-Object { $_.evidence })
        }
        owner_count = $owners.Count
        owner_results = $results.ToArray()
    }
}

function Get-I04RouteEvidence {
    param([Parameter(Mandatory = $true)][string]$RemoteAddress)

    try {
        $route = Find-NetRoute -RemoteIPAddress $RemoteAddress `
            -ErrorAction Stop | Select-Object -First 1
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex `
            -ErrorAction SilentlyContinue
        $onLink = $route.NextHop -eq '0.0.0.0' -or $route.NextHop -eq '::'
        $isVirtual = $true
        $overlayLike = $true
        $physicalNonvirtual = $false
        if ($adapter) {
            $isVirtual = $false
            if ($adapter.PSObject.Properties.Name -contains 'Virtual') {
                $isVirtual = [bool]$adapter.Virtual
            }
            $overlayLike =
                ([string]$adapter.Name) -match $overlayPattern -or
                ([string]$adapter.InterfaceDescription) -match
                    $overlayPattern
            $physicalNonvirtual =
                [bool]$adapter.HardwareInterface -and
                -not $isVirtual -and -not $overlayLike -and
                [string]$adapter.Status -eq 'Up'
        }
        return [pscustomobject][ordered]@{
            available = $true
            family = if ($RemoteAddress.Contains(':')) { 'IPv6' } else { 'IPv4' }
            remote_address = Get-I04NormalizedIp -Address $RemoteAddress
            interface_index = [int]$route.InterfaceIndex
            interface_id = if ($adapter) {
                Get-LabInterfaceId -Id ([string]$adapter.InterfaceGuid) `
                    -Name ([string]$adapter.Name) `
                    -Description ([string]$adapter.InterfaceDescription)
            } else { '' }
            interface_status = if ($adapter) {
                [string]$adapter.Status
            } else { 'Unknown' }
            hardware_interface = if ($adapter) {
                [bool]$adapter.HardwareInterface
            } else { $false }
            virtual = $isVirtual
            overlay_or_vpn_like = $overlayLike
            physical_nonvirtual = $physicalNonvirtual
            on_link = $onLink
            source_address = Get-I04NormalizedIp -Address ([string]$route.IPAddress)
            next_hop = Get-I04NormalizedIp -Address ([string]$route.NextHop)
            next_hop_class = if ($onLink) {
                'on-link'
            } else {
                Get-LabAddressClass -Address ([string]$route.NextHop)
            }
            error = $null
        }
    } catch {
        return [pscustomobject][ordered]@{
            available = $false
            family = if ($RemoteAddress.Contains(':')) { 'IPv6' } else { 'IPv4' }
            remote_address = Get-I04NormalizedIp -Address $RemoteAddress
            interface_index = $null
            interface_id = ''
            interface_status = 'Unknown'
            hardware_interface = $false
            virtual = $true
            overlay_or_vpn_like = $true
            physical_nonvirtual = $false
            on_link = $false
            source_address = ''
            next_hop = ''
            next_hop_class = 'unknown'
            error = $_.Exception.Message
        }
    }
}

function Get-I04IsolationEvidence {
    $adapterQueryError = $null
    $adapters = @()
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop)
    } catch {
        $adapterQueryError = $_.Exception.Message
    }
    $overlays = @(
        $adapters | Where-Object {
            [string]$_.Status -eq 'Up' -and (
                ([string]$_.Name) -match $overlayPattern -or
                ([string]$_.InterfaceDescription) -match $overlayPattern
            )
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                interface_index = [int]$_.InterfaceIndex
                interface_id = Get-LabInterfaceId `
                    -Id ([string]$_.InterfaceGuid) `
                    -Name ([string]$_.Name) `
                    -Description ([string]$_.InterfaceDescription)
            }
        }
    )
    $proxyEnvironmentNames = @(
        'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
        'http_proxy', 'https_proxy', 'all_proxy'
    )
    $setProxyEnvironmentNames = @(
        $proxyEnvironmentNames | Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                [Environment]::GetEnvironmentVariable($_)
            )
        } | Sort-Object -Unique
    )
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        adapter_inventory_error = $adapterQueryError
        active_overlay_or_vpn_adapters = $overlays
        active_overlay_or_vpn_count = $overlays.Count
        proxy_environment_variable_names_set = $setProxyEnvironmentNames
        proxy_environment_variable_count = $setProxyEnvironmentNames.Count
        strict_isolation_valid =
            -not $adapterQueryError -and $overlays.Count -eq 0 -and
            $setProxyEnvironmentNames.Count -eq 0
    }
}

function Convert-I04ValueSet {
    param(
        [AllowNull()][object[]]$Values,
        [switch]$NormalizeIp,
        [switch]$NormalizePath
    )

    $result = @()
    foreach ($value in @($Values)) {
        foreach ($item in @(([string]$value) -split ',')) {
            $text = $item.Trim()
            if (-not $text) { continue }
            if ($NormalizeIp) {
                $text = Get-I04NormalizedIp -Address $text
            } elseif ($NormalizePath) {
                try { $text = [IO.Path]::GetFullPath($text) } catch {}
                $text = $text.ToLowerInvariant()
            } else {
                $text = $text.ToLowerInvariant()
            }
            $result += $text
        }
    }
    return @($result | Sort-Object -Unique)
}

function Test-I04ValueSetEqual {
    param(
        [AllowNull()][object[]]$Actual,
        [AllowNull()][object[]]$Expected,
        [switch]$NormalizeIp,
        [switch]$NormalizePath
    )

    $actualSet = @(Convert-I04ValueSet -Values $Actual `
        -NormalizeIp:$NormalizeIp -NormalizePath:$NormalizePath)
    $expectedSet = @(Convert-I04ValueSet -Values $Expected `
        -NormalizeIp:$NormalizeIp -NormalizePath:$NormalizePath)
    return ($actualSet.Count -eq $expectedSet.Count -and
        ($actualSet -join "`n") -ceq ($expectedSet -join "`n"))
}

function Get-I04FirewallRuleEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][ValidateSet('Allow', 'Block')]
        [string]$Action,
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$LocalAddresses,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddresses,
        [Parameter(Mandatory = $true)][int]$LocalPort
    )

    $rules = @(Get-NetFirewallRule -DisplayName $DisplayName `
        -ErrorAction SilentlyContinue)
    $application = @()
    $address = @()
    $port = @()
    if ($rules.Count -eq 1) {
        $application = @($rules[0] | Get-NetFirewallApplicationFilter `
            -ErrorAction SilentlyContinue)
        $address = @($rules[0] | Get-NetFirewallAddressFilter `
            -ErrorAction SilentlyContinue)
        $port = @($rules[0] | Get-NetFirewallPortFilter `
            -ErrorAction SilentlyContinue)
    }
    $protocolExact = $port.Count -eq 1 -and
        @('6', 'tcp') -contains ([string]$port[0].Protocol).ToLowerInvariant()
    $exact = $rules.Count -eq 1 -and $application.Count -eq 1 -and
        $address.Count -eq 1 -and $port.Count -eq 1 -and
        ([string]$rules[0].Direction) -eq 'Inbound' -and
        ([string]$rules[0].Action) -eq $Action -and
        ([string]$rules[0].Enabled) -eq 'True' -and
        ([string]$rules[0].Profile) -eq 'Any' -and
        (Test-I04ValueSetEqual -Actual @($application[0].Program) `
            -Expected @($Program) -NormalizePath) -and
        (Test-I04ValueSetEqual -Actual @($address[0].LocalAddress) `
            -Expected $LocalAddresses -NormalizeIp) -and
        (Test-I04ValueSetEqual -Actual @($address[0].RemoteAddress) `
            -Expected $RemoteAddresses -NormalizeIp) -and
        $protocolExact -and
        ([string]$port[0].LocalPort) -eq ([string]$LocalPort) -and
        ([string]$port[0].RemotePort) -eq 'Any'
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        display_name = $DisplayName
        rule_count = $rules.Count
        direction = if ($rules.Count -eq 1) {
            [string]$rules[0].Direction
        } else { '' }
        action = if ($rules.Count -eq 1) {
            [string]$rules[0].Action
        } else { '' }
        enabled = $rules.Count -eq 1 -and
            ([string]$rules[0].Enabled) -eq 'True'
        profile = if ($rules.Count -eq 1) {
            [string]$rules[0].Profile
        } else { '' }
        program = if ($application.Count -eq 1) {
            [string]$application[0].Program
        } else { '' }
        program_file_sha256 = if ($application.Count -eq 1 -and
            (Test-Path -LiteralPath ([string]$application[0].Program) `
                -PathType Leaf)) {
            Get-LabSha256 -Path ([string]$application[0].Program)
        } else { '' }
        protocol = if ($port.Count -eq 1) {
            [string]$port[0].Protocol
        } else { '' }
        local_addresses = if ($address.Count -eq 1) {
            @(Convert-I04ValueSet -Values @($address[0].LocalAddress) -NormalizeIp)
        } else { @() }
        remote_addresses = if ($address.Count -eq 1) {
            @(Convert-I04ValueSet -Values @($address[0].RemoteAddress) -NormalizeIp)
        } else { @() }
        local_port = if ($port.Count -eq 1) {
            [string]$port[0].LocalPort
        } else { '' }
        remote_port = if ($port.Count -eq 1) {
            [string]$port[0].RemotePort
        } else { '' }
        exact = $exact
    }
}

function Invoke-I04Pktmon {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
    )

    $process = $null
    $timedOut = $false
    $output = @()
    $errorOutput = @()
    $exitCode = 9009
    try {
        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = (Get-Command pktmon.exe -ErrorAction Stop).Source
        # Quote according to CommandLineToArgvW rules. All values are
        # harness-derived, but paths may contain whitespace or quotes.
        $quotedArguments = foreach ($argumentValue in $Arguments) {
            $argument = [string]$argumentValue
            if ($argument -notmatch '[\s"]') {
                $argument
                continue
            }
            $builder = New-Object Text.StringBuilder
            $null = $builder.Append('"')
            $backslashes = 0
            foreach ($character in $argument.ToCharArray()) {
                if ($character -eq '\') {
                    $backslashes++
                    continue
                }
                if ($character -eq '"') {
                    $null = $builder.Append(('\' * ($backslashes * 2 + 1)))
                    $null = $builder.Append('"')
                    $backslashes = 0
                    continue
                }
                if ($backslashes -gt 0) {
                    $null = $builder.Append(('\' * $backslashes))
                    $backslashes = 0
                }
                $null = $builder.Append($character)
            }
            if ($backslashes -gt 0) {
                $null = $builder.Append(('\' * ($backslashes * 2)))
            }
            $null = $builder.Append('"')
            $builder.ToString()
        }
        $startInfo.Arguments = $quotedArguments -join ' '
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'pktmon process did not start'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { $process.Kill() } catch {}
            $null = $process.WaitForExit(10000)
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $output = if ($stdout) { @($stdout -split '\r?\n') } else { @() }
        $errorOutput = if ($stderr) { @($stderr -split '\r?\n') } else { @() }
        if ($timedOut) {
            $exitCode = 1460
        } elseif ($process.HasExited) {
            $exitCode = $process.ExitCode
        }
    } catch {
        $errorOutput += $_.Exception.Message
        $exitCode = 9009
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
    $logError = $null
    try {
        Add-Content -LiteralPath $LogPath -Encoding utf8 -Value @(
            ('[{0}] pktmon {1}' -f (Get-LabUtcTimestamp),
                ($Arguments -join ' ')),
            ($output | ForEach-Object { [string]$_ }),
            ($errorOutput | ForEach-Object { [string]$_ }),
            "timed_out=$timedOut",
            "exit_code=$exitCode"
        )
    } catch {
        $logError = $_.Exception.Message
    }
    return [pscustomobject][ordered]@{
        exit_code = $exitCode
        timed_out = $timedOut
        output = @($output + $errorOutput)
        log_error = $logError
    }
}

function Get-I04EtwLossEvidence {
    param([Parameter(Mandatory = $true)][string]$SessionName)

    if (-not ('V91I04EtwTraceQuery' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class V91I04EtwTraceQuery {
    [StructLayout(LayoutKind.Sequential)]
    private struct WNODE_HEADER {
        public UInt32 BufferSize;
        public UInt32 ProviderId;
        public UInt64 HistoricalContext;
        public Int64 TimeStamp;
        public Guid Guid;
        public UInt32 ClientContext;
        public UInt32 Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_TRACE_PROPERTIES {
        public WNODE_HEADER Wnode;
        public UInt32 BufferSize;
        public UInt32 MinimumBuffers;
        public UInt32 MaximumBuffers;
        public UInt32 MaximumFileSize;
        public UInt32 LogFileMode;
        public UInt32 FlushTimer;
        public UInt32 EnableFlags;
        public Int32 AgeLimit;
        public UInt32 NumberOfBuffers;
        public UInt32 FreeBuffers;
        public UInt32 EventsLost;
        public UInt32 BuffersWritten;
        public UInt32 LogBuffersLost;
        public UInt32 RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public UInt32 LogFileNameOffset;
        public UInt32 LoggerNameOffset;
    }

    public sealed class Result {
        public UInt32 ErrorCode;
        public UInt32 EventsLost;
        public UInt32 LogBuffersLost;
        public UInt32 RealTimeBuffersLost;
        public UInt32 BuffersWritten;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern UInt32 ControlTrace(
        UInt64 sessionHandle, string sessionName, IntPtr properties,
        UInt32 controlCode);

    public static Result Query(string sessionName) {
        int propertiesSize = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
        byte[] encodedName = Encoding.Unicode.GetBytes(sessionName + "\0");
        int totalSize = propertiesSize + encodedName.Length + 2;
        IntPtr buffer = Marshal.AllocHGlobal(totalSize);
        try {
            byte[] zero = new byte[totalSize];
            Marshal.Copy(zero, 0, buffer, zero.Length);
            EVENT_TRACE_PROPERTIES properties = new EVENT_TRACE_PROPERTIES();
            properties.Wnode.BufferSize = (UInt32)totalSize;
            properties.Wnode.Flags = 0x00020000; // WNODE_FLAG_TRACED_GUID
            properties.LoggerNameOffset = (UInt32)propertiesSize;
            Marshal.StructureToPtr(properties, buffer, false);
            Marshal.Copy(encodedName, 0, IntPtr.Add(buffer, propertiesSize),
                encodedName.Length);
            UInt32 error = ControlTrace(0, sessionName, buffer, 0);
            Result result = new Result();
            result.ErrorCode = error;
            if (error == 0) {
                properties = (EVENT_TRACE_PROPERTIES)
                    Marshal.PtrToStructure(
                        buffer, typeof(EVENT_TRACE_PROPERTIES));
                result.EventsLost = properties.EventsLost;
                result.LogBuffersLost = properties.LogBuffersLost;
                result.RealTimeBuffersLost = properties.RealTimeBuffersLost;
                result.BuffersWritten = properties.BuffersWritten;
            }
            return result;
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
'@
    }

    try {
        $query = [V91I04EtwTraceQuery]::Query($SessionName)
        $buffersLost = [UInt64]$query.LogBuffersLost +
            [UInt64]$query.RealTimeBuffersLost
        return [pscustomobject][ordered]@{
            available = [UInt32]$query.ErrorCode -eq 0
            error_code = [UInt32]$query.ErrorCode
            events_lost = [UInt64]$query.EventsLost
            log_buffers_lost = [UInt64]$query.LogBuffersLost
            realtime_buffers_lost = [UInt64]$query.RealTimeBuffersLost
            buffers_lost = $buffersLost
            buffers_written = [UInt64]$query.BuffersWritten
            proved_zero = [UInt32]$query.ErrorCode -eq 0 -and
                [UInt64]$query.EventsLost -eq 0 -and $buffersLost -eq 0
            error = if ([UInt32]$query.ErrorCode -eq 0) {
                $null
            } else {
                "ControlTrace query returned Win32 $($query.ErrorCode)"
            }
        }
    } catch {
        return [pscustomobject][ordered]@{
            available = $false
            error_code = $null
            events_lost = $null
            log_buffers_lost = $null
            realtime_buffers_lost = $null
            buffers_lost = $null
            buffers_written = $null
            proved_zero = $false
            error = $_.Exception.Message
        }
    }
}

function Start-I04PacketCapture {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$FilterPrefix,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$JournalPath
    )

    $state = [ordered]@{
        available = $false
        started = $false
        start_attempted = $false
        ever_started = $false
        capture_ended_epoch_ms = $null
        filters = @()
        etl_path = Join-Path $EvidencePath 'i04-packets.etl'
        pcapng_path = Join-Path $EvidencePath 'i04-packets.pcapng'
        command_log = Join-Path $EvidencePath 'pktmon.log'
        filters_before_path = Join-Path $EvidencePath 'pktmon-filters-before.txt'
        filters_armed_path = Join-Path $EvidencePath 'pktmon-filters-armed.txt'
        session_started_path =
            Join-Path $EvidencePath 'pktmon-etw-session-started.txt'
        status_after_path = Join-Path $EvidencePath 'pktmon-status-after.txt'
        filters_after_path = Join-Path $EvidencePath 'pktmon-filters-after.txt'
        etw_after_path = Join-Path $EvidencePath 'pktmon-etw-session-after.txt'
        etw_session_stopped_verified = $null
        etw_session_owned_by_start_attempt = $false
        owned_filters_absent_verified = $null
        filter_inventory_restored_verified = $null
        filters_applied_verified = $false
        etw_loss_proved_zero = $false
        etw_events_lost = $null
        etw_buffers_lost = $null
        etw_log_buffers_lost = $null
        etw_realtime_buffers_lost = $null
        etw_buffers_written = $null
        etw_query_error = $null
        etl_size_bytes = $null
        etl_below_circular_limit = $false
        error = $null
    }
    if ($null -eq (Get-Command pktmon.exe -ErrorAction SilentlyContinue)) {
        $state.error = 'pktmon.exe is unavailable'
        return [pscustomobject]$state
    }

    $statusPath = Join-Path $EvidencePath 'pktmon-status-before.txt'
    $filterPath = $state.filters_before_path
    @(& pktmon.exe status 2>&1) | Set-Content -LiteralPath $statusPath -Encoding utf8
    $filtersBefore = @(& pktmon.exe filter list 2>&1)
    $filtersBeforeExit = $LASTEXITCODE
    $filtersBefore |
        Set-Content -LiteralPath $filterPath -Encoding utf8
    $etwProbePath = Join-Path $EvidencePath 'pktmon-etw-session-before.txt'
    $etwProbe = @(& logman.exe query -ets PktMon 2>&1)
    $etwProbeExit = $LASTEXITCODE
    $etwProbe | Set-Content -LiteralPath $etwProbePath -Encoding utf8
    Add-I04Journal -Path $JournalPath -Mutation 'pktmon-state' `
        -State 'backed_up' -Detail 'Status and filter list captured before mutation'
    if ($etwProbeExit -eq 0) {
        $state.error = 'An existing PktMon ETW capture owns the global session; refusing to alter its filters or stop it'
        return [pscustomobject]$state
    }
    $filtersBeforeText = $filtersBefore -join "`n"
    $emptyFilterInventory = $filtersBeforeExit -eq 0 -and
        $filtersBeforeText -match
            '(?im)^\s*(?:none|no\s+filters(?:\s+(?:are\s+)?(?:configured|present))?|ning[uú]n[oa]?|ning[uú]n\s+filtro|no\s+hay\s+filtros|sin\s+filtros|no\s+se\s+especificaron\s+filtros\s+de\s+paquete)\.?\s*$'
    if (-not $emptyFilterInventory) {
        $state.error = (
            'PktMon filter inventory was not provably empty before the run; ' +
            'refusing to capture with global third-party filters'
        )
        return [pscustomobject]$state
    }

    $filterV4 = "$FilterPrefix-v4"
    $filterV6 = "$FilterPrefix-v6"
    $filterIcmp = "$FilterPrefix-icmp6"
    $preexistingFilterText = (
        Get-Content -LiteralPath $filterPath -Raw -ErrorAction Stop
    )
    $preexistingOwnedNames = @(
        @($filterV4, $filterV6, $filterIcmp) | Where-Object {
            $preexistingFilterText.IndexOf(
                [string]$_, [StringComparison]::OrdinalIgnoreCase
            ) -ge 0
        }
    )
    if ($preexistingOwnedNames.Count -ne 0) {
        $state.error = (
            'A run-owned PktMon filter name already exists before mutation: ' +
            ($preexistingOwnedNames -join ',')
        )
        return [pscustomobject]$state
    }
    # Register every intended mutation before the first controller call. A
    # timed-out pktmon invocation may have applied its filter even when no
    # success result reached this process, so rollback must know all names.
    $state.filters = @($filterV4, $filterV6, $filterIcmp)
    try {
        $filterV4Result = Invoke-I04Pktmon -LogPath $state.command_log `
            -Arguments @(
            'filter', 'add', $filterV4, '-i', $IPv4,
            '-p', ([string]$Port), '-t', 'TCP'
        )
        if ($filterV4Result.exit_code -ne 0 -or
            $filterV4Result.log_error) {
            throw 'pktmon rejected the IPv4 TCP filter'
        }
        $filterV6Result = Invoke-I04Pktmon -LogPath $state.command_log `
            -Arguments @(
            'filter', 'add', $filterV6, '-i', $IPv6,
            '-p', ([string]$Port), '-t', 'TCP'
        )
        if ($filterV6Result.exit_code -ne 0 -or
            $filterV6Result.log_error) {
            throw 'pktmon rejected the IPv6 TCP filter'
        }
        # Capture every ICMPv6 error, not only packets whose outer address is
        # the peer: a router can reject the route while quoting the peer only
        # inside the ICMP payload. Without this filter "silent" is unprovable.
        $filterIcmpResult = Invoke-I04Pktmon -LogPath $state.command_log `
            -Arguments @(
            'filter', 'add', $filterIcmp, '-t', 'ICMPV6'
        )
        if ($filterIcmpResult.exit_code -ne 0 -or
            $filterIcmpResult.log_error) {
            throw 'pktmon rejected the required all-ICMPv6 filter'
        }
        Add-I04Journal -Path $JournalPath -Mutation 'pktmon-filters' `
            -State 'applied' -Detail ($state.filters -join ',')

        $armedFilters = @(& pktmon.exe filter list 2>&1)
        $armedFilterExit = $LASTEXITCODE
        $armedFilters | Set-Content -LiteralPath $state.filters_armed_path `
            -Encoding utf8
        $armedFilterText = $armedFilters -join "`n"
        $state.filters_applied_verified = $armedFilterExit -eq 0 -and
            @($state.filters | Where-Object {
                $armedFilterText.IndexOf(
                    [string]$_, [StringComparison]::OrdinalIgnoreCase
                ) -lt 0
            }).Count -eq 0
        if (-not $state.filters_applied_verified) {
            throw 'PktMon did not list every run-owned filter before capture'
        }

        $state.start_attempted = $true
        $startResult = Invoke-I04Pktmon -LogPath $state.command_log `
            -Arguments @(
            'start', '--capture', '--comp', 'nics', '--pkt-size', '0',
            '--file-name', $state.etl_path, '--file-size', '256'
        )
        $sessionProbe = @(& logman.exe query -ets PktMon 2>&1)
        $sessionProbeExit = $LASTEXITCODE
        $sessionProbe | Set-Content `
            -LiteralPath $state.session_started_path -Encoding utf8
        if ($sessionProbeExit -eq 0) {
            # Preflight proved this global session absent immediately before
            # the unique start attempt. Even an ambiguous controller return
            # therefore creates an owned cleanup obligation.
            $state.etw_session_owned_by_start_attempt = $true
            $state.started = $true
            $state.ever_started = $true
        }
        if ($startResult.exit_code -ne 0 -or $startResult.log_error) {
            throw 'pktmon capture could not start; another capture may own the global session'
        }
        if ($sessionProbeExit -ne 0) {
            throw 'pktmon start returned success but no PktMon ETW session exists'
        }
        $state.started = $true
        $state.ever_started = $true
        Add-I04Journal -Path $JournalPath -Mutation 'pktmon-capture' `
            -State 'applied' -Detail $state.etl_path
        $state.available = $true
    } catch {
        $state.available = $false
        $state.error = $_.Exception.Message
    }
    return [pscustomobject]$state
}

function Stop-I04PacketCapture {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$CleanupFailures
    )

    $pktmonCommand = Get-Command pktmon.exe -ErrorAction SilentlyContinue
    $logmanCommand = Get-Command logman.exe -ErrorAction SilentlyContinue
    if ($null -eq $pktmonCommand -or $null -eq $logmanCommand) {
        $State.etw_session_stopped_verified = $null
        $State.owned_filters_absent_verified = $null
        $State.filter_inventory_restored_verified = $null
        $State.etw_loss_proved_zero = $false
        $CleanupFailures.Add(
            'pktmon/logman disappeared before cleanup; capture, filter and ' +
            'ETW-session restoration cannot be verified'
        )
        return
    }

    $sessionPresent = $false
    if ([bool]$State.start_attempted) {
        try {
            $sessionProbe = @(& logman.exe query -ets PktMon 2>&1)
            $sessionPresent = $LASTEXITCODE -eq 0
            if ($sessionPresent) {
                $State.etw_session_owned_by_start_attempt = $true
                $State.started = $true
                $State.ever_started = $true
            }
        } catch {
            $CleanupFailures.Add(
                "PktMon ownership probe failed: $($_.Exception.Message)"
            )
        }
    }
    $captureStopped = -not $sessionPresent -and -not [bool]$State.started
    if ($sessionPresent -or [bool]$State.started) {
        try {
            # This is the conservative upper boundary of admissible packet
            # observation. It is recorded before ETW loss inspection and stop.
            $captureEnd = [DateTimeOffset]::UtcNow
            $State.capture_ended_epoch_ms =
                Get-I04EpochMilliseconds -Timestamp $captureEnd
            $loss = Get-I04EtwLossEvidence -SessionName 'PktMon'
            $State.etw_events_lost = $loss.events_lost
            $State.etw_buffers_lost = $loss.buffers_lost
            $State.etw_log_buffers_lost = $loss.log_buffers_lost
            $State.etw_realtime_buffers_lost = $loss.realtime_buffers_lost
            $State.etw_buffers_written = $loss.buffers_written
            $State.etw_loss_proved_zero = [bool]$loss.proved_zero
            $State.etw_query_error = $loss.error
            $stopResult = Invoke-I04Pktmon -LogPath $State.command_log `
                -Arguments @('stop')
            if ($stopResult.exit_code -ne 0 -or $stopResult.log_error) {
                throw 'pktmon stop returned a failure'
            }
            $State.started = $false
            $captureStopped = $true
            if (Test-Path -LiteralPath $State.etl_path -PathType Leaf) {
                $State.etl_size_bytes =
                    (Get-Item -LiteralPath $State.etl_path `
                        -ErrorAction Stop).Length
                $State.etl_below_circular_limit =
                    [Int64]$State.etl_size_bytes -lt 256MB
                if (-not $State.etl_below_circular_limit) {
                    throw (
                        'PktMon ETL reached its 256 MiB circular limit; ' +
                        'capture-start retention is not provable'
                    )
                }
            }
            Add-I04RollbackJournal -Path $JournalPath `
                -Mutation 'pktmon-capture' -State 'rolled_back' `
                -Detail 'capture stopped' -CleanupFailures $CleanupFailures
        } catch {
            $CleanupFailures.Add($_.Exception.Message)
        }
    }
    if ($captureStopped -and
        (Test-Path -LiteralPath $State.etl_path -PathType Leaf)) {
        try {
            $conversionResult = Invoke-I04Pktmon `
                -LogPath $State.command_log -Arguments @(
                'etl2pcap', $State.etl_path, '--out', $State.pcapng_path
            )
            if ($conversionResult.exit_code -ne 0 -or
                $conversionResult.log_error) {
                throw 'pktmon ETL to PCAPNG conversion failed'
            }
        } catch {
            $CleanupFailures.Add($_.Exception.Message)
        }
    }

    $ownedFilterNames = @($State.filters)
    $remainingFilters = New-Object 'Collections.Generic.List[string]'
    try {
        $filterInventory = @(& pktmon.exe filter list 2>&1)
        $filterInventoryExit = $LASTEXITCODE
        $filterInventoryText = $filterInventory -join "`n"
    } catch {
        $filterInventory = @()
        $filterInventoryExit = -1
        $filterInventoryText = ''
        $CleanupFailures.Add(
            "pktmon filter inventory query failed: $($_.Exception.Message)"
        )
    }
    foreach ($filter in $ownedFilterNames) {
        $listed = $filterInventoryExit -ne 0 -or
            $filterInventoryText.IndexOf(
                [string]$filter, [StringComparison]::OrdinalIgnoreCase
            ) -ge 0
        if (-not $listed) { continue }
        try {
            $removeResult = Invoke-I04Pktmon `
                -LogPath $State.command_log -Arguments @(
                'filter', 'remove', [string]$filter
            )
            if ($removeResult.exit_code -ne 0 -or
                $removeResult.log_error) {
                throw "pktmon filter '$filter' could not be removed"
            }
        } catch {
            $CleanupFailures.Add($_.Exception.Message)
            $remainingFilters.Add([string]$filter)
        }
    }
    if ($ownedFilterNames.Count -gt 0 -and $remainingFilters.Count -eq 0) {
        Add-I04RollbackJournal -Path $JournalPath `
            -Mutation 'pktmon-filters' -State 'rolled_back' `
            -Detail ($ownedFilterNames -join ',') `
            -CleanupFailures $CleanupFailures
    }
    $State.filters = @($remainingFilters)

    try {
        $statusAfter = @(& pktmon.exe status 2>&1)
        $statusAfter | Set-Content -LiteralPath $State.status_after_path `
            -Encoding utf8
        $filtersAfter = @(& pktmon.exe filter list 2>&1)
        $filtersAfter | Set-Content -LiteralPath $State.filters_after_path `
            -Encoding utf8
        $filterText = $filtersAfter -join "`n"
        $ownedStillListed = @($ownedFilterNames | Where-Object {
            $filterText.IndexOf([string]$_,
                [StringComparison]::OrdinalIgnoreCase) -ge 0
        })
        $State.owned_filters_absent_verified =
            $ownedStillListed.Count -eq 0 -and $State.filters.Count -eq 0
        if (-not $State.owned_filters_absent_verified) {
            $CleanupFailures.Add(
                'pktmon post-cleanup filter list still contains an owned filter'
            )
        }
        $filtersBeforeText = if (Test-Path `
            -LiteralPath $State.filters_before_path -PathType Leaf) {
            Get-Content -LiteralPath $State.filters_before_path -Raw
        } else { $null }
        $filtersBeforeNormalized = if ($null -eq $filtersBeforeText) {
            $null
        } else { $filtersBeforeText.Trim() -replace "`r`n", "`n" }
        $filtersAfterNormalized =
            (($filtersAfter -join "`n").Trim() -replace "`r`n", "`n")
        $State.filter_inventory_restored_verified =
            $null -ne $filtersBeforeNormalized -and
            $filtersBeforeNormalized -ceq $filtersAfterNormalized
        if (-not $State.filter_inventory_restored_verified) {
            $CleanupFailures.Add(
                'pktmon full filter inventory differs from its pre-mutation snapshot'
            )
        }

        $etwAfter = @(& logman.exe query -ets PktMon 2>&1)
        $etwAfterExit = $LASTEXITCODE
        $etwAfter | Set-Content -LiteralPath $State.etw_after_path -Encoding utf8
        $State.etw_session_stopped_verified = $etwAfterExit -ne 0
        if ($State.ever_started -and
            -not $State.etw_session_stopped_verified) {
            $State.started = $true
            $CleanupFailures.Add(
                'PktMon ETW session is still active after owned-capture cleanup'
            )
        }
    } catch {
        $CleanupFailures.Add(
            "pktmon post-cleanup state could not be verified: $($_.Exception.Message)"
        )
    }
}

function Initialize-I04SocketSampler {
    if ('V91I04SocketSampler' -as [type]) { return }
    Add-Type @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class V91I04SocketSampler {
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public uint owningPid;
    }

    public sealed class Row {
        public string Family;
        public string State;
        public string LocalAddress;
        public int LocalPort;
        public string RemoteAddress;
        public int RemotePort;
        public int OwningProcess;
    }

    public sealed class Handle {
        internal CancellationTokenSource Cancellation;
        internal Task Worker;
        public string Path;
        public string Error;
        public long Samples;
        public long Rows;
        public bool Stopped;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table, ref int size, bool order, int family,
        int tableClass, uint reserved);

    private static int Port(uint raw) {
        return (int)(((raw & 0xFFu) << 8) | ((raw & 0xFF00u) >> 8));
    }

    private static string StateName(uint state) {
        switch (state) {
        case 2: return "Listen";
        case 3: return "SynSent";
        case 4: return "SynReceived";
        case 5: return "Established";
        case 6: return "FinWait1";
        case 7: return "FinWait2";
        case 8: return "CloseWait";
        case 9: return "Closing";
        case 10: return "LastAck";
        case 11: return "TimeWait";
        case 12: return "DeleteTcb";
        default: return "Closed";
        }
    }

    private static string V4(uint raw) {
        return new IPAddress(BitConverter.GetBytes(raw)).ToString();
    }

    private static string V6(byte[] bytes, uint scope) {
        IPAddress ip = new IPAddress(bytes, scope);
        if (ip.IsIPv4MappedToIPv6)
            return ip.MapToIPv4().ToString();
        return ip.ToString().Split('%')[0];
    }

    private static void AppendFamily(List<Row> rows, int family) {
        int size = 0;
        uint first = GetExtendedTcpTable(
            IntPtr.Zero, ref size, false, family,
            TCP_TABLE_OWNER_PID_ALL, 0);
        if (first != 0 && first != 122)
            throw new InvalidOperationException(
                "GetExtendedTcpTable size failed: " + first);
        if (size < 4) size = 4;
        IntPtr buffer = IntPtr.Zero;
        try {
            uint result = 122;
            for (int attempt = 0; attempt < 8 && result == 122; ++attempt) {
                if (buffer != IntPtr.Zero) {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                }
                buffer = Marshal.AllocHGlobal(size);
                int returnedSize = size;
                result = GetExtendedTcpTable(
                    buffer, ref returnedSize, false, family,
                    TCP_TABLE_OWNER_PID_ALL, 0);
                if (result == 122) {
                    size = Math.Max(returnedSize, checked(size * 2));
                } else {
                    size = returnedSize;
                }
            }
            if (result != 0)
                throw new InvalidOperationException(
                    "GetExtendedTcpTable failed after bounded resize: " +
                    result);
            int count = Marshal.ReadInt32(buffer);
            IntPtr cursor = IntPtr.Add(buffer, 4);
            if (family == AF_INET) {
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                for (int i = 0; i < count; ++i) {
                    MIB_TCPROW_OWNER_PID raw =
                        (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(
                            cursor, typeof(MIB_TCPROW_OWNER_PID));
                    rows.Add(new Row {
                        Family = "IPv4",
                        State = StateName(raw.state),
                        LocalAddress = V4(raw.localAddr),
                        LocalPort = Port(raw.localPort),
                        RemoteAddress = V4(raw.remoteAddr),
                        RemotePort = Port(raw.remotePort),
                        OwningProcess = unchecked((int)raw.owningPid)
                    });
                    cursor = IntPtr.Add(cursor, rowSize);
                }
            } else {
                int rowSize = Marshal.SizeOf(typeof(MIB_TCP6ROW_OWNER_PID));
                for (int i = 0; i < count; ++i) {
                    MIB_TCP6ROW_OWNER_PID raw =
                        (MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(
                            cursor, typeof(MIB_TCP6ROW_OWNER_PID));
                    rows.Add(new Row {
                        Family = "IPv6",
                        State = StateName(raw.state),
                        LocalAddress = V6(raw.localAddr, raw.localScopeId),
                        LocalPort = Port(raw.localPort),
                        RemoteAddress = V6(
                            raw.remoteAddr, raw.remoteScopeId),
                        RemotePort = Port(raw.remotePort),
                        OwningProcess = unchecked((int)raw.owningPid)
                    });
                    cursor = IntPtr.Add(cursor, rowSize);
                }
            }
        } finally {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }
    }

    private static Row[] TargetRows(
        string target4, string target6, int targetPort) {
        List<Row> all = new List<Row>();
        AppendFamily(all, AF_INET);
        AppendFamily(all, AF_INET6);
        List<Row> target = new List<Row>();
        foreach (Row row in all) {
            if (row.RemotePort == targetPort &&
                (String.Equals(row.RemoteAddress, target4,
                    StringComparison.OrdinalIgnoreCase) ||
                 String.Equals(row.RemoteAddress, target6,
                    StringComparison.OrdinalIgnoreCase)))
                target.Add(row);
        }
        return target.ToArray();
    }

    private static string Escape(string value) {
        return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }

    private static void WriteSample(
        StreamWriter writer, double epochMs, long qpc, Row[] rows) {
        StringBuilder line = new StringBuilder();
        line.Append("{\"epoch_ms\":");
        line.Append(epochMs.ToString("R", CultureInfo.InvariantCulture));
        line.Append(",\"qpc\":");
        line.Append(qpc.ToString(CultureInfo.InvariantCulture));
        line.Append(",\"rows\":[");
        for (int i = 0; i < rows.Length; ++i) {
            if (i != 0) line.Append(',');
            Row r = rows[i];
            line.Append("{\"family\":\"");
            line.Append(Escape(r.Family));
            line.Append("\",\"state\":\"");
            line.Append(Escape(r.State));
            line.Append("\",\"local_address\":\"");
            line.Append(Escape(r.LocalAddress));
            line.Append("\",\"local_port\":");
            line.Append(r.LocalPort.ToString(CultureInfo.InvariantCulture));
            line.Append(",\"remote_address\":\"");
            line.Append(Escape(r.RemoteAddress));
            line.Append("\",\"remote_port\":");
            line.Append(r.RemotePort.ToString(CultureInfo.InvariantCulture));
            line.Append(",\"owning_process\":");
            line.Append(
                r.OwningProcess.ToString(CultureInfo.InvariantCulture));
            line.Append('}');
        }
        line.Append("]}");
        writer.WriteLine(line.ToString());
        writer.Flush();
    }

    public static Handle Start(
        string path, string target4, string target6,
        int targetPort, int intervalMs) {
        Handle handle = new Handle();
        handle.Path = path;
        handle.Error = "";
        handle.Cancellation = new CancellationTokenSource();
        CancellationToken token = handle.Cancellation.Token;
        handle.Worker = Task.Run(delegate {
            try {
                using (StreamWriter writer = new StreamWriter(
                    new FileStream(path, FileMode.Create, FileAccess.Write,
                        FileShare.Read),
                    new UTF8Encoding(false))) {
                    while (!token.IsCancellationRequested) {
                        Row[] rows = TargetRows(
                            target4, target6, targetPort);
                        // Timestamp the completed snapshot.  epoch_ms and qpc
                        // must describe the same edge of the table query.
                        DateTimeOffset now = DateTimeOffset.UtcNow;
                        long qpc = Stopwatch.GetTimestamp();
                        double epochMs = (now.UtcTicks -
                            new DateTimeOffset(1970, 1, 1, 0, 0, 0,
                                TimeSpan.Zero).UtcTicks) /
                            (double)TimeSpan.TicksPerMillisecond;
                        WriteSample(writer, epochMs, qpc, rows);
                        Interlocked.Increment(ref handle.Samples);
                        Interlocked.Add(ref handle.Rows, rows.Length);
                        if (token.WaitHandle.WaitOne(intervalMs))
                            break;
                    }
                }
            } catch (Exception ex) {
                handle.Error = ex.ToString();
            } finally {
                handle.Stopped = true;
            }
        });
        return handle;
    }

    public static bool Stop(Handle handle, int timeoutMs) {
        if (handle == null) return true;
        handle.Cancellation.Cancel();
        bool stopped = handle.Worker.Wait(timeoutMs);
        handle.Stopped = stopped;
        return stopped;
    }
}
'@
}

function Start-I04SocketSampler {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][int]$Port
    )

    Initialize-I04SocketSampler
    return [V91I04SocketSampler]::Start(
        $Path, $IPv4, $IPv6, $Port, 25
    )
}

function Stop-I04SocketSampler {
    param(
        [AllowNull()][object]$Sampler,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$CleanupFailures
    )

    if ($null -eq $Sampler) { return $true }
    $stopped = $false
    try {
        $stopped = [V91I04SocketSampler]::Stop($Sampler, 10000)
        if (-not $stopped) {
            $CleanupFailures.Add(
                'PID socket sampler did not stop within 10 seconds'
            )
        }
        if ([string]$Sampler.Error) {
            $CleanupFailures.Add(
                "PID socket sampler failed: $($Sampler.Error)"
            )
        }
    } catch {
        $CleanupFailures.Add(
            "PID socket sampler cleanup failed: $($_.Exception.Message)"
        )
    }
    return $stopped
}

function Get-I04SamplerClockValidation {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [object[]]$Samples,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [Int64]::MaxValue)][Int64]$QpcFrequency,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0.001, 1000)][double]$CoherenceToleranceMs,
        [Parameter(Mandatory = $true)][double]$BoundaryEpochMs,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [Int64]::MaxValue)][Int64]$BoundaryQpc
    )

    $violations = New-Object 'Collections.Generic.List[object]'
    $previousEpoch = $null
    $previousQpc = $null
    $firstEpoch = $null
    $lastEpoch = $null
    $firstQpc = $null
    $lastQpc = $null
    $maximumEpochGapMs = 0.0
    $maximumQpcGapMs = 0.0
    $maximumIntervalErrorMs = 0.0
    $maximumBoundaryProjectionErrorMs = 0.0
    $epochMonotonic = $true
    $qpcStrictlyIncreasing = $true
    $intervalsCoherent = $true
    $boundaryProjectionCoherent = $true
    $index = 0

    foreach ($sample in $Samples) {
        $index++
        $epoch = [double]$sample.epoch_ms
        $qpc = [Int64]$sample.qpc
        if ([double]::IsNaN($epoch) -or
            [double]::IsInfinity($epoch) -or $epoch -le 0 -or $qpc -le 0) {
            $violations.Add([pscustomobject][ordered]@{
                sample_index = $index
                code = 'invalid-clock-value'
                epoch_ms = $epoch
                qpc = $qpc
                error_ms = $null
            })
            continue
        }
        if ($null -eq $firstEpoch) {
            $firstEpoch = $epoch
            $firstQpc = $qpc
        }
        $lastEpoch = $epoch
        $lastQpc = $qpc

        $boundaryQpcDeltaMs =
            (([double]$qpc - [double]$BoundaryQpc) * 1000.0) /
                [double]$QpcFrequency
        $boundaryEpochDeltaMs = $epoch - $BoundaryEpochMs
        $boundaryProjectionErrorMs = [Math]::Abs(
            $boundaryEpochDeltaMs - $boundaryQpcDeltaMs
        )
        $maximumBoundaryProjectionErrorMs = [Math]::Max(
            $maximumBoundaryProjectionErrorMs,
            $boundaryProjectionErrorMs
        )
        if ($boundaryProjectionErrorMs -gt $CoherenceToleranceMs) {
            $boundaryProjectionCoherent = $false
            $violations.Add([pscustomobject][ordered]@{
                sample_index = $index
                code = 'boundary-clock-incoherent'
                epoch_ms = $epoch
                qpc = $qpc
                error_ms = [Math]::Round(
                    $boundaryProjectionErrorMs, 6
                )
            })
        }

        if ($null -ne $previousEpoch) {
            $epochDeltaMs = $epoch - [double]$previousEpoch
            $qpcIncreasing = $qpc -gt [Int64]$previousQpc
            if ($epochDeltaMs -lt 0) {
                $epochMonotonic = $false
                $violations.Add([pscustomobject][ordered]@{
                    sample_index = $index
                    code = 'epoch-regressed'
                    epoch_ms = $epoch
                    qpc = $qpc
                    error_ms = [Math]::Round($epochDeltaMs, 6)
                })
            } else {
                $maximumEpochGapMs = [Math]::Max(
                    $maximumEpochGapMs, $epochDeltaMs
                )
            }
            if (-not $qpcIncreasing) {
                $qpcStrictlyIncreasing = $false
                $violations.Add([pscustomobject][ordered]@{
                    sample_index = $index
                    code = 'qpc-not-strictly-increasing'
                    epoch_ms = $epoch
                    qpc = $qpc
                    error_ms = $null
                })
            } else {
                $qpcDeltaMs =
                    (([double]$qpc - [double]$previousQpc) * 1000.0) /
                        [double]$QpcFrequency
                $maximumQpcGapMs = [Math]::Max(
                    $maximumQpcGapMs, $qpcDeltaMs
                )
                if ($epochDeltaMs -ge 0) {
                    $intervalErrorMs =
                        [Math]::Abs($epochDeltaMs - $qpcDeltaMs)
                    $maximumIntervalErrorMs = [Math]::Max(
                        $maximumIntervalErrorMs, $intervalErrorMs
                    )
                    if ($intervalErrorMs -gt $CoherenceToleranceMs) {
                        $intervalsCoherent = $false
                        $violations.Add([pscustomobject][ordered]@{
                            sample_index = $index
                            code = 'interval-clock-incoherent'
                            epoch_ms = $epoch
                            qpc = $qpc
                            error_ms = [Math]::Round(
                                $intervalErrorMs, 6
                            )
                        })
                    }
                }
            }
        }
        $previousEpoch = $epoch
        $previousQpc = $qpc
    }

    return [pscustomobject][ordered]@{
        valid = $violations.Count -eq 0
        sample_count = $Samples.Count
        qpc_frequency = $QpcFrequency
        coherence_tolerance_ms = $CoherenceToleranceMs
        boundary_epoch_ms = $BoundaryEpochMs
        boundary_qpc = $BoundaryQpc
        epoch_monotonic_non_decreasing = $epochMonotonic
        qpc_strictly_increasing = $qpcStrictlyIncreasing
        interval_deltas_coherent = $intervalsCoherent
        boundary_projection_coherent = $boundaryProjectionCoherent
        first_epoch_ms = $firstEpoch
        last_epoch_ms = $lastEpoch
        first_qpc = $firstQpc
        last_qpc = $lastQpc
        maximum_epoch_gap_ms = [Math]::Round($maximumEpochGapMs, 6)
        maximum_qpc_gap_ms = [Math]::Round($maximumQpcGapMs, 6)
        maximum_interval_error_ms =
            [Math]::Round($maximumIntervalErrorMs, 6)
        maximum_boundary_projection_error_ms =
            [Math]::Round($maximumBoundaryProjectionErrorMs, 6)
        violation_count = $violations.Count
        violations = $violations.ToArray()
    }
}

function Get-I04SocketSamplerEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId,
        [Parameter(Mandatory = $true)][double]$BoundaryEpochMs,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [Int64]::MaxValue)][Int64]$BoundaryQpc,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0.001, 1000)][double]$ClockCoherenceToleranceMs
    )

    $v4Ports = New-Object 'Collections.Generic.HashSet[int]'
    $v6Ports = New-Object 'Collections.Generic.HashSet[int]'
    $allTargetRows = New-Object 'Collections.Generic.List[object]'
    $candidateTargetRows = New-Object 'Collections.Generic.List[object]'
    $otherPidRows = New-Object 'Collections.Generic.List[object]'
    $preBoundaryRows = New-Object 'Collections.Generic.List[object]'
    $sampleTimings = New-Object 'Collections.Generic.List[object]'
    $sampleCount = 0
    $parseErrors = 0
    $v4Established = $false
    $v6Attempt = $false
    foreach ($lineValue in @(
        Get-Content -LiteralPath $Path -ErrorAction Stop
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$lineValue)) { continue }
        try {
            $sample = [string]$lineValue | ConvertFrom-Json -ErrorAction Stop
        } catch {
            $parseErrors++
            continue
        }
        try {
            $epoch = [double]$sample.epoch_ms
            $qpc = [Int64]$sample.qpc
        } catch {
            $parseErrors++
            continue
        }
        $sampleCount++
        $sampleTimings.Add([pscustomobject][ordered]@{
            sample_index = $sampleCount
            epoch_ms = $epoch
            qpc = $qpc
        })
        foreach ($row in @($sample.rows)) {
            $localAddress =
                Get-I04NormalizedIp -Address ([string]$row.local_address)
            $remoteAddress =
                Get-I04NormalizedIp -Address ([string]$row.remote_address)
            $record = [pscustomobject][ordered]@{
                epoch_ms = $epoch
                qpc = $qpc
                family = [string]$row.family
                state = [string]$row.state
                local_address = $localAddress
                local_port = [int]$row.local_port
                remote_address = $remoteAddress
                remote_port = [int]$row.remote_port
                owning_process = [int]$row.owning_process
                tuple_key = Get-I04TupleKey `
                    -Family ([string]$row.family) `
                    -LocalAddress $localAddress `
                    -LocalPort ([int]$row.local_port) `
                    -RemoteAddress $remoteAddress `
                    -RemotePort ([int]$row.remote_port)
            }
            $allTargetRows.Add($record)
            # QPC is the authoritative side of the formal boundary. Wall-clock
            # epoch remains necessary only for PCAP correlation and is admitted
            # after dual-clock coherence validation below.
            if ($qpc -lt $BoundaryQpc) {
                $preBoundaryRows.Add($record)
                continue
            }
            if ([int]$row.owning_process -ne $CandidateProcessId) {
                $otherPidRows.Add($record)
                continue
            }
            $candidateTargetRows.Add($record)
            if ([string]$row.family -eq 'IPv6' -and
                [string]$row.state -in @('SynSent', 'Established')) {
                $null = $v6Ports.Add([int]$row.local_port)
                $v6Attempt = $true
            }
            if ([string]$row.family -eq 'IPv4' -and
                [string]$row.state -in @('SynSent', 'Established')) {
                $null = $v4Ports.Add([int]$row.local_port)
                if ([string]$row.state -eq 'Established') {
                    $v4Established = $true
                }
            }
        }
    }
    $clockValidation = Get-I04SamplerClockValidation `
        -Samples $sampleTimings.ToArray() `
        -QpcFrequency ([Diagnostics.Stopwatch]::Frequency) `
        -CoherenceToleranceMs $ClockCoherenceToleranceMs `
        -BoundaryEpochMs $BoundaryEpochMs -BoundaryQpc $BoundaryQpc
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-pid-socket-sampler/v1'
        path = $Path
        candidate_process_id = $CandidateProcessId
        boundary_epoch_ms = $BoundaryEpochMs
        boundary_qpc = $BoundaryQpc
        qpc_frequency = [Diagnostics.Stopwatch]::Frequency
        clock_coherence_tolerance_ms = $ClockCoherenceToleranceMs
        clock_coherence_valid = [bool]$clockValidation.valid
        clock_validation = $clockValidation
        sample_count = $sampleCount
        parse_error_count = $parseErrors
        first_sample_epoch_ms = $clockValidation.first_epoch_ms
        last_sample_epoch_ms = $clockValidation.last_epoch_ms
        first_sample_qpc = $clockValidation.first_qpc
        last_sample_qpc = $clockValidation.last_qpc
        maximum_sample_gap_ms = $clockValidation.maximum_qpc_gap_ms
        maximum_epoch_gap_ms = $clockValidation.maximum_epoch_gap_ms
        target_row_count = $allTargetRows.Count
        target_rows = $allTargetRows.ToArray()
        candidate_target_row_count = $candidateTargetRows.Count
        candidate_target_rows = $candidateTargetRows.ToArray()
        candidate_ipv4_local_ports = @($v4Ports | Sort-Object)
        candidate_ipv6_local_ports = @($v6Ports | Sort-Object)
        candidate_ipv6_attempt_observed = $v6Attempt
        candidate_ipv4_established_observed = $v4Established
        pre_boundary_target_row_count = $preBoundaryRows.Count
        pre_boundary_target_rows = $preBoundaryRows.ToArray()
        other_pid_target_row_count = $otherPidRows.Count
        other_pid_target_rows = $otherPidRows.ToArray()
        sampler_coverage_valid = $sampleCount -ge 2 -and
            $parseErrors -eq 0 -and [bool]$clockValidation.valid -and
            [double]$clockValidation.maximum_qpc_gap_ms -lt 250
    }
}

function Read-I04UInt16LE {
    param([byte[]]$Bytes, [int]$Offset)
    return [BitConverter]::ToUInt16($Bytes, $Offset)
}

function Read-I04UInt32LE {
    param([byte[]]$Bytes, [int]$Offset)
    return [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Read-I04UInt16BE {
    param([byte[]]$Bytes, [int]$Offset)
    return ([int]$Bytes[$Offset] -shl 8) -bor [int]$Bytes[$Offset + 1]
}

function Read-I04UInt32BE {
    param([byte[]]$Bytes, [int]$Offset)
    return [uint32](
        ([uint32]$Bytes[$Offset] -shl 24) -bor
        ([uint32]$Bytes[$Offset + 1] -shl 16) -bor
        ([uint32]$Bytes[$Offset + 2] -shl 8) -bor
        [uint32]$Bytes[$Offset + 3]
    )
}

function Convert-I04Packet {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Packet,
        [Parameter(Mandatory = $true)][int]$LinkType,
        [Parameter(Mandatory = $true)][double]$TimestampMs
    )

    $offset = 0
    $etherType = 0
    if ($LinkType -eq 1) {
        if ($Packet.Length -lt 14) { return $null }
        $etherType = Read-I04UInt16BE -Bytes $Packet -Offset 12
        $offset = 14
        while ($etherType -eq 0x8100 -or $etherType -eq 0x88a8) {
            if ($Packet.Length -lt $offset + 4) { return $null }
            $etherType = Read-I04UInt16BE -Bytes $Packet -Offset ($offset + 2)
            $offset += 4
        }
    } elseif ($LinkType -eq 101) {
        if ($Packet.Length -lt 1) { return $null }
        $version = $Packet[0] -shr 4
        $etherType = if ($version -eq 4) { 0x0800 } elseif ($version -eq 6) {
            0x86dd
        } else { 0 }
    } elseif ($LinkType -eq 228) {
        $etherType = 0x0800
    } elseif ($LinkType -eq 229) {
        $etherType = 0x86dd
    } else {
        return $null
    }

    if ($etherType -eq 0x0800) {
        if ($Packet.Length -lt $offset + 20) { return $null }
        $ihl = ($Packet[$offset] -band 0x0f) * 4
        if ($ihl -lt 20 -or $Packet.Length -lt $offset + $ihl) { return $null }
        $protocol = [int]$Packet[$offset + 9]
        $sourceBytes = New-Object byte[] 4
        $destinationBytes = New-Object byte[] 4
        [Array]::Copy($Packet, $offset + 12, $sourceBytes, 0, 4)
        [Array]::Copy($Packet, $offset + 16, $destinationBytes, 0, 4)
        $source = ([Net.IPAddress]::new($sourceBytes)).ToString()
        $destination = ([Net.IPAddress]::new($destinationBytes)).ToString()
        $transportOffset = $offset + $ihl
        if ($protocol -ne 6 -or $Packet.Length -lt $transportOffset + 20) {
            return $null
        }
        $sourcePort = Read-I04UInt16BE -Bytes $Packet -Offset $transportOffset
        $destinationPort = Read-I04UInt16BE -Bytes $Packet `
            -Offset ($transportOffset + 2)
        $flags = [int]$Packet[$transportOffset + 13]
        return [pscustomobject][ordered]@{
            timestamp_ms = $TimestampMs
            family = 'IPv4'
            protocol = 'TCP'
            source = $source
            destination = $destination
            source_port = $sourcePort
            destination_port = $destinationPort
            sequence_number = Read-I04UInt32BE -Bytes $Packet `
                -Offset ($transportOffset + 4)
            acknowledgement_number = Read-I04UInt32BE -Bytes $Packet `
                -Offset ($transportOffset + 8)
            syn = ($flags -band 0x02) -ne 0
            ack = ($flags -band 0x10) -ne 0
            rst = ($flags -band 0x04) -ne 0
            fin = ($flags -band 0x01) -ne 0
            icmp_type = $null
            quoted_family = $null
            quoted_protocol = $null
            quoted_source = $null
            quoted_destination = $null
            quoted_source_port = $null
            quoted_destination_port = $null
            quoted_sequence_number = $null
        }
    }

    if ($etherType -ne 0x86dd -or $Packet.Length -lt $offset + 40) {
        return $null
    }
    $nextHeader = [int]$Packet[$offset + 6]
    $sourceV6Bytes = New-Object byte[] 16
    $destinationV6Bytes = New-Object byte[] 16
    [Array]::Copy($Packet, $offset + 8, $sourceV6Bytes, 0, 16)
    [Array]::Copy($Packet, $offset + 24, $destinationV6Bytes, 0, 16)
    $sourceV6 = ([Net.IPAddress]::new($sourceV6Bytes)).ToString()
    $destinationV6 = ([Net.IPAddress]::new($destinationV6Bytes)).ToString()
    $transport = $offset + 40
    while ($nextHeader -in @(0, 43, 44, 51, 60)) {
        if ($Packet.Length -lt $transport + 8) { return $null }
        $following = [int]$Packet[$transport]
        $extensionBytes = if ($nextHeader -eq 44) {
            8
        } elseif ($nextHeader -eq 51) {
            ([int]$Packet[$transport + 1] + 2) * 4
        } else {
            ([int]$Packet[$transport + 1] + 1) * 8
        }
        $transport += $extensionBytes
        $nextHeader = $following
        if ($Packet.Length -lt $transport) { return $null }
    }
    if ($nextHeader -eq 58 -and $Packet.Length -ge $transport + 4) {
        $quotedFamily = $null
        $quotedProtocol = $null
        $quotedSource = $null
        $quotedDestination = $null
        $quotedSourcePort = $null
        $quotedDestinationPort = $null
        $quotedSequence = $null
        $quotedOffset = $transport + 8
        if ($Packet.Length -ge $quotedOffset + 40 -and
            ($Packet[$quotedOffset] -shr 4) -eq 6) {
            $quotedFamily = 'IPv6'
            $quotedNext = [int]$Packet[$quotedOffset + 6]
            $quotedSourceBytes = New-Object byte[] 16
            $quotedDestinationBytes = New-Object byte[] 16
            [Array]::Copy(
                $Packet, $quotedOffset + 8, $quotedSourceBytes, 0, 16
            )
            [Array]::Copy(
                $Packet, $quotedOffset + 24, $quotedDestinationBytes, 0, 16
            )
            $quotedSource = ([Net.IPAddress]::new(
                $quotedSourceBytes
            )).ToString()
            $quotedDestination = ([Net.IPAddress]::new(
                $quotedDestinationBytes
            )).ToString()
            $quotedTransport = $quotedOffset + 40
            while ($quotedNext -in @(0, 43, 44, 51, 60)) {
                if ($Packet.Length -lt $quotedTransport + 8) { break }
                $quotedFollowing = [int]$Packet[$quotedTransport]
                $quotedExtensionBytes = if ($quotedNext -eq 44) {
                    8
                } elseif ($quotedNext -eq 51) {
                    ([int]$Packet[$quotedTransport + 1] + 2) * 4
                } else {
                    ([int]$Packet[$quotedTransport + 1] + 1) * 8
                }
                $quotedTransport += $quotedExtensionBytes
                $quotedNext = $quotedFollowing
            }
            if ($quotedNext -eq 6 -and
                $Packet.Length -ge $quotedTransport + 8) {
                $quotedProtocol = 'TCP'
                $quotedSourcePort = Read-I04UInt16BE -Bytes $Packet `
                    -Offset $quotedTransport
                $quotedDestinationPort = Read-I04UInt16BE -Bytes $Packet `
                    -Offset ($quotedTransport + 2)
                $quotedSequence = Read-I04UInt32BE -Bytes $Packet `
                    -Offset ($quotedTransport + 4)
            }
        }
        return [pscustomobject][ordered]@{
            timestamp_ms = $TimestampMs
            family = 'IPv6'
            protocol = 'ICMPv6'
            source = $sourceV6
            destination = $destinationV6
            source_port = $null
            destination_port = $null
            sequence_number = $null
            acknowledgement_number = $null
            syn = $false
            ack = $false
            rst = $false
            fin = $false
            icmp_type = [int]$Packet[$transport]
            quoted_family = $quotedFamily
            quoted_protocol = $quotedProtocol
            quoted_source = $quotedSource
            quoted_destination = $quotedDestination
            quoted_source_port = $quotedSourcePort
            quoted_destination_port = $quotedDestinationPort
            quoted_sequence_number = $quotedSequence
        }
    }
    if ($nextHeader -ne 6 -or $Packet.Length -lt $transport + 20) {
        return $null
    }
    $sourceV6Port = Read-I04UInt16BE -Bytes $Packet -Offset $transport
    $destinationV6Port = Read-I04UInt16BE -Bytes $Packet -Offset ($transport + 2)
    $v6Flags = [int]$Packet[$transport + 13]
    return [pscustomobject][ordered]@{
        timestamp_ms = $TimestampMs
        family = 'IPv6'
        protocol = 'TCP'
        source = $sourceV6
        destination = $destinationV6
        source_port = $sourceV6Port
        destination_port = $destinationV6Port
        sequence_number = Read-I04UInt32BE -Bytes $Packet `
            -Offset ($transport + 4)
        acknowledgement_number = Read-I04UInt32BE -Bytes $Packet `
            -Offset ($transport + 8)
        syn = ($v6Flags -band 0x02) -ne 0
        ack = ($v6Flags -band 0x10) -ne 0
        rst = ($v6Flags -band 0x04) -ne 0
        fin = ($v6Flags -band 0x01) -ne 0
        icmp_type = $null
        quoted_family = $null
        quoted_protocol = $null
        quoted_source = $null
        quoted_destination = $null
        quoted_source_port = $null
        quoted_destination_port = $null
        quoted_sequence_number = $null
    }
}

function Read-I04PcapNg {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 28 -or
        (Read-I04UInt32LE -Bytes $bytes -Offset 0) -ne 0x0a0d0d0a -or
        (Read-I04UInt32LE -Bytes $bytes -Offset 8) -ne 0x1a2b3c4d) {
        throw 'Only little-endian PCAPNG produced by pktmon is supported'
    }
    $interfaces = @{}
    $interfaceNumber = 0
    $packets = New-Object 'Collections.Generic.List[object]'
    $offset = 0
    while ($offset + 12 -le $bytes.Length) {
        $type = Read-I04UInt32LE -Bytes $bytes -Offset $offset
        $length = [int](Read-I04UInt32LE -Bytes $bytes -Offset ($offset + 4))
        if ($length -lt 12 -or $offset + $length -gt $bytes.Length -or
            (Read-I04UInt32LE -Bytes $bytes -Offset ($offset + $length - 4)) -ne
                [uint32]$length) {
            throw "Invalid PCAPNG block at offset $offset"
        }
        if ($type -eq 1 -and $length -ge 20) {
            $linkType = Read-I04UInt16LE -Bytes $bytes -Offset ($offset + 8)
            $resolution = 0.000001
            $option = $offset + 16
            while ($option + 4 -le $offset + $length - 4) {
                $code = Read-I04UInt16LE -Bytes $bytes -Offset $option
                $optionLength = Read-I04UInt16LE -Bytes $bytes `
                    -Offset ($option + 2)
                if ($code -eq 0) { break }
                if ($code -eq 9 -and $optionLength -ge 1) {
                    $value = [int]$bytes[$option + 4]
                    if (($value -band 0x80) -ne 0) {
                        $resolution = [Math]::Pow(2, -($value -band 0x7f))
                    } else {
                        $resolution = [Math]::Pow(10, -$value)
                    }
                }
                $option += 4 + (($optionLength + 3) -band (-bnot 3))
            }
            $interfaces[$interfaceNumber] = [pscustomobject]@{
                link_type = [int]$linkType
                timestamp_resolution = [double]$resolution
            }
            $interfaceNumber++
        } elseif ($type -eq 6 -and $length -ge 32) {
            $interfaceId = [int](Read-I04UInt32LE -Bytes $bytes `
                -Offset ($offset + 8))
            $capturedLength = [int](Read-I04UInt32LE -Bytes $bytes `
                -Offset ($offset + 20))
            if ($interfaces.ContainsKey($interfaceId) -and
                $capturedLength -ge 0 -and
                $offset + 28 + $capturedLength -le $offset + $length - 4) {
                $high = [UInt64](Read-I04UInt32LE -Bytes $bytes `
                    -Offset ($offset + 12))
                $low = [UInt64](Read-I04UInt32LE -Bytes $bytes `
                    -Offset ($offset + 16))
                $ticks = ($high -shl 32) -bor $low
                $timeMs = [double]$ticks *
                    [double]$interfaces[$interfaceId].timestamp_resolution * 1000.0
                $packetBytes = New-Object byte[] $capturedLength
                [Array]::Copy($bytes, $offset + 28, $packetBytes, 0,
                    $capturedLength)
                $parsed = Convert-I04Packet -Packet $packetBytes `
                    -LinkType $interfaces[$interfaceId].link_type `
                    -TimestampMs $timeMs
                if ($null -ne $parsed) { $packets.Add($parsed) }
            }
        }
        $offset += $length
    }
    return @($packets)
}

function Get-I04SynPidCorrelation {
    param(
        [Parameter(Mandatory = $true)][object]$Packet,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [object[]]$SamplerRows,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)][double]$ToleranceMs
    )

    $tuple = Get-I04TupleKey -Family ([string]$Packet.family) `
        -LocalAddress ([string]$Packet.source) `
        -LocalPort ([int]$Packet.source_port) `
        -RemoteAddress ([string]$Packet.destination) `
        -RemotePort ([int]$Packet.destination_port)
    $packetEpochMs = [double]$Packet.timestamp_ms
    $matching = @($SamplerRows | Where-Object {
        [string]$_.tuple_key -eq $tuple -and
        [string]$_.state -in @('SynSent', 'Established') -and
        [Math]::Abs([double]$_.epoch_ms - $packetEpochMs) -le $ToleranceMs
    })
    $candidateMatches = @($matching | Where-Object {
        [int]$_.owning_process -eq $CandidateProcessId
    })
    $otherMatches = @($matching | Where-Object {
        [int]$_.owning_process -ne $CandidateProcessId
    })
    $nearestCandidate = if ($candidateMatches.Count -eq 0) {
        $null
    } else {
        @($candidateMatches | ForEach-Object {
            [Math]::Abs([double]$_.epoch_ms - $packetEpochMs)
        } | Measure-Object -Minimum).Minimum
    }
    $nearestOther = if ($otherMatches.Count -eq 0) {
        $null
    } else {
        @($otherMatches | ForEach-Object {
            [Math]::Abs([double]$_.epoch_ms - $packetEpochMs)
        } | Measure-Object -Minimum).Minimum
    }
    $candidateObserved = $candidateMatches.Count -gt 0
    $otherObserved = $otherMatches.Count -gt 0
    $status = if ($candidateObserved -and -not $otherObserved) {
        'candidate'
    } elseif ($candidateObserved -and $otherObserved) {
        'ambiguous-owner'
    } elseif ($otherObserved) {
        'foreign-owner'
    } else {
        'unobserved'
    }

    return [pscustomobject][ordered]@{
        packet_timestamp_ms = $packetEpochMs
        family = [string]$Packet.family
        tuple_key = $tuple
        tolerance_ms = $ToleranceMs
        status = $status
        candidate_process_id = $CandidateProcessId
        candidate_sample_count = $candidateMatches.Count
        other_pid_sample_count = $otherMatches.Count
        candidate_correlated = $status -eq 'candidate'
        correlation_ambiguous = $status -eq 'ambiguous-owner'
        nearest_candidate_sample_delta_ms = if ($null -eq
            $nearestCandidate) {
            $null
        } else { [Math]::Round([double]$nearestCandidate, 3) }
        nearest_other_pid_sample_delta_ms = if ($null -eq $nearestOther) {
            $null
        } else { [Math]::Round([double]$nearestOther, 3) }
        matching_process_ids = @(
            $matching | ForEach-Object { [int]$_.owning_process } |
                Sort-Object -Unique
        )
        candidate_matching_sample_epoch_ms = @(
            $candidateMatches | ForEach-Object { [double]$_.epoch_ms }
        )
        other_matching_samples = @($otherMatches | ForEach-Object {
            [pscustomobject][ordered]@{
                epoch_ms = [double]$_.epoch_ms
                owning_process = [int]$_.owning_process
                state = [string]$_.state
            }
        })
    }
}

function Get-I04FailureDisposition {
    param(
        [Parameter(Mandatory = $true)][bool]$CaseArmed,
        [Parameter(Mandatory = $true)][bool]$FormalBoundaryPublished,
        [AllowEmptyString()][string]$ExceptionMessage = ''
    )

    $candidatePostBoundary = $CaseArmed -and $FormalBoundaryPublished
    return [pscustomobject][ordered]@{
        classification = if ($candidatePostBoundary) {
            'FAIL'
        } else { 'BLOCKED' }
        candidate_post_boundary = $candidatePostBoundary
        case_armed = $CaseArmed
        formal_boundary_published = $FormalBoundaryPublished
        exception_message = $ExceptionMessage
    }
}

function Get-I04PartialVerdict {
    param(
        [Parameter(Mandatory = $true)][bool]$AdjudicationClean,
        [Parameter(Mandatory = $true)]
        [bool]$PostBoundaryCandidateFailure,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)][int]$ProductFailureCount
    )

    if ($PostBoundaryCandidateFailure -and $AdjudicationClean) {
        return 'FAIL'
    }
    if (-not $AdjudicationClean) { return 'BLOCKED' }
    if ($ProductFailureCount -gt 0) { return 'FAIL' }
    return 'PASS'
}

function Get-I04PacketVerdict {
    param(
        [Parameter(Mandatory = $true)][string]$PcapNgPath,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][string]$CoordinatorIPv4,
        [Parameter(Mandatory = $true)][string]$CoordinatorIPv6,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][double]$NotBeforeEpochMs,
        [Parameter(Mandatory = $true)][double]$ScenarioBoundaryEpochMs,
        [Parameter(Mandatory = $true)][double]$ObservationEndEpochMs,
        [Parameter(Mandatory = $true)][int]$LimitSeconds,
        [Parameter(Mandatory = $true)][int]$MinimumSilentWindowMs,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId,
        [Parameter(Mandatory = $true)][object]$SocketSamplerEvidence,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)][int]$SynCorrelationToleranceMs,
        [string[]]$ExcludedTupleKeys = @()
    )

    if ($NotBeforeEpochMs -gt $ScenarioBoundaryEpochMs -or
        $ObservationEndEpochMs -le $ScenarioBoundaryEpochMs) {
        throw 'Coordinator PCAP timestamps are not a valid capture/trigger/stop interval'
    }
    if ([string]$SocketSamplerEvidence.schema -ne
            'ese.v91.i04-pid-socket-sampler/v1' -or
        [int]$SocketSamplerEvidence.candidate_process_id -ne
            $CandidateProcessId -or
        [Math]::Abs(
            [double]$SocketSamplerEvidence.boundary_epoch_ms -
            $ScenarioBoundaryEpochMs
        ) -gt 1 -or
        -not [bool]$SocketSamplerEvidence.clock_coherence_valid -or
        [Int64]$SocketSamplerEvidence.qpc_frequency -ne
            [Diagnostics.Stopwatch]::Frequency -or
        -not [bool]$SocketSamplerEvidence.sampler_coverage_valid) {
        throw 'PID socket-sampler evidence does not identify this exact scenario'
    }
    $samplerRows = @($SocketSamplerEvidence.target_rows)
    $samplerMaximumGapMs =
        [double]$SocketSamplerEvidence.maximum_sample_gap_ms
    $samplerTemporalCoverage =
        [double]$SocketSamplerEvidence.first_sample_epoch_ms -le
            ($NotBeforeEpochMs + $SynCorrelationToleranceMs) -and
        [double]$SocketSamplerEvidence.last_sample_epoch_ms -ge
            ($ObservationEndEpochMs - $SynCorrelationToleranceMs) -and
        $samplerMaximumGapMs -lt $SynCorrelationToleranceMs
    $excluded = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($tuple in @($ExcludedTupleKeys)) {
        $null = $excluded.Add([string]$tuple)
    }
    $packets = @(Read-I04PcapNg -Path $PcapNgPath | Where-Object {
        $_.timestamp_ms -ge $NotBeforeEpochMs -and
        $_.timestamp_ms -le $ObservationEndEpochMs
    } | Sort-Object timestamp_ms)

    $outboundTargetSyn = @($packets | Where-Object {
        $_.protocol -eq 'TCP' -and $_.syn -and -not $_.ack -and
        $_.destination_port -eq $Port -and
        (($_.family -eq 'IPv4' -and $_.source -eq $CoordinatorIPv4 -and
            $_.destination -eq $IPv4) -or
         ($_.family -eq 'IPv6' -and $_.source -eq $CoordinatorIPv6 -and
            $_.destination -eq $IPv6))
    } | ForEach-Object {
        $family = [string]$_.family
        $tuple = Get-I04TupleKey -Family $family `
            -LocalAddress ([string]$_.source) -LocalPort ([int]$_.source_port) `
            -RemoteAddress ([string]$_.destination) `
            -RemotePort ([int]$_.destination_port)
        $correlation = Get-I04SynPidCorrelation -Packet $_ `
            -CandidateProcessId $CandidateProcessId `
            -SamplerRows $samplerRows `
            -ToleranceMs $SynCorrelationToleranceMs
        [pscustomobject][ordered]@{
            packet = $_
            tuple_key = $tuple
            # Never suppress by a historical 5-tuple: Windows may reuse the
            # ephemeral port after the old prewarm disappears.  Capture starts
            # with the old connection already established, so every captured
            # target SYN is a new attempt and must remain adjudicable.
            excluded_prewarm = $false
            matches_historical_prewarm_tuple = $excluded.Contains($tuple)
            correlation = $correlation
            candidate_correlated = [bool]$correlation.candidate_correlated
            correlation_ambiguous = [bool]$correlation.correlation_ambiguous
        }
    })
    $uncorrelated = @($outboundTargetSyn | Where-Object {
        [string]$_.correlation.status -in @('foreign-owner', 'unobserved')
    })
    $ambiguous = @($outboundTargetSyn | Where-Object {
        [bool]$_.correlation_ambiguous
    })
    $preBoundaryTargetSyn = @($outboundTargetSyn | Where-Object {
        $_.packet.timestamp_ms -lt $ScenarioBoundaryEpochMs -and
        $true
    })
    $excludedPrewarmPackets = @($outboundTargetSyn | Where-Object {
        $_.matches_historical_prewarm_tuple
    })
    $candidateSynPackets = @($outboundTargetSyn | Where-Object {
        $_.packet.timestamp_ms -ge $ScenarioBoundaryEpochMs -and
        $_.candidate_correlated
    } | ForEach-Object { $_.packet })

    $syn6 = @($candidateSynPackets | Where-Object {
        $_.family -eq 'IPv6' -and $_.destination -eq $IPv6
    })
    $syn4 = @($candidateSynPackets | Where-Object {
        $_.family -eq 'IPv4' -and $_.destination -eq $IPv4
    })
    $candidateV6Tuples = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($packet in $syn6) {
        $null = $candidateV6Tuples.Add((
            Get-I04TupleKey -Family 'IPv6' `
                -LocalAddress ([string]$packet.source) `
                -LocalPort ([int]$packet.source_port) `
                -RemoteAddress ([string]$packet.destination) `
                -RemotePort ([int]$packet.destination_port)
        ))
    }
    $candidateV4Tuples = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($packet in $syn4) {
        $null = $candidateV4Tuples.Add((
            Get-I04TupleKey -Family 'IPv4' `
                -LocalAddress ([string]$packet.source) `
                -LocalPort ([int]$packet.source_port) `
                -RemoteAddress ([string]$packet.destination) `
                -RemotePort ([int]$packet.destination_port)
        ))
    }
    $v6Responses = @($packets | Where-Object {
        if ($_.protocol -ne 'TCP' -or $_.family -ne 'IPv6' -or
            $_.source -ne $IPv6 -or $_.source_port -ne $Port -or
            $_.destination -ne $CoordinatorIPv6) {
            return $false
        }
        $reverseTuple = Get-I04TupleKey -Family 'IPv6' `
            -LocalAddress ([string]$_.destination) `
            -LocalPort ([int]$_.destination_port) `
            -RemoteAddress ([string]$_.source) `
            -RemotePort ([int]$_.source_port)
        return $candidateV6Tuples.Contains($reverseTuple)
    })
    $synAck4 = @($packets | Where-Object {
        if ($_.protocol -ne 'TCP' -or $_.family -ne 'IPv4' -or
            $_.source -ne $IPv4 -or $_.source_port -ne $Port -or
            $_.destination -ne $CoordinatorIPv4 -or
            -not $_.syn -or -not $_.ack) {
            return $false
        }
        $reverseTuple = Get-I04TupleKey -Family 'IPv4' `
            -LocalAddress ([string]$_.destination) `
            -LocalPort ([int]$_.destination_port) `
            -RemoteAddress ([string]$_.source) `
            -RemotePort ([int]$_.source_port)
        return $candidateV4Tuples.Contains($reverseTuple)
    })

    $firstSyn6 = $syn6 | Select-Object -First 1
    $firstSyn4 = if ($null -ne $firstSyn6) {
        $syn4 | Where-Object timestamp_ms -gt $firstSyn6.timestamp_ms |
            Select-Object -First 1
    } else { $null }
    $firstSynAck4 = if ($null -ne $firstSyn4) {
        $expectedAck = [uint32](
            ([uint64]$firstSyn4.sequence_number + 1) % 4294967296
        )
        $synAck4 | Where-Object {
            $_.timestamp_ms -ge $firstSyn4.timestamp_ms -and
            $_.destination_port -eq $firstSyn4.source_port -and
            $_.acknowledgement_number -eq $expectedAck
        } | Select-Object -First 1
    } else { $null }
    $firstAck4 = if ($null -ne $firstSynAck4) {
        $expectedClientSequence = [uint32](
            ([uint64]$firstSyn4.sequence_number + 1) % 4294967296
        )
        $expectedServerAck = [uint32](
            ([uint64]$firstSynAck4.sequence_number + 1) % 4294967296
        )
        $packets | Where-Object {
            $_.protocol -eq 'TCP' -and $_.family -eq 'IPv4' -and
            $_.destination -eq $IPv4 -and $_.destination_port -eq $Port -and
            $_.source -eq $CoordinatorIPv4 -and
            $_.source_port -eq $firstSyn4.source_port -and
            $_.ack -and -not $_.syn -and
            $_.sequence_number -eq $expectedClientSequence -and
            $_.acknowledgement_number -eq $expectedServerAck -and
            $_.timestamp_ms -ge $firstSynAck4.timestamp_ms
        } | Select-Object -First 1
    } else { $null }
    $fallbackMs = if ($null -ne $firstSyn6 -and $null -ne $firstSyn4) {
        [Math]::Round($firstSyn4.timestamp_ms - $firstSyn6.timestamp_ms, 3)
    } else { $null }
    $connectedMs = if ($null -ne $firstSyn6 -and $null -ne $firstAck4) {
        [Math]::Round($firstAck4.timestamp_ms - $firstSyn6.timestamp_ms, 3)
    } else { $null }
    $postConnectionObservationMs = if ($null -ne $firstAck4) {
        [Math]::Round(
            $ObservationEndEpochMs - $firstAck4.timestamp_ms, 3
        )
    } else { $null }
    $limitMs = $LimitSeconds * 1000
    $distinctV6Attempts = @($syn6 | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}' -f $_.source, $_.source_port,
            $_.destination, $_.destination_port, $_.sequence_number
    } | Sort-Object -Unique)
    $distinctV4Attempts = @($syn4 | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}' -f $_.source, $_.source_port,
            $_.destination, $_.destination_port, $_.sequence_number
    } | Sort-Object -Unique)
    $syn6AttemptKeys = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::Ordinal)
    foreach ($packet in $syn6) {
        $null = $syn6AttemptKeys.Add((
            '{0}|{1}|{2}|{3}|{4}' -f $packet.source,
                $packet.source_port, $packet.destination,
                $packet.destination_port, $packet.sequence_number
        ))
    }
    $correlatedIcmp = @($packets | Where-Object {
        if ($_.protocol -ne 'ICMPv6' -or $_.icmp_type -lt 1 -or
            $_.icmp_type -gt 4 -or $_.quoted_family -ne 'IPv6' -or
            $_.quoted_protocol -ne 'TCP') {
            return $false
        }
        $quotedKey = '{0}|{1}|{2}|{3}|{4}' -f $_.quoted_source,
            $_.quoted_source_port, $_.quoted_destination,
            $_.quoted_destination_port, $_.quoted_sequence_number
        return $syn6AttemptKeys.Contains($quotedKey)
    })
    # Environment validation is a fixed window after SYN6.  Do not shorten it
    # at SYN4: an overly eager product fallback must remain a product FAIL,
    # while any TCP/RST/application/ICMP response within this fixed interval
    # means the environment was not a silent blackhole.
    $silentWindowEndMs = if ($null -ne $firstSyn6) {
        [double]$firstSyn6.timestamp_ms + $MinimumSilentWindowMs
    } else { [double]$ObservationEndEpochMs }
    $captureCoverageAfterSyn6Ms = if ($null -ne $firstSyn6) {
        [Math]::Round(
            $ObservationEndEpochMs - $firstSyn6.timestamp_ms, 3
        )
    } else { $null }
    $silentWindowObservedMs = if ($null -ne $firstSyn6) {
        [Math]::Round(
            $silentWindowEndMs - $firstSyn6.timestamp_ms, 3
        )
    } else { $null }
    $silentWindowResponses = if ($null -ne $firstSyn6) {
        @($v6Responses | Where-Object {
            $_.timestamp_ms -ge $firstSyn6.timestamp_ms -and
            $_.timestamp_ms -le $silentWindowEndMs
        }).Count
    } else { $v6Responses.Count }
    $silentWindowIcmp = if ($null -ne $firstSyn6) {
        @($correlatedIcmp | Where-Object {
            $_.timestamp_ms -ge $firstSyn6.timestamp_ms -and
            $_.timestamp_ms -le $silentWindowEndMs
        }).Count
    } else { $correlatedIcmp.Count }
    $environmentResponseWindowEnd = if ($null -ne $firstSyn6) {
        [double]$firstSyn6.timestamp_ms + $MinimumSilentWindowMs
    } else { $null }
    $earlyV6Responses = if ($null -ne $firstSyn6) {
        @($v6Responses | Where-Object {
            $_.timestamp_ms -ge $firstSyn6.timestamp_ms -and
            $_.timestamp_ms -lt $environmentResponseWindowEnd
        }).Count
    } else { 0 }
    $earlyIcmp = if ($null -ne $firstSyn6) {
        @($correlatedIcmp | Where-Object {
            $_.timestamp_ms -ge $firstSyn6.timestamp_ms -and
            $_.timestamp_ms -lt $environmentResponseWindowEnd
        }).Count
    } else { 0 }
    $correlationComplete = $samplerTemporalCoverage -and
        $uncorrelated.Count -eq 0 -and $ambiguous.Count -eq 0
    $planningUpperBoundMs = [Math]::Min($limitMs, 8000)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-packet-verdict/v1'
        not_before_epoch_ms = $NotBeforeEpochMs
        coordinator_stop_a_boundary_epoch_ms = $ScenarioBoundaryEpochMs
        coordinator_observation_end_epoch_ms = $ObservationEndEpochMs
        packet_count = $packets.Count
        ipv6_syn_count = $syn6.Count
        distinct_ipv6_connection_attempts = $distinctV6Attempts.Count
        ipv6_tcp_response_count_before_fallback = $silentWindowResponses
        correlated_icmpv6_error_count_before_fallback = $silentWindowIcmp
        ipv6_tcp_response_count_in_fixed_silent_window =
            $earlyV6Responses
        correlated_icmpv6_error_count_in_fixed_silent_window =
            $earlyIcmp
        environment_rejected_blackhole_in_fixed_window =
            $earlyV6Responses -gt 0 -or $earlyIcmp -gt 0
        ipv4_syn_count = $syn4.Count
        distinct_ipv4_connection_attempts = $distinctV4Attempts.Count
        ipv4_synack_observed = $null -ne $firstSynAck4
        ipv4_final_ack_observed = $null -ne $firstAck4
        syn6_to_syn4_ms = $fallbackMs
        syn6_to_ipv4_connected_ms = $connectedMs
        post_ipv4_connected_observation_ms = $postConnectionObservationMs
        minimum_silent_window_ms = $MinimumSilentWindowMs
        silent_window_observed_ms = $silentWindowObservedMs
        capture_coverage_after_syn6_ms = $captureCoverageAfterSyn6Ms
        pid_observed_ipv4_local_ports = @(
            $SocketSamplerEvidence.candidate_target_rows |
                Where-Object family -eq 'IPv4' |
                ForEach-Object { [int]$_.local_port } |
                Sort-Object -Unique
        )
        pid_observed_ipv6_local_ports = @(
            $SocketSamplerEvidence.candidate_target_rows |
                Where-Object family -eq 'IPv6' |
                ForEach-Object { [int]$_.local_port } |
                Sort-Object -Unique
        )
        pid_correlation_tolerance_ms = $SynCorrelationToleranceMs
        pid_sampler_temporal_coverage_valid = $samplerTemporalCoverage
        pid_sampler_maximum_gap_ms = $samplerMaximumGapMs
        target_syn_count = $outboundTargetSyn.Count
        pid_correlated_target_syn_count = @(
            $outboundTargetSyn | Where-Object candidate_correlated
        ).Count
        excluded_prewarm_tuple_count = $excluded.Count
        excluded_prewarm_syn_packet_count = $excludedPrewarmPackets.Count
        pre_boundary_target_syn_count = $preBoundaryTargetSyn.Count
        uncorrelated_target_syn_count = $uncorrelated.Count
        ambiguous_owner_target_syn_count = $ambiguous.Count
        target_syn_pid_correlations = @(
            $outboundTargetSyn | ForEach-Object { $_.correlation }
        )
        pid_packet_correlation_complete = $correlationComplete
        silent_drop_proved = $null -ne $firstSyn6 -and
            $silentWindowObservedMs -ge $MinimumSilentWindowMs -and
            $captureCoverageAfterSyn6Ms -ge $MinimumSilentWindowMs -and
            $silentWindowResponses -eq 0 -and $silentWindowIcmp -eq 0
        ipv4_attempt_absent_proved = $null -ne $firstSyn6 -and
            $syn4.Count -eq 0 -and
            $captureCoverageAfterSyn6Ms -ge $limitMs
        fallback_under_limit = $null -ne $fallbackMs -and
            $fallbackMs -ge 0 -and $fallbackMs -lt $limitMs
        fallback_in_planning_window = $null -ne $fallbackMs -and
            $fallbackMs -ge $MinimumSilentWindowMs -and
            $fallbackMs -lt $planningUpperBoundMs
        fallback_planning_upper_bound_ms = $planningUpperBoundMs
        connection_under_limit = $null -ne $connectedMs -and
            $connectedMs -ge 0 -and $connectedMs -lt $limitMs
    }
}

function Invoke-I04PeerRole {
    if (-not (Test-I04Administrator)) {
        throw 'Peer role requires an elevated Administrator PowerShell for scoped firewall setup/rollback'
    }
    foreach ($firewallCommand in @(
        'Get-NetFirewallRule', 'New-NetFirewallRule',
        'Remove-NetFirewallRule', 'Get-NetFirewallAddressFilter',
        'Get-NetFirewallApplicationFilter', 'Get-NetFirewallPortFilter'
    )) {
        if ($null -eq (Get-Command $firewallCommand `
            -ErrorAction SilentlyContinue)) {
            throw "Peer firewall prerequisite is missing: $firewallCommand"
        }
    }
    if (-not $RunNonce) {
        throw 'Peer role requires -RunNonce from the coordinator'
    }
    $outputPath = Get-LabFullPath -Path $OutputRoot
    if (Test-Path -LiteralPath $outputPath) {
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Peer OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $journal = Join-Path $evidence 'mutation-journal.jsonl'
    $cleanupPath = Join-Path $evidence 'cleanup.json'
    $formalTriggerBoundaryPath =
        Join-Path $evidence 'formal-trigger-boundary.json'
    $coordination = Get-LabFullPath -Path (Join-Path `
        -Path (Get-LabFullPath -Path $CoordinationRoot) `
        -ChildPath "v91-i04-$($RunNonce.ToLowerInvariant())")
    if (-not (Test-Path -LiteralPath $coordination -PathType Container)) {
        throw "Peer requires the coordinator-created run directory: $coordination"
    }
    $initialCoordinationEntries = @(
        Get-ChildItem -LiteralPath $coordination -Force -ErrorAction Stop
    )
    if ($initialCoordinationEntries.Count -ne 1 -or
        $initialCoordinationEntries[0].Name -ne 'run.json') {
        throw 'Peer coordination run directory is stale or was not pristine (expected only run.json)'
    }
    $runPath = Join-Path $coordination 'run.json'
    $runManifest = Get-Content -LiteralPath $runPath -Raw |
        ConvertFrom-Json -ErrorAction Stop
    if ([string]$runManifest.schema -ne 'ese.v91.i04-run/v1' -or
        [string]$runManifest.case_id -ne $caseId -or
        [string]$runManifest.run_nonce -ne $RunNonce.ToLowerInvariant() -or
        [string]$runManifest.expected_candidate_commit -ne $candidate.commit -or
        [string]$runManifest.expected_emule_sha256 -ne $expectedHash -or
        [string]$runManifest.peer.hostname -ne $canonicalHostname -or
        [string]$runManifest.peer.ipv4 -ne $peerV4Text -or
        [string]$runManifest.peer.local_ipv4 -ne $peerLocalV4Text -or
        [string]$runManifest.peer.ipv6 -ne $peerV6Text -or
        [int]$runManifest.peer.tcp_port -ne $PeerTcpPort -or
        [int]$runManifest.peer.udp_port -ne $PeerUdpPort -or
        [int]$runManifest.peer.web_port -ne $PeerWebPort -or
        [int]$runManifest.client.tcp_port -ne $ClientTcpPort -or
        [int]$runManifest.client.udp_port -ne $ClientUdpPort -or
        [int]$runManifest.client.web_port -ne $ClientWebPort -or
        [Int64]$runManifest.file_size_bytes -ne $FileSizeBytes -or
        [Int64]$runManifest.file_b_size_bytes -ne $fileBSizeBytes -or
        [int]$runManifest.scheduler_reconnect_floor_seconds -ne
            $schedulerReconnectFloorSeconds -or
        [int]$runManifest.fallback_limit_seconds -ne
            $FallbackLimitSeconds -or
        [int]$runManifest.expected_fallback_delay_ms -ne
            $expectedFallbackDelayMs -or
        [int]$runManifest.capture_tolerance_ms -ne
            $captureTimingToleranceMs -or
        [int]$runManifest.socket_clock_coherence_tolerance_ms -ne
            $socketClockCoherenceToleranceMs) {
        throw 'Peer run manifest does not exactly match the requested candidate/endpoints'
    }
    $coordinatorV4Address = Convert-I04RequiredAddress `
        -Value $CoordinatorIPv4 `
        -AddressFamily ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'CoordinatorIPv4'
    $coordinatorV6Address = Convert-I04RequiredAddress `
        -Value $CoordinatorIPv6 `
        -AddressFamily ([Net.Sockets.AddressFamily]::InterNetworkV6) `
        -Name 'CoordinatorIPv6'
    $coordinatorV4Text = $coordinatorV4Address.ToString()
    $coordinatorV6Text = $coordinatorV6Address.ToString()
    if ([string]$runManifest.coordinator.ipv4 -ne $coordinatorV4Text -or
        [string]$runManifest.coordinator.ipv6 -ne $coordinatorV6Text) {
        throw 'Peer coordinator addresses do not match the signed run manifest'
    }
    $readyPath = Join-Path $coordination 'peer-ready.json'
    $armPath = Join-Path $coordination 'arm-drop.json'
    $armedPath = Join-Path $coordination 'peer-drop-armed.json'
    $quiescePath = Join-Path $coordination 'quiesce.json'
    $quiescedPath = Join-Path $coordination 'peer-quiesced.json'
    $restartPath = Join-Path $coordination 'restart.json'
    $resumedPath = Join-Path $coordination 'peer-resumed.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $resultPath = Join-Path $coordination 'peer-result.json'

    $password = 'v91-i04-peer'
    $source = $null
    $sourceExe = ''
    $sourceNode = ''
    $controlledServer = $null
    $controlledServersOwned =
        New-Object 'Collections.Generic.List[object]'
    $controlledServerStop = $null
    $allow4Rule = "eSE V91 I04 allow4 $RunNonce"
    $allow6Rule = "eSE V91 I04 allow6 $RunNonce"
    $dropRule = "eSE V91 I04 DROP6 $RunNonce"
    $allow4RuleName =
        "ese-v91-i04-allow4-$($RunNonce.ToLowerInvariant())"
    $allow6RuleName =
        "ese-v91-i04-allow6-$($RunNonce.ToLowerInvariant())"
    $dropRuleName = "ese-v91-i04-drop6-$($RunNonce.ToLowerInvariant())"
    $firewallNamesOwned = $false
    $runtimeFailure = $null
    $cleanupFailures = New-Object 'Collections.Generic.List[string]'
    $armedAt = $null
    $oldPid = $null
    $newPid = $null
    $restartElapsedMs = $null
    $allow4Evidence = $null
    $allow6Evidence = $null
    $dropEvidence = $null
    $observedCoordinatorV4 = ''
    $observedCoordinatorPort = $null
    $fixtureA = $null
    $fixtureB = $null
    $sharedA = $null
    $sharedB = $null
    $peerEvidence = $null
    $sourceIdentityInitial = $null
    $sourceRuntimeInitial = $null
    $sourceRuntimeResumed = $null
    $serverLoginInitial = $null
    $serverLoginResumed = $null
    $peerIsolationInitial = $null
    $peerIsolationFinal = $null
    $peerRouteV6 = $null
    $peerRouteV4Observed = $null

    try {
        $peerIsolationInitial = Get-I04IsolationEvidence
        Write-LabJson -Value $peerIsolationInitial -Path (
            Join-Path $evidence 'peer-isolation-initial.json'
        ) | Out-Null
        if (-not [bool]$peerIsolationInitial.strict_isolation_valid) {
            throw 'Peer has an active overlay/VPN adapter or proxy environment'
        }
        $assignedV4 = Get-NetIPAddress -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue | Where-Object {
                (Get-I04NormalizedIp -Address $_.IPAddress) -eq
                    $peerLocalV4Text -and
                $_.AddressState -eq 'Preferred'
            } | Select-Object -First 1
        $assignedV6 = Get-NetIPAddress -AddressFamily IPv6 `
            -ErrorAction SilentlyContinue | Where-Object {
                (Get-I04NormalizedIp -Address $_.IPAddress) -eq $peerV6Text -and
                $_.AddressState -eq 'Preferred'
            } | Select-Object -First 1
        if ($null -eq $assignedV4 -or $null -eq $assignedV6) {
            throw 'PeerLocalIPv4 and PeerIPv6 must both be Preferred addresses assigned to this peer'
        }
        if ([int]$assignedV4.InterfaceIndex -ne
            [int]$assignedV6.InterfaceIndex) {
            throw 'Peer IPv4 and IPv6 must be assigned to the same adapter'
        }
        if ((Get-LabAddressClass -Address $peerV6Text) -ne 'global-v6') {
            throw 'The real peer must advertise a native global IPv6 address; ULA/overlay-only is not a direct T1/T2 I04 fixture'
        }
        $adapter = Get-NetAdapter -InterfaceIndex $assignedV6.InterfaceIndex `
            -ErrorAction Stop
        $adapterVirtual = $false
        if ($adapter.PSObject.Properties.Name -contains 'Virtual') {
            $adapterVirtual = [bool]$adapter.Virtual
        }
        $adapterOverlayLike =
            ([string]$adapter.Name) -match $overlayPattern -or
            ([string]$adapter.InterfaceDescription) -match $overlayPattern
        $physical = [bool]$adapter.HardwareInterface -and
            -not $adapterVirtual -and -not $adapterOverlayLike
        if (-not $physical -or ([string]$adapter.Status) -ne 'Up') {
            throw 'Peer dual-stack adapter must be an Up physical, non-virtual interface'
        }
        $peerRouteV6 = Get-I04RouteEvidence `
            -RemoteAddress $coordinatorV6Text
        if (-not [bool]$peerRouteV6.available -or
            -not [bool]$peerRouteV6.physical_nonvirtual -or
            [int]$peerRouteV6.interface_index -ne
                [int]$assignedV6.InterfaceIndex -or
            [string]$peerRouteV6.source_address -ne $peerV6Text) {
            throw 'Peer does not have a native physical IPv6 route to coordinator'
        }
        $peerEvidence = [ordered]@{
            machine_id_sha256 = Get-I04MachineId
            computer_name_sha256 = Get-LabStringSha256 -Value $env:COMPUTERNAME
            interface_id = Get-LabInterfaceId `
                -Id ([string]$adapter.InterfaceGuid) `
                -Name ([string]$adapter.Name) `
                -Description ([string]$adapter.InterfaceDescription)
            interface_status = [string]$adapter.Status
            hardware_interface = [bool]$adapter.HardwareInterface
            virtual = $adapterVirtual
            overlay_or_vpn_like = $adapterOverlayLike
            physical = $physical
            ipv4_assigned = $true
            ipv6_assigned = $true
            public_ipv4_endpoint = $peerV4Text
            local_ipv4 = $peerLocalV4Text
            ipv4_interface_index = [int]$assignedV4.InterfaceIndex
            ipv6_interface_index = [int]$assignedV6.InterfaceIndex
            same_interface = [int]$assignedV4.InterfaceIndex -eq
                [int]$assignedV6.InterfaceIndex
            route_to_coordinator_ipv6 = $peerRouteV6
            isolation = $peerIsolationInitial
        }

        $offset = $PeerTcpPort - 4662
        if (($PeerUdpPort - 4672) -ne $offset -or
            ($PeerWebPort - 4711) -ne $offset) {
            throw 'Peer TCP/UDP/Web ports must share the standard 4662/4672/4711 offset'
        }
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
            -SourcePackage $candidate.package_path -OutputRoot $nodes `
            -RunId 'v91-i04-peer' -PortOffset $offset
        $sourceNode = Join-Path $nodes 'v91-i04-peer-a'
        $sourceExe = Join-Path $sourceNode 'emule.exe'
        if ((Get-LabSha256 -Path $sourceExe) -ne $expectedHash) {
            throw 'Prepared peer node is not the exact candidate binary'
        }
        $incoming = New-LabDirectory -Path (Join-Path $sourceNode 'Incoming')
        $temp = New-LabDirectory -Path (Join-Path $sourceNode 'Temp')
        $isolation = Set-I04IsolatedPreferences -NodePath $sourceNode `
            -IPv6Mode 2 -IPv6BindAddress $peerV6Text `
            -WebPort $PeerWebPort -Password $password `
            -IncomingPath $incoming -TempPath $temp -MaxUploadKiBps 64
        if (-not $isolation.preferences_dat_absent_before_start -or
            -not $isolation.cryptkey_dat_absent_before_start) {
            throw 'Peer profile inherited identity state'
        }

        $fileAName = "v91-i04-$RunNonce-a.bin"
        $fileBName = "v91-i04-$RunNonce-b.bin"
        $fixtureA = New-I04FixtureFile `
            -Path (Join-Path $incoming $fileAName) `
            -Bytes $FileSizeBytes `
            -Seed (
                "V91-I04|peer|A|$($RunNonce.ToLowerInvariant())|" +
                "$($candidate.commit)|$FileSizeBytes"
            )
        $fixtureB = New-I04FixtureFile `
            -Path (Join-Path $incoming $fileBName) `
            -Bytes $fileBSizeBytes `
            -Seed (
                "V91-I04|peer|B|$($RunNonce.ToLowerInvariant())|" +
                "$($candidate.commit)|$fileBSizeBytes"
            )
        if ($fixtureA.sha256 -eq $fixtureB.sha256) {
            throw 'Peer files A and B are not unique'
        }

        $firewallPrecheck = @(
            Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop
        )
        foreach ($ruleIdentity in @(
            [pscustomobject]@{
                name = $allow4RuleName; display = $allow4Rule
            },
            [pscustomobject]@{
                name = $allow6RuleName; display = $allow6Rule
            },
            [pscustomobject]@{ name = $dropRuleName; display = $dropRule }
        )) {
            if (@($firewallPrecheck | Where-Object {
                [string]$_.Name -eq $ruleIdentity.name
            }).Count -ne 0) {
                throw "Refusing to reuse firewall Name '$($ruleIdentity.name)'"
            }
            if (@($firewallPrecheck | Where-Object {
                [string]$_.DisplayName -eq $ruleIdentity.display
            }).Count -ne 0) {
                throw "Refusing to reuse firewall DisplayName '$($ruleIdentity.display)'"
            }
        }
        $firewallNamesOwned = $true
        New-NetFirewallRule `
            -Name $allow4RuleName -DisplayName $allow4Rule `
            -Direction Inbound -Action Allow -Program $sourceExe `
            -Protocol TCP -LocalAddress $peerLocalV4Text `
            -LocalPort $PeerTcpPort -RemoteAddress Any `
            -Profile Any -Enabled True | Out-Null
        Add-I04Journal -Path $journal -Mutation 'peer-firewall-allow4' `
            -State 'applied' -Detail "$allow4Rule remote=Any provisional"
        New-NetFirewallRule `
            -Name $allow6RuleName -DisplayName $allow6Rule `
            -Direction Inbound `
            -Action Allow -Program $sourceExe -Protocol TCP `
            -LocalAddress $peerV6Text -LocalPort $PeerTcpPort `
            -RemoteAddress $coordinatorV6Text `
            -Profile Any -Enabled True | Out-Null
        Add-I04Journal -Path $journal -Mutation 'peer-firewall-allow6' `
            -State 'applied' -Detail $allow6Rule
        $allow4Evidence = Get-I04FirewallRuleEvidence `
            -DisplayName $allow4Rule -Action Allow -Program $sourceExe `
            -LocalAddresses @($peerLocalV4Text) `
            -RemoteAddresses @('Any') `
            -LocalPort $PeerTcpPort
        $allow6Evidence = Get-I04FirewallRuleEvidence `
            -DisplayName $allow6Rule -Action Allow -Program $sourceExe `
            -LocalAddresses @($peerV6Text) `
            -RemoteAddresses @($coordinatorV6Text) `
            -LocalPort $PeerTcpPort
        if (-not $allow4Evidence.exact -or
            -not $allow6Evidence.exact) {
            throw 'Peer provisional allow rules did not round-trip exactly'
        }

        function Start-PeerSource {
            param(
                [AllowNull()][Diagnostics.Stopwatch]$RestartWatch = $null,
                [switch]$RequireEd2k,
                [ValidateRange(0, 16)][int]$MinimumServerLogin = 0
            )

            $process = $null
            try {
                $process = Start-Process -FilePath $sourceExe `
                    -ArgumentList @(
                        '--portable', '--ignoreinstances',
                        "--metrics-port=$PeerWebPort",
                        "--tcp-port=$PeerTcpPort",
                        "--udp-port=$PeerUdpPort"
                    ) -WorkingDirectory $sourceNode -PassThru -WindowStyle Hidden
                $listeners = Wait-I04Listener -Port $PeerTcpPort `
                    -Process $process -RequireDualStack
                $listenerReadyMs = if ($null -eq $RestartWatch) {
                    $null
                } else { [Int64]$RestartWatch.ElapsedMilliseconds }
                Wait-I04Api -Port $PeerWebPort -Process $process | Out-Null
                if ((Get-LabSha256 -Path $process.Path) -ne $expectedHash) {
                    throw 'Started peer process is not the exact candidate binary'
                }
                $serverLogin = $null
                if ($MinimumServerLogin -gt 0) {
                    if ($null -eq $controlledServer) {
                        throw 'Peer controlled eD2K server was not started'
                    }
                    $serverLogin = Wait-I04ControlledEd2kLogin `
                        -Server $controlledServer -Process $process `
                        -ExpectedTcpPort $PeerTcpPort `
                        -MinimumLoginCount $MinimumServerLogin `
                        -TimeoutSeconds 90
                }
                $apiDeadline = [DateTime]::UtcNow.AddSeconds(90)
                do {
                    $api = Get-I04ApiProbe -Port $PeerWebPort
                    if (Test-I04ApiIsolation -Data $api `
                        -RequireEd2k ([bool]$RequireEd2k)) {
                        break
                    }
                    Start-Sleep -Milliseconds 200
                } while ([DateTime]::UtcNow -lt $apiDeadline)
                if (-not (Test-I04ApiIsolation -Data $api `
                    -RequireEd2k ([bool]$RequireEd2k))) {
                    throw 'Peer runtime violated eD2K/Kad/NetLab isolation gates'
                }
                return [pscustomobject]@{
                    process = $process
                    listeners = $listeners
                    listener_ready_elapsed_ms = $listenerReadyMs
                    api = $api
                    controlled_server_login = $serverLogin
                }
            } catch {
                if ($null -ne $process -and -not (
                    Stop-I04OwnedProcess -Process $process `
                        -ExpectedPath $sourceExe
                )) {
                    $cleanupFailures.Add(
                        "partially started peer process $($process.Id) could not be stopped safely"
                    )
                }
                throw
            }
        }

        # A clean normal-mode start/stop materializes preferences.dat.  The
        # campaign source then reloads that exact persisted user hash on every
        # controlled restart; a first-run in-memory identity is not sufficient
        # evidence for the "same peer" requirement.
        $initialized = Start-PeerSource
        $source = $initialized.process
        Add-I04Journal -Path $journal -Mutation 'peer-identity-init-process' `
            -State 'applied' -Detail "pid=$($source.Id)"
        if (-not (Stop-I04OwnedProcess -Process $source `
            -ExpectedPath $sourceExe -RequireGraceful)) {
            throw 'Peer identity initialization did not stop gracefully'
        }
        Add-I04Journal -Path $journal -Mutation 'peer-identity-init-process' `
            -State 'rolled_back' -Detail "pid=$($source.Id)"
        $source = $null
        $sourceIdentitySeed = Get-I04PersistedUserHash -NodePath $sourceNode

        $controlledServer = Start-I04ControlledEd2kServer `
            -EvidencePath (
                Join-Path $evidence 'peer-controlled-ed2k-server.json'
            ) -ListenAddress $peerLocalV4Text `
            -ExpectedClientAddress $peerLocalV4Text `
            -HighIdAddress $peerV4Text `
            -RunNonce $RunNonce.ToLowerInvariant() -OwnerRole 'peer' `
            -OwnerInventory $controlledServersOwned
        $controlledProfile = Enable-I04ControlledEd2kProfile `
            -NodePath $sourceNode -ServerAddress $peerLocalV4Text `
            -ServerPort $controlledServer.port `
            -RunNonce $RunNonce.ToLowerInvariant() -OwnerRole 'peer'

        $started = Start-PeerSource -RequireEd2k -MinimumServerLogin 1
        $source = $started.process
        $sourceRuntimeInitial = $started.api
        $serverLoginInitial = $started.controlled_server_login
        $sourceIdentityInitial = Get-I04PersistedUserHash `
            -NodePath $sourceNode
        if ([string]$sourceIdentityInitial.user_hash -ne
                [string]$sourceIdentitySeed.user_hash -or
            [string]$sourceRuntimeInitial.user_hash -ne
                [string]$sourceIdentitySeed.user_hash -or
            [string]$serverLoginInitial.runtime_user_hash -ne
                [string]$sourceIdentitySeed.user_hash) {
            throw 'Peer persisted/runtime/server-login identity mismatch'
        }
        Add-I04Journal -Path $journal -Mutation 'peer-process' `
            -State 'applied' -Detail "pid=$($source.Id)"
        $session = Get-I04ClassicSession -Port $PeerWebPort -Password $password
        $sharedA = Get-I04SharedLink -Port $PeerWebPort -Session $session `
            -FileName $fileAName -FileBytes $FileSizeBytes
        $sharedB = Get-I04SharedLink -Port $PeerWebPort -Session $session `
            -FileName $fileBName -FileBytes $fileBSizeBytes
        if ([string]$sharedA.ed2k_hash -eq
            [string]$sharedB.ed2k_hash) {
            throw 'Peer files A and B have the same eD2K hash'
        }
        $ready = [ordered]@{
            schema = 'ese.v91.i04-peer-ready/v1'
            case_id = $caseId
            run_nonce = $RunNonce.ToLowerInvariant()
            ready_at_utc = Get-LabUtcTimestamp
            candidate = [ordered]@{
                commit = $candidate.commit
                version = $candidate.version
                emule_sha256 = $candidate.emule_sha256
                process_emule_sha256 = Get-LabSha256 -Path $sourceExe
            }
            peer = $peerEvidence
            endpoint = [ordered]@{
                hostname = $canonicalHostname
                ipv4 = $peerV4Text
                local_ipv4 = $peerLocalV4Text
                ipv6 = $peerV6Text
                tcp_port = $PeerTcpPort
                dual_stack_listener = $true
                ipv6_bind_preference = $peerV6Text
                hello_ipv6_advertisement_configured = $true
            }
            coordinator = [ordered]@{
                ipv4 = $coordinatorV4Text
                ipv6 = $coordinatorV6Text
            }
            process = [ordered]@{
                id = $source.Id
                executable_sha256 = Get-LabSha256 -Path $sourceExe
                source_mode = 'non-headless'
                persisted_identity = $sourceIdentityInitial
                runtime_identity = [string]$sourceRuntimeInitial.user_hash
                controlled_server_login = $serverLoginInitial
            }
            fixtures = [ordered]@{
                a = $fixtureA
                b = $fixtureB
                unique_sha256 =
                    [string]$fixtureA.sha256 -ne [string]$fixtureB.sha256
            }
            ed2k = [ordered]@{
                a = [ordered]@{
                    base_link = $sharedA.link
                    hash = $sharedA.ed2k_hash
                }
                b = [ordered]@{
                    base_link = $sharedB.link
                    hash = $sharedB.ed2k_hash
                }
                unique_hash =
                    [string]$sharedA.ed2k_hash -ne
                        [string]$sharedB.ed2k_hash
                controlled_server = [ordered]@{
                    profile = $controlledProfile
                    login = $serverLoginInitial
                    minimum_logins_required_across_restart = 2
                }
            }
            controls = [ordered]@{
                inbound_ipv6_drop_is_remote = $true
                drop_action = 'Block'
                rejection_rule_created = $false
                allow4_rule_provisional = $allow4Evidence
                allow6_rule = $allow6Evidence
            }
            runtime_isolation = $sourceRuntimeInitial
        }
        Write-LabJson -Value $ready -Path $readyPath | Out-Null

        $control = Wait-I04PeerControl -ArmPath $armPath `
            -StopPath $stopPath -TimeoutSeconds $ScenarioTimeoutSeconds
        if ($null -eq $control) {
            throw 'Coordinator sent neither arm nor stop within the bounded wait'
        }
        if ([string]$control.data.run_nonce -ne
            $RunNonce.ToLowerInvariant()) {
            throw 'Peer received a control command for a different run'
        }
        if ($control.kind -eq 'stop' -and (
            [string]$control.data.schema -ne
                'ese.v91.i04-stop-command/v1' -or
            [string]$control.data.case_id -ne $caseId -or
            [string]$control.data.action -ne 'stop-and-restore' -or
            [string]$control.data.candidate_commit -ne $candidate.commit -or
            [string]$control.data.candidate_emule_sha256 -ne $expectedHash
        )) {
            throw 'Peer received an invalid stop command'
        }

        if ($control.kind -eq 'arm') {
            $arm = $control.data
            if ([string]$arm.schema -ne 'ese.v91.i04-arm-command/v1' -or
                [string]$arm.case_id -ne $caseId -or
                [string]$arm.action -ne 'arm-remote-silent-drop' -or
                [string]$arm.run_nonce -ne $RunNonce.ToLowerInvariant() -or
                [string]$arm.candidate_commit -ne $candidate.commit -or
                [string]$arm.candidate_emule_sha256 -ne $expectedHash -or
                [int]$arm.expected_source_process_id -ne $source.Id -or
                [string]$arm.expected_peer_ipv4 -ne $peerV4Text -or
                [string]$arm.expected_peer_ipv6 -ne $peerV6Text -or
                [int]$arm.expected_peer_tcp_port -ne $PeerTcpPort) {
                throw 'Peer received an invalid arm command'
            }
            $armPrewarmTuples = @($arm.prewarm_tuples)
            $armPrewarmExact = $armPrewarmTuples.Count -gt 0 -and
                @($armPrewarmTuples | Where-Object {
                    [string]$_.state -ne 'Established' -or
                    (Get-I04NormalizedIp -Address ([string]$_.remote_address)) -ne
                        $peerV4Text -or
                    [int]$_.remote_port -ne $PeerTcpPort
                }).Count -eq 0
            if (-not $armPrewarmExact) {
                throw 'Peer received invalid prewarm tuple evidence'
            }

            $oldPid = $source.Id
            $source.Refresh()
            $oldListeners = @(
                Get-NetTCPConnection -State Listen -LocalPort $PeerTcpPort `
                    -OwningProcess $oldPid -ErrorAction SilentlyContinue
            )
            $prewarmInbound = @(
                Get-NetTCPConnection -State Established -LocalPort $PeerTcpPort `
                    -OwningProcess $oldPid -ErrorAction SilentlyContinue |
                    Where-Object {
                        (Get-I04NormalizedIp -Address $_.LocalAddress) -eq
                            $peerLocalV4Text -and
                        -not (
                            Get-I04NormalizedIp -Address $_.RemoteAddress
                        ).Contains(':')
                    }
            )
            $oldDualListener = @($oldListeners | Where-Object {
                (Get-I04NormalizedIp -Address $_.LocalAddress) -eq '::'
            }).Count -gt 0
            if ($source.HasExited -or
                (Get-LabSha256 -Path $source.Path) -ne $expectedHash -or
                -not $oldDualListener -or $prewarmInbound.Count -ne 1) {
                throw 'Old peer source/prewarm was not alive at the DROP barrier'
            }
            $observedCoordinatorV4 = Get-I04NormalizedIp -Address (
                [string]$prewarmInbound[0].RemoteAddress
            )
            $observedCoordinatorPort = [int]$prewarmInbound[0].RemotePort
            if ((Get-LabAddressClass -Address $observedCoordinatorV4) -in @(
                'invalid', 'loopback-v4', 'linklocal-v4', 'special-v4'
            )) {
                throw 'Peer observed an inadmissible post-NAT IPv4 source'
            }
            $peerRouteV4Observed = Get-I04RouteEvidence `
                -RemoteAddress $observedCoordinatorV4
            if (-not [bool]$peerRouteV4Observed.available -or
                -not [bool]$peerRouteV4Observed.physical_nonvirtual -or
                [int]$peerRouteV4Observed.interface_index -ne
                    [int]$assignedV4.InterfaceIndex -or
                [string]$peerRouteV4Observed.source_address -ne
                    $peerLocalV4Text) {
                throw 'Peer observed IPv4 client is not reached over the native physical data-plane adapter'
            }

            # The peer can only know the post-NAT remote endpoint.  First allow
            # any remote IPv4 long enough to observe the unique established
            # prewarm, then atomically replace it with that observed IP.  The
            # remote port deliberately remains Any because NAT may rewrite it.
            Remove-NetFirewallRule -Name $allow4RuleName -ErrorAction Stop
            New-NetFirewallRule `
                -Name $allow4RuleName -DisplayName $allow4Rule `
                -Direction Inbound -Action Allow -Program $sourceExe `
                -Protocol TCP -LocalAddress $peerLocalV4Text `
                -LocalPort $PeerTcpPort `
                -RemoteAddress $observedCoordinatorV4 `
                -Profile Any -Enabled True | Out-Null
            Add-I04Journal -Path $journal -Mutation 'peer-firewall-allow4' `
                -State 'narrowed' `
                -Detail (
                    "observed_post_nat_remote=$observedCoordinatorV4;" +
                    " remote_port_any; prewarm_remote_port=" +
                    "$observedCoordinatorPort"
                )

            New-NetFirewallRule -Name $dropRuleName -DisplayName $dropRule `
                -Direction Inbound `
                -Action Block -Program $sourceExe -Protocol TCP `
                -LocalAddress $peerV6Text -LocalPort $PeerTcpPort `
                -RemoteAddress $coordinatorV6Text `
                -Profile Any -Enabled True | Out-Null
            $dropEvidence = Get-I04FirewallRuleEvidence `
                -DisplayName $dropRule -Action Block -Program $sourceExe `
                -LocalAddresses @($peerV6Text) `
                -RemoteAddresses @($coordinatorV6Text) `
                -LocalPort $PeerTcpPort
            $allow4Evidence = Get-I04FirewallRuleEvidence `
                -DisplayName $allow4Rule -Action Allow -Program $sourceExe `
                -LocalAddresses @($peerLocalV4Text) `
                -RemoteAddresses @($observedCoordinatorV4) `
                -LocalPort $PeerTcpPort
            $allow6Evidence = Get-I04FirewallRuleEvidence `
                -DisplayName $allow6Rule -Action Allow -Program $sourceExe `
                -LocalAddresses @($peerV6Text) `
                -RemoteAddresses @($coordinatorV6Text) `
                -LocalPort $PeerTcpPort
            $source.Refresh()
            $listenersAfterDrop = @(
                Get-NetTCPConnection -State Listen -LocalPort $PeerTcpPort `
                    -OwningProcess $oldPid -ErrorAction SilentlyContinue
            )
            $dualStackStillAlive = @($listenersAfterDrop | Where-Object {
                (Get-I04NormalizedIp -Address $_.LocalAddress) -eq '::'
            }).Count -gt 0
            $prewarmStillAlive = @(
                Get-NetTCPConnection -State Established -LocalPort $PeerTcpPort `
                    -OwningProcess $oldPid -ErrorAction SilentlyContinue |
                    Where-Object {
                        (Get-I04NormalizedIp -Address $_.RemoteAddress) -eq
                            $observedCoordinatorV4 -and
                        [int]$_.RemotePort -eq $observedCoordinatorPort
                    }
            ).Count -gt 0
            if (-not $dropEvidence.exact -or
                -not $allow4Evidence.exact -or
                -not $allow6Evidence.exact -or
                $source.HasExited -or -not $dualStackStillAlive -or
                -not $prewarmStillAlive -or
                (Get-LabSha256 -Path $source.Path) -ne $expectedHash) {
                throw 'DROP/allow rules or old source/prewarm failed exact armed verification'
            }
            $armedAt = [DateTime]::UtcNow
            Add-I04Journal -Path $journal -Mutation 'peer-ipv6-silent-drop' `
                -State 'applied' -Detail $dropRule
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i04-peer-drop-armed/v1'
                case_id = $caseId
                run_nonce = $RunNonce.ToLowerInvariant()
                candidate_commit = $candidate.commit
                candidate_emule_sha256 = $candidate.emule_sha256
                armed_at_utc = $armedAt.ToString('o')
                source_process_id = $oldPid
                source_process_alive = $true
                source_process_emule_sha256 = Get-LabSha256 -Path $source.Path
                dual_stack_listener_alive = $dualStackStillAlive
                prewarm_connection_alive = $prewarmStillAlive
                observed_ipv4_client = [ordered]@{
                    address = $observedCoordinatorV4
                    port = $observedCoordinatorPort
                    comparison_to_manifest_coordinator_ipv4 =
                        'intentionally_not_required_due_to_nat'
                    firewall_remote_port = 'Any'
                }
                route_to_observed_ipv4_client = $peerRouteV4Observed
                allow4_rule = $allow4Evidence
                allow6_rule = $allow6Evidence
                drop_rule = $dropEvidence
                semantic = 'remote inbound WFP DROP; no local reject/reset rule'
            }) -Path $armedPath | Out-Null

            $quiesceControl = Wait-I04RestartControl `
                -RestartPath $quiescePath -StopPath $stopPath `
                -TimeoutSeconds $ScenarioTimeoutSeconds
            if ($null -eq $quiesceControl) {
                throw 'Coordinator sent neither quiesce nor stop after DROP was armed'
            }
            if ([string]$quiesceControl.data.run_nonce -ne
                $RunNonce.ToLowerInvariant()) {
                throw 'Peer received post-arm control for a different run'
            }
            if ($quiesceControl.kind -eq 'stop' -and (
                [string]$quiesceControl.data.schema -ne
                    'ese.v91.i04-stop-command/v1' -or
                [string]$quiesceControl.data.case_id -ne $caseId -or
                [string]$quiesceControl.data.action -ne 'stop-and-restore' -or
                [string]$quiesceControl.data.candidate_commit -ne
                    $candidate.commit -or
                [string]$quiesceControl.data.candidate_emule_sha256 -ne
                    $expectedHash
            )) {
                throw 'Peer received an invalid post-arm stop command'
            }
            if ($quiesceControl.kind -eq 'restart') {
                $quiesce = $quiesceControl.data
                if ([string]$quiesce.schema -ne
                        'ese.v91.i04-quiesce-command/v1' -or
                    [string]$quiesce.case_id -ne $caseId -or
                    [string]$quiesce.action -ne
                        'stop-source-under-drop' -or
                    [string]$quiesce.candidate_commit -ne
                        $candidate.commit -or
                    [string]$quiesce.candidate_emule_sha256 -ne
                        $expectedHash -or
                    [int]$quiesce.expected_old_process_id -ne $oldPid) {
                    throw 'Peer received an invalid quiesce barrier command'
                }
                $source.Refresh()
                $prewarmAtQuiesce = @(
                    Get-NetTCPConnection -State Established `
                        -LocalPort $PeerTcpPort -OwningProcess $oldPid `
                        -ErrorAction SilentlyContinue | Where-Object {
                            (Get-I04NormalizedIp -Address $_.RemoteAddress) -eq
                                $observedCoordinatorV4 -and
                            [int]$_.RemotePort -eq $observedCoordinatorPort
                        }
                ).Count -gt 0
                if ($source.HasExited -or -not $prewarmAtQuiesce -or
                    (Get-LabSha256 -Path $source.Path) -ne $expectedHash) {
                    throw 'Old source/prewarm did not survive to quiesce release'
                }
                $sourceIdentityBeforeRestart = Get-I04PersistedUserHash `
                    -NodePath $sourceNode
                if ([string]$sourceIdentityBeforeRestart.user_hash -ne
                    [string]$sourceIdentityInitial.user_hash) {
                    throw 'Peer persisted identity changed before the controlled restart'
                }
                if (-not (Stop-I04OwnedProcess -Process $source `
                    -ExpectedPath $sourceExe -ForceImmediate)) {
                    throw 'Peer source could not be stopped safely at quiesce barrier'
                }
                Add-I04RollbackJournal -Path $journal `
                    -Mutation 'peer-process' -State 'rolled_back' `
                    -Detail "old_pid=$oldPid quiesced under DROP" `
                    -CleanupFailures $cleanupFailures
                $source = $null

                $oldTupleGoneDeadline =
                    [DateTime]::UtcNow.AddSeconds(30)
                do {
                    $oldSockets = @(
                        Get-NetTCPConnection -OwningProcess $oldPid `
                            -ErrorAction SilentlyContinue
                    )
                    if ($oldSockets.Count -eq 0) { break }
                    Start-Sleep -Milliseconds 100
                } while ([DateTime]::UtcNow -lt $oldTupleGoneDeadline)
                if ($oldSockets.Count -ne 0 -or
                    $null -ne (
                        Get-Process -Id $oldPid -ErrorAction SilentlyContinue
                    )) {
                    throw 'Old peer PID/tuple remained after quiesce'
                }
                $quiescedAt = [DateTimeOffset]::UtcNow
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i04-peer-quiesced/v1'
                    case_id = $caseId
                    run_nonce = $RunNonce.ToLowerInvariant()
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $candidate.emule_sha256
                    quiesced_at_utc = $quiescedAt.ToString('o')
                    quiesced_epoch_ms =
                        Get-I04EpochMilliseconds -Timestamp $quiescedAt
                    old_process_id = $oldPid
                    old_process_absent = $true
                    old_listener_and_tuple_absent = $true
                    drop_rule = $dropEvidence
                    allow4_rule = $allow4Evidence
                    allow6_rule = $allow6Evidence
                }) -Path $quiescedPath | Out-Null

                $restartControl = Wait-I04RestartControl `
                    -RestartPath $restartPath -StopPath $stopPath `
                    -TimeoutSeconds $ScenarioTimeoutSeconds
                if ($null -eq $restartControl) {
                    throw 'Coordinator sent neither restart nor stop after quiesce'
                }
                if ([string]$restartControl.data.run_nonce -ne
                    $RunNonce.ToLowerInvariant()) {
                    throw 'Peer received post-quiesce control for another run'
                }
                if ($restartControl.kind -eq 'stop') {
                    if ([string]$restartControl.data.schema -ne
                            'ese.v91.i04-stop-command/v1' -or
                        [string]$restartControl.data.case_id -ne $caseId -or
                        [string]$restartControl.data.action -ne
                            'stop-and-restore') {
                        throw 'Peer received invalid stop after quiesce'
                    }
                    throw 'I04 coordinator stopped after peer quiesce'
                }
                $restart = $restartControl.data
                if ([string]$restart.schema -ne
                        'ese.v91.i04-restart-command/v1' -or
                    [string]$restart.case_id -ne $caseId -or
                    [string]$restart.action -ne
                        'restart-source-under-drop' -or
                    [string]$restart.candidate_commit -ne
                        $candidate.commit -or
                    [string]$restart.candidate_emule_sha256 -ne
                        $expectedHash -or
                    [int]$restart.expected_old_process_id -ne $oldPid -or
                    -not [bool]$restart.scheduler_floor_satisfied) {
                    throw 'Peer received an invalid restart barrier command'
                }
                $restartWatch = [Diagnostics.Stopwatch]::StartNew()
                $restarted = Start-PeerSource -RestartWatch $restartWatch `
                    -RequireEd2k -MinimumServerLogin 2
                $restartElapsedMs = [Int64]$restarted.listener_ready_elapsed_ms
                $restartWatch.Stop()
                $source = $restarted.process
                $newPid = $source.Id
                $sourceRuntimeResumed = $restarted.api
                $serverLoginResumed =
                    $restarted.controlled_server_login
                $sourceIdentityAfterRestart = Get-I04PersistedUserHash `
                    -NodePath $sourceNode
                $dualStackListenerReady = @($restarted.listeners |
                    Where-Object {
                        (Get-I04NormalizedIp -Address $_.LocalAddress) -eq '::'
                    }).Count -gt 0
                $dropEvidence = Get-I04FirewallRuleEvidence `
                    -DisplayName $dropRule -Action Block -Program $sourceExe `
                    -LocalAddresses @($peerV6Text) `
                    -RemoteAddresses @($coordinatorV6Text) `
                    -LocalPort $PeerTcpPort
                $allow4Evidence = Get-I04FirewallRuleEvidence `
                    -DisplayName $allow4Rule -Action Allow `
                    -Program $sourceExe `
                    -LocalAddresses @($peerLocalV4Text) `
                    -RemoteAddresses @($observedCoordinatorV4) `
                    -LocalPort $PeerTcpPort
                $allow6Evidence = Get-I04FirewallRuleEvidence `
                    -DisplayName $allow6Rule -Action Allow `
                    -Program $sourceExe `
                    -LocalAddresses @($peerV6Text) `
                    -RemoteAddresses @($coordinatorV6Text) `
                    -LocalPort $PeerTcpPort
                if ($newPid -eq $oldPid -or
                    (Get-LabSha256 -Path $source.Path) -ne $expectedHash -or
                    [string]$sourceIdentityAfterRestart.user_hash -ne
                        [string]$sourceIdentityInitial.user_hash -or
                    [string]$sourceRuntimeResumed.user_hash -ne
                        [string]$sourceIdentityInitial.user_hash -or
                    [string]$serverLoginResumed.runtime_user_hash -ne
                        [string]$sourceIdentityInitial.user_hash -or
                    [int]$serverLoginResumed.login_count -lt 2 -or
                    -not $dualStackListenerReady -or
                    -not $dropEvidence.exact -or
                    -not $allow4Evidence.exact -or
                    -not $allow6Evidence.exact) {
                    throw 'Restarted source failed PID/hash/identity/eD2K/listener/firewall verification'
                }
                Add-I04Journal -Path $journal -Mutation 'peer-process' `
                    -State 'applied' -Detail "new_pid=$newPid after DROP"
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i04-peer-resumed/v1'
                    case_id = $caseId
                    run_nonce = $RunNonce.ToLowerInvariant()
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $candidate.emule_sha256
                    resumed_at_utc = Get-LabUtcTimestamp
                    old_process_id = $oldPid
                    process_id = $newPid
                    process_emule_sha256 = Get-LabSha256 -Path $source.Path
                    stop_to_listener_ready_ms = $restartElapsedMs
                    restart_readiness_limit_ms = 90000
                    restart_within_readiness_limit =
                        $restartElapsedMs -le 90000
                    dual_stack_listener = $true
                    ipv4_capable_dual_stack_listener = $dualStackListenerReady
                    persisted_identity = $sourceIdentityAfterRestart
                    runtime_identity =
                        [string]$sourceRuntimeResumed.user_hash
                    runtime_isolation = $sourceRuntimeResumed
                    controlled_server_login = $serverLoginResumed
                    same_persisted_user_hash =
                        [string]$sourceIdentityAfterRestart.user_hash -eq
                            [string]$sourceIdentityInitial.user_hash
                    allow4_rule = $allow4Evidence
                    allow6_rule = $allow6Evidence
                    drop_rule = $dropEvidence
                }) -Path $resumedPath | Out-Null
                if ($restartElapsedMs -gt 90000) {
                    throw "Restart readiness exceeded 90 seconds: $restartElapsedMs ms"
                }

                $stop = Wait-I04StopWhileProcessAlive -StopPath $stopPath `
                    -TimeoutSeconds $ScenarioTimeoutSeconds -Process $source `
                    -ExpectedPath $sourceExe
                if ($null -eq $stop) {
                    throw 'Coordinator did not send the stop command within the bounded wait'
                }
                if ([string]$stop.run_nonce -ne $RunNonce.ToLowerInvariant()) {
                    throw 'Peer received a stop command for a different run'
                }
                if ([string]$stop.schema -ne
                        'ese.v91.i04-stop-command/v1' -or
                    [string]$stop.case_id -ne $caseId -or
                    [string]$stop.action -ne 'stop-and-restore' -or
                    [string]$stop.candidate_commit -ne $candidate.commit -or
                    [string]$stop.candidate_emule_sha256 -ne $expectedHash) {
                    throw 'Peer received an invalid final stop command'
                }
            }
        }
    } catch {
        $runtimeFailure = $_
    } finally {
        if ($null -ne $source -and -not (
            Stop-I04OwnedProcess -Process $source -ExpectedPath $sourceExe
        )) {
            $cleanupFailures.Add('peer source process could not be stopped safely')
        } elseif ($null -ne $source) {
            Add-I04RollbackJournal -Path $journal `
                -Mutation 'peer-process' -State 'rolled_back' `
                -Detail "pid=$($source.Id)" `
                -CleanupFailures $cleanupFailures
        }
        $controlledServerStop =
            Stop-I04ControlledEd2kServerInventory `
                -OwnerInventory $controlledServersOwned `
                -PrimaryServer $controlledServer
        if (-not [bool]$controlledServerStop.stopped -or
            [string]$controlledServerStop.error) {
            $cleanupFailures.Add(
                "peer controlled eD2K server cleanup failed: " +
                [string]$controlledServerStop.error
            )
        }
        if ($firewallNamesOwned) {
            foreach ($ownedRule in @(
                [pscustomobject]@{
                    name = $dropRuleName
                    display = $dropRule
                    mutation = 'peer-ipv6-silent-drop'
                },
                [pscustomobject]@{
                    name = $allow6RuleName
                    display = $allow6Rule
                    mutation = 'peer-firewall-allow6'
                },
                [pscustomobject]@{
                    name = $allow4RuleName
                    display = $allow4Rule
                    mutation = 'peer-firewall-allow4'
                }
            )) {
                try {
                    $existing = @(
                        Get-NetFirewallRule -PolicyStore ActiveStore `
                            -ErrorAction Stop | Where-Object {
                                [string]$_.Name -eq $ownedRule.name
                            }
                    )
                    if ($existing.Count -gt 0) {
                        Remove-NetFirewallRule -Name $ownedRule.name `
                            -ErrorAction Stop
                    }
                    $remaining = @(
                        Get-NetFirewallRule -PolicyStore ActiveStore `
                            -ErrorAction Stop | Where-Object {
                                [string]$_.Name -eq $ownedRule.name
                            }
                    )
                    if ($remaining.Count -ne 0) {
                        throw "firewall Name '$($ownedRule.name)' remains after removal"
                    }
                    Add-I04RollbackJournal -Path $journal `
                        -Mutation $ownedRule.mutation -State 'rolled_back' `
                        -Detail $ownedRule.display `
                        -CleanupFailures $cleanupFailures
                } catch {
                    $cleanupFailures.Add(
                        "firewall cleanup failed for '$($ownedRule.name)': $($_.Exception.Message)"
                    )
                }
            }
        }
    }

    try {
        $firewallAfter = @(
            Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop
        )
        $dropStillPresent = @($firewallAfter | Where-Object {
            [string]$_.Name -eq $dropRuleName
        }).Count -ne 0
        $allow4StillPresent = @($firewallAfter | Where-Object {
            [string]$_.Name -eq $allow4RuleName
        }).Count -ne 0
        $allow6StillPresent = @($firewallAfter | Where-Object {
            [string]$_.Name -eq $allow6RuleName
        }).Count -ne 0
    } catch {
        $dropStillPresent = $true
        $allow4StillPresent = $true
        $allow6StillPresent = $true
        $cleanupFailures.Add(
            "firewall absence could not be verified: $($_.Exception.Message)"
        )
    }
    if ($dropStillPresent) { $cleanupFailures.Add('DROP rule is still present') }
    if ($allow4StillPresent) {
        $cleanupFailures.Add('allow4 rule is still present')
    }
    if ($allow6StillPresent) {
        $cleanupFailures.Add('allow6 rule is still present')
    }
    $candidateAfter = Get-LabCandidateInfo -PackagePath $PackagePath `
        -ExpectedCommit $Commit
    if ($candidateAfter.emule_sha256 -ne $expectedHash) {
        $cleanupFailures.Add('peer candidate package changed during execution')
    }
    $peerIsolationFinal = Get-I04IsolationEvidence
    Write-LabJson -Value $peerIsolationFinal -Path (
        Join-Path $evidence 'peer-isolation-final.json'
    ) | Out-Null
    if (-not [bool]$peerIsolationFinal.strict_isolation_valid) {
        $cleanupFailures.Add(
            'peer overlay/VPN/proxy isolation was not intact at final audit'
        )
    }
    $cleanup = [ordered]@{
        schema = 'ese.v91.i04-peer-cleanup/v1'
        captured_at_utc = Get-LabUtcTimestamp
        source_process_stopped = if ($null -eq $source) {
            $true
        } else {
            $null -eq (Get-Process -Id $source.Id -ErrorAction SilentlyContinue)
        }
        drop_rule_present = $dropStillPresent
        allow4_rule_present = $allow4StillPresent
        allow6_rule_present = $allow6StillPresent
        controlled_ed2k_server_stopped =
            $null -ne $controlledServerStop -and
            [bool]$controlledServerStop.stopped -and
            -not [string]$controlledServerStop.error
        hosts_file_modified = $false
        dns_cache_modified = $false
        routes_modified = $false
        adapters_modified = $false
        isolation_initial = $peerIsolationInitial
        isolation_final = $peerIsolationFinal
        retained_by_design = @('peer OutputRoot profile', 'fixture', 'evidence')
        failures = @($cleanupFailures)
    }
    Write-LabJson -Value $cleanup -Path $cleanupPath | Out-Null
    $peerResult = [ordered]@{
        schema = 'ese.v91.i04-peer-result/v1'
        case_id = $caseId
        run_nonce = $RunNonce.ToLowerInvariant()
        finished_at_utc = Get-LabUtcTimestamp
        status = if ($null -eq $runtimeFailure -and
            $cleanupFailures.Count -eq 0 -and -not $dropStillPresent -and
            -not $allow4StillPresent -and
            -not $allow6StillPresent) { 'COMPLETE' } else { 'BLOCKED' }
        candidate_commit = $candidate.commit
        candidate_emule_sha256 = $candidate.emule_sha256
        old_process_id = $oldPid
        restarted_process_id = $newPid
        restart_stop_to_listener_ready_ms = $restartElapsedMs
        barrier_completed = $null -ne $newPid -and
            $null -ne $restartElapsedMs -and
            $restartElapsedMs -le 90000 -and
            $null -ne $serverLoginResumed -and
            [int]$serverLoginResumed.login_count -ge 2
        controlled_ed2k_server = $controlledServerStop
        remote_ipv6_drop_was_armed = $null -ne $armedAt
        drop_armed_at_utc = if ($null -eq $armedAt) {
            $null
        } else { $armedAt.ToString('o') }
        cleanup = $cleanup
        runtime_error = if ($null -eq $runtimeFailure) {
            $null
        } else { $runtimeFailure.Exception.Message }
        evidence_root = $output
    }
    Write-LabJson -Value $peerResult -Path $resultPath | Out-Null
    Write-LabJson -Value $peerResult `
        -Path (Join-Path $evidence 'peer-result.json') | Out-Null
    $password = $null

    if ($peerResult.status -ne 'COMPLETE') {
        throw "I04 peer phase is BLOCKED: $($peerResult.runtime_error)"
    }
    Write-Host "I04 peer phase complete and restored: $output" `
        -ForegroundColor Green
}

function Invoke-I04CoordinatorRole {
    if (-not (Test-I04Administrator)) {
        throw 'Coordinator role requires an elevated Administrator PowerShell for pktmon capture'
    }
    foreach ($captureCommand in @('pktmon.exe', 'logman.exe')) {
        if ($null -eq (Get-Command $captureCommand -ErrorAction SilentlyContinue)) {
            throw "Coordinator capture prerequisite is missing: $captureCommand"
        }
    }
    $existingPktmonSession = @(& logman.exe query -ets PktMon 2>&1)
    $existingPktmonExit = $LASTEXITCODE
    if ($existingPktmonExit -eq 0) {
        throw 'Coordinator found an existing PktMon ETW session; stop its owner before V91-I04'
    }
    if (-not $RunNonce) {
        $script:RunNonce = [Guid]::NewGuid().ToString('N')
    }
    $nonce = $RunNonce.ToLowerInvariant()
    $outputPath = Get-LabFullPath -Path $OutputRoot
    if (Test-Path -LiteralPath $outputPath) {
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Coordinator OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $captureEvidence = New-LabDirectory -Path (Join-Path $evidence 'capture')
    $journal = Join-Path $evidence 'mutation-journal.jsonl'
    $samplesPath = Join-Path $evidence 'runtime-samples.jsonl'
    $socketSamplesPath = Join-Path $evidence 'socket-samples.ndjson'
    $summaryPath = Join-Path $evidence 'summary.json'
    $cleanupPath = Join-Path $evidence 'cleanup.json'
    $coordination = Get-LabFullPath -Path (Join-Path `
        -Path (Get-LabFullPath -Path $CoordinationRoot) `
        -ChildPath "v91-i04-$nonce")
    if (Test-Path -LiteralPath $coordination) {
        throw "Coordinator run directory must be fresh/absent: $coordination"
    }
    $coordinationParent = Split-Path -Parent $coordination
    $null = New-LabDirectory -Path $coordinationParent
    $null = New-Item -ItemType Directory -Path $coordination -ErrorAction Stop
    $runPath = Join-Path $coordination 'run.json'
    $readyPath = Join-Path $coordination 'peer-ready.json'
    $armPath = Join-Path $coordination 'arm-drop.json'
    $armedPath = Join-Path $coordination 'peer-drop-armed.json'
    $quiescePath = Join-Path $coordination 'quiesce.json'
    $quiescedPath = Join-Path $coordination 'peer-quiesced.json'
    $restartPath = Join-Path $coordination 'restart.json'
    $resumedPath = Join-Path $coordination 'peer-resumed.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $peerResultPath = Join-Path $coordination 'peer-result.json'
    $manualPath = Join-Path $evidence 'MANUAL-PEER-COMMAND.txt'

    $client = $null
    $clientOwnedProcesses =
        New-Object 'Collections.Generic.List[object]'
    $clientProcessesStopped = $false
    $clientPassword = 'v91-i04-client'
    $clientNode = ''
    $clientExe = ''
    $clientControlledServer = $null
    $clientControlledServersOwned =
        New-Object 'Collections.Generic.List[object]'
    $clientControlledServerStop = $null
    $clientIdentity = $null
    $clientRuntime = $null
    $clientServerLogin = $null
    $clientSession = ''
    $capture = $null
    $socketSampler = $null
    $socketSamplerEvidence = $null
    $remoteJob = $null
    $runtimeFailure = $null
    $candidatePostTriggerFailure = ''
    $caseArmed = $false
    $formalBoundaryPublished = $false
    $cleanupFailures = New-Object 'Collections.Generic.List[string]'
    $blockedReasons = New-Object 'Collections.Generic.List[string]'
    $productFailures = New-Object 'Collections.Generic.List[string]'
    $peerReady = $null
    $peerArmed = $null
    $peerResumed = $null
    $peerResult = $null
    $peerReadyExact = $false
    $peerArmedExact = $false
    $peerResumedExact = $false
    $peerResultExact = $false
    $peerRestorationExact = $false
    $peerExact = $false
    $baselineV4 = $null
    $baselineV6 = $null
    $routeV4 = $null
    $routeV6 = $null
    $packetVerdict = $null
    $logBefore = $null
    $logAfter = $null
    $armCommandWritten = $false
    $stopCommandWritten = $false
    $prewarmEstablished = $false
    $prewarmProgress = $false
    $prewarmFirstEstablishedAt = $null
    $prewarmFirstEstablishedEpochMs = $null
    $schedulerFloorSatisfied = $false
    $fileAPreProgress = $null
    $fileAProgress = $null
    $fileBReady = $null
    $fileAPaused = $null
    $fileAStopped = $null
    $fileBAfterTrigger = $null
    $pauseOperation = $null
    $stopAOperation = $null
    $prewarmTuples = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    $scenarioV4LocalPorts = New-Object 'Collections.Generic.HashSet[int]'
    $scenarioV6LocalPorts = New-Object 'Collections.Generic.HashSet[int]'
    $otherPidObserved = $false
    $otherPidConnections = New-Object 'Collections.Generic.List[object]'
    $scenarioV6SocketObserved = $false
    $scenarioV4SocketObserved = $false
    $scenarioV4Established = $false
    $apiProbeCount = 0
    $apiFailureCount = 0
    $apiMaxMs = 0L
    $uiProbeCount = 0
    $uiMissingCount = 0
    $uiFailureCount = 0
    $uiMaxMs = 0L
    $scenarioStarted = $null
    $scenarioFinished = $null
    $successObservedAt = $null
    $armRequestedEpochMs = $null
    $armRequestedQpc = $null
    $pauseBoundaryEpochMs = $null
    $pauseBoundaryQpc = $null
    $restartPreparationAt = $null
    $restartPreparationEpochMs = $null
    $restartPreparationQpc = $null
    $restartBoundaryEpochMs = $null
    $restartBoundaryQpc = $null
    $captureStoppedEpochMs = $null
    $apiTelemetryBaseline = $null
    $apiTelemetryTrigger = $null
    $apiTelemetryPeak = $null
    $apiTelemetryFinal = $null
    $telemetryObservedCurrentMax = 0L
    $telemetryObservedAddsMax = $null
    $telemetryObservedDuplicateMax = $null
    $telemetryObservedHighWaterMax = $null
    $clientIsolationExact = $false
    $coordinatorIsolationInitial = $null
    $coordinatorIsolationFinal = $null

    $localMachineId = Get-I04MachineId
    $coordinatorIsolationInitial = Get-I04IsolationEvidence
    Write-LabJson -Value $coordinatorIsolationInitial -Path (
        Join-Path $evidence 'coordinator-isolation-initial.json'
    ) | Out-Null
    if (-not [bool]$coordinatorIsolationInitial.strict_isolation_valid) {
        throw 'Coordinator has an active overlay/VPN adapter or proxy environment'
    }
    $routeV4 = Get-I04RouteEvidence -RemoteAddress $peerV4Text
    $routeV6 = Get-I04RouteEvidence -RemoteAddress $peerV6Text
    if (-not $routeV4.available -or -not $routeV6.available -or
        -not [bool]$routeV4.physical_nonvirtual -or
        -not [bool]$routeV6.physical_nonvirtual) {
        throw 'Coordinator cannot derive native physical IPv4 and IPv6 routes to the peer'
    }
    $coordinatorV4Value = if ([string]::IsNullOrWhiteSpace($CoordinatorIPv4)) {
        [string]$routeV4.source_address
    } else { $CoordinatorIPv4 }
    $coordinatorV6Value = if ([string]::IsNullOrWhiteSpace($CoordinatorIPv6)) {
        [string]$routeV6.source_address
    } else { $CoordinatorIPv6 }
    $coordinatorV4Address = Convert-I04RequiredAddress `
        -Value $coordinatorV4Value `
        -AddressFamily ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'CoordinatorIPv4'
    $coordinatorV6Address = Convert-I04RequiredAddress `
        -Value $coordinatorV6Value `
        -AddressFamily ([Net.Sockets.AddressFamily]::InterNetworkV6) `
        -Name 'CoordinatorIPv6'
    $coordinatorV4Text = $coordinatorV4Address.ToString()
    $coordinatorV6Text = $coordinatorV6Address.ToString()
    if ($coordinatorV4Address.Equals([Net.IPAddress]::Any) -or
        [Net.IPAddress]::IsLoopback($coordinatorV4Address) -or
        ($coordinatorV4Address.GetAddressBytes()[0] -ge 224 -and
            $coordinatorV4Address.GetAddressBytes()[0] -le 239) -or
        $coordinatorV6Address.Equals([Net.IPAddress]::IPv6Any) -or
        [Net.IPAddress]::IsLoopback($coordinatorV6Address) -or
        $coordinatorV6Address.IsIPv6Multicast -or
        (Get-LabAddressClass -Address $coordinatorV6Text) -ne 'global-v6' -or
        $coordinatorV4Text -eq $peerV4Text -or
        $coordinatorV6Text -eq $peerV6Text -or
        (Get-I04NormalizedIp -Address $routeV4.source_address) -ne
            $coordinatorV4Text -or
        (Get-I04NormalizedIp -Address $routeV6.source_address) -ne
            $coordinatorV6Text) {
        throw 'Coordinator source addresses must be exact non-loopback route sources distinct from the peer'
    }
    $coordinatorAssignedV4 = Get-NetIPAddress -AddressFamily IPv4 `
        -ErrorAction SilentlyContinue | Where-Object {
            (Get-I04NormalizedIp -Address $_.IPAddress) -eq
                $coordinatorV4Text -and $_.AddressState -eq 'Preferred'
        } | Select-Object -First 1
    $coordinatorAssignedV6 = Get-NetIPAddress -AddressFamily IPv6 `
        -ErrorAction SilentlyContinue | Where-Object {
            (Get-I04NormalizedIp -Address $_.IPAddress) -eq
                $coordinatorV6Text -and $_.AddressState -eq 'Preferred'
        } | Select-Object -First 1
    if ($null -eq $coordinatorAssignedV4 -or
        $null -eq $coordinatorAssignedV6 -or
        [int]$coordinatorAssignedV4.InterfaceIndex -ne
            [int]$coordinatorAssignedV6.InterfaceIndex) {
        throw 'Coordinator route sources must be Preferred addresses on one adapter'
    }
    $coordinatorAdapter = Get-NetAdapter `
        -InterfaceIndex $coordinatorAssignedV4.InterfaceIndex -ErrorAction Stop
    $coordinatorAdapterVirtual = $false
    if ($coordinatorAdapter.PSObject.Properties.Name -contains 'Virtual') {
        $coordinatorAdapterVirtual = [bool]$coordinatorAdapter.Virtual
    }
    $coordinatorAdapterOverlayLike =
        ([string]$coordinatorAdapter.Name) -match $overlayPattern -or
        ([string]$coordinatorAdapter.InterfaceDescription) -match
            $overlayPattern
    $coordinatorPhysical = [bool]$coordinatorAdapter.HardwareInterface -and
        -not $coordinatorAdapterVirtual -and
        -not $coordinatorAdapterOverlayLike -and
        ([string]$coordinatorAdapter.Status) -eq 'Up'
    if (-not $coordinatorPhysical) {
        throw 'Coordinator dual-stack data plane is not one Up physical, non-overlay adapter'
    }

    Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i04-run/v1'
        case_id = $caseId
        run_nonce = $nonce
        created_at_utc = Get-LabUtcTimestamp
        expected_candidate_commit = $candidate.commit
        expected_emule_sha256 = $expectedHash
        peer = [ordered]@{
            hostname = $canonicalHostname
            ipv4 = $peerV4Text
            local_ipv4 = $peerLocalV4Text
            ipv6 = $peerV6Text
            tcp_port = $PeerTcpPort
            udp_port = $PeerUdpPort
            web_port = $PeerWebPort
        }
        client = [ordered]@{
            tcp_port = $ClientTcpPort
            udp_port = $ClientUdpPort
            web_port = $ClientWebPort
        }
        coordinator = [ordered]@{
            ipv4 = $coordinatorV4Text
            ipv6 = $coordinatorV6Text
            interface_index = [int]$coordinatorAssignedV4.InterfaceIndex
            physical = $coordinatorPhysical
            isolation = $coordinatorIsolationInitial
        }
        file_size_bytes = $FileSizeBytes
        file_b_size_bytes = $fileBSizeBytes
        scheduler_reconnect_floor_seconds =
            $schedulerReconnectFloorSeconds
        fallback_limit_seconds = $FallbackLimitSeconds
        expected_fallback_delay_ms = $expectedFallbackDelayMs
        capture_tolerance_ms = $captureTimingToleranceMs
        socket_clock_coherence_tolerance_ms =
            $socketClockCoherenceToleranceMs
        control_mode = $PeerControlMode
    }) -Path $runPath | Out-Null

    Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i04-pre-mutation/v1'
        captured_at_utc = Get-LabUtcTimestamp
        candidate = $candidate
        local_machine_id_sha256 = $localMachineId
        routes = @($routeV4, $routeV6)
        coordinator = [ordered]@{
            ipv4 = $coordinatorV4Text
            ipv6 = $coordinatorV6Text
            same_interface = [int]$coordinatorAssignedV4.InterfaceIndex -eq
                [int]$coordinatorAssignedV6.InterfaceIndex
            interface_status = [string]$coordinatorAdapter.Status
            hardware_interface = [bool]$coordinatorAdapter.HardwareInterface
            virtual = $coordinatorAdapterVirtual
            overlay_or_vpn_like = $coordinatorAdapterOverlayLike
            physical = $coordinatorPhysical
            isolation = $coordinatorIsolationInitial
        }
        existing_target_processes = @(
            Get-Process -Name emule -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [pscustomobject]@{
                        id = $_.Id
                        path_sha256 = try {
                            Get-LabStringSha256 -Value $_.Path
                        } catch { '' }
                    }
                }
        )
        planned_mutations = @(
            'isolated client profile/process',
            'unique pktmon filters/global capture',
            'remote unique allow and IPv6 inbound Block rules',
            'remote controlled source restart'
        )
        forbidden_and_not_planned = @(
            'hosts file', 'DNS cache', 'routes', 'adapters',
            'test-only product endpoint', 'local IPv6 reject rule'
        )
    }) -Path (Join-Path $evidence 'pre-mutation.json') | Out-Null

    try {
        if ($PeerControlMode -eq 'PowerShellRemoting') {
            foreach ($required in @(
                $PeerComputerName, $RemoteScriptPath, $RemotePackagePath,
                $RemoteOutputRoot, $RemoteCoordinationRoot
            )) {
                if ([string]::IsNullOrWhiteSpace($required)) {
                    throw 'PowerShellRemoting requires PeerComputerName, RemoteScriptPath, RemotePackagePath, RemoteOutputRoot and RemoteCoordinationRoot'
                }
            }
            $remoteArguments = @{
                Role = 'Peer'
                PackagePath = $RemotePackagePath
                OutputRoot = $RemoteOutputRoot
                Commit = $candidate.commit
                ExpectedEmuleSha256 = $expectedHash
                PeerHostname = $canonicalHostname
                PeerIPv4 = $peerV4Text
                PeerLocalIPv4 = $peerLocalV4Text
                PeerIPv6 = $peerV6Text
                CoordinatorIPv4 = $coordinatorV4Text
                CoordinatorIPv6 = $coordinatorV6Text
                CoordinationRoot = $RemoteCoordinationRoot
                ControlledPeerAcknowledged = $true
                PeerTcpPort = $PeerTcpPort
                PeerUdpPort = $PeerUdpPort
                PeerWebPort = $PeerWebPort
                ClientTcpPort = $ClientTcpPort
                ClientUdpPort = $ClientUdpPort
                ClientWebPort = $ClientWebPort
                FileSizeBytes = $FileSizeBytes
                PeerReadyTimeoutSeconds = $PeerReadyTimeoutSeconds
                ScenarioTimeoutSeconds = $ScenarioTimeoutSeconds
                FallbackLimitSeconds = $FallbackLimitSeconds
                RunNonce = $nonce
            }
            $invoke = @{
                ComputerName = $PeerComputerName
                AsJob = $true
                ScriptBlock = {
                    param($ScriptPath, $ArgumentMap)
                    & $ScriptPath @ArgumentMap
                }
                ArgumentList = @($RemoteScriptPath, $remoteArguments)
            }
            if ($null -ne $PeerCredential) {
                $invoke.Credential = $PeerCredential
            }
            $remoteJob = Invoke-Command @invoke
        } else {
            $manualCommand = @"
Run this on the controlled physical peer while this coordinator waits:

& '$PSCommandPath' ``
  -Role Peer ``
  -PackagePath '<exact-package-on-peer>' ``
  -OutputRoot '<new-empty-peer-output-root>' ``
  -Commit '$($candidate.commit)' ``
  -ExpectedEmuleSha256 '$expectedHash' ``
  -PeerHostname '$canonicalHostname' ``
  -PeerIPv4 '$peerV4Text' ``
  -PeerLocalIPv4 '$peerLocalV4Text' ``
  -PeerIPv6 '$peerV6Text' ``
  -CoordinatorIPv4 '$coordinatorV4Text' ``
  -CoordinatorIPv6 '$coordinatorV6Text' ``
  -CoordinationRoot '$CoordinationRoot' ``
  -ControlledPeerAcknowledged ``
  -PeerTcpPort $PeerTcpPort -PeerUdpPort $PeerUdpPort -PeerWebPort $PeerWebPort ``
  -ClientTcpPort $ClientTcpPort -ClientUdpPort $ClientUdpPort -ClientWebPort $ClientWebPort ``
  -FileSizeBytes $FileSizeBytes ``
  -FallbackLimitSeconds $FallbackLimitSeconds ``
  -ScenarioTimeoutSeconds $ScenarioTimeoutSeconds ``
  -RunNonce '$nonce'

The coordination root must identify the same shared directory from both hosts.
Do not create a local REJECT/RST rule: Peer role creates an inbound IPv6 Block
on the remote peer and restores it transactionally.
"@
            Write-LabText -Value $manualCommand -Path $manualPath | Out-Null
            Write-Host $manualCommand -ForegroundColor Yellow
        }

        $peerReady = Wait-I04File -Path $readyPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $peerReady) {
            $blockedReasons.Add(
                "Peer phase did not publish peer-ready.json within $PeerReadyTimeoutSeconds seconds"
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value $peerReady `
            -Path (Join-Path $evidence 'peer-ready.json') | Out-Null
        $peerReadyExact =
            [string]$peerReady.schema -eq 'ese.v91.i04-peer-ready/v1' -and
            [string]$peerReady.case_id -eq $caseId -and
            [string]$peerReady.run_nonce -eq $nonce -and
            [string]$peerReady.candidate.commit -eq $candidate.commit -and
            [string]$peerReady.candidate.emule_sha256 -eq $expectedHash -and
            [string]$peerReady.candidate.process_emule_sha256 -eq
                $expectedHash -and
            [bool]$peerReady.peer.physical -and
            [bool]$peerReady.peer.same_interface -and
            -not [bool]$peerReady.peer.overlay_or_vpn_like -and
            [bool]$peerReady.peer.isolation.strict_isolation_valid -and
            [bool]$peerReady.peer.route_to_coordinator_ipv6.available -and
            [bool]$peerReady.peer.route_to_coordinator_ipv6.
                physical_nonvirtual -and
            [int]$peerReady.peer.route_to_coordinator_ipv6.interface_index -eq
                [int]$peerReady.peer.ipv6_interface_index -and
            [string]$peerReady.peer.route_to_coordinator_ipv6.source_address -eq
                $peerV6Text -and
            [string]$peerReady.endpoint.ipv4 -eq $peerV4Text -and
            [string]$peerReady.endpoint.local_ipv4 -eq $peerLocalV4Text -and
            [string]$peerReady.endpoint.ipv6 -eq $peerV6Text -and
            [int]$peerReady.endpoint.tcp_port -eq $PeerTcpPort -and
            [string]$peerReady.coordinator.ipv4 -eq $coordinatorV4Text -and
            [string]$peerReady.coordinator.ipv6 -eq $coordinatorV6Text -and
            [bool]$peerReady.endpoint.dual_stack_listener -and
            [bool]$peerReady.endpoint.hello_ipv6_advertisement_configured -and
            [int]$peerReady.process.id -gt 0 -and
            [string]$peerReady.process.executable_sha256 -eq $expectedHash -and
            [string]$peerReady.process.source_mode -eq 'non-headless' -and
            [string]$peerReady.process.persisted_identity.user_hash -match
                '^[0-9A-F]{32}$' -and
            [string]$peerReady.process.persisted_identity.source_mode -eq
                'non-headless persisted preferences.dat identity' -and
            [string]$peerReady.process.runtime_identity -eq
                [string]$peerReady.process.persisted_identity.user_hash -and
            [string]$peerReady.process.controlled_server_login.runtime_user_hash -eq
                [string]$peerReady.process.persisted_identity.user_hash -and
            [int]$peerReady.process.controlled_server_login.login_count -eq 1 -and
            [string]$peerReady.fixtures.a.name -eq
                "v91-i04-$nonce-a.bin" -and
            [Int64]$peerReady.fixtures.a.bytes -eq $FileSizeBytes -and
            [string]$peerReady.fixtures.a.sha256 -match
                '^[0-9a-fA-F]{64}$' -and
            [string]$peerReady.fixtures.b.name -eq
                "v91-i04-$nonce-b.bin" -and
            [Int64]$peerReady.fixtures.b.bytes -eq $fileBSizeBytes -and
            [string]$peerReady.fixtures.b.sha256 -match
                '^[0-9a-fA-F]{64}$' -and
            [bool]$peerReady.fixtures.unique_sha256 -and
            [string]$peerReady.ed2k.a.hash -match
                '^[0-9a-fA-F]{32}$' -and
            [string]$peerReady.ed2k.b.hash -match
                '^[0-9a-fA-F]{32}$' -and
            [bool]$peerReady.ed2k.unique_hash -and
            [string]$peerReady.ed2k.a.base_link -match
                ('^ed2k://\|file\|' +
                    [regex]::Escape("v91-i04-$nonce-a.bin") + '\|' +
                    $FileSizeBytes + '\|') -and
            [string]$peerReady.ed2k.b.base_link -match
                ('^ed2k://\|file\|' +
                    [regex]::Escape("v91-i04-$nonce-b.bin") + '\|' +
                    $fileBSizeBytes + '\|') -and
            [bool]$peerReady.controls.allow4_rule_provisional.exact -and
            [bool]$peerReady.controls.allow6_rule.exact -and
            (Test-I04ApiIsolation -Data $peerReady.runtime_isolation `
                -RequireEd2k $true)
        if (-not $peerReadyExact) {
            $blockedReasons.Add('Peer identity is not the exact candidate/run')
            throw 'I04_FIXTURE_BLOCKED'
        }
        if ([string]$peerReady.peer.machine_id_sha256 -eq $localMachineId) {
            $blockedReasons.Add(
                'Peer and coordinator are the same Windows host; direct T1/T2 requires two physical hosts'
            )
        }
        if (-not [bool]$peerReady.peer.physical -or
            -not [bool]$peerReady.peer.same_interface) {
            $blockedReasons.Add('Peer endpoint is not backed by a physical interface')
        }
        if (-not [bool]$peerReady.endpoint.dual_stack_listener -or
            -not [bool]$peerReady.endpoint.hello_ipv6_advertisement_configured) {
            $blockedReasons.Add('Peer did not prove a real dual-stack listener/HELLO configuration')
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-dns-scope/v1'
            captured_at_utc = Get-LabUtcTimestamp
            status = 'NOT_IN_SCOPE_V91_D01'
            hostname = $canonicalHostname
            note = 'I04 uses literal controlled peer addresses; DNS retention/order is adjudicated by V91-D01'
        }) -Path (Join-Path $evidence 'dns-scope.json') | Out-Null

        $baselineV4 = Test-I04TcpEndpoint -Address $peerV4Address `
            -Port $PeerTcpPort
        $baselineV6 = Test-I04TcpEndpoint -Address $peerV6Address `
            -Port $PeerTcpPort
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-baseline-reachability/v1'
            IPv4 = $baselineV4
            IPv6 = $baselineV6
        }) -Path (Join-Path $evidence 'baseline-reachability.json') | Out-Null
        if (-not $baselineV4.connected -or -not $baselineV6.connected) {
            $blockedReasons.Add(
                'Literal IPv4 and IPv6 must both reach the real peer before DROP'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        Start-Sleep -Seconds 1

        $offset = $ClientTcpPort - 4662
        if (($ClientUdpPort - 4672) -ne $offset -or
            ($ClientWebPort - 4711) -ne $offset) {
            throw 'Client TCP/UDP/Web ports must share the standard 4662/4672/4711 offset'
        }
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
            -SourcePackage $candidate.package_path -OutputRoot $nodes `
            -RunId 'v91-i04-client' -PortOffset $offset
        $clientNode = Join-Path $nodes 'v91-i04-client-b'
        $clientExe = Join-Path $clientNode 'emule.exe'
        if ((Get-LabSha256 -Path $clientExe) -ne $expectedHash) {
            throw 'Prepared client node is not the exact candidate binary'
        }
        $incoming = New-LabDirectory -Path (Join-Path $clientNode 'Incoming')
        $temp = New-LabDirectory -Path (Join-Path $clientNode 'Temp')
        $clientIsolation = Set-I04IsolatedPreferences `
            -NodePath $clientNode -IPv6Mode 2 `
            -IPv6BindAddress $coordinatorV6Text `
            -WebPort $ClientWebPort -Password $clientPassword `
            -IncomingPath $incoming -TempPath $temp
        if (-not $clientIsolation.preferences_dat_absent_before_start -or
            -not $clientIsolation.cryptkey_dat_absent_before_start) {
            throw 'Client profile inherited identity state'
        }

        function Start-ClientSource {
            $process = $null
            try {
                $process = Start-Process -FilePath $clientExe `
                    -ArgumentList @(
                        '--portable', '--ignoreinstances',
                        "--metrics-port=$ClientWebPort",
                        "--tcp-port=$ClientTcpPort",
                        "--udp-port=$ClientUdpPort"
                    ) -WorkingDirectory $clientNode -PassThru `
                    -WindowStyle Hidden
                $clientOwnedProcesses.Add($process)
                Wait-I04Api -Port $ClientWebPort -Process $process |
                    Out-Null
                Wait-I04Listener -Port $ClientTcpPort -Process $process |
                    Out-Null
                return $process
            } catch {
                # The caller cannot receive $process when startup validation
                # throws. Keep it in clientOwnedProcesses and make a best
                # effort here; the outer finally retries and certifies every
                # PID before cleanup can be reported complete.
                if ($null -ne $process) {
                    $null = Stop-I04OwnedProcess -Process $process `
                        -ExpectedPath $clientExe
                }
                throw
            }
        }

        # Create a genuinely fresh, persisted identity with both discovery
        # networks disabled, then stop normally before enabling the private
        # controlled eD2K server.
        $client = Start-ClientSource
        Add-I04Journal -Path $journal `
            -Mutation 'client-identity-init-process' `
            -State 'applied' -Detail "pid=$($client.Id)"
        $bootstrapApi = Get-I04ApiProbe -Port $ClientWebPort
        if (-not (Test-I04ApiIsolation -Data $bootstrapApi `
            -RequireEd2k $false)) {
            throw 'Client identity bootstrap violated isolation gates'
        }
        if (-not (Stop-I04OwnedProcess -Process $client `
            -ExpectedPath $clientExe -RequireGraceful)) {
            throw 'Client identity initialization did not stop gracefully'
        }
        Add-I04Journal -Path $journal `
            -Mutation 'client-identity-init-process' `
            -State 'rolled_back' -Detail "pid=$($client.Id)"
        $client = $null
        $clientIdentity = Get-I04PersistedUserHash -NodePath $clientNode

        $clientControlledServer = Start-I04ControlledEd2kServer `
            -EvidencePath (
                Join-Path $evidence 'client-controlled-ed2k-server.json'
            ) -ListenAddress $coordinatorV4Text `
            -ExpectedClientAddress $coordinatorV4Text `
            -HighIdAddress $coordinatorV4Text `
            -RunNonce $nonce -OwnerRole 'coordinator' `
            -OwnerInventory $clientControlledServersOwned
        $clientControlledProfile = Enable-I04ControlledEd2kProfile `
            -NodePath $clientNode -ServerAddress $coordinatorV4Text `
            -ServerPort $clientControlledServer.port `
            -RunNonce $nonce -OwnerRole 'coordinator'

        $client = Start-ClientSource
        Add-I04Journal -Path $journal -Mutation 'client-process' `
            -State 'applied' -Detail "pid=$($client.Id)"
        $clientServerLogin = Wait-I04ControlledEd2kLogin `
            -Server $clientControlledServer -Process $client `
            -ExpectedTcpPort $ClientTcpPort -MinimumLoginCount 1 `
            -TimeoutSeconds 90
        $apiDeadline = [DateTime]::UtcNow.AddSeconds(90)
        do {
            $clientRuntime = Get-I04ApiProbe -Port $ClientWebPort
            if (Test-I04ApiIsolation -Data $clientRuntime `
                -RequireEd2k $true) {
                break
            }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $apiDeadline)
        $clientIsolationExact = Test-I04ApiIsolation `
            -Data $clientRuntime -RequireEd2k $true
        if (-not $clientIsolationExact -or
            [string]$clientIdentity.user_hash -ne
                [string]$clientRuntime.user_hash -or
            [string]$clientIdentity.user_hash -ne
                [string]$clientServerLogin.runtime_user_hash -or
            [string]$clientIdentity.user_hash -eq
                [string]$peerReady.process.persisted_identity.user_hash) {
            throw 'Client runtime/server identity is invalid or not independent from peer'
        }
        $clientSession = Get-I04ClassicSession `
            -Port $ClientWebPort -Password $clientPassword

        # A starts from a literal public IPv4 source.  Its genuine HELLOANSWER
        # teaches this same CUpDownClient the peer IPv6/DUALSTACK identity.
        # B is then injected with that same source while A owns it, producing
        # the ordinary A4AF relationship used by StopFile/RemoveAllSources.
        $directLinkA = [string]$peerReady.ed2k.a.base_link +
            "|sources,$peerV4Text`:$PeerTcpPort|/"
        Send-I04Ed2kLink -Process $client `
            -Link ([string]$peerReady.ed2k.a.base_link)
        $aRowDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $fileAPreProgress = Get-I04TransferSnapshot `
                -Port $ClientWebPort -Session $clientSession `
                -FileHash ([string]$peerReady.ed2k.a.hash)
            if ([bool]$fileAPreProgress.found) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $aRowDeadline)
        if (-not [bool]$fileAPreProgress.found -or
            [bool]$fileAPreProgress.transferred_nonzero) {
            throw 'File A did not begin as an untransferred Classic Web row'
        }
        Send-I04Ed2kLink -Process $client -Link $directLinkA
        $prewarmDeadline = [DateTime]::UtcNow.AddMinutes(5)
        do {
            $client.Refresh()
            if ($client.HasExited) { throw 'Client exited during peer prewarm' }
            $connections = @(
                Get-NetTCPConnection -OwningProcess $client.Id `
                    -ErrorAction SilentlyContinue | Where-Object {
                        $_.RemotePort -eq $PeerTcpPort -and
                        (Get-I04NormalizedIp -Address $_.RemoteAddress) -eq
                            $peerV4Text
                    }
            )
            if (@($connections |
                Where-Object State -eq 'Established').Count -gt 0) {
                if (-not $prewarmEstablished) {
                    $prewarmFirstEstablishedAt = [DateTimeOffset]::UtcNow
                    $prewarmFirstEstablishedEpochMs =
                        Get-I04EpochMilliseconds `
                            -Timestamp $prewarmFirstEstablishedAt
                }
                $prewarmEstablished = $true
            }
            $fileAProgress = Get-I04TransferSnapshot `
                -Port $ClientWebPort -Session $clientSession `
                -FileHash ([string]$peerReady.ed2k.a.hash)
            $prewarmProgress = [bool]$fileAProgress.found -and
                [bool]$fileAProgress.transferred_nonzero
            if ($prewarmEstablished -and $prewarmProgress) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $prewarmDeadline)
        if (-not $prewarmEstablished -or -not $prewarmProgress) {
            $blockedReasons.Add('Real IPv4 prewarm did not establish and advance data')
            throw 'I04_FIXTURE_BLOCKED'
        }
        $prewarmConnectionEvidence = @(
            $connections | Where-Object State -eq 'Established' |
                ForEach-Object {
                    $local = Get-I04NormalizedIp -Address $_.LocalAddress
                    $remote = Get-I04NormalizedIp -Address $_.RemoteAddress
                    $tupleKey = Get-I04TupleKey -Family 'IPv4' `
                        -LocalAddress $local -LocalPort ([int]$_.LocalPort) `
                        -RemoteAddress $remote -RemotePort ([int]$_.RemotePort)
                    $null = $prewarmTuples.Add($tupleKey)
                    [pscustomobject][ordered]@{
                        owning_process = [int]$_.OwningProcess
                        state = [string]$_.State
                        local_address = $local
                        local_port = [int]$_.LocalPort
                        remote_address = $remote
                        remote_port = [int]$_.RemotePort
                        tuple_key = $tupleKey
                    }
                }
        )
        if ($prewarmTuples.Count -eq 0) {
            $blockedReasons.Add('Established prewarm tuple could not be frozen')
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-prewarm-tuples/v1'
            captured_at_utc = Get-LabUtcTimestamp
            client_process_id = $client.Id
            first_established_at_utc =
                $prewarmFirstEstablishedAt.ToString('o')
            first_established_epoch_ms =
                $prewarmFirstEstablishedEpochMs
            classic_web_before = $fileAPreProgress
            classic_web_progress = $fileAProgress
            tuples = $prewarmConnectionEvidence
        }) -Path (Join-Path $evidence 'prewarm-tuples.json') | Out-Null

        $directLinkB = [string]$peerReady.ed2k.b.base_link +
            "|sources,$peerV4Text`:$PeerTcpPort|/"
        Send-I04Ed2kLink -Process $client -Link $directLinkB
        $bDeadline = [DateTime]::UtcNow.AddSeconds(60)
        do {
            $fileBReady = Get-I04TransferSnapshot `
                -Port $ClientWebPort -Session $clientSession `
                -FileHash ([string]$peerReady.ed2k.b.hash)
            if ([bool]$fileBReady.found -and
                $null -ne $fileBReady.source_total -and
                [int]$fileBReady.source_total -ge 1 -and
                ([int]$fileBReady.source_transferring -eq 0)) {
                break
            }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $bDeadline)
        if (-not [bool]$fileBReady.found -or
            $null -eq $fileBReady.source_total -or
            [int]$fileBReady.source_total -lt 1 -or
            [int]$fileBReady.source_transferring -ne 0) {
            $blockedReasons.Add(
                'File B did not retain the same peer as an inactive A4AF source'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }

        # Capture and the PID-independent 25 ms socket sampler begin while the
        # old prewarm is already Established.  Consequently every captured SYN
        # is a new attempt; no historical 5-tuple is ever excluded.
        $scenarioV6SocketObserved = $false
        $scenarioV4SocketObserved = $false
        $scenarioV4Established = $false

        $capture = Start-I04PacketCapture -EvidencePath $captureEvidence `
            -FilterPrefix ("i04-" + $nonce) `
            -IPv4 $peerV4Text -IPv6 $peerV6Text -Port $PeerTcpPort `
            -JournalPath $journal
        if (-not $capture.available) {
            $blockedReasons.Add(
                "Packet capture unavailable; silent DROP cannot be proved: $($capture.error)"
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        $socketSampler = Start-I04SocketSampler `
            -Path $socketSamplesPath `
            -IPv4 $peerV4Text -IPv6 $peerV6Text `
            -Port $PeerTcpPort

        $armRequestedAt = [DateTimeOffset]::UtcNow
        $armRequestedEpochMs =
            Get-I04EpochMilliseconds -Timestamp $armRequestedAt
        $armRequestedQpc = [Diagnostics.Stopwatch]::GetTimestamp()
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-arm-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            action = 'arm-remote-silent-drop'
            requested_at_utc = $armRequestedAt.ToString('o')
            coordinator_epoch_ms = $armRequestedEpochMs
            coordinator_qpc = $armRequestedQpc
            coordinator_qpc_frequency = [Diagnostics.Stopwatch]::Frequency
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            expected_source_process_id = [int]$peerReady.process.id
            expected_peer_ipv6 = $peerV6Text
            expected_peer_ipv4 = $peerV4Text
            expected_peer_tcp_port = $PeerTcpPort
            prewarm_tuples = $prewarmConnectionEvidence
        }) -Path $armPath | Out-Null
        $armCommandWritten = $true
        $scenarioStarted = [DateTime]::UtcNow

        # First barrier: the peer installs and verifies DROP while the original
        # source process and the real IPv4 prewarm connection are still alive.
        # Only the coordinator may release that barrier.
        $peerStageDeadline = [DateTime]::UtcNow.AddSeconds(90)
        $nextStageHealth = [DateTime]::UtcNow
        $sample = 0
        do {
            $now = [DateTime]::UtcNow
            if ($null -eq $peerArmed -and
                (Test-Path -LiteralPath $armedPath -PathType Leaf)) {
                $peerArmed = Get-Content -LiteralPath $armedPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $resumedPath -PathType Leaf) {
                $blockedReasons.Add(
                    'Peer published resumed before coordinator restart barrier'
                )
                throw 'I04_FIXTURE_BLOCKED'
            }
            $client.Refresh()
            if ($client.HasExited) {
                throw 'Client exited while the remote DROP was being armed'
            }
            $stageConnections = @(Get-I04TargetConnections `
                -IPv4 $peerV4Text -IPv6 $peerV6Text -Port $PeerTcpPort)
            foreach ($connection in $stageConnections) {
                $isPrewarm = $prewarmTuples.Contains(
                    [string]$connection.tuple_key
                )
                if ($isPrewarm) { continue }
                if ($connection.state -notin @('SynSent', 'Established')) {
                    continue
                }
                if ([int]$connection.owning_process -ne $client.Id) {
                    $otherPidObserved = $true
                    $otherPidConnections.Add($connection)
                    continue
                }
                if ($connection.remote_address -eq $peerV6Text) {
                    $null = $scenarioV6LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV6SocketObserved = $true
                } elseif ($connection.remote_address -eq $peerV4Text) {
                    $null = $scenarioV4LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV4SocketObserved = $true
                    if ($connection.state -eq 'Established') {
                        $scenarioV4Established = $true
                    }
                }
            }
            if ($now -ge $nextStageHealth) {
                $api = Get-I04ApiProbe -Port $ClientWebPort
                $ui = Get-I04UiProbe -Process $client
                $apiProbeCount++
                if (-not $api.available) { $apiFailureCount++ }
                $apiMaxMs = [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
                $uiProbeCount++
                if (-not $ui.main_window_present) { $uiMissingCount++ }
                if ($ui.main_window_present -and
                    -not $ui.message_pump_responsive) {
                    $uiFailureCount++
                }
                $uiMaxMs = [Math]::Max(
                    $uiMaxMs, [Int64]$ui.probe_duration_ms
                )
                Add-I04JsonLine -Path $samplesPath -Value ([ordered]@{
                    schema = 'ese.v91.i04-runtime-sample/v1'
                    sample_number = ++$sample
                    stage = 'peer-arm-and-blackhole'
                    captured_at_utc = Get-LabUtcTimestamp
                    elapsed_seconds = [Math]::Round(
                        ($now - $scenarioStarted).TotalSeconds, 3
                    )
                    connections = $stageConnections
                    api = $api
                    ui = $ui
                })
                $nextStageHealth = $now.AddSeconds(1)
            }
            if ($null -ne $peerArmed) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $peerStageDeadline)
        if ($null -eq $peerArmed) {
            $blockedReasons.Add('Peer did not prove DROP while old source was alive')
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value $peerArmed `
            -Path (Join-Path $evidence 'peer-drop-armed.json') | Out-Null
        $peerArmedExact =
            [string]$peerArmed.schema -eq
                'ese.v91.i04-peer-drop-armed/v1' -and
            [string]$peerArmed.case_id -eq $caseId -and
            [string]$peerArmed.run_nonce -eq $nonce -and
            [string]$peerArmed.candidate_commit -eq $candidate.commit -and
            [string]$peerArmed.candidate_emule_sha256 -eq $expectedHash -and
            [int]$peerArmed.source_process_id -eq
                [int]$peerReady.process.id -and
            [bool]$peerArmed.source_process_alive -and
            [bool]$peerArmed.dual_stack_listener_alive -and
            [bool]$peerArmed.prewarm_connection_alive -and
            [string]$peerArmed.source_process_emule_sha256 -eq
                $expectedHash -and
            [bool]$peerArmed.allow4_rule.exact -and
            [bool]$peerArmed.allow6_rule.exact -and
            [bool]$peerArmed.drop_rule.exact -and
            [string]$peerArmed.allow4_rule.program_file_sha256 -eq
                $expectedHash -and
            [string]$peerArmed.allow6_rule.program_file_sha256 -eq
                $expectedHash -and
            [string]$peerArmed.drop_rule.program_file_sha256 -eq
                $expectedHash -and
            [string]$peerArmed.drop_rule.action -eq 'Block' -and
            [string]$peerArmed.drop_rule.direction -eq 'Inbound' -and
            [string]$peerArmed.drop_rule.profile -eq 'Any' -and
            @('6', 'tcp') -contains
                ([string]$peerArmed.drop_rule.protocol).ToLowerInvariant() -and
            [string]$peerArmed.drop_rule.local_port -eq
                ([string]$PeerTcpPort) -and
            [string]$peerArmed.drop_rule.remote_port -eq 'Any' -and
            [string]$peerArmed.allow4_rule.action -eq 'Allow' -and
            [string]$peerArmed.allow4_rule.direction -eq 'Inbound' -and
            [string]$peerArmed.allow4_rule.profile -eq 'Any' -and
            @('6', 'tcp') -contains
                ([string]$peerArmed.allow4_rule.protocol).ToLowerInvariant() -and
            [string]$peerArmed.allow4_rule.local_port -eq
                ([string]$PeerTcpPort) -and
            [string]$peerArmed.allow4_rule.remote_port -eq 'Any' -and
            [string]$peerArmed.allow6_rule.remote_port -eq 'Any' -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.drop_rule.local_addresses) `
                -Expected @($peerV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.drop_rule.remote_addresses) `
                -Expected @($coordinatorV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.allow4_rule.local_addresses) `
                -Expected @($peerLocalV4Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.allow4_rule.remote_addresses) `
                -Expected @(
                    [string]$peerArmed.observed_ipv4_client.address
                ) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.allow6_rule.local_addresses) `
                -Expected @($peerV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.allow6_rule.remote_addresses) `
                -Expected @($coordinatorV6Text) -NormalizeIp) -and
            [string]$peerArmed.observed_ipv4_client.firewall_remote_port -eq
                'Any' -and
            [bool]$peerArmed.route_to_observed_ipv4_client.available -and
            [bool]$peerArmed.route_to_observed_ipv4_client.
                physical_nonvirtual -and
            [int]$peerArmed.route_to_observed_ipv4_client.interface_index -eq
                [int]$peerReady.peer.ipv4_interface_index -and
            [string]$peerArmed.route_to_observed_ipv4_client.source_address -eq
                $peerLocalV4Text -and
            [string]$peerArmed.route_to_observed_ipv4_client.remote_address -eq
                [string]$peerArmed.observed_ipv4_client.address -and
            -not ([string]$peerArmed.observed_ipv4_client.address).Contains(
                ':'
            ) -and
            (Get-LabAddressClass -Address (
                [string]$peerArmed.observed_ipv4_client.address
            )) -notin @(
                'invalid', 'loopback-v4', 'linklocal-v4', 'special-v4'
            ) -and
            [int]$peerArmed.observed_ipv4_client.port -gt 0
        $coordinatorPrewarmAlive = @(
            Get-NetTCPConnection -OwningProcess $client.Id -State Established `
                -ErrorAction SilentlyContinue | Where-Object {
                    $tuple = Get-I04TupleKey -Family 'IPv4' `
                        -LocalAddress $_.LocalAddress `
                        -LocalPort ([int]$_.LocalPort) `
                        -RemoteAddress $_.RemoteAddress `
                        -RemotePort ([int]$_.RemotePort)
                    $prewarmTuples.Contains($tuple)
                }
        ).Count -gt 0
        if (-not $peerArmedExact -or -not $coordinatorPrewarmAlive) {
            $blockedReasons.Add(
                'Remote armed evidence is not exact or prewarm died before restart release'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }

        $pauseOperation = Invoke-I04DownloadOperation `
            -Port $ClientWebPort -Session $clientSession `
            -Operation pause `
            -FileHash ([string]$peerReady.ed2k.a.hash)
        $pauseBoundaryEpochMs =
            [double]$pauseOperation.boundary_before_request_epoch_ms
        $pauseBoundaryQpc =
            [Int64]$pauseOperation.boundary_before_request_qpc
        $pauseDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $fileAPaused = Get-I04TransferSnapshot `
                -Port $ClientWebPort -Session $clientSession `
                -FileHash ([string]$peerReady.ed2k.a.hash)
            $fileBReady = Get-I04TransferSnapshot `
                -Port $ClientWebPort -Session $clientSession `
                -FileHash ([string]$peerReady.ed2k.b.hash)
            if ([bool]$fileAPaused.found -and
                [string]$fileAPaused.state -eq 'paused' -and
                [bool]$fileBReady.found -and
                [int]$fileBReady.source_total -ge 1) {
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $pauseDeadline)
        if ([string]$fileAPaused.state -ne 'paused' -or
            -not [bool]$fileBReady.found -or
            [int]$fileBReady.source_total -lt 1) {
            $blockedReasons.Add(
                'Pause A did not preserve the ordinary A/B A4AF fixture'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }

        $quiesceRequestedAt = [DateTimeOffset]::UtcNow
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-quiesce-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            action = 'stop-source-under-drop'
            requested_at_utc = $quiesceRequestedAt.ToString('o')
            coordinator_epoch_ms =
                Get-I04EpochMilliseconds -Timestamp $quiesceRequestedAt
            coordinator_qpc = [Diagnostics.Stopwatch]::GetTimestamp()
            coordinator_qpc_frequency = [Diagnostics.Stopwatch]::Frequency
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            expected_old_process_id = [int]$peerArmed.source_process_id
            pause_a_operation = $pauseOperation
        }) -Path $quiescePath | Out-Null

        $peerQuiesced = Wait-I04File -Path $quiescedPath `
            -TimeoutSeconds 90
        if ($null -eq $peerQuiesced -or
            [string]$peerQuiesced.schema -ne
                'ese.v91.i04-peer-quiesced/v1' -or
            [string]$peerQuiesced.case_id -ne $caseId -or
            [string]$peerQuiesced.run_nonce -ne $nonce -or
            [int]$peerQuiesced.old_process_id -ne
                [int]$peerArmed.source_process_id -or
            -not [bool]$peerQuiesced.old_process_absent -or
            -not [bool]$peerQuiesced.old_listener_and_tuple_absent -or
            -not [bool]$peerQuiesced.drop_rule.exact) {
            $blockedReasons.Add(
                'Peer did not prove the old PID/listener/tuple absent under DROP'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value $peerQuiesced `
            -Path (Join-Path $evidence 'peer-quiesced.json') | Out-Null

        $oldTupleDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $oldClientTuple = @(
                Get-I04TargetConnections -IPv4 $peerV4Text `
                    -IPv6 $peerV6Text -Port $PeerTcpPort |
                    Where-Object {
                        [int]$_.owning_process -eq $client.Id -and
                        $prewarmTuples.Contains([string]$_.tuple_key) -and
                        [string]$_.state -in @(
                            'Established', 'SynSent', 'CloseWait'
                        )
                    }
            )
            if ($oldClientTuple.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $oldTupleDeadline)
        if ($oldClientTuple.Count -ne 0) {
            $blockedReasons.Add(
                'Coordinator prewarm tuple remained after peer quiesce'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }

        $schedulerDeadlineUtc =
            $prewarmFirstEstablishedAt.UtcDateTime.AddSeconds(
                $schedulerReconnectFloorSeconds
            )
        $nextFloorHealth = [DateTime]::UtcNow
        do {
            $now = [DateTime]::UtcNow
            $client.Refresh()
            if ($client.HasExited) {
                throw 'Client exited while waiting for scheduler floor'
            }
            if ($now -ge $nextFloorHealth) {
                $api = Get-I04ApiProbe -Port $ClientWebPort
                $ui = Get-I04UiProbe -Process $client
                $apiProbeCount++
                if (-not [bool]$api.available) {
                    $candidatePostTriggerFailure =
                        'candidate API became unavailable during the formal scenario'
                    throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
                }
                if (-not (Test-I04ApiIsolation -Data $api `
                        -RequireEd2k $true)) {
                    $apiFailureCount++
                }
                $apiMaxMs =
                    [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
                $uiProbeCount++
                if (-not $ui.main_window_present) { $uiMissingCount++ }
                if ($ui.main_window_present -and
                    -not $ui.message_pump_responsive) {
                    $uiFailureCount++
                }
                $uiMaxMs = [Math]::Max(
                    $uiMaxMs, [Int64]$ui.probe_duration_ms
                )
                $pausedCheck = Get-I04TransferSnapshot `
                    -Port $ClientWebPort -Session $clientSession `
                    -FileHash ([string]$peerReady.ed2k.a.hash)
                Add-I04JsonLine -Path $samplesPath -Value ([ordered]@{
                    schema = 'ese.v91.i04-runtime-sample/v1'
                    sample_number = ++$sample
                    stage = 'paused-a-scheduler-floor'
                    captured_at_utc = Get-LabUtcTimestamp
                    connections = @(
                        Get-I04TargetConnections -IPv4 $peerV4Text `
                            -IPv6 $peerV6Text -Port $PeerTcpPort
                    )
                    api = $api
                    ui = $ui
                    file_a = $pausedCheck
                })
                if ([string]$pausedCheck.state -ne 'paused') {
                    throw 'File A left Paused state before formal Stop A'
                }
                $nextFloorHealth = $now.AddSeconds(5)
            }
            if ($now -ge $schedulerDeadlineUtc) { break }
            Start-Sleep -Milliseconds 100
        } while ($true)
        $schedulerFloorSatisfied =
            [DateTime]::UtcNow -ge $schedulerDeadlineUtc
        if (-not $schedulerFloorSatisfied) {
            throw 'Scheduler reconnect floor was not satisfied'
        }

        $restartPreparationAt = [DateTimeOffset]::UtcNow
        $restartPreparationEpochMs =
            Get-I04EpochMilliseconds -Timestamp $restartPreparationAt
        $restartPreparationQpc =
            [Diagnostics.Stopwatch]::GetTimestamp()
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-restart-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            action = 'restart-source-under-drop'
            requested_at_utc = $restartPreparationAt.ToString('o')
            coordinator_epoch_ms = $restartPreparationEpochMs
            coordinator_qpc = $restartPreparationQpc
            coordinator_qpc_frequency = [Diagnostics.Stopwatch]::Frequency
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            expected_old_process_id = [int]$peerArmed.source_process_id
            prewarm_first_established_at_utc =
                $prewarmFirstEstablishedAt.ToString('o')
            scheduler_floor_seconds =
                $schedulerReconnectFloorSeconds
            scheduler_floor_satisfied = $schedulerFloorSatisfied
        }) -Path $restartPath | Out-Null

        $resumeDeadline = [DateTime]::UtcNow.AddSeconds(90)
        do {
            $now = [DateTime]::UtcNow
            if ($null -eq $peerResumed -and
                (Test-Path -LiteralPath $resumedPath -PathType Leaf)) {
                $peerResumed = Get-Content -LiteralPath $resumedPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
            $client.Refresh()
            if ($client.HasExited) {
                throw 'Client exited while peer source was restarting'
            }
            $stageConnections = @(Get-I04TargetConnections `
                -IPv4 $peerV4Text -IPv6 $peerV6Text -Port $PeerTcpPort)
            foreach ($connection in $stageConnections) {
                if ($prewarmTuples.Contains([string]$connection.tuple_key)) {
                    continue
                }
                if ($connection.state -notin @('SynSent', 'Established')) {
                    continue
                }
                if ([int]$connection.owning_process -ne $client.Id) {
                    $otherPidObserved = $true
                    $otherPidConnections.Add($connection)
                    continue
                }
                if ($connection.remote_address -eq $peerV6Text) {
                    $null = $scenarioV6LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV6SocketObserved = $true
                } elseif ($connection.remote_address -eq $peerV4Text) {
                    $null = $scenarioV4LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV4SocketObserved = $true
                    if ($connection.state -eq 'Established') {
                        $scenarioV4Established = $true
                    }
                }
            }
            if ($now -ge $nextStageHealth) {
                $api = Get-I04ApiProbe -Port $ClientWebPort
                $ui = Get-I04UiProbe -Process $client
                $apiProbeCount++
                if (-not $api.available) { $apiFailureCount++ }
                $apiMaxMs = [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
                $uiProbeCount++
                if (-not $ui.main_window_present) { $uiMissingCount++ }
                if ($ui.main_window_present -and
                    -not $ui.message_pump_responsive) {
                    $uiFailureCount++
                }
                $uiMaxMs = [Math]::Max(
                    $uiMaxMs, [Int64]$ui.probe_duration_ms
                )
                Add-I04JsonLine -Path $samplesPath -Value ([ordered]@{
                    schema = 'ese.v91.i04-runtime-sample/v1'
                    sample_number = ++$sample
                    stage = 'coordinator-restart-barrier'
                    captured_at_utc = Get-LabUtcTimestamp
                    elapsed_seconds = [Math]::Round(
                        ($now - $scenarioStarted).TotalSeconds, 3
                    )
                    connections = $stageConnections
                    api = $api
                    ui = $ui
                })
                $nextStageHealth = $now.AddSeconds(1)
            }
            if ($null -ne $peerResumed) { break }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $resumeDeadline)
        if ($null -eq $peerResumed) {
            $blockedReasons.Add('Peer did not publish resumed after restart release')
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value $peerResumed `
            -Path (Join-Path $evidence 'peer-resumed.json') | Out-Null
        $peerResumedExact =
            [string]$peerResumed.schema -eq 'ese.v91.i04-peer-resumed/v1' -and
            [string]$peerResumed.case_id -eq $caseId -and
            [string]$peerResumed.run_nonce -eq $nonce -and
            [string]$peerResumed.candidate_commit -eq $candidate.commit -and
            [string]$peerResumed.candidate_emule_sha256 -eq $expectedHash -and
            [int]$peerResumed.old_process_id -eq
                [int]$peerArmed.source_process_id -and
            [int]$peerResumed.process_id -gt 0 -and
            [int]$peerResumed.process_id -ne
                [int]$peerArmed.source_process_id -and
            [string]$peerResumed.process_emule_sha256 -eq $expectedHash -and
            [Int64]$peerResumed.stop_to_listener_ready_ms -ge 0 -and
            [Int64]$peerResumed.stop_to_listener_ready_ms -le 90000 -and
            [bool]$peerResumed.restart_within_readiness_limit -and
            [bool]$peerResumed.dual_stack_listener -and
            [bool]$peerResumed.ipv4_capable_dual_stack_listener -and
            [bool]$peerResumed.same_persisted_user_hash -and
            [string]$peerResumed.persisted_identity.user_hash -eq
                [string]$peerReady.process.persisted_identity.user_hash -and
            [string]$peerResumed.persisted_identity.source_mode -eq
                'non-headless persisted preferences.dat identity' -and
            [string]$peerResumed.runtime_identity -eq
                [string]$peerReady.process.persisted_identity.user_hash -and
            [string]$peerResumed.controlled_server_login.runtime_user_hash -eq
                [string]$peerReady.process.persisted_identity.user_hash -and
            [int]$peerResumed.controlled_server_login.login_count -ge 2 -and
            (Test-I04ApiIsolation -Data $peerResumed.runtime_isolation `
                -RequireEd2k $true) -and
            [bool]$peerResumed.allow4_rule.exact -and
            [bool]$peerResumed.allow6_rule.exact -and
            [bool]$peerResumed.drop_rule.exact -and
            [string]$peerResumed.drop_rule.program_file_sha256 -eq
                $expectedHash -and
            [string]$peerResumed.drop_rule.action -eq 'Block' -and
            [string]$peerResumed.drop_rule.local_port -eq
                ([string]$PeerTcpPort) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.drop_rule.local_addresses) `
                -Expected @($peerV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.drop_rule.remote_addresses) `
                -Expected @($coordinatorV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.allow4_rule.local_addresses) `
                -Expected @($peerLocalV4Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.allow4_rule.remote_addresses) `
                -Expected @(
                    [string]$peerArmed.observed_ipv4_client.address
                ) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.allow6_rule.local_addresses) `
                -Expected @($peerV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.allow6_rule.remote_addresses) `
                -Expected @($coordinatorV6Text) -NormalizeIp)
        if (-not $peerResumedExact) {
            $blockedReasons.Add(
                'Peer restart failed PID/hash/identity/eD2K/listener/firewall/readiness validation'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }

        $baselineDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $apiTelemetryBaseline =
                Get-I04ApiProbe -Port $ClientWebPort
            $baselineFieldsPresent =
                $null -ne $apiTelemetryBaseline.connecting_client_count -and
                $null -ne $apiTelemetryBaseline.connecting_client_adds -and
                $null -ne
                    $apiTelemetryBaseline.connecting_client_high_water -and
                $null -ne
                    $apiTelemetryBaseline.connecting_client_duplicate_adds
            if ($baselineFieldsPresent -and
                [Int64]$apiTelemetryBaseline.connecting_client_count -eq 0) {
                break
            }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $baselineDeadline)
        if (-not $baselineFieldsPresent -or
            [Int64]$apiTelemetryBaseline.connecting_client_count -ne 0 -or
            [Int64]$apiTelemetryBaseline.connecting_client_high_water -ne 1 -or
            -not (Test-I04ApiIsolation -Data $apiTelemetryBaseline `
                -RequireEd2k $true)) {
            $blockedReasons.Add(
                'Pre-Stop-A connecting-client/API baseline is absent or invalid'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        $telemetryObservedCurrentMax =
            [Int64]$apiTelemetryBaseline.connecting_client_count
        $telemetryObservedAddsMax =
            [Int64]$apiTelemetryBaseline.connecting_client_adds
        $telemetryObservedDuplicateMax =
            [Int64]$apiTelemetryBaseline.connecting_client_duplicate_adds
        $telemetryObservedHighWaterMax =
            [Int64]$apiTelemetryBaseline.connecting_client_high_water

        $preStopA = Get-I04TransferSnapshot `
            -Port $ClientWebPort -Session $clientSession `
            -FileHash ([string]$peerReady.ed2k.a.hash)
        $preStopB = Get-I04TransferSnapshot `
            -Port $ClientWebPort -Session $clientSession `
            -FileHash ([string]$peerReady.ed2k.b.hash)
        if ([string]$preStopA.state -ne 'paused' -or
            -not [bool]$preStopB.found -or
            [int]$preStopB.source_total -lt 1) {
            $blockedReasons.Add(
                'A/B ordinary fixture was not intact immediately before Stop A'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        $logBefore = Get-I04ProductLogCounts -NodePath $clientNode `
            -PeerIPv4 $peerV4Text -PeerIPv6 $peerV6Text `
            -PeerPort $PeerTcpPort -FileAName (
                [string]$peerReady.fixtures.a.name
            ) -FileBName ([string]$peerReady.fixtures.b.name)
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-formal-trigger-baseline/v1'
            captured_at_utc = Get-LabUtcTimestamp
            logs = $logBefore
            api = $apiTelemetryBaseline
            file_a = $preStopA
            file_b = $preStopB
        }) -Path (Join-Path $evidence 'formal-trigger-baseline.json') |
            Out-Null

        # From here onward the complete external fixture has been proved and
        # the only remaining trigger is the candidate's formal Stop A path.
        # Once the boundary artifact is published, candidate/API/telemetry
        # failures take FAIL precedence; pre-boundary setup failures remain
        # BLOCKED.
        $caseArmed = $true
        # The only formal trigger boundary is immediately before this Classic
        # Web Stop A request. Publish and assign it before entering the
        # potentially blocking request so a candidate crash/hang cannot erase
        # the boundary and be mislabeled as harness uncertainty. Restart was
        # preparation; StopFile invokes RemoveAllSources(true), swaps the same
        # CUpDownClient A->B with reask=0, and the expired 20-minute floor
        # permits AskForDownload immediately.
        $stopABefore = [DateTimeOffset]::UtcNow
        $stopABoundary = [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-formal-trigger-boundary/v1'
            case_id = $caseId
            run_nonce = $nonce
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            operation = 'stop'
            file_hash =
                ([string]$peerReady.ed2k.a.hash).ToUpperInvariant()
            boundary_before_request_utc = $stopABefore.ToString('o')
            boundary_before_request_epoch_ms =
                Get-I04EpochMilliseconds -Timestamp $stopABefore
            boundary_before_request_qpc =
                [Diagnostics.Stopwatch]::GetTimestamp()
            qpc_frequency = [Diagnostics.Stopwatch]::Frequency
        }
        Write-LabJson -Value $stopABoundary `
            -Path $formalTriggerBoundaryPath | Out-Null
        $formalBoundaryPublished = $true
        $restartBoundaryEpochMs =
            [double]$stopABoundary.boundary_before_request_epoch_ms
        $restartBoundaryQpc =
            [Int64]$stopABoundary.boundary_before_request_qpc
        $restartBoundaryAt = [DateTimeOffset]::FromUnixTimeMilliseconds(
            [Int64][Math]::Floor($restartBoundaryEpochMs)
        )
        $scenarioStarted = $restartBoundaryAt.UtcDateTime
        try {
            $stopAOperation = Invoke-I04DownloadOperation `
                -Port $ClientWebPort -Session $clientSession `
                -Operation stop `
                -FileHash ([string]$peerReady.ed2k.a.hash) `
                -PreparedBoundary $stopABoundary
        } catch {
            $requestFailure = $_.Exception.Message
            $requestAfter = [DateTimeOffset]::UtcNow
            $stopAOperation = [pscustomobject][ordered]@{
                operation = 'stop'
                file_hash =
                    ([string]$peerReady.ed2k.a.hash).ToUpperInvariant()
                boundary_before_request_utc =
                    $stopABoundary.boundary_before_request_utc
                boundary_before_request_epoch_ms =
                    $stopABoundary.boundary_before_request_epoch_ms
                boundary_before_request_qpc =
                    $stopABoundary.boundary_before_request_qpc
                response_completed_utc = $requestAfter.ToString('o')
                response_completed_epoch_ms =
                    Get-I04EpochMilliseconds -Timestamp $requestAfter
                response_completed_qpc =
                    [Diagnostics.Stopwatch]::GetTimestamp()
                qpc_frequency = [Diagnostics.Stopwatch]::Frequency
                request_completed = $false
                request_error = $requestFailure
                http_status = $null
                response_sha256 = ''
            }
            $client.Refresh()
            $candidatePostTriggerFailure = if ($client.HasExited) {
                "candidate exited while processing formal Stop A (exit " +
                    "$($client.ExitCode))"
            } else {
                'candidate Classic Web Stop A request failed or timed out ' +
                    "after the formal boundary: $requestFailure"
            }
            throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
        }
        $apiTelemetryTrigger = Get-I04ApiProbe -Port $ClientWebPort
        if (-not [bool]$apiTelemetryTrigger.available -or
            $null -eq $apiTelemetryTrigger.connecting_client_count -or
            $null -eq $apiTelemetryTrigger.connecting_client_adds -or
            $null -eq $apiTelemetryTrigger.connecting_client_high_water -or
            $null -eq
                $apiTelemetryTrigger.connecting_client_duplicate_adds) {
            $candidatePostTriggerFailure =
                'candidate API/connecting telemetry was unavailable ' +
                'immediately after formal Stop A'
            throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
        }
        $telemetryObservedCurrentMax = [Math]::Max(
            $telemetryObservedCurrentMax,
            [Int64]$apiTelemetryTrigger.connecting_client_count
        )
        $telemetryObservedAddsMax = [Math]::Max(
            [Int64]$telemetryObservedAddsMax,
            [Int64]$apiTelemetryTrigger.connecting_client_adds
        )
        $telemetryObservedDuplicateMax = [Math]::Max(
            [Int64]$telemetryObservedDuplicateMax,
            [Int64]$apiTelemetryTrigger.connecting_client_duplicate_adds
        )
        $telemetryObservedHighWaterMax = [Math]::Max(
            [Int64]$telemetryObservedHighWaterMax,
            [Int64]$apiTelemetryTrigger.connecting_client_high_water
        )

        $deadline = [DateTime]::UtcNow.AddSeconds($ScenarioTimeoutSeconds)
        $nextHealth = [DateTime]::UtcNow
        $nextTelemetry = [DateTime]::UtcNow
        $nextLogCheck = [DateTime]::UtcNow
        $fallbackDeltaObserved = 0
        do {
            $now = [DateTime]::UtcNow
            $client.Refresh()
            if ($client.HasExited) {
                $candidatePostTriggerFailure =
                    "candidate exited during formal scenario (exit " +
                    "$($client.ExitCode))"
                throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
            }
            $matching = @(Get-I04TargetConnections `
                -IPv4 $peerV4Text -IPv6 $peerV6Text -Port $PeerTcpPort)
            foreach ($connection in $matching) {
                if ($connection.state -notin @('SynSent', 'Established')) {
                    continue
                }
                if ([int]$connection.owning_process -ne $client.Id) {
                    $otherPidObserved = $true
                    $otherPidConnections.Add($connection)
                    continue
                }
                if ($connection.remote_address -eq $peerV6Text) {
                    $null = $scenarioV6LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV6SocketObserved = $true
                }
                if ($connection.remote_address -eq $peerV4Text) {
                    $null = $scenarioV4LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV4SocketObserved = $true
                    if ($connection.state -eq 'Established') {
                        $scenarioV4Established = $true
                    }
                }
            }
            if ($now -ge $nextTelemetry) {
                $telemetry = Get-I04ApiProbe -Port $ClientWebPort
                if (-not [bool]$telemetry.available -or
                    $null -eq $telemetry.connecting_client_count -or
                    $null -eq $telemetry.connecting_client_adds -or
                    $null -eq $telemetry.connecting_client_high_water -or
                    $null -eq
                        $telemetry.connecting_client_duplicate_adds) {
                    $candidatePostTriggerFailure =
                        'candidate API/connecting telemetry became unavailable'
                    throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
                }
                $telemetryObservedCurrentMax = [Math]::Max(
                    $telemetryObservedCurrentMax,
                    [Int64]$telemetry.connecting_client_count
                )
                $telemetryObservedAddsMax = [Math]::Max(
                    [Int64]$telemetryObservedAddsMax,
                    [Int64]$telemetry.connecting_client_adds
                )
                $telemetryObservedDuplicateMax = [Math]::Max(
                    [Int64]$telemetryObservedDuplicateMax,
                    [Int64]$telemetry.connecting_client_duplicate_adds
                )
                $telemetryObservedHighWaterMax = [Math]::Max(
                    [Int64]$telemetryObservedHighWaterMax,
                    [Int64]$telemetry.connecting_client_high_water
                )
                if ($null -eq $apiTelemetryPeak -or
                    [Int64]$telemetry.connecting_client_count -gt
                        [Int64]$apiTelemetryPeak.connecting_client_count -or
                    [Int64]$telemetry.connecting_client_adds -gt
                        [Int64]$apiTelemetryPeak.connecting_client_adds) {
                    $apiTelemetryPeak = $telemetry
                }
                $nextTelemetry = $now.AddMilliseconds(100)
            }
            if ($now -ge $nextHealth) {
                $api = Get-I04ApiProbe -Port $ClientWebPort
                $ui = Get-I04UiProbe -Process $client
                $apiProbeCount++
                if (-not $api.available -or
                    -not (Test-I04ApiIsolation -Data $api `
                        -RequireEd2k $true)) {
                    $apiFailureCount++
                }
                $apiMaxMs = [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
                $uiProbeCount++
                if (-not $ui.main_window_present) { $uiMissingCount++ }
                if ($ui.main_window_present -and
                    -not $ui.message_pump_responsive) {
                    $uiFailureCount++
                }
                $uiMaxMs = [Math]::Max($uiMaxMs, [Int64]$ui.probe_duration_ms)
                Add-I04JsonLine -Path $samplesPath -Value ([ordered]@{
                    schema = 'ese.v91.i04-runtime-sample/v1'
                    sample_number = ++$sample
                    stage = 'fallback-observation'
                    captured_at_utc = Get-LabUtcTimestamp
                    elapsed_seconds = [Math]::Round(
                        ($now - $scenarioStarted).TotalSeconds, 3
                    )
                    connections = $matching
                    api = $api
                    ui = $ui
                })
                $nextHealth = $now.AddSeconds(1)
            }
            if ($now -ge $nextLogCheck) {
                $liveLog = Get-I04ProductLogCounts -NodePath $clientNode `
                    -PeerIPv4 $peerV4Text -PeerIPv6 $peerV6Text `
                    -PeerPort $PeerTcpPort -FileAName (
                        [string]$peerReady.fixtures.a.name
                    ) -FileBName (
                        [string]$peerReady.fixtures.b.name
                    )
                $fallbackDeltaObserved = $liveLog.fallback_count -
                    $logBefore.fallback_count
                $nextLogCheck = $now.AddSeconds(1)
            }
            if ($fallbackDeltaObserved -ge 1 -and
                $scenarioV4Established) {
                if ($null -eq $successObservedAt) {
                    $successObservedAt = $now
                } elseif (($now - $successObservedAt).TotalSeconds -ge 10) {
                    break
                }
            }
            if ($null -eq $successObservedAt -and
                ($now - $restartBoundaryAt.UtcDateTime).TotalSeconds -ge
                    ($FallbackLimitSeconds + 10)) {
                # The formal fallback deadline plus the late-retry window has
                # elapsed under capture. Continuing to the broad scenario
                # timeout cannot turn this product failure into a PASS.
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        $scenarioFinished = [DateTime]::UtcNow
        $finalTelemetryDeadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            $apiTelemetryFinal =
                Get-I04ApiProbe -Port $ClientWebPort
            if ([bool]$apiTelemetryFinal.available -and
                $null -ne $apiTelemetryFinal.connecting_client_count -and
                [Int64]$apiTelemetryFinal.connecting_client_count -eq 0) {
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $finalTelemetryDeadline)
        if (-not [bool]$apiTelemetryFinal.available -or
            $null -eq $apiTelemetryFinal.connecting_client_count -or
            $null -eq $apiTelemetryFinal.connecting_client_adds -or
            $null -eq $apiTelemetryFinal.connecting_client_high_water -or
            $null -eq
                $apiTelemetryFinal.connecting_client_duplicate_adds) {
            $candidatePostTriggerFailure =
                'candidate final API/connecting telemetry remained unavailable'
            throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
        }
        $telemetryObservedCurrentMax = [Math]::Max(
            $telemetryObservedCurrentMax,
            [Int64]$apiTelemetryFinal.connecting_client_count
        )
        $telemetryObservedAddsMax = [Math]::Max(
            [Int64]$telemetryObservedAddsMax,
            [Int64]$apiTelemetryFinal.connecting_client_adds
        )
        $telemetryObservedDuplicateMax = [Math]::Max(
            [Int64]$telemetryObservedDuplicateMax,
            [Int64]$apiTelemetryFinal.connecting_client_duplicate_adds
        )
        $telemetryObservedHighWaterMax = [Math]::Max(
            [Int64]$telemetryObservedHighWaterMax,
            [Int64]$apiTelemetryFinal.connecting_client_high_water
        )
        $fileAStopped = Get-I04TransferSnapshot `
            -Port $ClientWebPort -Session $clientSession `
            -FileHash ([string]$peerReady.ed2k.a.hash)
        $fileBAfterTrigger = Get-I04TransferSnapshot `
            -Port $ClientWebPort -Session $clientSession `
            -FileHash ([string]$peerReady.ed2k.b.hash)
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-pid-port-correlation/v1'
            captured_at_utc = Get-LabUtcTimestamp
            candidate_process_id = $client.Id
            ipv4_local_ports = @($scenarioV4LocalPorts | Sort-Object)
            ipv6_local_ports = @($scenarioV6LocalPorts | Sort-Object)
            prewarm_tuple_keys = @($prewarmTuples | Sort-Object)
            other_pid_observed = $otherPidObserved
            other_pid_connections = @($otherPidConnections)
            telemetry = [ordered]@{
                baseline = $apiTelemetryBaseline
                immediate_after_stop_a = $apiTelemetryTrigger
                peak_sample = $apiTelemetryPeak
                final = $apiTelemetryFinal
                observed_current_max = $telemetryObservedCurrentMax
                observed_adds_max = $telemetryObservedAddsMax
                observed_duplicate_adds_max =
                    $telemetryObservedDuplicateMax
                observed_high_water_max =
                    $telemetryObservedHighWaterMax
            }
            classic_web = [ordered]@{
                pause_a = $pauseOperation
                stop_a = $stopAOperation
                a_after_stop = $fileAStopped
                b_after_stop = $fileBAfterTrigger
            }
            post_success_observation_seconds = if ($null -eq $successObservedAt) {
                0
            } else {
                [Math]::Round(
                    ($scenarioFinished - $successObservedAt).TotalSeconds, 3
                )
            }
        }) -Path (Join-Path $evidence 'pid-port-correlation.json') | Out-Null
    } catch {
        $failureDisposition = Get-I04FailureDisposition `
            -CaseArmed $caseArmed `
            -FormalBoundaryPublished $formalBoundaryPublished `
            -ExceptionMessage $_.Exception.Message
        if ([string]$failureDisposition.classification -eq 'FAIL') {
            # Once the exact fixture and formal boundary are published, any
            # exception in the candidate scenario is a post-trigger product
            # failure. Capture and transactional cleanup still continue so
            # unrelated external integrity failures can remain BLOCKED.
            if (-not $candidatePostTriggerFailure) {
                $candidatePostTriggerFailure =
                    'candidate scenario raised an exception after the formal ' +
                    "Stop A boundary: $($_.Exception.Message)"
            }
        } elseif ($_.Exception.Message -ne 'I04_FIXTURE_BLOCKED') {
            $runtimeFailure = $_
        }
    } finally {
        if ($null -ne $socketSampler) {
            $null = Stop-I04SocketSampler -Sampler $socketSampler `
                -CleanupFailures $cleanupFailures
            if ($null -ne $restartBoundaryEpochMs -and
                $null -ne $restartBoundaryQpc -and
                (Test-Path -LiteralPath $socketSamplesPath `
                    -PathType Leaf)) {
                try {
                    $socketSamplerEvidence =
                        Get-I04SocketSamplerEvidence `
                            -Path $socketSamplesPath `
                            -CandidateProcessId $client.Id `
                            -BoundaryEpochMs $restartBoundaryEpochMs `
                            -BoundaryQpc $restartBoundaryQpc `
                            -ClockCoherenceToleranceMs `
                                $socketClockCoherenceToleranceMs
                    foreach ($portValue in @(
                        $socketSamplerEvidence.candidate_ipv4_local_ports
                    )) {
                        $null = $scenarioV4LocalPorts.Add(
                            [int]$portValue
                        )
                    }
                    foreach ($portValue in @(
                        $socketSamplerEvidence.candidate_ipv6_local_ports
                    )) {
                        $null = $scenarioV6LocalPorts.Add(
                            [int]$portValue
                        )
                    }
                    $scenarioV6SocketObserved =
                        [bool]$socketSamplerEvidence.candidate_ipv6_attempt_observed
                    $scenarioV4Established =
                        [bool]$socketSamplerEvidence.candidate_ipv4_established_observed
                    $scenarioV4SocketObserved =
                        @(
                            $socketSamplerEvidence.candidate_ipv4_local_ports
                        ).Count -gt 0
                    if (@(
                        $socketSamplerEvidence.other_pid_target_rows
                    ).Count -gt 0) {
                        $otherPidObserved = $true
                        foreach ($row in @(
                            $socketSamplerEvidence.other_pid_target_rows
                        )) {
                            $otherPidConnections.Add($row)
                        }
                    }
                    Write-LabJson -Value $socketSamplerEvidence `
                        -Path (
                            Join-Path $evidence 'socket-sampler.json'
                        ) | Out-Null
                } catch {
                    $cleanupFailures.Add(
                        "socket sampler evidence failed: " +
                        $_.Exception.Message
                    )
                }
            }
        }
        if ($null -ne $capture) {
            Stop-I04PacketCapture -State $capture -JournalPath $journal `
                -CleanupFailures $cleanupFailures
            $captureStoppedEpochMs = $capture.capture_ended_epoch_ms
        }
        # Publish stop even when peer-ready timed out. A manually launched or
        # delayed remote peer will then see stop before arm and restore/exit
        # instead of leaving a source process or allow rule behind.
        if (-not $stopCommandWritten) {
            try {
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i04-stop-command/v1'
                    case_id = $caseId
                    run_nonce = $nonce
                    action = 'stop-and-restore'
                    requested_at_utc = Get-LabUtcTimestamp
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $expectedHash
                }) -Path $stopPath | Out-Null
                $stopCommandWritten = $true
            } catch {
                $cleanupFailures.Add(
                    "peer stop command could not be written: $($_.Exception.Message)"
                )
            }
        }
        if ($stopCommandWritten -and $null -ne $peerReady) {
            $peerResult = Wait-I04File -Path $peerResultPath -TimeoutSeconds 90
            if ($null -eq $peerResult) {
                $cleanupFailures.Add('peer did not publish restoration evidence')
            } else {
                Write-LabJson -Value $peerResult `
                    -Path (Join-Path $evidence 'peer-result.json') | Out-Null
                try {
                    $peerRestorationExact =
                        [string]$peerResult.schema -eq
                            'ese.v91.i04-peer-result/v1' -and
                        [string]$peerResult.case_id -eq $caseId -and
                        [string]$peerResult.run_nonce -eq $nonce -and
                        [string]$peerResult.candidate_commit -eq
                            $candidate.commit -and
                        [string]$peerResult.candidate_emule_sha256 -eq
                            $expectedHash -and
                        [string]$peerResult.status -eq 'COMPLETE' -and
                        $null -eq $peerResult.runtime_error -and
                        [bool]$peerResult.cleanup.source_process_stopped -and
                        [bool]$peerResult.cleanup.controlled_ed2k_server_stopped -and
                        -not [bool]$peerResult.cleanup.drop_rule_present -and
                        -not [bool]$peerResult.cleanup.allow4_rule_present -and
                        -not [bool]$peerResult.cleanup.allow6_rule_present -and
                        [bool]$peerResult.cleanup.isolation_initial.
                            strict_isolation_valid -and
                        [bool]$peerResult.cleanup.isolation_final.
                            strict_isolation_valid -and
                        @($peerResult.cleanup.failures).Count -eq 0
                    $peerResultExact = $peerRestorationExact -and
                        [bool]$peerResult.barrier_completed -and
                        $null -ne $peerArmed -and $null -ne $peerResumed -and
                        [int]$peerResult.old_process_id -eq
                            [int]$peerArmed.source_process_id -and
                        [int]$peerResult.restarted_process_id -eq
                            [int]$peerResumed.process_id
                } catch {
                    $peerRestorationExact = $false
                    $peerResultExact = $false
                    $cleanupFailures.Add(
                        "peer result schema could not be validated: $($_.Exception.Message)"
                    )
                }
                if (-not $peerRestorationExact) {
                    $cleanupFailures.Add('peer restoration did not complete')
                }
            }
        }
        foreach ($ownedClientProcess in @(
            $clientOwnedProcesses | Sort-Object Id -Unique
        )) {
            $ownedWasRunning = $null -ne (
                Get-Process -Id $ownedClientProcess.Id `
                    -ErrorAction SilentlyContinue
            )
            if (-not (Stop-I04OwnedProcess `
                -Process $ownedClientProcess -ExpectedPath $clientExe)) {
                $cleanupFailures.Add(
                    "client process $($ownedClientProcess.Id) could not be stopped safely"
                )
            } elseif ($ownedWasRunning) {
                Add-I04RollbackJournal -Path $journal `
                    -Mutation 'client-process' -State 'rolled_back' `
                    -Detail "pid=$($ownedClientProcess.Id)" `
                    -CleanupFailures $cleanupFailures
            }
        }
        $clientProcessesStopped = @(
            $clientOwnedProcesses | Where-Object {
                $null -ne (
                    Get-Process -Id $_.Id -ErrorAction SilentlyContinue
                )
            }
        ).Count -eq 0
        $clientControlledServerStop =
            Stop-I04ControlledEd2kServerInventory `
                -OwnerInventory $clientControlledServersOwned `
                -PrimaryServer $clientControlledServer
        if (-not [bool]$clientControlledServerStop.stopped -or
            [string]$clientControlledServerStop.error) {
            $cleanupFailures.Add(
                'coordinator controlled eD2K server cleanup failed: ' +
                [string]$clientControlledServerStop.error
            )
        }
        if ($null -ne $remoteJob) {
            try {
                $null = Receive-Job -Job $remoteJob -Wait -ErrorAction Continue
                Remove-Job -Job $remoteJob -Force -ErrorAction SilentlyContinue
            } catch {
                $cleanupFailures.Add(
                    "remote peer job cleanup failed: $($_.Exception.Message)"
                )
            }
        }
        if ($null -eq $scenarioFinished -and $null -ne $scenarioStarted) {
            $scenarioFinished = [DateTime]::UtcNow
        }
    }

    if ($clientNode -and (Test-Path -LiteralPath $clientNode)) {
        $logAfter = Get-I04ProductLogCounts -NodePath $clientNode `
            -PeerIPv4 $peerV4Text -PeerIPv6 $peerV6Text `
            -PeerPort $PeerTcpPort -FileAName (
                [string]$peerReady.fixtures.a.name
            ) -FileBName ([string]$peerReady.fixtures.b.name)
        Write-LabJson -Value $logAfter `
            -Path (Join-Path $evidence 'logs-after-drop.json') | Out-Null
    }
    if ($null -ne $capture) {
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-etw-loss/v1'
            captured_at_utc = Get-LabUtcTimestamp
            query_error = $capture.etw_query_error
            events_lost = $capture.etw_events_lost
            log_buffers_lost = $capture.etw_log_buffers_lost
            realtime_buffers_lost = $capture.etw_realtime_buffers_lost
            buffers_lost = $capture.etw_buffers_lost
            buffers_written = $capture.etw_buffers_written
            loss_proved_zero = [bool]$capture.etw_loss_proved_zero
        }) -Path (Join-Path $evidence 'capture\etw-loss.json') | Out-Null
    }
    if ($null -ne $capture -and
        (Test-Path -LiteralPath $capture.pcapng_path -PathType Leaf) -and
        $null -ne $socketSamplerEvidence -and $null -ne $client -and
        $null -ne $armRequestedEpochMs -and
        $null -ne $restartBoundaryEpochMs -and
        $null -ne $captureStoppedEpochMs) {
        try {
            $packetVerdict = Get-I04PacketVerdict `
                -PcapNgPath $capture.pcapng_path `
                -IPv4 $peerV4Text -IPv6 $peerV6Text `
                -CoordinatorIPv4 $coordinatorV4Text `
                -CoordinatorIPv6 $coordinatorV6Text -Port $PeerTcpPort `
                -NotBeforeEpochMs $armRequestedEpochMs `
                -ScenarioBoundaryEpochMs $restartBoundaryEpochMs `
                -ObservationEndEpochMs $captureStoppedEpochMs `
                -LimitSeconds $FallbackLimitSeconds `
                -MinimumSilentWindowMs $minimumSilentWindowMs `
                -CandidateProcessId $client.Id `
                -SocketSamplerEvidence $socketSamplerEvidence `
                -SynCorrelationToleranceMs $captureTimingToleranceMs `
                -ExcludedTupleKeys @($prewarmTuples)
            Write-LabJson -Value $packetVerdict `
                -Path (Join-Path $evidence 'packet-verdict.json') | Out-Null
        } catch {
            $blockedReasons.Add(
                "Packet capture could not be adjudicated: $($_.Exception.Message)"
            )
        }
    }

    $fallbackDelta = if ($null -ne $logBefore -and $null -ne $logAfter) {
        [int]$logAfter.fallback_count - [int]$logBefore.fallback_count
    } else { 0 }
    $boundedFallbackDelta = if ($null -ne $logBefore -and
        $null -ne $logAfter) {
        [int]$logAfter.bounded_fallback_count -
            [int]$logBefore.bounded_fallback_count
    } else { 0 }
    $helloDelta = if ($null -ne $logBefore -and $null -ne $logAfter) {
        [int]$logAfter.hello_send_count - [int]$logBefore.hello_send_count
    } else { 0 }
    $helloAnswerDelta = if ($null -ne $logBefore -and
        $null -ne $logAfter) {
        [int]$logAfter.hello_answer_receive_count -
            [int]$logBefore.hello_answer_receive_count
    } else { 0 }
    $a4afSwapDelta = if ($null -ne $logBefore -and
        $null -ne $logAfter) {
        [int]$logAfter.a4af_swap_a_to_b_count -
            [int]$logBefore.a4af_swap_a_to_b_count
    } else { 0 }
    $ambiguousMarkerDelta = if ($null -ne $logBefore -and
        $null -ne $logAfter) {
        [int]$logAfter.ambiguous_target_marker_count -
            [int]$logBefore.ambiguous_target_marker_count
    } else { 0 }

    $telemetryFieldsComplete =
        $null -ne $apiTelemetryBaseline -and
        $null -ne $apiTelemetryFinal -and
        $null -ne $apiTelemetryBaseline.connecting_client_count -and
        $null -ne $apiTelemetryBaseline.connecting_client_adds -and
        $null -ne $apiTelemetryBaseline.connecting_client_high_water -and
        $null -ne
            $apiTelemetryBaseline.connecting_client_duplicate_adds -and
        $null -ne $apiTelemetryFinal.connecting_client_count -and
        $null -ne $apiTelemetryFinal.connecting_client_adds -and
        $null -ne $apiTelemetryFinal.connecting_client_high_water -and
        $null -ne
            $apiTelemetryFinal.connecting_client_duplicate_adds
    $telemetryAddsDelta = if ($telemetryFieldsComplete) {
        [Int64]$apiTelemetryFinal.connecting_client_adds -
            [Int64]$apiTelemetryBaseline.connecting_client_adds
    } else { $null }
    $telemetryDuplicateDelta = if ($telemetryFieldsComplete) {
        [Int64]$apiTelemetryFinal.connecting_client_duplicate_adds -
        [Int64]$apiTelemetryBaseline.connecting_client_duplicate_adds
    } else { $null }
    $apiFinalIsolationExact = [bool]$candidatePostTriggerFailure -or (
        $telemetryFieldsComplete -and
        (Test-I04ApiIsolation -Data $apiTelemetryFinal `
            -RequireEd2k $true)
    )

    $peerExact = $peerReadyExact -and $peerArmedExact -and
        $peerResumedExact -and $peerResultExact
    if ($otherPidObserved) {
        $blockedReasons.Add(
            'A non-candidate PID owned a post-boundary target connection'
        )
    }
    if ($ambiguousMarkerDelta -ne 0) {
        $blockedReasons.Add(
            "Target log attribution is ambiguous ($ambiguousMarkerDelta marker(s))"
        )
    }
    if ($null -ne $packetVerdict -and
        -not [bool]$packetVerdict.pid_packet_correlation_complete) {
        $blockedReasons.Add(
            'PCAP target SYNs were ambiguous or lacked a nearby exact 5-tuple sample owned only by the candidate PID'
        )
    }
    if ($null -eq $capture -or
        -not [bool]$capture.etw_loss_proved_zero) {
        $blockedReasons.Add(
            'PktMon ETW zero-loss capture was not proved; packet absence is inadmissible'
        )
    }
    if ($null -ne $capture -and
        -not [bool]$capture.etl_below_circular_limit) {
        $blockedReasons.Add(
            'PktMon ETL may have wrapped at its 256 MiB circular limit'
        )
    }
    if ($null -ne $socketSamplerEvidence -and
        -not [bool]$socketSamplerEvidence.clock_coherence_valid) {
        $blockedReasons.Add(
            'PID socket-sampler epoch/QPC clock coherence was not proved'
        )
    }
    if ($null -eq $socketSamplerEvidence -or
        -not [bool]$socketSamplerEvidence.sampler_coverage_valid) {
        $blockedReasons.Add(
            'Independent 25 ms PID socket-sampler coverage was not proved'
        )
    }
    if ($null -ne $packetVerdict -and
        [int]$packetVerdict.pre_boundary_target_syn_count -ne 0) {
        $blockedReasons.Add(
            'A target SYN occurred between capture/pause and formal Stop A; scheduler trigger was consumed early'
        )
    }
    if ($null -ne $packetVerdict -and
        [bool]$packetVerdict.environment_rejected_blackhole_in_fixed_window) {
        $blockedReasons.Add(
            'IPv6 returned TCP/RST/application or correlated ICMPv6 in the fixed 2.75-second environment window'
        )
    }
    if ($null -ne $packetVerdict -and
        [int]$packetVerdict.ipv6_syn_count -gt 0 -and
        [double]$packetVerdict.capture_coverage_after_syn6_ms -lt
            $minimumSilentWindowMs -and
        -not $candidatePostTriggerFailure) {
        $blockedReasons.Add(
            'Capture did not cover the full fixed 2.75-second environment window after SYN6'
        )
    }
    if (-not $telemetryFieldsComplete -and
        -not $candidatePostTriggerFailure) {
        $blockedReasons.Add(
            'Final connecting-client telemetry is absent; product deltas are not adjudicable'
        )
    }
    if (-not $apiFinalIsolationExact) {
        $blockedReasons.Add(
            'Final client eD2K/Kad/NetLab isolation gates were not proved'
        )
    }
    $triggerFixtureRuntimeValid = $peerExact -and
        $null -ne $baselineV4 -and $baselineV4.connected -and
        $null -ne $baselineV6 -and $baselineV6.connected -and
        $prewarmEstablished -and $prewarmProgress -and
        $schedulerFloorSatisfied -and
        $null -ne $pauseOperation -and
        $null -ne $stopAOperation -and
        [string]$pauseOperation.operation -eq 'pause' -and
        [string]$stopAOperation.operation -eq 'stop' -and
        [string]$fileAPaused.state -eq 'paused' -and
        $clientIsolationExact -and
        $apiFinalIsolationExact -and
        $null -ne $clientIdentity -and
        [string]$clientIdentity.user_hash -ne
            [string]$peerReady.process.persisted_identity.user_hash -and
        $null -ne $packetVerdict -and
        $null -ne $capture -and
        [bool]$capture.etw_loss_proved_zero -and
        [bool]$capture.etl_below_circular_limit -and
        $null -ne $socketSamplerEvidence -and
        [bool]$socketSamplerEvidence.sampler_coverage_valid -and
        [int]$packetVerdict.pre_boundary_target_syn_count -eq 0 -and
        [bool]$packetVerdict.pid_packet_correlation_complete -and
        ($candidatePostTriggerFailure -or
            [int]$packetVerdict.ipv6_syn_count -eq 0 -or
            [bool]$packetVerdict.silent_drop_proved) -and
        -not [bool]$packetVerdict.environment_rejected_blackhole_in_fixed_window -and
        -not $otherPidObserved -and $ambiguousMarkerDelta -eq 0
    if ($triggerFixtureRuntimeValid) {
        if ($candidatePostTriggerFailure) {
            $productFailures.Add($candidatePostTriggerFailure)
        } elseif ([int]$packetVerdict.ipv6_syn_count -eq 0) {
            $productFailures.Add(
                'Candidate emitted no IPv6 SYN after formal Stop A'
            )
        }
        if ([int]$packetVerdict.ipv6_syn_count -gt 0 -and
            -not $packetVerdict.fallback_in_planning_window) {
            $productFailures.Add(
                'First IPv4 SYN was not in the required 2.75-to-<8 second planning window'
            )
        }
        if ([int]$packetVerdict.ipv6_syn_count -gt 0 -and (
            -not $packetVerdict.connection_under_limit -or
            -not $packetVerdict.ipv4_final_ack_observed)) {
            $productFailures.Add(
                "IPv4 did not complete below $FallbackLimitSeconds seconds"
            )
        }
        if ([int]$packetVerdict.ipv6_syn_count -gt 0 -and
            [int]$packetVerdict.distinct_ipv4_connection_attempts -ne 1) {
            $productFailures.Add(
                "Expected one IPv4 fallback transport, observed $($packetVerdict.distinct_ipv4_connection_attempts)"
            )
        }
        if ([int]$packetVerdict.ipv6_syn_count -gt 0 -and
            [int]$packetVerdict.distinct_ipv6_connection_attempts -ne 1) {
            $productFailures.Add(
                "Expected one IPv6 transport attempt (retransmissions share ISN), observed $($packetVerdict.distinct_ipv6_connection_attempts)"
            )
        }
        if (-not $candidatePostTriggerFailure -and (
            $fallbackDelta -ne 1 -or $boundedFallbackDelta -ne 1)) {
            $productFailures.Add(
                "Expected one bounded fallback log, observed fallback=$fallbackDelta bounded=$boundedFallbackDelta"
            )
        }
        if (-not $candidatePostTriggerFailure -and
            $helloDelta -ne 1) {
            $productFailures.Add(
                "Expected one queued HELLO after fallback, observed $helloDelta"
            )
        }
        if (-not $candidatePostTriggerFailure -and
            $helloAnswerDelta -ne 1) {
            $productFailures.Add(
                "Expected one HELLOANSWER after fallback, observed $helloAnswerDelta"
            )
        }
        if (-not $candidatePostTriggerFailure -and
            $a4afSwapDelta -ne 1) {
            $productFailures.Add(
                "Expected one A-to-B A4AF swap log, observed $a4afSwapDelta"
            )
        }
        if (-not $candidatePostTriggerFailure -and (
            $null -eq $fileAStopped -or
            [string]$fileAStopped.state -ne 'stopped')) {
            $productFailures.Add(
                'Classic Web did not prove file A stopped after the formal request'
            )
        }
        if (-not $candidatePostTriggerFailure -and (
            $null -eq $fileBAfterTrigger -or
            -not [bool]$fileBAfterTrigger.found -or
            $null -eq $fileBAfterTrigger.source_total -or
            [int]$fileBAfterTrigger.source_total -lt 1 -or
            -not [bool]$fileBAfterTrigger.transferred_nonzero)) {
            $productFailures.Add(
                'Classic Web did not prove file B retained the source and advanced data after A-to-B swap'
            )
        }
        if ([bool]$packetVerdict.ipv4_final_ack_observed -and
            [double]$packetVerdict.post_ipv4_connected_observation_ms -lt
                10000) {
            $productFailures.Add(
                'The required 10-second late-retry observation window did not complete'
            )
        }
        if ([int]$packetVerdict.ipv6_syn_count -gt 0 -and (
            -not $scenarioV4SocketObserved -or
            -not $scenarioV4Established)) {
            $productFailures.Add('No working candidate IPv4 fallback socket was observed')
        }
        if (-not $candidatePostTriggerFailure -and
            $telemetryFieldsComplete -and (
                [Int64]$apiTelemetryBaseline.connecting_client_count -ne 0 -or
                [Int64]$apiTelemetryBaseline.connecting_client_high_water -ne 1 -or
                [Int64]$telemetryObservedCurrentMax -ne 1 -or
                [Int64]$telemetryAddsDelta -ne 1 -or
                [Int64]$telemetryObservedAddsMax -ne
                    ([Int64]$apiTelemetryBaseline.connecting_client_adds + 1) -or
                [Int64]$telemetryDuplicateDelta -ne 0 -or
                [Int64]$telemetryObservedDuplicateMax -ne
                    [Int64]$apiTelemetryBaseline.connecting_client_duplicate_adds -or
                [Int64]$telemetryObservedHighWaterMax -ne 1 -or
                [Int64]$apiTelemetryFinal.connecting_client_high_water -ne 1 -or
                [Int64]$apiTelemetryFinal.connecting_client_count -ne 0
            )) {
            $productFailures.Add(
                'connecting_client_* telemetry did not prove exactly one logical A-to-B dial with no duplicate/re-add'
            )
        }
        if ($apiProbeCount -eq 0 -or $apiFailureCount -ne 0 -or
            $apiMaxMs -ge 1000) {
            $productFailures.Add(
                "API liveness failed: probes=$apiProbeCount failures=$apiFailureCount max_ms=$apiMaxMs"
            )
        }
        if ($uiProbeCount -eq 0 -or $uiMissingCount -ne 0 -or
            $uiFailureCount -ne 0 -or $uiMaxMs -ge 500) {
            $productFailures.Add(
                "UI liveness failed: probes=$uiProbeCount missing=$uiMissingCount failures=$uiFailureCount max_ms=$uiMaxMs"
            )
        }
    } elseif ($blockedReasons.Count -eq 0) {
        $blockedReasons.Add(
            'The complete identities/A4AF/scheduler/DROP/capture trigger fixture was not proved'
        )
    }

    $candidateAfter = Get-LabCandidateInfo -PackagePath $PackagePath `
        -ExpectedCommit $Commit
    $candidateUnchanged = $candidateAfter.emule_sha256 -eq $expectedHash
    $clientHashAfter = if ($clientExe -and
        (Test-Path -LiteralPath $clientExe -PathType Leaf)) {
        Get-LabSha256 -Path $clientExe
    } else { ''
    }
    if (-not $candidateUnchanged) {
        $cleanupFailures.Add('candidate package changed during execution')
    }
    if ($clientHashAfter -and $clientHashAfter -ne $expectedHash) {
        $cleanupFailures.Add('isolated client binary changed during execution')
    }
    $coordinatorIsolationFinal = Get-I04IsolationEvidence
    Write-LabJson -Value $coordinatorIsolationFinal -Path (
        Join-Path $evidence 'coordinator-isolation-final.json'
    ) | Out-Null
    if (-not [bool]$coordinatorIsolationFinal.strict_isolation_valid) {
        $cleanupFailures.Add(
            'coordinator overlay/VPN/proxy isolation was not intact at final audit'
        )
    }
    $cleanup = [ordered]@{
        schema = 'ese.v91.i04-coordinator-cleanup/v1'
        captured_at_utc = Get-LabUtcTimestamp
        client_process_stopped = $clientProcessesStopped
        client_process_ids = @(
            $clientOwnedProcesses | ForEach-Object { [int]$_.Id } |
                Sort-Object -Unique
        )
        controlled_ed2k_server_stopped =
            $null -ne $clientControlledServerStop -and
            [bool]$clientControlledServerStop.stopped -and
            -not [string]$clientControlledServerStop.error
        controlled_ed2k_server_owner_count =
            if ($null -eq $clientControlledServerStop) {
                0
            } else { [int]$clientControlledServerStop.owner_count }
        controlled_ed2k_server_owner_results =
            if ($null -eq $clientControlledServerStop) {
                @()
            } else { @($clientControlledServerStop.owner_results) }
        socket_sampler_stopped = if ($null -eq $socketSampler) {
            $true
        } else { [bool]$socketSampler.Stopped }
        pktmon_capture_stopped = if ($null -eq $capture) {
            $true
        } else {
            -not [bool]$capture.started -and
            (-not [bool]$capture.ever_started -or
                [bool]$capture.etw_session_stopped_verified)
        }
        pktmon_owned_filters_remaining = if ($null -eq $capture) {
            0
        } else { @($capture.filters).Count }
        pktmon_owned_filters_absent_verified = if ($null -eq $capture) {
            $true
        } else { [bool]$capture.owned_filters_absent_verified }
        pktmon_filter_inventory_restored = if ($null -eq $capture) {
            $true
        } else { [bool]$capture.filter_inventory_restored_verified }
        pktmon_etl_below_circular_limit = if ($null -eq $capture) {
            $false
        } else { [bool]$capture.etl_below_circular_limit }
        peer_restoration_confirmed = $peerRestorationExact
        hosts_file_modified = $false
        dns_cache_modified = $false
        routes_modified = $false
        adapters_modified = $false
        local_firewall_modified = $false
        isolation_initial = $coordinatorIsolationInitial
        isolation_final = $coordinatorIsolationFinal
        retained_by_design = @(
            'coordinator OutputRoot profile', 'partial fixture', 'evidence',
            'nonce-scoped coordination records'
        )
        failures = @($cleanupFailures)
    }
    Write-LabJson -Value $cleanup -Path $cleanupPath | Out-Null

    $distinctPhysicalHosts = $peerReadyExact -and
        [string]$peerReady.peer.machine_id_sha256 -ne $localMachineId
    $nativeGlobalIpv6 = (Get-LabAddressClass -Address $peerV6Text) -eq
            'global-v6' -and
        (Get-LabAddressClass -Address $coordinatorV6Text) -eq 'global-v6'
    $coordinatorNativeRoutes = $routeV4.available -and
        $routeV6.available -and
        [bool]$routeV4.physical_nonvirtual -and
        [bool]$routeV6.physical_nonvirtual -and
        [int]$routeV4.interface_index -eq [int]$routeV6.interface_index -and
        [int]$routeV4.interface_index -eq
            [int]$coordinatorAssignedV4.InterfaceIndex -and
        [string]$routeV4.source_address -eq $coordinatorV4Text -and
        [string]$routeV6.source_address -eq $coordinatorV6Text
    $peerNativeRoutes = $peerReadyExact -and $peerArmedExact -and
        [bool]$peerReady.peer.route_to_coordinator_ipv6.available -and
        [bool]$peerReady.peer.route_to_coordinator_ipv6.
            physical_nonvirtual -and
        [bool]$peerArmed.route_to_observed_ipv4_client.available -and
        [bool]$peerArmed.route_to_observed_ipv4_client.
            physical_nonvirtual -and
        [int]$peerReady.peer.route_to_coordinator_ipv6.interface_index -eq
            [int]$peerReady.peer.ipv6_interface_index -and
        [int]$peerArmed.route_to_observed_ipv4_client.interface_index -eq
            [int]$peerReady.peer.ipv4_interface_index -and
        [string]$peerReady.peer.route_to_coordinator_ipv6.source_address -eq
            $peerV6Text -and
        [string]$peerArmed.route_to_observed_ipv4_client.source_address -eq
            $peerLocalV4Text
    $physicalAdaptersAndSockets = $peerReadyExact -and
        [bool]$peerReady.peer.physical -and
        [bool]$peerReady.peer.same_interface -and
        -not [bool]$peerReady.peer.overlay_or_vpn_like -and
        $coordinatorPhysical -and
        -not $coordinatorAdapterOverlayLike -and
        $null -ne $baselineV4 -and [bool]$baselineV4.connected -and
        $null -ne $baselineV6 -and [bool]$baselineV6.connected -and
        [bool]$peerReady.endpoint.dual_stack_listener -and
        $prewarmEstablished
    $overlayVpnProxyAbsent = $peerReadyExact -and
        $peerResultExact -and
        [bool]$peerReady.peer.isolation.strict_isolation_valid -and
        [bool]$peerResult.cleanup.isolation_initial.strict_isolation_valid -and
        [bool]$peerResult.cleanup.isolation_final.strict_isolation_valid -and
        [bool]$coordinatorIsolationInitial.strict_isolation_valid -and
        [bool]$coordinatorIsolationFinal.strict_isolation_valid
    $relayAbsentBeforeTrigger = $peerReadyExact -and $peerResumedExact -and
        $clientIsolationExact -and $null -ne $apiTelemetryBaseline -and
        (Test-I04ApiIsolation -Data $peerReady.runtime_isolation `
            -RequireEd2k $true) -and
        (Test-I04ApiIsolation -Data $peerResumed.runtime_isolation `
            -RequireEd2k $true) -and
        (Test-I04ApiIsolation -Data $apiTelemetryBaseline `
            -RequireEd2k $true)
    $topologyDirectBase = $distinctPhysicalHosts -and
        $nativeGlobalIpv6 -and $coordinatorNativeRoutes -and
        $peerNativeRoutes -and $physicalAdaptersAndSockets -and
        $overlayVpnProxyAbsent -and $relayAbsentBeforeTrigger
    $topologyT1 = $topologyDirectBase -and
        $peerV4Text -eq $peerLocalV4Text -and
        [string]$peerArmed.observed_ipv4_client.address -eq
            $coordinatorV4Text -and
        [bool]$routeV4.on_link -and [bool]$routeV6.on_link -and
        [bool]$peerArmed.route_to_observed_ipv4_client.on_link -and
        [bool]$peerReady.peer.route_to_coordinator_ipv6.on_link
    $topologyT2Discriminator = $topologyDirectBase -and
        -not $topologyT1 -and (
            $peerV4Text -ne $peerLocalV4Text -or
            [string]$peerArmed.observed_ipv4_client.address -ne
                $coordinatorV4Text -or
            -not [bool]$routeV4.on_link -or
            -not [bool]$routeV6.on_link -or
            -not [bool]$peerArmed.route_to_observed_ipv4_client.on_link -or
            -not [bool]$peerReady.peer.route_to_coordinator_ipv6.on_link
        )
    $admissibleT2Ipv6NextHopClasses = @(
        'linklocal-v6', 'ula-v6', 'global-v6'
    )
    $topologyT2BilateralNativeNextHops =
        $topologyT2Discriminator -and
        [string]$routeV6.next_hop_class -in
            $admissibleT2Ipv6NextHopClasses -and
        [string]$peerReady.peer.route_to_coordinator_ipv6.next_hop_class -in
            $admissibleT2Ipv6NextHopClasses
    $topologyT2 = $topologyT2Discriminator -and
        $topologyT2BilateralNativeNextHops
    $topologyDirectStrict = $topologyT1 -or $topologyT2
    $observedTopology = if ($topologyT1) {
        'T1'
    } elseif ($topologyT2) {
        'T2'
    } else {
        'UNPROVED'
    }
    if (-not $topologyDirectStrict) {
        $blockedReasons.Add(
            'Neither strict direct T1 nor T2 was proved: two physical hosts, native global IPv6, physical data-plane routes/sockets and zero overlay/VPN/proxy/relay are required'
        )
    }
    $cleanupComplete = [bool]$cleanup.client_process_stopped -and
        [bool]$cleanup.controlled_ed2k_server_stopped -and
        [bool]$cleanup.socket_sampler_stopped -and
        [bool]$cleanup.pktmon_capture_stopped -and
        [int]$cleanup.pktmon_owned_filters_remaining -eq 0 -and
        [bool]$cleanup.pktmon_owned_filters_absent_verified -and
        [bool]$cleanup.pktmon_filter_inventory_restored -and
        [bool]$cleanup.peer_restoration_confirmed -and
        [bool]$cleanup.isolation_initial.strict_isolation_valid -and
        [bool]$cleanup.isolation_final.strict_isolation_valid
    if ($cleanupFailures.Count -gt 0) {
        $blockedReasons.Add('Transactional cleanup did not complete')
    }
    if (-not $cleanupComplete) {
        $blockedReasons.Add('Cleanup postconditions were not all proved')
    }
    if ($null -ne $runtimeFailure) {
        $blockedReasons.Add(
            "Harness/runtime error: $($runtimeFailure.Exception.Message)"
        )
    }

    $triggerFixtureValid = $triggerFixtureRuntimeValid -and
        $topologyDirectStrict -and $cleanupComplete -and
        $cleanupFailures.Count -eq 0 -and
        $null -eq $runtimeFailure -and
        $blockedReasons.Count -eq 0
    $adjudicationClean = $triggerFixtureValid -and $peerExact -and
        $null -eq $runtimeFailure -and $blockedReasons.Count -eq 0 -and
        $cleanupFailures.Count -eq 0 -and $cleanupComplete
    $adjudicablePostBoundaryCandidateFailure =
        $caseArmed -and $formalBoundaryPublished -and
        [bool]$candidatePostTriggerFailure -and $adjudicationClean
    $partialVerdict = Get-I04PartialVerdict `
        -AdjudicationClean $adjudicationClean `
        -PostBoundaryCandidateFailure `
            $adjudicablePostBoundaryCandidateFailure `
        -ProductFailureCount $productFailures.Count
    $formalStatus = if ($partialVerdict -eq 'PASS' -and
        $topologyDirectStrict) {
        'PASS'
    } elseif ($partialVerdict -eq 'FAIL' -and
        $topologyDirectStrict) {
        'FAIL'
    } else {
        'BLOCKED'
    }

    $summary = [ordered]@{
        schema = 'ese.v91.i04-fallback/v1'
        case_id = $caseId
        formal_status = $formalStatus
        partial_verdict = $partialVerdict
        formal_v91_i04_eligible =
            $topologyDirectStrict -and $adjudicationClean
        candidate = [ordered]@{
            commit = $candidate.commit
            version = $candidate.version
            expected_emule_sha256 = $expectedHash
            package_sha256_before = $candidate.emule_sha256
            package_sha256_after = $candidateAfter.emule_sha256
            client_sha256_after = $clientHashAfter
            unchanged = $candidateUnchanged
            post_trigger_failure = $candidatePostTriggerFailure
            case_armed = $caseArmed
            formal_boundary_published = $formalBoundaryPublished
            post_boundary_failure_fail_precedence =
                $adjudicablePostBoundaryCandidateFailure
        }
        topology = [ordered]@{
            required = 'T1_OR_T2_DIRECT_STRICT'
            accepted_topologies = @('T1', 'T2')
            observed_topology = $observedTopology
            proved = $topologyDirectStrict
            t1_direct_on_link = $topologyT1
            t2_direct_native_discriminator = $topologyT2Discriminator
            t2_bilateral_native_next_hops =
                $topologyT2BilateralNativeNextHops
            t2_proved = $topologyT2
            t2_admissible_ipv6_next_hop_classes =
                $admissibleT2Ipv6NextHopClasses
            distinct_physical_hosts = $distinctPhysicalHosts
            native_global_ipv6 = $nativeGlobalIpv6
            physical_adapters_and_sockets = $physicalAdaptersAndSockets
            overlay_vpn_proxy_absent = $overlayVpnProxyAbsent
            relay_absent_before_trigger = $relayAbsentBeforeTrigger
            local_machine_id_sha256 = $localMachineId
            peer_machine_id_sha256 = if (-not $peerReadyExact) {
                ''
            } else { [string]$peerReady.peer.machine_id_sha256 }
            peer_public_ipv4_endpoint = $peerV4Text
            peer_local_ipv4 = $peerLocalV4Text
            coordinator_route_to_peer_ipv4 = $routeV4
            coordinator_route_to_peer_ipv6 = $routeV6
            peer_route_to_observed_coordinator_ipv4 =
                if (-not $peerArmedExact) {
                    $null
                } else {
                    $peerArmed.route_to_observed_ipv4_client
                }
            peer_route_to_coordinator_ipv6 = if (-not $peerReadyExact) {
                $null
            } else {
                $peerReady.peer.route_to_coordinator_ipv6
            }
            coordinator_isolation_initial = $coordinatorIsolationInitial
            coordinator_isolation_final = $coordinatorIsolationFinal
            peer_isolation_initial = if (-not $peerReadyExact) {
                $null
            } else { $peerReady.peer.isolation }
            peer_isolation_final = if (-not $peerResultExact) {
                $null
            } else { $peerResult.cleanup.isolation_final }
        }
        fixture = [ordered]@{
            trigger_runtime_valid = $triggerFixtureRuntimeValid
            trigger_and_cleanup_valid = $triggerFixtureValid
            controlled_peer_acknowledged = $true
            dns_dependency = 'NOT_IN_SCOPE_V91_D01'
            exact_peer_artifacts = $peerExact
            peer_ready_exact = $peerReadyExact
            peer_armed_exact = $peerArmedExact
            peer_resumed_exact = $peerResumedExact
            peer_result_exact = $peerResultExact
            peer_restoration_exact = $peerRestorationExact
            persisted_peer_identity = [ordered]@{
                initial_user_hash = if (-not $peerReadyExact) {
                    ''
                } else {
                    [string]$peerReady.process.persisted_identity.user_hash
                }
                resumed_user_hash = if (-not $peerResumedExact) {
                    ''
                } else {
                    [string]$peerResumed.persisted_identity.user_hash
                }
                same_across_restart = $peerReadyExact -and
                    $peerResumedExact -and
                    [string]$peerReady.process.persisted_identity.user_hash -eq
                        [string]$peerResumed.persisted_identity.user_hash
            }
            independent_client_identity = [ordered]@{
                user_hash = if ($null -eq $clientIdentity) {
                    ''
                } else { [string]$clientIdentity.user_hash }
                runtime_user_hash = if ($null -eq $clientRuntime) {
                    ''
                } else { [string]$clientRuntime.user_hash }
                controlled_server_user_hash =
                    if ($null -eq $clientServerLogin) {
                        ''
                    } else {
                        [string]$clientServerLogin.runtime_user_hash
                    }
                distinct_from_peer = $null -ne $clientIdentity -and
                    $peerReadyExact -and
                    [string]$clientIdentity.user_hash -ne
                        [string]$peerReady.process.persisted_identity.user_hash
            }
            IPv4_reached_real_listener_before_drop = if ($null -eq $baselineV4) {
                $false
            } else { [bool]$baselineV4.connected }
            IPv6_reached_real_listener_before_drop = if ($null -eq $baselineV6) {
                $false
            } else { [bool]$baselineV6.connected }
            real_ipv4_prewarm_established = $prewarmEstablished
            real_ipv4_prewarm_advanced_data = $prewarmProgress
            prewarm_first_established_at_utc =
                if ($null -eq $prewarmFirstEstablishedAt) {
                    $null
                } else { $prewarmFirstEstablishedAt.ToString('o') }
            scheduler_floor_seconds = $schedulerReconnectFloorSeconds
            scheduler_floor_satisfied = $schedulerFloorSatisfied
            pause_a_preparation = $pauseOperation
            stop_a_formal_trigger = $stopAOperation
            file_a_paused_before_trigger = $fileAPaused
            file_a_after_trigger = $fileAStopped
            file_b_before_trigger = $fileBReady
            file_b_after_trigger = $fileBAfterTrigger
            same_peer_dual_route_model = 'Initial connection to the real public HighID IPv4 endpoint (which may NAT-map to PeerLocalIPv4) receives the peer HELLO with configured global IPv6/DUALSTACK; the same persisted peer is then restarted behind a remote inbound IPv6 DROP. No DNS dependency, proxy, synthetic endpoint or test-only API is used.'
            remote_ipv6_drop_proved = if ($null -eq $packetVerdict) {
                $false
            } else { [bool]$packetVerdict.silent_drop_proved }
            packet_capture_zero_loss = $null -ne $capture -and
                [bool]$capture.etw_loss_proved_zero
            packet_capture_below_circular_limit =
                $null -ne $capture -and
                [bool]$capture.etl_below_circular_limit
            socket_sampler = $socketSamplerEvidence
            pre_boundary_target_syn_count =
                if ($null -eq $packetVerdict) {
                    $null
                } else {
                    [int]$packetVerdict.pre_boundary_target_syn_count
                }
            IPv4_operational_after_drop = $scenarioV4Established
            non_candidate_pid_observed = $otherPidObserved
            candidate_ipv4_local_ports = @(
                $scenarioV4LocalPorts | Sort-Object
            )
            candidate_ipv6_local_ports = @(
                $scenarioV6LocalPorts | Sort-Object
            )
        }
        timing = [ordered]@{
            limit_seconds = $FallbackLimitSeconds
            expected_fallback_delay_ms = $expectedFallbackDelayMs
            capture_tolerance_ms = $captureTimingToleranceMs
            socket_clock_coherence_tolerance_ms =
                $socketClockCoherenceToleranceMs
            minimum_silent_window_ms = $minimumSilentWindowMs
            arm_not_before_local_epoch_ms = $armRequestedEpochMs
            arm_not_before_local_qpc = $armRequestedQpc
            pause_a_boundary_local_epoch_ms = $pauseBoundaryEpochMs
            pause_a_boundary_local_qpc = $pauseBoundaryQpc
            restart_preparation_local_epoch_ms =
                $restartPreparationEpochMs
            restart_preparation_local_qpc = $restartPreparationQpc
            stop_a_formal_boundary_local_epoch_ms =
                $restartBoundaryEpochMs
            stop_a_formal_boundary_local_qpc = $restartBoundaryQpc
            local_qpc_frequency = [Diagnostics.Stopwatch]::Frequency
            capture_ended_local_epoch_ms = $captureStoppedEpochMs
            peer_stop_to_listener_ready_ms = if (-not $peerResumedExact) {
                $null
            } else { [Int64]$peerResumed.stop_to_listener_ready_ms }
            scenario_started_at_utc = if ($null -eq $scenarioStarted) {
                $null
            } else { $scenarioStarted.ToString('o') }
            scenario_finished_at_utc = if ($null -eq $scenarioFinished) {
                $null
            } else { $scenarioFinished.ToString('o') }
            packet_verdict = $packetVerdict
        }
        single_retry = [ordered]@{
            fallback_log_delta = $fallbackDelta
            bounded_fallback_log_delta = $boundedFallbackDelta
            hello_send_delta = $helloDelta
            hello_answer_receive_delta = $helloAnswerDelta
            a4af_swap_a_to_b_delta = $a4afSwapDelta
            ambiguous_target_marker_delta = $ambiguousMarkerDelta
            exactly_one_fallback = $fallbackDelta -eq 1 -and
                $boundedFallbackDelta -eq 1
            exactly_one_hello = $helloDelta -eq 1
            exactly_one_hello_answer = $helloAnswerDelta -eq 1
            exactly_one_a4af_swap = $a4afSwapDelta -eq 1
            connecting_client_telemetry = [ordered]@{
                complete = $telemetryFieldsComplete
                baseline = $apiTelemetryBaseline
                immediate_after_stop_a = $apiTelemetryTrigger
                peak = $apiTelemetryPeak
                final = $apiTelemetryFinal
                adds_delta = $telemetryAddsDelta
                duplicate_adds_delta = $telemetryDuplicateDelta
                observed_current_max = $telemetryObservedCurrentMax
                observed_adds_max = $telemetryObservedAddsMax
                observed_duplicate_adds_max =
                    $telemetryObservedDuplicateMax
                observed_high_water_max =
                    $telemetryObservedHighWaterMax
            }
        }
        liveness = [ordered]@{
            api_probe_count = $apiProbeCount
            api_failure_count = $apiFailureCount
            api_max_duration_ms = $apiMaxMs
            ui_probe_count = $uiProbeCount
            ui_missing_window_count = $uiMissingCount
            ui_unresponsive_count = $uiFailureCount
            ui_max_duration_ms = $uiMaxMs
        }
        product_failures = @($productFailures)
        blocked_reasons = @($blockedReasons | Select-Object -Unique)
        cleanup = $cleanup
        evidence = [ordered]@{
            dns_scope = 'evidence\dns-scope.json'
            baseline = 'evidence\baseline-reachability.json'
            prewarm_tuples = 'evidence\prewarm-tuples.json'
            pid_port_correlation = 'evidence\pid-port-correlation.json'
            peer_ready = 'evidence\peer-ready.json'
            peer_drop = 'evidence\peer-drop-armed.json'
            peer_quiesced = 'evidence\peer-quiesced.json'
            peer_resumed = 'evidence\peer-resumed.json'
            peer_result = 'evidence\peer-result.json'
            runtime_samples = 'evidence\runtime-samples.jsonl'
            socket_samples = 'evidence\socket-samples.ndjson'
            socket_sampler = 'evidence\socket-sampler.json'
            packet_capture = 'evidence\capture\i04-packets.pcapng'
            etw_loss = 'evidence\capture\etw-loss.json'
            packet_verdict = 'evidence\packet-verdict.json'
            formal_trigger_baseline =
                'evidence\formal-trigger-baseline.json'
            formal_trigger_boundary =
                'evidence\formal-trigger-boundary.json'
            log_counts_after = 'evidence\logs-after-drop.json'
            client_controlled_ed2k_server =
                'evidence\client-controlled-ed2k-server.json'
            mutation_journal = 'evidence\mutation-journal.jsonl'
            cleanup = 'evidence\cleanup.json'
            manual_peer_command = if ($PeerControlMode -eq 'Manual') {
                'evidence\MANUAL-PEER-COMMAND.txt'
            } else { $null }
        }
    }
    Write-LabJson -Value $summary -Path $summaryPath | Out-Null

    if ($formalStatus -eq 'FAIL') {
        throw "V91-I04 FAIL: $($productFailures -join '; '). Evidence: $summaryPath"
    }
    if ($formalStatus -eq 'BLOCKED') {
        throw (
            'V91-I04 BLOCKED: ' +
            (@($summary.blocked_reasons) -join '; ') +
            ". Evidence: $summaryPath"
        )
    }
    Write-Host (
        "V91-I04 PASS on exact candidate/${observedTopology}: $output"
    ) `
        -ForegroundColor Green
}

if ($Role -eq 'Peer') {
    Invoke-I04PeerRole
} else {
    Invoke-I04CoordinatorRole
}
