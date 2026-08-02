<#
.SYNOPSIS
Arms the physical H3 downloader for the formal V91-I05 T1 run.

.DESCRIPTION
This parameterless kit entry point validates the exact RC3 candidate, a
physical on-link IPv4 LAN path to H1, at least 10 GiB on local NTFS, and a real
IPv6 challenge/response over that same physical NIC. Only after the IPv6 probe
succeeds does it create a clean portable profile with IPv6Mode=0.

The script opens one nonce-scoped inbound firewall rule, maps the selected
physical adapter to one exact PktMon component, arms a component-scoped
capture, starts the exact downloader with both Kad generations disabled, and
emits the private READY-V91-I05-T1.json contract. It deliberately leaves owned
resources running for the coordinator. STOP-V91-I05-DOWNLOADER.cmd performs
the exact cleanup.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$expectedCommit = '815b45ca7a1415bd3e06ff043d53794bc340b346'
$expectedVersion = '9.1.0-rc.3'
$expectedEmuleSha256 =
    '94620cf502c954cda29fa7f40f834ef1eebacb753f1fe277865d1d173e0b9b41'
$expectedEseServerSha256 =
    'c12e71a1602bb7b55077b82a72000a6980790fdf75d90bdbcba8d2843f7a0ba2'
$expectedBuildInfoSha256 =
    '48445ff0231908aa1edbb21970bcb38b91397c643c7012b65b62686bc8a63428'
$expectedArchiveBytes = 212040831L
$expectedArchiveSha256 =
    '359272c764c532c32cfd97eeb92e2db4feaa620c5d3f6318a82a7453dbf1b56f'
$fixtureName = 'v91-i05-canonical-4294967296.bin'
$fixtureBytes = 4294967296L
$fixtureSha256 =
    '1016d6f63ae1649a879a7c0de30865ed132deb37b1c3b2bc9ca004c88feee26c'
$fixtureEd2k = '796A95E75DF8E78D54A57CDEA1FEDE84'
$expectedSourceTcpPort = 7862
$expectedSourceUdpPort = 7872
$expectedSourceWebPort = 7911
$expectedProbePort = 7912
$tcpPort = 7962
$udpPort = 7972
$webPort = 8011
$controlPort = 8012
$reservedI05Ports = @(
    7862, 7872, 7911, 7912, 7962, 7972, 8011, 8012
)
$minimumFreeBytes = 10737418240L
$forbiddenInterfacePattern =
    '(?i)Tailscale|Cloudflare|WARP|vEthernet|Hyper-V'
$internalForbiddenInterfacePattern =
    '(?i)Tailscale|Cloudflare|WARP|vEthernet|Hyper-V|VPN|WireGuard|' +
    'Loopback|Npcap|Virtual|Bluetooth'
$captureFileSizeMiB = 2048
$capturePacketSize = 256
$maximumControlDocumentBytes = 1048576
$transferTimeoutSeconds = 7200
$peerConnectTimeoutSeconds = 300

$layoutRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$configAtLayout = Join-Path $layoutRoot 'V91-I05-T1-CONFIG.json'
$configAtScripts = Join-Path $PSScriptRoot 'V91-I05-T1-CONFIG.json'
$kitRoot = if (Test-Path -LiteralPath $configAtScripts -PathType Leaf) {
    [IO.Path]::GetFullPath($PSScriptRoot)
} else {
    $layoutRoot
}
$configPath = Join-Path $kitRoot 'V91-I05-T1-CONFIG.json'
$archivePath = Join-Path $kitRoot (
    'payload\candidates\eSE-LiveTV-v0.70b-eSE9.1.0-rc.3-x64.zip')
$deployedBaseManifestPath = Join-Path $kitRoot (
    'tools\lab\I05-BASE-MANIFEST.json')
$baseManifestPath = if (Test-Path -LiteralPath $deployedBaseManifestPath `
        -PathType Leaf) {
    $deployedBaseManifestPath
} else {
    Join-Path $kitRoot 'I05-BASE-MANIFEST.json'
}
$packagePath = ''
$activePath = Join-Path $kitRoot 'ACTIVE-V91-I05-T1.json'
$latestReadyPath = Join-Path $kitRoot 'READY-V91-I05-T1.json'
$latestFailurePath = Join-Path $kitRoot 'LAST-FAILURE-V91-I05-T1.json'
$latestErrorPath = Join-Path $kitRoot 'LAST-ERROR-V91-I05-T1.txt'
$latestProgressPath = Join-Path $kitRoot 'LAST-PROGRESS-V91-I05-T1.json'
$commonPath = Join-Path $PSScriptRoot 'common.ps1'
$contractPath = Join-Path $PSScriptRoot 'v91_i05_t1_contract.ps1'
$preparePath = Join-Path $PSScriptRoot 'prepare_node.ps1'
$cleanupPath = Join-Path $PSScriptRoot 'cleanup_v91_i05_downloader.ps1'
$fixtureVerifierPath = Join-Path $PSScriptRoot `
    'ensure_v91_i05_canonical_fixture.ps1'

if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) {
    throw "El kit no contiene common.ps1: $commonPath"
}
. $commonPath
if (-not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
    throw "El kit no contiene v91_i05_t1_contract.ps1: $contractPath"
}
. $contractPath

$process = $null
$processId = 0
$firewallCreated = $false
$firewallName = ''
$firewallDisplayName = ''
$controlFirewallCreated = $false
$controlFirewallName = ''
$controlFirewallDisplayName = ''
$controlListener = $null
$controlClient = $null
$controlStream = $null
$capture = $null
$captureCompleted = $false
$cleanupInvoked = $false
$runRoot = ''
$evidenceRoot = ''
$nodePath = ''
$emulePath = ''
$active = $null
$sessionPath = ''
$phase = 'preflight'
$nonce = ''
$containmentPlan = $null
$containmentCreated = $false
$containmentWatchdogIntervalMilliseconds = 500
$instanceMutex = $null
$instanceMutexOwned = $false

function Assert-I05Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'El kit V91-I05 H3 debe ejecutarse como administrador.'
    }
}

function Write-I05BootProgress {
    param([Parameter(Mandatory = $true)][string]$Stage)

    Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i05.t1-h3-progress/v1'
        case_id = 'V91-I05'
        stage = $Stage
        nonce = $script:nonce
        updated_at_utc = Get-LabUtcTimestamp
        process_id = $PID
    }) -Path $latestProgressPath | Out-Null
    Write-Output ("V91-I05-PHASE {0}" -f $Stage)
}

function Get-I05FirewallRulesByExactName {
    param([Parameter(Mandatory = $true)][string[]]$Name)

    $rules = [Collections.Generic.List[object]]::new()
    foreach ($item in $Name) {
        try {
            foreach ($rule in @(Get-NetFirewallRule -Name $item `
                    -PolicyStore ActiveStore -ErrorAction Stop)) {
                $rules.Add($rule)
            }
        } catch {
            $notFound = $_.CategoryInfo.Category -eq 'ObjectNotFound' -or
                $_.FullyQualifiedErrorId -match
                    'NoMatching.*GetNetFirewallRule|ObjectNotFound'
            if (-not $notFound) { throw }
        }
    }
    return $rules.ToArray()
}

function Get-I05FirewallRulesByExactDisplayName {
    param([Parameter(Mandatory = $true)][string]$DisplayName)

    try {
        return @(Get-NetFirewallRule -DisplayName $DisplayName `
            -PolicyStore ActiveStore -ErrorAction Stop)
    } catch {
        $notFound = $_.CategoryInfo.Category -eq 'ObjectNotFound' -or
            $_.FullyQualifiedErrorId -match
                'NoMatching.*GetNetFirewallRule|ObjectNotFound'
        if (-not $notFound) { throw }
        return @()
    }
}

function Enter-I05SingleInstance {
    param([Parameter(Mandatory = $true)][string]$RunNonce)

    $script:instanceMutex = [Threading.Mutex]::new(
        $false, "Local\eSE-V91-I05-H3-$RunNonce")
    try {
        $script:instanceMutexOwned =
            $script:instanceMutex.WaitOne(0, $false)
    } catch [Threading.AbandonedMutexException] {
        $script:instanceMutexOwned = $true
    }
    if (-not $script:instanceMutexOwned) {
        throw (
            'Ya hay una instancia V91-I05 activa para este kit. ' +
            'No vuelva a ejecutar START.'
        )
    }
}

function Exit-I05SingleInstance {
    if ($null -eq $instanceMutex) { return }
    if ($instanceMutexOwned) {
        try { $instanceMutex.ReleaseMutex() } catch {}
        $script:instanceMutexOwned = $false
    }
    try { $instanceMutex.Dispose() } catch {}
    $script:instanceMutex = $null
}

function Get-I05RequiredProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )
    if ($null -eq $InputObject) {
        throw "$Context no existe."
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "$Context.$Name no existe."
    }
    return $property.Value
}

function Assert-I05ExactString {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]$Value -cne $Expected) {
        throw "$Label no coincide. Esperado='$Expected'; actual='$Value'."
    }
}

function Assert-I05ExactPropertySet {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [Parameter(Mandatory = $true)][string]$Context
    )
    if ($null -eq $InputObject) {
        throw "$Context no existe."
    }
    $actual = @($InputObject.PSObject.Properties |
        ForEach-Object { [string]$_.Name } | Sort-Object)
    $expected = @($Names | Sort-Object -Unique)
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        throw "$Context no tiene el conjunto exacto de propiedades."
    }
}

function Throw-I05ClassifiedFailure {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('LAB_BLOCKED', 'PRODUCT_INVARIANT')]
        [string]$Classification,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $exception = New-Object InvalidOperationException($Message)
    $exception.Data['i05_classification'] = $Classification
    $exception.Data['i05_category'] = $Category
    throw $exception
}

function Assert-I05StrictBooleanFalse {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $property = if ($null -eq $InputObject) {
        $null
    } else {
        $InputObject.PSObject.Properties[$Name]
    }
    if ($null -eq $property -or $property.Value -isnot [bool] -or
        [bool]$property.Value) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'network_disabled_invariant' `
            -Message "$Context.$Name debe existir como booleano false."
    }
}

function Convert-I05IPAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$Family,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $text = $Value.Trim().Trim('[', ']')
    if ($text.Contains('%')) {
        $text = $text.Split('%')[0]
    }
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($text, [ref]$parsed) -or
        $parsed.AddressFamily -ne $Family) {
        throw "$Label no tiene la familia esperada."
    }
    return $parsed
}

function Test-I05AddressInPrefix {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][Net.IPAddress]$NetworkAddress,
        [Parameter(Mandatory = $true)][ValidateRange(0, 128)]
        [int]$PrefixLength
    )
    if ($Address.AddressFamily -ne $NetworkAddress.AddressFamily) {
        return $false
    }
    $left = $Address.GetAddressBytes()
    $right = $NetworkAddress.GetAddressBytes()
    $fullBytes = [Math]::Floor($PrefixLength / 8)
    $remainingBits = $PrefixLength % 8
    for ($index = 0; $index -lt $fullBytes; $index++) {
        if ($left[$index] -ne $right[$index]) { return $false }
    }
    if ($remainingBits -gt 0) {
        $mask = [byte](
            (0xff -shl (8 - $remainingBits)) -band 0xff)
        if (($left[$fullBytes] -band $mask) -ne
            ($right[$fullBytes] -band $mask)) {
            return $false
        }
    }
    return $true
}

function Get-I05NetworkAddress {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][ValidateRange(0, 32)]
        [int]$PrefixLength
    )
    $bytes = $Address.GetAddressBytes()
    for ($bit = $PrefixLength; $bit -lt 32; $bit++) {
        $byteIndex = [Math]::Floor($bit / 8)
        $bitIndex = 7 - ($bit % 8)
        $bytes[$byteIndex] =
            [byte]($bytes[$byteIndex] -band (-bnot (1 -shl $bitIndex)))
    }
    return New-Object Net.IPAddress -ArgumentList (, $bytes)
}

function Get-I05PhysicalLanContext {
    param([Parameter(Mandatory = $true)][Net.IPAddress]$SourceIPv4)

    $lanMatches =
        [System.Collections.Generic.List[object]]::new()
    foreach ($adapter in @(
        Get-NetAdapter -Physical -ErrorAction Stop |
            Where-Object {
                [string]$_.Status -eq 'Up' -and
                [bool]$_.HardwareInterface -and -not [bool]$_.Virtual
            }
    )) {
        $adapterText = '{0}|{1}' -f $adapter.Name,
            $adapter.InterfaceDescription
        if ($adapterText -match $internalForbiddenInterfacePattern) {
            continue
        }
        foreach ($address in @(
            Get-NetIPAddress -InterfaceIndex $adapter.ifIndex `
                -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.AddressState -eq 'Preferred' -and
                    -not $_.SkipAsSource
                }
        )) {
            $local = Convert-I05IPAddress -Value ([string]$address.IPAddress) `
                -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
                -Label 'IPv4 local'
            if ((Get-LabAddressClass -Address $local.ToString()) -ne
                'private-v4') {
                continue
            }
            $network = Get-I05NetworkAddress -Address $local `
                -PrefixLength ([int]$address.PrefixLength)
            if (-not (Test-I05AddressInPrefix -Address $SourceIPv4 `
                    -NetworkAddress $network `
                    -PrefixLength ([int]$address.PrefixLength))) {
                continue
            }
            if ($local.Equals($SourceIPv4)) {
                throw 'H1 y H3 no pueden usar la misma IPv4 LAN.'
            }
            $onLinkRoutes = @(
                Get-NetRoute -InterfaceIndex $adapter.ifIndex `
                    -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object {
                        [string]$_.NextHop -eq '0.0.0.0'
                    }
            )
            $routeMatches = @($onLinkRoutes | Where-Object {
                $parts = ([string]$_.DestinationPrefix).Split('/')
                if ($parts.Count -ne 2) { return $false }
                $routeAddress = $null
                if (-not [Net.IPAddress]::TryParse(
                        $parts[0], [ref]$routeAddress)) {
                    return $false
                }
                return Test-I05AddressInPrefix -Address $SourceIPv4 `
                    -NetworkAddress $routeAddress `
                    -PrefixLength ([int]$parts[1])
            })
            if ($routeMatches.Count -eq 0) { continue }

            $profile = Get-NetConnectionProfile `
                -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
                Select-Object -First 1
            $lanMatches.Add([pscustomobject][ordered]@{
                adapter = $adapter
                local_ipv4 = $local
                prefix_length = [int]$address.PrefixLength
                network_address = $network
                on_link_route = $routeMatches |
                    Sort-Object PrefixLength -Descending |
                    Select-Object -First 1
                network_profile = $profile
            })
        }
    }
    if ($lanMatches.Count -ne 1) {
        throw (
            'Se esperaba una sola IPv4 privada on-link hacia H1 por una NIC ' +
            "fisica activa; encontradas=$($lanMatches.Count)."
        )
    }
    return $lanMatches[0]
}

function Get-I05StorageContext {
    $volumeRoot = [IO.Path]::GetPathRoot($kitRoot)
    if ($volumeRoot -notmatch '^(?<drive>[A-Za-z]):\\$') {
        throw 'El kit debe estar en una unidad local con letra.'
    }
    $drive = $Matches['drive'].ToUpperInvariant()
    $volume = Get-Volume -DriveLetter $drive -ErrorAction Stop
    $disk = Get-CimInstance Win32_LogicalDisk -Filter (
        "DeviceID='$drive`:'") -ErrorAction Stop
    if ([string]$volume.FileSystemType -cne 'NTFS') {
        throw "La unidad del kit debe ser NTFS; actual=$($volume.FileSystemType)."
    }
    if ([int]$disk.DriveType -ne 3) {
        throw 'La unidad del kit debe ser un disco local fijo.'
    }
    if ([Int64]$disk.FreeSpace -lt $minimumFreeBytes) {
        throw (
            'Espacio insuficiente para fixture, perfil y captura. ' +
            "Libre=$([Int64]$disk.FreeSpace); requerido=$minimumFreeBytes."
        )
    }
    return [pscustomobject][ordered]@{
        drive = $drive
        filesystem = [string]$volume.FileSystemType
        free_bytes = [Int64]$disk.FreeSpace
        drive_type = [int]$disk.DriveType
        health_status = [string]$volume.HealthStatus
    }
}

function Invoke-I05IPv6Probe {
    param(
        [Parameter(Mandatory = $true)][object]$Lan,
        [Parameter(Mandatory = $true)][Net.IPAddress]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$RemotePort,
        [Parameter(Mandatory = $true)][string]$RequestLine,
        [Parameter(Mandatory = $true)][string]$ResponseLine
    )
    $binding = Get-NetAdapterBinding `
        -Name ([string]$Lan.adapter.Name) -ComponentID ms_tcpip6 `
        -ErrorAction Stop
    if ($null -eq $binding -or -not [bool]$binding.Enabled) {
        throw 'La vinculacion IPv6 ms_tcpip6 de la NIC fisica no esta activa.'
    }

    $remoteClass = Get-LabAddressClass -Address $RemoteAddress.ToString()
    $localCandidates = @(
        Get-NetIPAddress -InterfaceIndex $Lan.adapter.ifIndex `
            -AddressFamily IPv6 -ErrorAction Stop |
            Where-Object {
                $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource
            } | ForEach-Object {
                $parsed = Convert-I05IPAddress -Value ([string]$_.IPAddress) `
                    -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
                    -Label 'IPv6 local'
                [pscustomobject]@{
                    address = $parsed
                    class = Get-LabAddressClass -Address $parsed.ToString()
                }
            } | Where-Object {
                if ($remoteClass -eq 'linklocal-v6') {
                    $_.class -eq 'linklocal-v6'
                } else {
                    $_.class -in @('ula-v6', 'global-v6')
                }
            }
    )
    if ($localCandidates.Count -lt 1) {
        throw (
            "La NIC fisica no tiene una IPv6 util para probe $remoteClass."
        )
    }
    $local = $localCandidates[0].address
    if ($local.IsIPv6LinkLocal) {
        $local.ScopeId = [Int64]$Lan.adapter.ifIndex
    }
    if ($RemoteAddress.IsIPv6LinkLocal) {
        $RemoteAddress.ScopeId = [Int64]$Lan.adapter.ifIndex
    }

    $client = New-Object Net.Sockets.TcpClient(
        [Net.Sockets.AddressFamily]::InterNetworkV6)
    $stream = $null
    $writer = $null
    $reader = $null
    try {
        $client.Client.Bind((New-Object Net.IPEndPoint($local, 0)))
        $async = $client.BeginConnect($RemoteAddress, $RemotePort, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) {
            throw 'Timeout conectando al probe IPv6 H1.'
        }
        $client.EndConnect($async)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $stream.WriteTimeout = 5000
        $utf8 = New-Object Text.UTF8Encoding($false)
        $writer = New-Object IO.StreamWriter($stream, $utf8, 1024, $true)
        $writer.NewLine = "`n"
        $writer.AutoFlush = $true
        $reader = New-Object IO.StreamReader($stream, $utf8, $false, 1024, $true)
        $writer.WriteLine($RequestLine)
        $actualResponse = $reader.ReadLine()
        if ($actualResponse -cne $ResponseLine) {
            throw 'El challenge/response IPv6 no coincide con el nonce.'
        }
        $localEndPoint = [Net.IPEndPoint]$client.Client.LocalEndPoint
        $remoteEndPoint = [Net.IPEndPoint]$client.Client.RemoteEndPoint
        $localCanonical = $localEndPoint.Address.ToString().Split('%')[0].
            ToLowerInvariant()
        $remoteCanonical = $remoteEndPoint.Address.ToString().Split('%')[0].
            ToLowerInvariant()
        return [pscustomobject][ordered]@{
            success = $true
            family = 'IPv6'
            local_address = $localCanonical
            local_address_class =
                Get-LabAddressClass -Address $localCanonical
            local_ephemeral_port = [int]$localEndPoint.Port
            remote_address = $remoteCanonical
            remote_port = [int]$remoteEndPoint.Port
            request_line = $RequestLine
            response_line = $actualResponse
            completed_at_utc = Get-LabUtcTimestamp
            binding_enabled = [bool]$binding.Enabled
        }
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $writer) { $writer.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
        $client.Close()
    }
}

function Assert-I05PortAvailable {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('TCP', 'UDP')]
        [string]$Protocol,
        [Parameter(Mandatory = $true)][int]$Port
    )
    $endpoint = try {
        if ($Protocol -eq 'TCP') {
            Get-NetTCPConnection -ErrorAction Stop |
                Where-Object {
                    [string]$_.State -eq 'Listen' -and
                    [int]$_.LocalPort -eq $Port
                } | Select-Object -First 1
        } else {
            Get-NetUDPEndpoint -ErrorAction Stop |
                Where-Object { [int]$_.LocalPort -eq $Port } |
                Select-Object -First 1
        }
    } catch {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'socket_enumeration_unavailable' `
            -Message "No se pudo enumerar la tabla $Protocol."
    }
    if ($null -ne $endpoint) {
        throw "El puerto $Protocol/$Port ya esta en uso."
    }
}

function Get-I05CandidateTcpConnections {
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    try {
        return @(Get-NetTCPConnection -ErrorAction Stop |
            Where-Object { [int]$_.OwningProcess -eq $ProcessId })
    } catch {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'tcp_enumeration_unavailable' `
            -Message 'No se pudo enumerar la tabla TCP completa.'
    }
}

function Get-I05CandidateUdpEndpoints {
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    try {
        return @(Get-NetUDPEndpoint -ErrorAction Stop |
            Where-Object { [int]$_.OwningProcess -eq $ProcessId })
    } catch {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'udp_enumeration_unavailable' `
            -Message 'No se pudo enumerar la tabla UDP completa.'
    }
}

function Invoke-I05CandidateApi {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [ValidateRange(1, 30)][int]$TimeoutSec = 3,
        [Parameter(Mandatory = $true)][string]$Context,
        [ValidateRange(1, 8)][int]$MaxAttempts = 4,
        [ValidateRange(0, 5000)][int]$RetryDelayMilliseconds = 250
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return Invoke-RestMethod -Uri $Uri -TimeoutSec $TimeoutSec `
                -ErrorAction Stop
        } catch {
            if ($attempt -lt $MaxAttempts -and
                $RetryDelayMilliseconds -gt 0) {
                Start-Sleep -Milliseconds $RetryDelayMilliseconds
            }
        }
    }
    Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
        -Category 'candidate_api_unavailable' `
        -Message (
            "La API del candidato no respondio de forma estable en $Context."
        )
}

function Assert-I05FirewallEnforcementSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceStatus,
        [Parameter(Mandatory = $true)][object[]]$Profiles
    )
    if ($ServiceStatus -cne 'Running') {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'windows_firewall_disabled' `
            -Message 'MpsSvc no esta Running.'
    }
    $required = @('Domain', 'Private', 'Public')
    foreach ($name in $required) {
        $matches = @($Profiles | Where-Object {
            [string]$_.Name -ceq $name
        })
        if ($matches.Count -ne 1 -or -not [bool]$matches[0].Enabled) {
            Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
                -Category 'windows_firewall_disabled' `
                -Message "El perfil firewall $name no esta Enabled."
        }
    }
    return [pscustomobject][ordered]@{
        service_running = $true
        profiles_enabled = @($required)
        checked_at_utc = Get-LabUtcTimestamp
    }
}

function Assert-I05WindowsFirewallEnforced {
    try {
        $service = Get-Service -Name MpsSvc -ErrorAction Stop
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore `
            -ErrorAction Stop)
    } catch {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'windows_firewall_unavailable' `
            -Message 'No se pudo verificar MpsSvc/perfiles firewall.'
    }
    return Assert-I05FirewallEnforcementSnapshot `
        -ServiceStatus ([string]$service.Status) -Profiles $profiles
}

function Assert-I05ContainmentEngineTick {
    param([Parameter(Mandatory = $true)][object]$Plan)
    $null = Assert-I05WindowsFirewallEnforced
    try {
        $names = @($Plan.rules | ForEach-Object { [string]$_.name })
        $allRules = @(Get-NetFirewallRule -Name $names `
            -PolicyStore ActiveStore -ErrorAction Stop)
        $allPortFilters = @($allRules |
            Get-NetFirewallPortFilter -ErrorAction Stop)
        $allApplicationFilters = @($allRules |
            Get-NetFirewallApplicationFilter -ErrorAction Stop)
        $allAddressFilters = @($allRules |
            Get-NetFirewallAddressFilter -ErrorAction Stop)
        $allInterfaceFilters = @($allRules |
            Get-NetFirewallInterfaceFilter -ErrorAction Stop)
    } catch {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'firewall_containment_unavailable' `
            -Message (
                'No se pudo enumerar reglas/filtros firewall durante watchdog.'
            )
    }
    foreach ($spec in @($Plan.rules)) {
        $matches = @($allRules | Where-Object {
            [string]$_.Name -ceq [string]$spec.name
        })
        if ($matches.Count -ne 1) {
            Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
                -Category 'firewall_containment_changed' `
                -Message 'Una regla containment no esta presente/unica.'
        }
        $instanceId = [string]$matches[0].InstanceID
        try {
            $null = Assert-I05ContainmentRuleSnapshot `
                -Rule $matches[0] -Spec $spec `
                -Ports @($allPortFilters | Where-Object {
                    [string]$_.InstanceID -ceq $instanceId
                }) `
                -Applications @($allApplicationFilters | Where-Object {
                    [string]$_.InstanceID -ceq $instanceId
                }) `
                -Addresses @($allAddressFilters | Where-Object {
                    [string]$_.InstanceID -ceq $instanceId
                }) `
                -Interfaces @($allInterfaceFilters | Where-Object {
                    [string]$_.InstanceID -ceq $instanceId
                })
        } catch {
            Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
                -Category 'firewall_containment_changed' `
                -Message "Filtros containment alterados: $($spec.role)."
        }
    }
    return $true
}

function Get-I05IniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key
    )
    $current = ''
    $valueMatches = [System.Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*\[(.+?)\]\s*$') {
            $current = $Matches[1]
            continue
        }
        if ($current -ieq $Section -and
            $line -match '^\s*([^;#][^=]*?)\s*=(.*)$' -and
            $Matches[1].Trim() -ieq $Key) {
            $valueMatches.Add($Matches[2].Trim())
        }
    }
    if ($valueMatches.Count -ne 1) {
        throw "INI [$Section] $Key no es unico."
    }
    return $valueMatches[0]
}

function Set-I05DownloaderPreferences {
    param([Parameter(Mandatory = $true)][string]$Node)

    $config = Join-Path $Node 'config'
    $preferences = Join-Path $config 'preferences.ini'
    foreach ($identityName in @(
        'preferences.dat', 'cryptkey.dat', 'clients.met', 'known.met',
        'known2.met', 'known2_64.met', 'downloads.txt', 'downloads.bak'
    )) {
        $identityPath = Join-Path $config $identityName
        if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
            Remove-Item -LiteralPath $identityPath -Force -ErrorAction Stop
        }
    }
    foreach ($directoryName in @('Incoming', 'Temp', 'logs')) {
        $directory = Join-Path $Node $directoryName
        if (Test-Path -LiteralPath $directory -PathType Container) {
            Get-ChildItem -LiteralPath $directory -Force |
                Remove-Item -Recurse -Force -ErrorAction Stop
        } else {
            $null = New-Item -ItemType Directory -Path $directory
        }
    }
    $incoming = Join-Path $Node 'Incoming'
    $temp = Join-Path $Node 'Temp'
    foreach ($entry in ([ordered]@{
        Nick = 'eSE-B'
        Autoconnect = '0'
        NetworkED2K = '0'
        NetworkKademlia = '0'
        Serverlist = '0'
        UpdateNotifyTestClient = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        FilterBadIPs = '0'
        VerboseOptions = '1'
        Verbose = '1'
        SaveLogToDisk = '1'
        SaveDebugToDisk = '1'
        DebugClientTCP = '1'
        ConfirmExit = '0'
        CryptLayerRequested = '0'
        CryptLayerRequired = '0'
        CryptLayerSupported = '0'
        IncomingDir = ($incoming + '\')
        TempDir = ($temp + '\')
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
    }
    foreach ($entry in ([ordered]@{
        IPv6Mode = '0'
        IPv6BindAddr = ''
        KadNetworkMask = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'Connection' `
            -Key $entry.Key -Value $entry.Value
    }
    foreach ($entry in ([ordered]@{
        EseNetLabConsent = '0'
        EseNetLabAdvancedConsent = '0'
        EseNetLabContributionConsent = '0'
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
        Kad6PublicExitOptIn = '0'
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
        Port = [string]$webPort
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
    [IO.File]::WriteAllText(
        (Join-Path $config 'shareddir.dat'), '',
        (New-Object Text.UTF8Encoding($false)))
    return $preferences
}

function Get-I05FirewallProfile {
    param([AllowNull()][object]$Profile)
    if ($null -eq $Profile) { return 'Any' }
    switch ([string]$Profile.NetworkCategory) {
        'DomainAuthenticated' { return 'Domain' }
        'Private' { return 'Private' }
        'Public' { return 'Public' }
        default { return 'Any' }
    }
}

function Copy-I05MutationState {
    param(
        [Parameter(Mandatory = $true)]
        [Collections.IDictionary]$State
    )

    $names = @(
        'peer_firewall',
        'control_firewall',
        'containment_firewall',
        'pktmon_filters',
        'pktmon_session',
        'candidate_process'
    )
    if ($State.Count -ne $names.Count) {
        throw 'El estado de mutaciones I05 no tiene seis campos exactos.'
    }
    $copy = [ordered]@{}
    foreach ($name in $names) {
        if (-not $State.Contains($name)) {
            throw "Falta el estado de mutacion I05 '$name'."
        }
        $copy[$name] = [string]$State[$name]
    }
    return $copy
}

function Assert-I05FirewallRule {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string]$InterfaceAlias,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [int]$LocalPort = $tcpPort
    )
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore `
        -Name $Name -ErrorAction Stop)
    if ($rules.Count -ne 1) {
        throw 'La regla firewall nonce-scoped no es unica.'
    }
    $rule = $rules[0]
    if ([string]$rule.DisplayName -cne $DisplayName -or
        [string]$rule.Direction -ne 'Inbound' -or
        [string]$rule.Action -ne 'Allow' -or
        [string]$rule.Enabled -ne 'True') {
        throw 'La identidad base de la regla firewall no coincide.'
    }
    $portFilter = @(Get-NetFirewallPortFilter `
        -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $appFilter = @(Get-NetFirewallApplicationFilter `
        -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $addressFilter = @(Get-NetFirewallAddressFilter `
        -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $interfaceFilter = @(Get-NetFirewallInterfaceFilter `
        -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    if ($portFilter.Count -ne 1 -or
        [string]$portFilter[0].Protocol -notin @('TCP', '6') -or
        [int]$portFilter[0].LocalPort -ne $LocalPort -or
        $appFilter.Count -ne 1 -or
        [IO.Path]::GetFullPath([string]$appFilter[0].Program) -ne
            [IO.Path]::GetFullPath($Program) -or
        $addressFilter.Count -ne 1 -or
        [string]$addressFilter[0].LocalAddress -ne $LocalAddress -or
        [string]$addressFilter[0].RemoteAddress -ne $RemoteAddress -or
        $interfaceFilter.Count -ne 1 -or
        [string]$interfaceFilter[0].InterfaceAlias -ne $InterfaceAlias) {
        throw 'Los filtros de la regla firewall no coinciden exactamente.'
    }
    return $rule
}

function Convert-I05IPv4ToUInt32 {
    param([Parameter(Mandatory = $true)][string]$Address)
    $parsed = Convert-I05IPAddress -Value $Address `
        -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Label 'IPv4 containment'
    $bytes = $parsed.GetAddressBytes()
    return [UInt64]$bytes[0] * 16777216L +
        [UInt64]$bytes[1] * 65536L +
        [UInt64]$bytes[2] * 256L +
        [UInt64]$bytes[3]
}

function Convert-I05UInt32ToIPv4 {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 4294967295)][UInt64]$Value
    )
    $bytes = New-Object byte[] 4
    $bytes[0] = [byte](($Value -shr 24) -band 255)
    $bytes[1] = [byte](($Value -shr 16) -band 255)
    $bytes[2] = [byte](($Value -shr 8) -band 255)
    $bytes[3] = [byte]($Value -band 255)
    return (New-Object Net.IPAddress -ArgumentList (, $bytes)).ToString()
}

function New-I05IPv4ComplementRanges {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$AllowedIntervals
    )
    $normalized = @($AllowedIntervals | ForEach-Object {
        $start = [UInt64]$_.start
        $end = [UInt64]$_.end
        if ($start -gt $end -or $end -gt 4294967295L) {
            throw 'Intervalo IPv4 permitido invalido.'
        }
        [pscustomobject]@{ start = $start; end = $end }
    } | Sort-Object start, end)
    if ($normalized.Count -eq 0) {
        throw 'El complemento IPv4 requiere al menos un intervalo permitido.'
    }
    $merged = [System.Collections.Generic.List[object]]::new()
    foreach ($interval in $normalized) {
        if ($merged.Count -eq 0) {
            $merged.Add([pscustomobject]@{
                start = [UInt64]$interval.start
                end = [UInt64]$interval.end
            })
            continue
        }
        $last = $merged[$merged.Count - 1]
        if ([UInt64]$interval.start -le [UInt64]$last.end + 1L) {
            if ([UInt64]$interval.end -gt [UInt64]$last.end) {
                $last.end = [UInt64]$interval.end
            }
        } else {
            $merged.Add([pscustomobject]@{
                start = [UInt64]$interval.start
                end = [UInt64]$interval.end
            })
        }
    }
    $blocked = [System.Collections.Generic.List[string]]::new()
    [UInt64]$cursor = 0
    foreach ($allowed in $merged) {
        if ($cursor -lt [UInt64]$allowed.start) {
            $rangeStart = Convert-I05UInt32ToIPv4 -Value $cursor
            $rangeEnd = Convert-I05UInt32ToIPv4 `
                -Value ([UInt64]$allowed.start - 1L)
            $blocked.Add("$rangeStart-$rangeEnd")
        }
        if ([UInt64]$allowed.end -eq 4294967295L) {
            $cursor = 4294967296L
            break
        }
        $cursor = [UInt64]$allowed.end + 1L
    }
    if ($cursor -le 4294967295L) {
        $rangeStart = Convert-I05UInt32ToIPv4 -Value $cursor
        $rangeEnd = Convert-I05UInt32ToIPv4 -Value 4294967295L
        $blocked.Add("$rangeStart-$rangeEnd")
    }
    if ($blocked.Count -eq 0) {
        throw 'El complemento IPv4 no puede quedar vacio.'
    }
    return $blocked.ToArray()
}

function Test-I05IPv4InRangeSet {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][string[]]$Ranges
    )
    $value = Convert-I05IPv4ToUInt32 -Address $Address
    foreach ($range in $Ranges) {
        $parts = ([string]$range).Split('-')
        if ($parts.Count -eq 1) {
            $start = Convert-I05IPv4ToUInt32 -Address $parts[0]
            $end = $start
        } elseif ($parts.Count -eq 2) {
            $start = Convert-I05IPv4ToUInt32 -Address $parts[0]
            $end = Convert-I05IPv4ToUInt32 -Address $parts[1]
        } else {
            throw "Rango IPv4 containment invalido: $range"
        }
        if ($value -ge $start -and $value -le $end) { return $true }
    }
    return $false
}

function Get-I05CanonicalStringSetSha256 {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $material = (@($Values | Sort-Object -Unique) -join "`n")
    return Get-LabStringSha256 -Value $material
}

function Get-I05ContainmentRuleLine {
    param([Parameter(Mandatory = $true)][object]$Rule)
    return (
        'role={0}|name_sha256={1}|direction={2}|action={3}|' +
        'enabled={4}|profile={5}|protocol={6}|local_ports={7}|' +
        'remote_ports={8}|remote_addresses_sha256={9}|' +
        'remote_address_count={10}|program_sha256={11}|' +
        'all_interfaces={12}'
    ) -f [string]$Rule.role, [string]$Rule.name_sha256,
        [string]$Rule.direction, [string]$Rule.action,
        ([string]$Rule.enabled).ToLowerInvariant(),
        [string]$Rule.profile, [string]$Rule.protocol,
        (@($Rule.local_ports | Sort-Object -Unique) -join ','),
        (@($Rule.remote_ports | Sort-Object -Unique) -join ','),
        [string]$Rule.remote_addresses_sha256,
        [int]$Rule.remote_address_count,
        [string]$Rule.program_sha256,
        ([string]$Rule.all_interfaces).ToLowerInvariant()
}

function New-I05ContainmentPlan {
    param(
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string]$SourceIPv4,
        [Parameter(Mandatory = $true)][string]$Profile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot
    )
    if ($Profile -cne 'Any') {
        throw 'Las reglas containment deben aplicar a Profile Any.'
    }
    $h1 = Convert-I05IPv4ToUInt32 -Address $SourceIPv4
    $loopbackStart = Convert-I05IPv4ToUInt32 -Address '127.0.0.0'
    $loopbackEnd = Convert-I05IPv4ToUInt32 -Address '127.255.255.255'
    if ($h1 -ge $loopbackStart -and $h1 -le $loopbackEnd) {
        throw 'H1 no puede estar dentro de 127.0.0.0/8.'
    }
    $notH1 = New-I05IPv4ComplementRanges -AllowedIntervals @(
        [pscustomobject]@{ start = $h1; end = $h1 }
    )
    $notLoopback = New-I05IPv4ComplementRanges -AllowedIntervals @(
        [pscustomobject]@{
            start = $loopbackStart
            end = $loopbackEnd
        }
    )
    $notH1OrLoopback = New-I05IPv4ComplementRanges -AllowedIntervals @(
        [pscustomobject]@{ start = $h1; end = $h1 },
        [pscustomobject]@{
            start = $loopbackStart
            end = $loopbackEnd
        }
    )
    if ((Test-I05IPv4InRangeSet -Address $SourceIPv4 `
            -Ranges $notH1) -or
        (Test-I05IPv4InRangeSet -Address $SourceIPv4 `
            -Ranges $notH1OrLoopback) -or
        (Test-I05IPv4InRangeSet -Address '127.0.0.1' `
            -Ranges $notLoopback) -or
        (Test-I05IPv4InRangeSet -Address '127.0.0.1' `
            -Ranges $notH1OrLoopback)) {
        throw 'El complemento firewall solapa H1 o loopback.'
    }
    foreach ($representative in @('1.1.1.1', '100.64.0.1', '203.0.113.1')) {
        if (-not (Test-I05IPv4InRangeSet -Address $representative `
                -Ranges $notLoopback)) {
            throw 'El complemento firewall deja una IPv4 no-loopback libre.'
        }
    }
    $prefix = "eSE-V91-I05-H3-Isolation-$Nonce"
    $programSha256 = Get-LabSha256 -Path $Program
    $definitions = @(
        [ordered]@{
            role = 'in_tcp_v4_not_h1'
            direction = 'Inbound'; protocol = 'TCP'
            local_ports = @([string]$tcpPort)
            remote_ports = @('Any'); remote_addresses = @($notH1)
        },
        [ordered]@{
            role = 'in_tcp_v6_all'
            direction = 'Inbound'; protocol = 'TCP'
            local_ports = @('Any')
            remote_ports = @('Any')
            remote_addresses = @('::/1', '8000::/1')
        },
        [ordered]@{
            role = 'in_udp_v4_all'
            direction = 'Inbound'; protocol = 'UDP'
            local_ports = @('Any')
            remote_ports = @('Any')
            remote_addresses = @('0.0.0.0-255.255.255.255')
        },
        [ordered]@{
            role = 'in_udp_v6_all'
            direction = 'Inbound'; protocol = 'UDP'
            local_ports = @('Any')
            remote_ports = @('Any')
            remote_addresses = @('::/1', '8000::/1')
        },
        [ordered]@{
            role = 'out_tcp_v4_not_h1_loopback'
            direction = 'Outbound'; protocol = 'TCP'
            local_ports = @('Any'); remote_ports = @('Any')
            remote_addresses = @($notH1OrLoopback)
        },
        [ordered]@{
            role = 'out_tcp_v4_loopback_non_api_local_ports'
            direction = 'Outbound'; protocol = 'TCP'
            local_ports = @(
                "1-$($webPort - 1)", "$($webPort + 1)-65535"
            )
            remote_ports = @('Any')
            remote_addresses = @(
                '127.0.0.0-127.255.255.255'
            )
        },
        [ordered]@{
            role = 'out_tcp_v4_h1_wrong_ports'
            direction = 'Outbound'; protocol = 'TCP'
            local_ports = @('Any')
            remote_ports = @(
                "1-$($expectedSourceTcpPort - 1)",
                "$($expectedSourceTcpPort + 1)-65535"
            )
            remote_addresses = @($SourceIPv4)
        },
        [ordered]@{
            role = 'out_tcp_v6_all'
            direction = 'Outbound'; protocol = 'TCP'
            local_ports = @('Any'); remote_ports = @('Any')
            remote_addresses = @('::/1', '8000::/1')
        },
        [ordered]@{
            role = 'out_udp_v4_all'
            direction = 'Outbound'; protocol = 'UDP'
            local_ports = @('Any'); remote_ports = @('Any')
            remote_addresses = @('0.0.0.0-255.255.255.255')
        },
        [ordered]@{
            role = 'out_udp_v6_all'
            direction = 'Outbound'; protocol = 'UDP'
            local_ports = @('Any'); remote_ports = @('Any')
            remote_addresses = @('::/1', '8000::/1')
        }
    )
    $rules = [System.Collections.Generic.List[object]]::new()
    foreach ($definition in $definitions) {
        $roleToken = ([string]$definition.role -replace '_', '-')
        $name = "$prefix-$roleToken"
        $canonical = [ordered]@{
            role = [string]$definition.role
            name_sha256 = Get-LabStringSha256 -Value $name
            direction = [string]$definition.direction
            action = 'Block'
            enabled = $true
            profile = $Profile
            protocol = [string]$definition.protocol
            local_ports = @($definition.local_ports)
            remote_ports = @($definition.remote_ports)
            remote_addresses_sha256 =
                Get-I05CanonicalStringSetSha256 `
                    -Values @($definition.remote_addresses)
            remote_address_count =
                @($definition.remote_addresses | Sort-Object -Unique).Count
            program_sha256 = $programSha256
            all_interfaces = $true
        }
        $rules.Add([pscustomobject][ordered]@{
            role = [string]$definition.role
            name = $name
            display_name = "eSE V91 I05 H3 Isolation $Nonce $roleToken"
            direction = [string]$definition.direction
            action = 'Block'
            enabled = $true
            profile = $Profile
            protocol = [string]$definition.protocol
            local_ports = @($definition.local_ports)
            remote_ports = @($definition.remote_ports)
            remote_addresses = @($definition.remote_addresses)
            program = [IO.Path]::GetFullPath($Program)
            canonical = [pscustomobject]$canonical
        })
    }
    if ($rules.Count -ne 10) {
        throw 'El plan de containment debe tener exactamente diez reglas.'
    }
    $canonicalRules = @($rules | ForEach-Object { $_.canonical } |
        Sort-Object role)
    $specMaterial = @($canonicalRules | ForEach-Object {
        Get-I05ContainmentRuleLine -Rule $_
    }) -join "`n"
    $ruleNamesMaterial = @($rules | ForEach-Object {
        [string]$_.name
    } | Sort-Object) -join "`n"
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-firewall-containment-plan/v1'
        case_id = 'V91-I05'
        nonce = $Nonce
        rule_count = $rules.Count
        rules = $rules.ToArray()
        canonical_rules = $canonicalRules
        spec_material = $specMaterial
        spec_sha256 = Get-LabStringSha256 -Value $specMaterial
        rule_names_sha256 =
            Get-LabStringSha256 -Value $ruleNamesMaterial
        spec_path = Join-Path $EvidenceRoot `
            'firewall-containment-spec.json'
        inventory_before_path = Join-Path $EvidenceRoot `
            'firewall-containment-inventory-before.json'
        inventory_armed_path = Join-Path $EvidenceRoot `
            'firewall-containment-inventory-armed.json'
        inventory_verified_path = Join-Path $EvidenceRoot `
            'firewall-containment-inventory-verified.json'
        inventory_after_path = Join-Path $EvidenceRoot `
            'firewall-containment-inventory-after.json'
        inventory_before_sha256 = $null
        inventory_armed_sha256 = $null
        inventory_verified_sha256 = $null
        state_before_sha256 = $null
        state_armed_sha256 = $null
        state_verified_sha256 = $null
        spec_document_sha256 = $null
        armed_at_utc = $null
        verification_count = 0
        enforcement_check_count = 0
    }
}

function Convert-I05FirewallFilterValues {
    param([AllowNull()][object]$Value)
    $values = @($Value | ForEach-Object { [string]$_ } |
        Sort-Object -Unique)
    if ($values.Count -eq 0) { return @('Any') }
    return $values
}

function Assert-I05ContainmentRuleSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Rule,
        [Parameter(Mandatory = $true)][object]$Spec,
        [Parameter(Mandatory = $true)][object[]]$Ports,
        [Parameter(Mandatory = $true)][object[]]$Applications,
        [Parameter(Mandatory = $true)][object[]]$Addresses,
        [Parameter(Mandatory = $true)][object[]]$Interfaces
    )
    if ([string]$Rule.Name -cne [string]$Spec.name -or
        [string]$Rule.DisplayName -cne [string]$Spec.display_name -or
        [string]$Rule.Direction -cne [string]$Spec.direction -or
        [string]$Rule.Action -cne 'Block' -or
        [string]$Rule.Enabled -cne 'True' -or
        [string]$Rule.Profile -cne [string]$Spec.profile -or
        [string]$Rule.EdgeTraversalPolicy -cne 'Block') {
        throw "Identidad base containment invalida: $($Spec.role)."
    }
    if ($Ports.Count -ne 1 -or $Applications.Count -ne 1 -or
        $Addresses.Count -ne 1 -or $Interfaces.Count -ne 1) {
        throw "Cardinalidad de filtros containment invalida: $($Spec.role)."
    }
    $protocolExpected = if ([string]$Spec.protocol -ceq 'TCP') {
        @('TCP', '6')
    } else {
        @('UDP', '17')
    }
    $localPorts = Convert-I05FirewallFilterValues `
        -Value $Ports[0].LocalPort
    $remotePorts = Convert-I05FirewallFilterValues `
        -Value $Ports[0].RemotePort
    $remoteAddresses = Convert-I05FirewallFilterValues `
        -Value $Addresses[0].RemoteAddress
    $localAddresses = Convert-I05FirewallFilterValues `
        -Value $Addresses[0].LocalAddress
    $interfaceAliases = Convert-I05FirewallFilterValues `
        -Value $Interfaces[0].InterfaceAlias
    if ([string]$Ports[0].Protocol -notin $protocolExpected -or
        ($localPorts -join "`n") -cne
            ((@($Spec.local_ports | Sort-Object -Unique)) -join "`n") -or
        ($remotePorts -join "`n") -cne
            ((@($Spec.remote_ports | Sort-Object -Unique)) -join "`n") -or
        ($remoteAddresses -join "`n") -cne
            ((@($Spec.remote_addresses | Sort-Object -Unique)) -join "`n") -or
        ($localAddresses -join "`n") -cne 'Any' -or
        ($interfaceAliases -join "`n") -cne 'Any' -or
        [IO.Path]::GetFullPath([string]$Applications[0].Program) -ne
            [IO.Path]::GetFullPath([string]$Spec.program)) {
        throw "Filtros containment no exactos: $($Spec.role)."
    }
    return $Spec.canonical
}

function Assert-I05ContainmentRule {
    param(
        [Parameter(Mandatory = $true)][object]$Rule,
        [Parameter(Mandatory = $true)][object]$Spec
    )
    $ports = @(Get-NetFirewallPortFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $applications = @(Get-NetFirewallApplicationFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $addresses = @(Get-NetFirewallAddressFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $interfaces = @(Get-NetFirewallInterfaceFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    return Assert-I05ContainmentRuleSnapshot -Rule $Rule -Spec $Spec `
        -Ports $ports -Applications $applications `
        -Addresses $addresses -Interfaces $interfaces
}

function Get-I05ScopedContainmentInventory {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)]
        [ValidateSet('before', 'armed', 'after')][string]$Stage,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $allRules = if ($Stage -ceq 'armed') {
        @(Get-NetFirewallRule -Name @(
                $Plan.rules | ForEach-Object { [string]$_.name }
            ) -PolicyStore ActiveStore -ErrorAction Stop)
    } else {
        @(Get-I05FirewallRulesByExactName -Name @(
            $Plan.rules | ForEach-Object { [string]$_.name }
        ))
    }
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($spec in @($Plan.rules | Sort-Object role)) {
        $matches = @($allRules | Where-Object {
            [string]$_.Name -ceq [string]$spec.name
        })
        if ($matches.Count -gt 1) {
            throw "Regla containment ambigua: $($spec.role)."
        }
        $present = $matches.Count -eq 1
        $lineSha = $null
        if ($present) {
            $canonical = Assert-I05ContainmentRule `
                -Rule $matches[0] -Spec $spec
            $lineSha = Get-LabStringSha256 -Value (
                Get-I05ContainmentRuleLine -Rule $canonical)
        }
        $entries.Add([pscustomobject][ordered]@{
            role = [string]$spec.role
            name_sha256 = [string]$spec.canonical.name_sha256
            present = [bool]$present
            observed_spec_line_sha256 = $lineSha
        })
    }
    $stateMaterial = @($entries | Sort-Object role | ForEach-Object {
        'role={0}|name_sha256={1}|present={2}|spec_line_sha256={3}' -f
            [string]$_.role, [string]$_.name_sha256,
            ([string]$_.present).ToLowerInvariant(),
            [string]$_.observed_spec_line_sha256
    }) -join "`n"
    $document = [ordered]@{
        schema = 'ese.v91.i05.t1-firewall-containment-inventory/v1'
        case_id = 'V91-I05'
        nonce = [string]$Plan.nonce
        stage = $Stage
        created_at_utc = Get-LabUtcTimestamp
        scope = 'exact-ten-nonce-program-rules-only'
        global_inventory_included = $false
        rule_count = [int]$Plan.rule_count
        entries = $entries.ToArray()
        state_sha256 = Get-LabStringSha256 -Value $stateMaterial
    }
    $written = Write-LabJson -Value $document -Path $Path
    return [pscustomobject][ordered]@{
        path = $written
        sha256 = Get-LabSha256 -Path $written
        state_sha256 = [string]$document.state_sha256
        present_count = @($entries | Where-Object present).Count
        absent_count = @($entries | Where-Object { -not $_.present }).Count
        entries = $entries.ToArray()
    }
}

function Install-I05ContainmentRules {
    param([Parameter(Mandatory = $true)][object]$Plan)
    foreach ($spec in @($Plan.rules | Sort-Object role)) {
        $arguments = @{
            Name = [string]$spec.name
            DisplayName = [string]$spec.display_name
            Direction = [string]$spec.direction
            Action = 'Block'
            Enabled = 'True'
            Profile = [string]$spec.profile
            Protocol = [string]$spec.protocol
            RemoteAddress = @($spec.remote_addresses)
            Program = [string]$spec.program
            EdgeTraversalPolicy = 'Block'
            ErrorAction = 'Stop'
        }
        if ((@($spec.local_ports) -join '') -cne 'Any') {
            $arguments.LocalPort = @($spec.local_ports)
        }
        if ((@($spec.remote_ports) -join '') -cne 'Any') {
            $arguments.RemotePort = @($spec.remote_ports)
        }
        New-NetFirewallRule @arguments | Out-Null
    }
}

function Convert-I05GuidCanonical {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParse(([string]$Value).Trim(), [ref]$parsed)) {
        return $null
    }
    return $parsed.ToString('D').ToLowerInvariant()
}

function Convert-I05MacCanonical {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $text = (([string]$Value) -replace '[^0-9A-Fa-f]', '').
        ToLowerInvariant()
    if ($text -notmatch '^[0-9a-f]{12}$') { return $null }
    return $text
}

function ConvertTo-I05PktMonId {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$AllowZero
    )
    $text = [string]$Value
    $pattern = if ($AllowZero) { '^(?:0|[1-9][0-9]{0,9})$' } else {
        '^[1-9][0-9]{0,9}$'
    }
    if ($text -notmatch $pattern) {
        throw "$Label no es un identificador decimal valido."
    }
    $number = [Int64]$text
    if ($number -gt [Int32]::MaxValue) {
        throw "$Label excede Int32."
    }
    return [int]$number
}

function Get-I05PktMonComponentMappingFromJson {
    param(
        [Parameter(Mandatory = $true)][string]$Json,
        [Parameter(Mandatory = $true)][string]$InterfaceGuid,
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$MacAddress
    )
    try {
        $document = $Json | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "pktmon list --json no es JSON valido: $($_.Exception.Message)"
    }
    $components = [System.Collections.Generic.List[object]]::new()
    $trimmedJson = $Json.TrimStart()
    if ($trimmedJson.StartsWith('[')) {
        $groups = @($document)
        if ($groups.Count -eq 0) {
            throw 'pktmon list --json contiene una matriz de grupos vacia.'
        }
        foreach ($group in $groups) {
            if ($null -eq $group) {
                throw 'pktmon list --json contiene un grupo nulo.'
            }
            $groupComponents =
                $group.PSObject.Properties['Components']
            if ($null -eq $groupComponents -or
                $null -eq $groupComponents.Value) {
                throw (
                    'pktmon list --json contiene un grupo sin Components.'
                )
            }
            foreach ($component in @($groupComponents.Value)) {
                if ($null -ne $component) {
                    $components.Add($component)
                }
            }
        }
    } else {
        $componentsProperty =
            $document.PSObject.Properties['Components']
        if ($null -eq $componentsProperty -or
            $null -eq $componentsProperty.Value) {
            throw (
                'pktmon list --json no contiene Components ni una ' +
                'matriz de grupos con Components.'
            )
        }
        foreach ($component in @($componentsProperty.Value)) {
            if ($null -ne $component) {
                $components.Add($component)
            }
        }
    }
    if ($components.Count -eq 0) {
        throw 'pktmon list --json no contiene componentes.'
    }
    $expectedGuid = Convert-I05GuidCanonical -Value $InterfaceGuid
    if ($null -eq $expectedGuid) {
        throw 'Get-NetAdapter.InterfaceGuid no es un GUID valido.'
    }
    $expectedMac = Convert-I05MacCanonical -Value $MacAddress
    if ($null -eq $expectedMac) {
        throw 'Get-NetAdapter.MacAddress no es una MAC valida.'
    }
    $componentMatches =
        [System.Collections.Generic.List[object]]::new()
    foreach ($component in $components) {
        $propertiesProperty = $component.PSObject.Properties['Properties']
        if ($null -eq $propertiesProperty -or
            $null -eq $propertiesProperty.Value) {
            continue
        }
        $properties = @($propertiesProperty.Value)
        $guidValues = @($properties | ForEach-Object {
            $valueProperty = $_.PSObject.Properties['Value']
            if ($null -ne $valueProperty) {
                Convert-I05GuidCanonical -Value $valueProperty.Value
            }
        } | Where-Object { $null -ne $_ })
        if (@($guidValues | Where-Object {
                $_ -ceq $expectedGuid
            }).Count -eq 0) {
            continue
        }

        $ifIndexValues = [System.Collections.Generic.List[int]]::new()
        $macValues = [System.Collections.Generic.List[string]]::new()
        foreach ($property in $properties) {
            $nameProperty = $property.PSObject.Properties['Name']
            if ($null -eq $nameProperty) {
                $nameProperty = $property.PSObject.Properties['Key']
            }
            $valueProperty = $property.PSObject.Properties['Value']
            if ($null -eq $nameProperty -or $null -eq $valueProperty) {
                continue
            }
            $propertyName = [string]$nameProperty.Value
            $propertyNameNormalized = (
                $propertyName -replace '[^A-Za-z0-9]', ''
            ).ToLowerInvariant()
            if ($propertyNameNormalized -in @(
                    'ifindex', 'interfaceindex'
                )) {
                $ifText = [string]$valueProperty.Value
                if ($ifText -notmatch '^[1-9][0-9]{0,9}$' -or
                    [Int64]$ifText -gt [Int32]::MaxValue) {
                    throw 'PktMon expone un IfIndex no valido.'
                }
                $ifIndexValues.Add([int]$ifText)
            }
            if ($propertyNameNormalized -match
                    '(?:mac|physicaladdress|permanentaddress)') {
                $candidateMac = Convert-I05MacCanonical `
                    -Value $valueProperty.Value
                if ($null -ne $candidateMac) {
                    $macValues.Add($candidateMac)
                }
            }
        }
        if ($ifIndexValues.Count -gt 0 -and
            @($ifIndexValues | Where-Object {
                $_ -eq $InterfaceIndex
            }).Count -eq 0) {
            throw 'El componente GUID coincide pero su IfIndex contradice la NIC.'
        }
        if ($macValues.Count -gt 0 -and
            @($macValues | Where-Object {
                $_ -ceq $expectedMac
            }).Count -eq 0) {
            throw 'El componente GUID coincide pero su MAC contradice la NIC.'
        }
        $idProperty = $component.PSObject.Properties['Id']
        if ($null -eq $idProperty) {
            throw 'El componente PktMon exacto no contiene Id.'
        }
        $primaryId = ConvertTo-I05PktMonId -Value $idProperty.Value `
            -Label 'PktMon Components[].Id'
        $secondaryId = 0
        $secondaryProperty = $component.PSObject.Properties['SecondaryId']
        if ($null -ne $secondaryProperty -and
            $null -ne $secondaryProperty.Value -and
            [string]$secondaryProperty.Value -ne '') {
            $secondaryId = ConvertTo-I05PktMonId `
                -Value $secondaryProperty.Value `
                -Label 'PktMon Components[].SecondaryId' -AllowZero
        }
        if ($secondaryId -eq $primaryId) {
            throw 'PktMon Id y SecondaryId no pueden ser identicos.'
        }
        $nameProperty = $component.PSObject.Properties['Name']
        $typeProperty = $component.PSObject.Properties['Type']
        $componentMatches.Add([pscustomobject][ordered]@{
            interface_guid = $expectedGuid
            interface_index = $InterfaceIndex
            mac_address = $expectedMac
            primary_id = $primaryId
            secondary_id = $secondaryId
            conversion_component_ids = @(
                $primaryId
                if ($secondaryId -gt 0) { $secondaryId }
            )
            component_name = if ($null -ne $nameProperty) {
                [string]$nameProperty.Value
            } else { '' }
            component_type = if ($null -ne $typeProperty) {
                [string]$typeProperty.Value
            } else { '' }
            guid_property_matches =
                @($guidValues | Where-Object {
                    $_ -ceq $expectedGuid
                }).Count
            if_index_property_present = $ifIndexValues.Count -gt 0
            if_index_correlated = $ifIndexValues.Count -eq 0 -or
                @($ifIndexValues | Where-Object {
                    $_ -eq $InterfaceIndex
                }).Count -gt 0
            mac_property_present = $macValues.Count -gt 0
            mac_correlated = $macValues.Count -eq 0 -or
                @($macValues | Where-Object {
                    $_ -ceq $expectedMac
                }).Count -gt 0
        })
    }
    if ($componentMatches.Count -ne 1) {
        throw (
            'Get-NetAdapter.InterfaceGuid debe coincidir con exactamente un ' +
            "Components[].Properties[].Value de PktMon; encontrados=" +
            $componentMatches.Count + '.'
        )
    }
    return $componentMatches[0]
}

function Get-I05PktMonMappingKey {
    param([Parameter(Mandatory = $true)][object]$Mapping)
    return ('{0}|{1}|{2}|{3}|{4}' -f
        ([string]$Mapping.interface_guid).ToLowerInvariant(),
        [int]$Mapping.interface_index,
        ([string]$Mapping.mac_address).ToLowerInvariant(),
        [int]$Mapping.primary_id,
        [int]$Mapping.secondary_id)
}

function Get-I05PktMonMappingSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Adapter,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$LogPath
    )
    $result = Invoke-I05Pktmon -Arguments @('list', '--json') `
        -LogPath $LogPath
    if ($result.exit_code -ne 0) {
        throw 'pktmon list --json fallo.'
    }
    $raw = ($result.output -join "`r`n").Trim()
    if (-not $raw) {
        throw 'pktmon list --json devolvio un documento vacio.'
    }
    [IO.File]::WriteAllText(
        $Path, $raw + "`r`n", (New-Object Text.UTF8Encoding($false)))
    $mapping = Get-I05PktMonComponentMappingFromJson -Json $raw `
        -InterfaceGuid ([string]$Adapter.InterfaceGuid) `
        -InterfaceIndex ([int]$Adapter.ifIndex) `
        -MacAddress ([string]$Adapter.MacAddress)
    $mapping | Add-Member -NotePropertyName inventory_path `
        -NotePropertyValue $Path
    $mapping | Add-Member -NotePropertyName inventory_bytes `
        -NotePropertyValue ([Int64](Get-Item -LiteralPath $Path).Length)
    $mapping | Add-Member -NotePropertyName inventory_sha256 `
        -NotePropertyValue (Get-LabSha256 -Path $Path)
    $mapping | Add-Member -NotePropertyName mapping_key_sha256 `
        -NotePropertyValue (
            Get-LabStringSha256 -Value (
                Get-I05PktMonMappingKey -Mapping $mapping))
    return $mapping
}

function Select-I05UniqueComponentConversion {
    param([Parameter(Mandatory = $true)][object[]]$Results)
    $hits = @($Results | Where-Object {
        $_.PSObject.Properties['exact_peer_flow'] -and
        [bool]$_.exact_peer_flow
    })
    if ($hits.Count -ne 1) {
        throw (
            'La conversion por component-id debe producir exactamente un ' +
            "hit de flujo peer exacto; hits=$($hits.Count)."
        )
    }
    return $hits[0]
}

function Assert-I05WireEvidence {
    param([Parameter(Mandatory = $true)][object]$Wire)

    if (-not [bool]$Wire.Valid) {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'capture_parser_invalid' `
            -Message 'El PCAPNG component-scoped no es parseable integramente.'
    }
    if ([Int64]$Wire.IPv4PeerPackets -le 0 -or
        [Int64]$Wire.RejectedPeerTuplePackets -ne 0 -or
        [Int64]$Wire.ThirdPartyPeerPackets -ne 0 -or
        [Int64]$Wire.IPv6PeerPackets -ne 0) {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'capture_scope_contaminated' `
            -Message (
                'La captura fisica no aisla unicamente el tuple IPv4 exacto. ' +
                'Los paquetes ajenos/IPv6 no estan atribuidos al PID candidato.'
            )
    }
    if ([Int64]$Wire.RequestPartsI64 -le 0 -or
        ([Int64]$Wire.CompressedPart32 +
            [Int64]$Wire.SendingPartI64 +
            [Int64]$Wire.CompressedPartI64) -le 0 -or
        [Int64]$Wire.InvalidFixtureI64Frames -ne 0) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'wire_invariant' -Message (
                'Una captura valida, completa y aislada contradice los ' +
                'opcodes C5:A3 + C5:40/A2/A1 o la identidad del fixture.'
            )
    }
}

function Save-I05OwnershipDocuments {
    param(
        [Parameter(Mandatory = $true)][object]$ActiveDocument,
        [Parameter(Mandatory = $true)][string]$ActiveDocumentPath,
        [Parameter(Mandatory = $true)][object]$SessionDocument,
        [Parameter(Mandatory = $true)][string]$SessionDocumentPath
    )
    $ActiveDocument.updated_at_utc = Get-LabUtcTimestamp
    $SessionDocument.updated_at_utc = $ActiveDocument.updated_at_utc
    Write-LabJson -Value $SessionDocument `
        -Path $SessionDocumentPath | Out-Null
    Write-LabJson -Value $ActiveDocument `
        -Path $ActiveDocumentPath | Out-Null
}

function Set-I05MutationState {
    param(
        [Parameter(Mandatory = $true)][object]$ActiveDocument,
        [Parameter(Mandatory = $true)][string]$ActiveDocumentPath,
        [Parameter(Mandatory = $true)][object]$SessionDocument,
        [Parameter(Mandatory = $true)][string]$SessionDocumentPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'peer_firewall', 'control_firewall', 'containment_firewall',
            'pktmon_filters', 'pktmon_session', 'candidate_process'
        )][string]$Resource,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'NOT_STARTED', 'PENDING', 'OWNED', 'COMPLETED', 'REMOVED'
        )][string]$State
    )
    $ActiveDocument.mutations.$Resource = $State
    $SessionDocument.mutations.$Resource = $State
    Save-I05OwnershipDocuments -ActiveDocument $ActiveDocument `
        -ActiveDocumentPath $ActiveDocumentPath `
        -SessionDocument $SessionDocument `
        -SessionDocumentPath $SessionDocumentPath
}

function Invoke-I05Pktmon {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath
    )
    $output = @(& pktmon.exe @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    Add-Content -LiteralPath $LogPath -Encoding utf8 -Value @(
        ('[{0}] pktmon {1}' -f (Get-LabUtcTimestamp),
            ($Arguments -join ' ')),
        ($output -join "`r`n"),
        "exit_code=$exitCode"
    )
    return [pscustomobject][ordered]@{
        exit_code = $exitCode
        output = $output
    }
}

function Get-I05PktMonFilterRows {
    param([Parameter(Mandatory = $true)][object[]]$Lines)

    return @($Lines | ForEach-Object {
        $line = [string]$_
        if ($line -match '^\s*\d+\s+(.+?)\s*$') {
            ([regex]::Replace($Matches[1], '\s+', ' ')).
                ToLowerInvariant()
        }
    } | Sort-Object)
}

function Assert-I05PktMonFilterRowsExact {
    param(
        [Parameter(Mandatory = $true)][object[]]$ExpectedLines,
        [Parameter(Mandatory = $true)][object[]]$ActualLines
    )

    $expected = @(Get-I05PktMonFilterRows -Lines $ExpectedLines)
    $actual = @(Get-I05PktMonFilterRows -Lines $ActualLines)
    if ($expected.Count -eq 0 -or
        ($expected -join "`n") -cne ($actual -join "`n")) {
        throw 'El inventario PktMon cambio mientras la captura estaba activa.'
    }
}

function Start-I05Capture {
    param(
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$SourceIPv4,
        [Parameter(Mandatory = $true)][object]$Adapter
    )
    if ($null -eq (Get-Command pktmon.exe -ErrorAction SilentlyContinue) -or
        $null -eq (Get-Command logman.exe -ErrorAction SilentlyContinue)) {
        throw 'PktMon/logman no estan disponibles.'
    }
    $prefix = 'ese-i05-' + $Nonce.Substring(0, 8)
    $state = [pscustomobject][ordered]@{
        backend = 'pktmon'
        started = $false
        session_owned = $false
        filters = @(
            "$prefix-v4-data", "$prefix-v6-src-tcp",
            "$prefix-v6-dst-tcp", "$prefix-v6-src-udp",
            "$prefix-v6-dst-udp"
        )
        filters_verified = $false
        filters_before = Join-Path $Evidence 'pktmon-filters-before.txt'
        filters_armed = Join-Path $Evidence 'pktmon-filters-armed.txt'
        filters_before_reset =
            Join-Path $Evidence 'pktmon-filters-before-reset.txt'
        filters_after = Join-Path $Evidence 'pktmon-filters-after.txt'
        command_log = Join-Path $Evidence 'pktmon.log'
        counters_path = Join-Path $Evidence 'pktmon-counters.txt'
        etl_path = Join-Path $Evidence 'v91-i05-t1-packets.etl'
        pcapng_path = Join-Path $Evidence 'v91-i05-t1-packets.pcapng'
        session_before = Join-Path $Evidence 'pktmon-session-before.txt'
        session_armed = Join-Path $Evidence 'pktmon-session-armed.txt'
        session_before_stop =
            Join-Path $Evidence 'pktmon-session-before-stop.txt'
        session_after = Join-Path $Evidence 'pktmon-session-after.txt'
        loss_path = Join-Path $Evidence 'pktmon-etw-loss.json'
        intent_path = Join-Path $Evidence 'pktmon-intent-private.json'
        component_pre_raw_path =
            Join-Path $Evidence 'pktmon-components-pre.raw.json'
        component_armed_raw_path =
            Join-Path $Evidence 'pktmon-components-armed.raw.json'
        component_post_raw_path =
            Join-Path $Evidence 'pktmon-components-post.raw.json'
        component_mapping_path =
            Join-Path $Evidence 'component-mapping.json'
        component_pre_compact_path =
            Join-Path $Evidence 'component-inventory-pre.json'
        component_armed_compact_path =
            Join-Path $Evidence 'component-inventory-armed.json'
        component_post_compact_path =
            Join-Path $Evidence 'component-inventory-post.json'
        component_pre = $null
        component_armed = $null
        component_post = $null
        conversion_results = @()
    }
    $state.component_pre = Get-I05PktMonMappingSnapshot `
        -Adapter $Adapter -Path $state.component_pre_raw_path `
        -LogPath $state.command_log
    @(& pktmon.exe filter list 2>&1) |
        Set-Content -LiteralPath $state.filters_before -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo inventariar los filtros PktMon.'
    }
    $before = Get-Content -LiteralPath $state.filters_before -Raw
    $emptyFilterInventory = $before -match
        '(?im)^\s*(?:none|no\s+filters(?:\s+(?:are\s+)?(?:configured|present))?|ning.n[oa]?|ning.n\s+filtro|no\s+hay\s+filtros|sin\s+filtros|no\s+se\s+especificaron\s+filtros\s+de\s+paquete)\.?\s*$'
    if (-not $emptyFilterInventory) {
        throw (
            'El inventario global PktMon no esta demostrablemente vacio; ' +
            'se rechaza una captura contaminada.'
        )
    }
    foreach ($filterName in $state.filters) {
        if ($before.IndexOf(
                $filterName, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "Ya existe el filtro PktMon propio '$filterName'."
        }
    }
    @(& logman.exe query -ets PktMon 2>&1) |
        Set-Content -LiteralPath $state.session_before -Encoding utf8
    if ($LASTEXITCODE -eq 0) {
        throw 'Ya existe una sesion ETW PktMon activa; no se toma propiedad.'
    }
    $definitions = @(
        @('filter', 'add', $state.filters[0], '-i', $SourceIPv4,
            '-t', 'TCP', '-p', [string]$expectedSourceTcpPort),
        @('filter', 'add', $state.filters[1], '-d', 'IPv6',
            '-t', 'TCP', '-p', [string]$expectedSourceTcpPort),
        @('filter', 'add', $state.filters[2], '-d', 'IPv6',
            '-t', 'TCP', '-p', [string]$tcpPort),
        @('filter', 'add', $state.filters[3], '-d', 'IPv6',
            '-t', 'UDP', '-p', [string]$expectedSourceUdpPort),
        @('filter', 'add', $state.filters[4], '-d', 'IPv6',
            '-t', 'UDP', '-p', [string]$udpPort)
    )
    try {
        foreach ($definition in $definitions) {
            $result = Invoke-I05Pktmon -Arguments $definition `
                -LogPath $state.command_log
            if ($result.exit_code -ne 0) {
                throw 'PktMon rechazo un filtro V91-I05.'
            }
        }
        @(& pktmon.exe filter list 2>&1) |
            Set-Content -LiteralPath $state.filters_armed -Encoding utf8
        $armed = Get-Content -LiteralPath $state.filters_armed -Raw
        foreach ($filterName in $state.filters) {
            if ($armed.IndexOf(
                    $filterName, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                throw "PktMon no enumera el filtro '$filterName'."
            }
        }
        $state.filters_verified = $true
        $state.component_armed = Get-I05PktMonMappingSnapshot `
            -Adapter $Adapter -Path $state.component_armed_raw_path `
            -LogPath $state.command_log
        if ((Get-I05PktMonMappingKey -Mapping $state.component_pre) -cne
            (Get-I05PktMonMappingKey -Mapping $state.component_armed)) {
            throw 'El mapping PktMon GUID/Id cambio entre pre y armed.'
        }
        $intent = [ordered]@{
            schema = 'ese.v91.i05.t1-pktmon-intent/v1'
            case_id = 'V91-I05'
            nonce = $Nonce
            created_at_utc = Get-LabUtcTimestamp
            source_ipv4 = $SourceIPv4
            source_ipv4_sha256 = Get-LabStringSha256 -Value $SourceIPv4
            source_tcp_port = $expectedSourceTcpPort
            source_udp_port = $expectedSourceUdpPort
            downloader_tcp_port = $tcpPort
            downloader_udp_port = $udpPort
            filters = $state.filters
            capture_component_id =
                [int]$state.component_pre.primary_id
            capture_secondary_component_id =
                [int]$state.component_pre.secondary_id
            interface_guid_sha256 = Get-LabStringSha256 -Value (
                [string]$state.component_pre.interface_guid)
            component_mapping_key_sha256 =
                [string]$state.component_pre.mapping_key_sha256
            packet_size = $capturePacketSize
            maximum_file_mib = $captureFileSizeMiB
            full_payload_requested = $false
            fail_closed = $true
        }
        Write-LabJson -Value $intent -Path $state.intent_path | Out-Null
        $start = Invoke-I05Pktmon -Arguments @(
            'start', '--capture', '--comp',
            [string]$state.component_pre.primary_id, '--pkt-size',
            [string]$capturePacketSize,
            '--file-name', $state.etl_path, '--file-size',
            [string]$captureFileSizeMiB, '--log-mode', 'circular'
        ) -LogPath $state.command_log
        @(& logman.exe query -ets PktMon 2>&1) |
            Set-Content -LiteralPath $state.session_armed -Encoding utf8
        $sessionArmedExit = $LASTEXITCODE
        $sessionArmedText =
            Get-Content -LiteralPath $state.session_armed -Raw
        $state.session_owned = $sessionArmedExit -eq 0 -and
            $sessionArmedText.IndexOf(
                ([IO.Path]::GetFullPath([string]$state.etl_path)),
                [StringComparison]::OrdinalIgnoreCase) -ge 0
        $state.started = $start.exit_code -eq 0 -and $state.session_owned
        if (-not $state.started) {
            throw 'No se pudo armar y verificar la captura PktMon.'
        }
        return $state
    } catch {
        # ACTIVE+session PENDING precede this function. The formal cleanup is
        # the only authority allowed to stop/remove partially owned resources.
        throw
    }
}

function Get-I05BytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Read-I05StreamExact {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1048576)][int]$Length
    )
    $bytes = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($bytes, $offset, $Length - $offset)
        if ($read -le 0) {
            throw 'El canal LAN se cerro antes de recibir el documento.'
        }
        $offset += $read
    }
    return $bytes
}

function Read-I05ControlLine {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [ValidateRange(32, 4096)][int]$MaximumBytes = 1024
    )
    $bytes = [System.Collections.Generic.List[byte]]::new()
    while ($bytes.Count -lt $MaximumBytes) {
        $value = $Stream.ReadByte()
        if ($value -lt 0) {
            throw 'El canal LAN se cerro esperando una cabecera.'
        }
        if ($value -eq 10) {
            $array = $bytes.ToArray()
            if ($array.Count -gt 0 -and
                $array[$array.Count - 1] -eq 13) {
                $array = $array[0..($array.Count - 2)]
            }
            return [Text.Encoding]::ASCII.GetString($array)
        }
        if ($value -gt 0x7f) {
            throw 'La cabecera LAN no es ASCII.'
        }
        $bytes.Add([byte]$value)
    }
    throw 'La cabecera LAN supera el limite.'
}

function Write-I05ControlLine {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][string]$Line
    )
    if ($Line -match '[\r\n]' -or
        -not [Text.Encoding]::ASCII.GetString(
            [Text.Encoding]::ASCII.GetBytes($Line)).Equals($Line)) {
        throw 'La cabecera de control no es una linea ASCII valida.'
    }
    $bytes = [Text.Encoding]::ASCII.GetBytes($Line + "`n")
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Send-I05ControlDocument {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)]
        [ValidateSet('READY', 'STARTED', 'COMPLETE', 'CLEANUP', 'FAILURE')]
        [string]$Type,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 2 -or
        $bytes.Length -gt $maximumControlDocumentBytes) {
        throw "$Type tiene un tamano no permitido."
    }
    $hash = Get-I05BytesSha256 -Bytes $bytes
    Write-I05ControlLine -Stream $Stream -Line (
        "V91-I05-$Type $Nonce $($bytes.Length) $hash")
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
    $ack = Read-I05ControlLine -Stream $Stream
    $expectedAck = "V91-I05-$Type-ACCEPTED $Nonce $hash"
    if ($ack -cne $expectedAck) {
        throw "H1 no confirmo exactamente el frame $Type."
    }
    return $hash
}

function Receive-I05ControlDocument {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)]
        [ValidateSet('COMMAND', 'STOP')][string]$Type,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $line = Read-I05ControlLine -Stream $Stream
    $pattern = '^V91-I05-' + $Type +
        ' ([0-9a-f]{32}) ([1-9][0-9]{0,6}) ([0-9a-f]{64})$'
    if ($line -notmatch $pattern) {
        throw "Cabecera $Type invalida."
    }
    if ($Matches[1] -cne $Nonce) {
        throw "$Type usa otro nonce."
    }
    $length = [int]$Matches[2]
    if ($length -gt $maximumControlDocumentBytes) {
        throw "$Type supera 1 MiB."
    }
    $expectedHash = $Matches[3]
    $bytes = Read-I05StreamExact -Stream $Stream -Length $length
    $actualHash = Get-I05BytesSha256 -Bytes $bytes
    if ($actualHash -cne $expectedHash) {
        throw "SHA-256 de $Type no coincide."
    }
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $text = $utf8.GetString($bytes)
    $document = $text | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $document -or $document -is [Array]) {
        throw "$Type no es un objeto JSON."
    }
    [IO.File]::WriteAllBytes($Destination, $bytes)
    return [pscustomobject][ordered]@{
        document = $document
        sha256 = $actualHash
        path = $Destination
        bytes = $length
    }
}

function Confirm-I05ReceivedDocument {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)]
        [ValidateSet('COMMAND', 'STOP')][string]$Type,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$Sha256
    )
    Write-I05ControlLine -Stream $Stream -Line (
        "V91-I05-$Type-ACCEPTED $Nonce $Sha256")
}

function Assert-I05Command {
    param(
        [Parameter(Mandatory = $true)][object]$Command,
        [Parameter(Mandatory = $true)][object]$Config,
        [Parameter(Mandatory = $true)][string]$Nonce
    )
    Assert-I05ExactString -Value $Command.schema `
        -Expected 'ese.v91.i05.t1-command/v1' -Label 'COMMAND schema'
    Assert-I05ExactString -Value $Command.case_id `
        -Expected 'V91-I05' -Label 'COMMAND case_id'
    Assert-I05ExactString -Value $Command.topology `
        -Expected 'T1' -Label 'COMMAND topology'
    Assert-I05ExactString -Value $Command.status `
        -Expected 'START' -Label 'COMMAND status'
    Assert-I05ExactString -Value $Command.nonce `
        -Expected $Nonce -Label 'COMMAND nonce'
    foreach ($property in @(
        'version', 'commit', 'emule_sha256', 'ese_server_sha256',
        'build_info_sha256', 'zip_sha256', 'zip_bytes'
    )) {
        Assert-I05ExactString -Value $Command.candidate.$property `
            -Expected ([string]$Config.candidate.$property) `
            -Label "COMMAND candidate.$property"
    }
    if ([bool]$Command.candidate.dirty) {
        throw 'COMMAND.candidate.dirty debe ser false.'
    }
    foreach ($property in @(
        'ipv4_address', 'ipv4_sha256', 'interface_id',
        'tcp_port', 'udp_port', 'web_port'
    )) {
        Assert-I05ExactString `
            -Value ([string]$Command.source.$property) `
            -Expected ([string]$Config.source.$property) `
            -Label "COMMAND source.$property"
    }
    Assert-I05ExactString -Value $Command.fixture.name `
        -Expected $fixtureName -Label 'COMMAND fixture.name'
    if ([Int64]$Command.fixture.bytes -ne $fixtureBytes) {
        throw 'COMMAND fixture.bytes no coincide.'
    }
    Assert-I05ExactString -Value (
        ([string]$Command.fixture.sha256).ToLowerInvariant()
    ) -Expected $fixtureSha256 -Label 'COMMAND fixture.sha256'
    Assert-I05ExactString -Value (
        ([string]$Command.fixture.ed2k).ToUpperInvariant()
    ) -Expected $fixtureEd2k -Label 'COMMAND fixture.ed2k'
    Assert-I05ExactPropertySet -InputObject $Command.fixture -Names @(
        'name', 'bytes', 'sha256', 'ed2k',
        'direct_link', 'direct_link_sha256'
    ) -Context 'COMMAND.fixture'
    $baseLink = 'ed2k://|file|{0}|{1}|{2}|/' -f `
        $fixtureName, $fixtureBytes, $fixtureEd2k
    $directLink = $baseLink +
        "|sources,$([string]$Config.source.ipv4_address):$expectedSourceTcpPort|/"
    Assert-I05ExactString -Value $Command.fixture.direct_link `
        -Expected $directLink -Label 'COMMAND fixture.direct_link'
    Assert-I05ExactString -Value $Command.fixture.direct_link_sha256 `
        -Expected (Get-LabStringSha256 -Value $directLink) `
        -Label 'COMMAND fixture.direct_link_sha256'
    Assert-I05ExactPropertySet -InputObject $Command.injection -Names @(
        'delivery_count', 'direct_only'
    ) -Context 'COMMAND.injection'
    $directOnlyProperty = $Command.injection.PSObject.Properties['direct_only']
    if ([int]$Command.injection.delivery_count -ne 1 -or
        $null -eq $directOnlyProperty -or
        $directOnlyProperty.Value -isnot [bool] -or
        -not [bool]$directOnlyProperty.Value -or
        [string]$Command.policy.data_family -cne 'IPv4' -or
        [int]$Command.policy.ipv6_mode -ne 0 -or
        -not [bool]$Command.policy.wire_capture_required -or
        [string]$Command.policy.wire_capture_host -cne 'H3' -or
        -not [bool]$Command.policy.classic_crypt_layers_disabled) {
        throw 'COMMAND no conserva la politica formal de inyeccion IPv4.'
    }
    foreach ($name in @(
        'kad2_enabled', 'kad6_enabled', 'third_party_peers_allowed'
    )) {
        $property = $Command.policy.PSObject.Properties[$name]
        if ($null -eq $property -or $property.Value -isnot [bool] -or
            [bool]$property.Value) {
            throw "COMMAND.policy.$name debe ser booleano false."
        }
    }
    foreach ($name in @(
        'direct_link_only', 'third_party_sources_forbidden'
    )) {
        $property = $Command.policy.PSObject.Properties[$name]
        if ($null -eq $property -or $property.Value -isnot [bool] -or
            -not [bool]$property.Value) {
            throw "COMMAND.policy.$name debe ser booleano true."
        }
    }
    if ([int]$Command.policy.kad_network_mask -ne 0 -or
        [string]$Command.policy.discovery -cne 'direct-link-only') {
        throw 'COMMAND no exige Kad off y discovery direct-link-only.'
    }
    return [pscustomobject][ordered]@{
        direct_link = $directLink
        direct_link_sha256 = Get-LabStringSha256 -Value $directLink
    }
}

function Send-I05Ed2kLink {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Link
    )
    if (-not ('V91I05CopyDataTimeout' -as [type])) {
        Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class V91I05CopyDataTimeout {
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
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $handles = @()
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'El downloader termino antes de inyectar el enlace.'
        }
        $handles = @()
        if ($Process.MainWindowHandle -ne [IntPtr]::Zero) {
            $handles += $Process.MainWindowHandle
        }
        foreach ($candidateHandle in @(
                [V91I05CopyDataTimeout]::FindTopLevelWindows(
                    [uint32]$Process.Id))) {
            if ($handles -notcontains $candidateHandle) {
                $handles += $candidateHandle
            }
        }
        if ($handles.Count -gt 0) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($handles.Count -eq 0) {
        throw 'El downloader no expuso su ventana para WM_COPYDATA.'
    }
    $pointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Link)
    try {
        $payload = New-Object V91I05CopyDataTimeout+COPYDATASTRUCT
        $payload.dwData = [IntPtr]12000
        $payload.cbData = ($Link.Length + 1) * 2
        $payload.lpData = $pointer
        $acceptedResult = [UInt64]0
        foreach ($handle in $handles) {
            $nativeResult = [UIntPtr]::Zero
            $sent = [V91I05CopyDataTimeout]::SendMessageTimeout(
                $handle, 0x004A, [IntPtr]::Zero, [ref]$payload,
                0x0003, 10000, [ref]$nativeResult)
            if ($sent -ne [IntPtr]::Zero -and
                $nativeResult.ToUInt64() -ne 0) {
                $acceptedResult = $nativeResult.ToUInt64()
                break
            }
        }
        if ($acceptedResult -eq 0) {
            throw 'El candidato rechazo o bloqueo WM_COPYDATA.'
        }
        return [pscustomobject][ordered]@{
            delivered = $true
            accepted = $true
            native_result = $acceptedResult
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
    }
}

function Wait-I05QueueOwnership {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Node
    )
    $temp = Join-Path $Node 'Temp'
    $incoming = Join-Path $Node 'Incoming'
    $destination = Join-Path $incoming $fixtureName
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'El downloader termino esperando propiedad de cola.'
        }
        try {
            $parts = @(Get-ChildItem -LiteralPath $temp -File `
                -Filter '*.part' -ErrorAction Stop)
            $met = @(Get-ChildItem -LiteralPath $temp -File `
                -Filter '*.part.met' -ErrorAction Stop)
            $destinationExists = Test-Path -LiteralPath $destination `
                -PathType Leaf -ErrorAction Stop
        } catch {
            Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
                -Category 'fixture_io_unavailable' `
                -Message 'No se pudo observar Temp/Incoming tras la inyeccion.'
        }
        if ($parts.Count -eq 1 -and $met.Count -ge 1 -and
            -not $destinationExists) {
            return [pscustomobject][ordered]@{
                part_count = $parts.Count
                part_met_count = $met.Count
                observed_at_utc = Get-LabUtcTimestamp
            }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'La cola no tomo propiedad tras la unica inyeccion direct-link.'
}

function Test-I05TcpRowAllowedByIPv4Profile {
    param([Parameter(Mandatory = $true)][object]$Connection)
    $local = [string]$Connection.LocalAddress
    $remote = [string]$Connection.RemoteAddress
    if (-not $local.Contains(':') -and -not $remote.Contains(':')) {
        return $true
    }
    return $local -ceq '::1' -and
        [int]$Connection.LocalPort -eq $webPort -and
        [string]$Connection.State -in @('Listen', 'Established') -and
        $remote -in @('', '::', '::1')
}

function Test-I05ApiListenerAllowedByIPv4Profile {
    param([Parameter(Mandatory = $true)][object]$Connection)
    return [string]$Connection.State -eq 'Listen' -and
        [int]$Connection.LocalPort -eq $webPort -and
        [string]$Connection.LocalAddress -in @(
            '0.0.0.0', '127.0.0.1'
        )
}

function Assert-I05LanApiForbidden {
    param([Parameter(Mandatory = $true)][object]$Lan)
    $uri = "http://$($Lan.local_ipv4):$webPort/api/status"
    $statusCode = 0
    $denialMode = ''
    try {
        $response = Invoke-WebRequest -Uri $uri -UseBasicParsing `
            -TimeoutSec 5 -ErrorAction Stop
        $statusCode = [int]$response.StatusCode
    } catch {
        if ($null -ne $_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        } elseif ($_.Exception -is [Net.WebException]) {
            # The containment rules intentionally make the candidate's LAN
            # address unreachable. Windows reports that denial with different
            # WebException statuses depending on the active firewall profile
            # and network stack version; the relevant invariant is that no
            # HTTP response was obtainable through the physical LAN address.
            $denialMode = 'firewall-blocked'
        } else {
            Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
                -Category 'candidate_api_lan_probe_unavailable' `
                -Message (
                    'No se pudo completar el probe HTTP por la IP LAN.'
                )
        }
    }
    if ($statusCode -eq 403) {
        $denialMode = 'http-403'
    } elseif ($denialMode -cne 'firewall-blocked') {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_api_lan_access' `
            -Message (
                "La API por la IP LAN devolvio HTTP $statusCode en vez de 403."
            )
    }
    return [pscustomobject][ordered]@{
        denied = $true
        mode = $denialMode
        http_status = $statusCode
    }
}

function Assert-I05RuntimeIPv4Only {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][object]$Lan,
        [Parameter(Mandatory = $true)][string]$Preferences
    )
    $binding = Get-NetAdapterBinding `
        -Name ([string]$Lan.adapter.Name) -ComponentID ms_tcpip6 `
        -ErrorAction Stop
    if (-not [bool]$binding.Enabled) {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'windows_ipv6_binding_changed' `
            -Message 'La vinculacion IPv6 de Windows se desactivo durante T1.'
    }
    if ([string](Get-I05IniValue -Path $Preferences `
            -Section 'Connection' -Key 'IPv6Mode') -cne '0' -or
        [string](Get-I05IniValue -Path $Preferences `
            -Section 'Connection' -Key 'KadNetworkMask') -cne '0' -or
        [string](Get-I05IniValue -Path $Preferences `
            -Section 'eMule' -Key 'NetworkED2K') -cne '0' -or
        [string](Get-I05IniValue -Path $Preferences `
            -Section 'eMule' -Key 'NetworkKademlia') -cne '0' -or
        [string](Get-I05IniValue -Path $Preferences `
            -Section 'eMule' -Key 'FilterBadIPs') -cne '0') {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'network_disabled_invariant' `
            -Message (
                'IPv6Mode/KadNetworkMask/NetworkED2K/NetworkKademlia/' +
                'FilterBadIPs cambiaron durante T1.'
            )
    }
    foreach ($key in @(
        'CryptLayerRequested', 'CryptLayerRequired', 'CryptLayerSupported'
    )) {
        if ([string](Get-I05IniValue -Path $Preferences `
                -Section 'eMule' -Key $key) -cne '0') {
            Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
                -Category 'candidate_preferences_changed' `
                -Message 'La capa de cifrado clasica se activo durante T1.'
        }
    }
    $statusNow = Invoke-I05CandidateApi `
        -Uri "http://127.0.0.1:$webPort/api/status" `
        -TimeoutSec 3 -Context 'runtime status'
    foreach ($name in @(
        'kad_connected', 'kad6_running', 'kad6_connected'
    )) {
        Assert-I05StrictBooleanFalse -InputObject $statusNow `
            -Name $name -Context 'API status'
    }
    $tcpConnections = @(Get-I05CandidateTcpConnections `
        -ProcessId $ProcessId)
    $v6Sockets = @($tcpConnections | Where-Object {
        -not (Test-I05TcpRowAllowedByIPv4Profile -Connection $_)
    })
    if ($v6Sockets.Count -ne 0) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_ipv6_socket' `
            -Message (
                'El candidato abrio un socket/listener IPv6 fuera de la ' +
                'unica excepcion API loopback TCP/8011.'
            )
    }
    $peerListeners = @($tcpConnections | Where-Object {
        [string]$_.State -eq 'Listen' -and
        [int]$_.LocalPort -eq $tcpPort
    })
    if ($peerListeners.Count -lt 1 -or
        @($peerListeners | Where-Object {
            ([string]$_.LocalAddress).Contains(':')
        }).Count -ne 0) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_peer_listener' `
            -Message 'El listener peer dejo de ser exclusivamente IPv4.'
    }
    $apiListeners = @($tcpConnections | Where-Object {
        [string]$_.State -eq 'Listen' -and
        [int]$_.LocalPort -eq $webPort
    })
    if ($apiListeners.Count -lt 1 -or
        @($apiListeners | Where-Object {
            -not (Test-I05ApiListenerAllowedByIPv4Profile `
                -Connection $_)
        }).Count -ne 0) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_api_binding' `
            -Message 'La API dejo de usar un listener IPv4 nativo permitido.'
    }
    $udpEndpoints = @(Get-I05CandidateUdpEndpoints `
        -ProcessId $ProcessId)
    $udpV6 = @($udpEndpoints | Where-Object {
            ([string]$_.LocalAddress).Contains(':')
        })
    if ($udpV6.Count -ne 0) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_ipv6_udp' `
            -Message 'El endpoint UDP peer dejo de ser IPv4 puro.'
    }
    return $statusNow
}

function Wait-I05TransferComplete {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][object]$Lan,
        [Parameter(Mandatory = $true)][string]$SourceIPv4,
        [Parameter(Mandatory = $true)][string]$Preferences,
        [Parameter(Mandatory = $true)][string]$Node,
        [Parameter(Mandatory = $true)][string]$SamplesPath,
        [Parameter(Mandatory = $true)][string]$SocketProofPath,
        [Parameter(Mandatory = $true)][string]$FixtureVerifier,
        [Parameter(Mandatory = $true)][string]$FixtureSeed,
        [Parameter(Mandatory = $true)][string]$FixtureReportPath,
        [Parameter(Mandatory = $true)][Net.Sockets.TcpClient]$ControlClient,
        [Parameter(Mandatory = $true)][object]$ContainmentPlan
    )
    $started = [DateTime]::UtcNow
    $deadline = $started.AddSeconds($transferTimeoutSeconds)
    $destination = Join-Path (Join-Path $Node 'Incoming') $fixtureName
    $sampleNumber = 0
    $sawExactIPv4 = $false
    $tupleRecords = @{}
    $forbiddenEstablishedCount = 0
    $containmentVerificationCount = 0
    $engineWatchdogSamples = 0
    $lastContainmentVerification = [DateTime]::MinValue
    do {
        if ($ControlClient.Client.Poll(
                0, [Net.Sockets.SelectMode]::SelectRead)) {
            if ($ControlClient.Client.Available -eq 0) {
                throw 'H1 cerro el canal durante la transferencia.'
            }
            throw 'H1 envio datos inesperados antes de COMPLETE.'
        }
        $Process.Refresh()
        if ($Process.HasExited) {
            Throw-I05ClassifiedFailure `
                -Classification PRODUCT_INVARIANT `
                -Category 'candidate_process_exit' `
                -Message 'El downloader termino durante la transferencia.'
        }
        $null = Assert-I05ContainmentEngineTick -Plan $ContainmentPlan
        $engineWatchdogSamples++
        $ContainmentPlan.enforcement_check_count =
            [int]$ContainmentPlan.enforcement_check_count + 1
        if (([DateTime]::UtcNow - $lastContainmentVerification).
                TotalSeconds -ge 5) {
            try {
                $containmentSnapshot =
                    Get-I05ScopedContainmentInventory `
                        -Plan $ContainmentPlan -Stage armed `
                        -Path $ContainmentPlan.inventory_verified_path
            } catch {
                Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
                    -Category 'firewall_containment_changed' `
                    -Message (
                        'No se pudo verificar el containment firewall exacto.'
                    )
            }
            if ([int]$containmentSnapshot.present_count -ne 10 -or
                [int]$containmentSnapshot.absent_count -ne 0) {
                Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
                    -Category 'firewall_containment_changed' `
                    -Message (
                        'El containment firewall dejo de tener diez reglas.'
                    )
            }
            $ContainmentPlan.inventory_verified_sha256 =
                [string]$containmentSnapshot.sha256
            $ContainmentPlan.state_verified_sha256 =
                [string]$containmentSnapshot.state_sha256
            $containmentVerificationCount++
            $ContainmentPlan.verification_count =
                $containmentVerificationCount
            $lastContainmentVerification = [DateTime]::UtcNow
        }
        $statusNow = Assert-I05RuntimeIPv4Only `
            -ProcessId $Process.Id -Lan $Lan -Preferences $Preferences
        $route = Get-I05EffectiveRouteEvidence `
            -RemoteIPv4 $SourceIPv4
        if ([int]$route.interface_index -ne
                [int]$Lan.adapter.ifIndex -or
            [string]$route.source_address -cne
                $Lan.local_ipv4.ToString() -or
            [string]$route.next_hop -cne '0.0.0.0') {
            Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
                -Category 'physical_route_changed' `
                -Message 'La ruta efectiva H3->H1 dejo la NIC fisica on-link.'
        }
        $connections = @(Get-I05CandidateTcpConnections `
            -ProcessId $Process.Id)
        $establishedNonLoopback = @($connections | Where-Object {
            [string]$_.State -eq 'Established' -and
            [string]$_.RemoteAddress -notin @(
                '', '0.0.0.0', '::', '127.0.0.1', '::1'
            )
        })
        $exact = @($establishedNonLoopback | Where-Object {
            [string]$_.State -eq 'Established' -and
            [string]$_.LocalAddress -eq $Lan.local_ipv4.ToString() -and
            [int]$_.LocalPort -gt 0 -and
            [int]$_.LocalPort -notin $reservedI05Ports -and
            [string]$_.RemoteAddress -eq $SourceIPv4 -and
            [int]$_.RemotePort -eq $expectedSourceTcpPort
        })
        $forbidden = @($establishedNonLoopback | Where-Object {
            -not (
                [string]$_.LocalAddress -eq
                    $Lan.local_ipv4.ToString() -and
                [int]$_.LocalPort -gt 0 -and
                [int]$_.LocalPort -notin $reservedI05Ports -and
                [string]$_.RemoteAddress -eq $SourceIPv4 -and
                [int]$_.RemotePort -eq $expectedSourceTcpPort
            )
        })
        if ($forbidden.Count -gt 0) {
            $forbiddenEstablishedCount += $forbidden.Count
            Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
                -Category 'unexpected_peer_socket' `
                -Message (
                    'eMule abrio una conexion TCP Established no-loopback ' +
                    'distinta de H3:ephemeral->H1:7862.'
                )
        }
        if ($exact.Count -gt 0) {
            $sawExactIPv4 = $true
            foreach ($connection in $exact) {
                $key = '{0}|{1}|{2}|{3}|TCP|{4}' -f
                    ([string]$connection.LocalAddress),
                    ([int]$connection.LocalPort),
                    ([string]$connection.RemoteAddress),
                    ([int]$connection.RemotePort),
                    $Process.Id
                if (-not $tupleRecords.ContainsKey($key)) {
                    $tupleRecords[$key] = [ordered]@{
                        protocol = 'TCP'
                        local_address_sha256 = Get-LabStringSha256 `
                            -Value ([string]$connection.LocalAddress)
                        local_port = [int]$connection.LocalPort
                        remote_address_sha256 = Get-LabStringSha256 `
                            -Value ([string]$connection.RemoteAddress)
                        remote_port = [int]$connection.RemotePort
                        pid = [int]$Process.Id
                        first_sample = $sampleNumber + 1
                        last_sample = $sampleNumber + 1
                        observations = 1
                    }
                } else {
                    $record = $tupleRecords[$key]
                    $record.last_sample = $sampleNumber + 1
                    $record.observations = [int]$record.observations + 1
                }
            }
        }
        if (-not $sawExactIPv4 -and
            ([DateTime]::UtcNow - $started).TotalSeconds -ge
                $peerConnectTimeoutSeconds) {
            Throw-I05ClassifiedFailure `
                -Classification PRODUCT_INVARIANT `
                -Category 'missing_exact_peer_socket' `
                -Message (
                    'No aparecio el socket IPv4 exacto H3->H1 ' +
                    'durante los primeros 300 segundos.'
                )
        }
        try {
            $part = @(Get-ChildItem -LiteralPath (Join-Path $Node 'Temp') `
                -File -Filter '*.part' -ErrorAction Stop)
            $destinationExists = Test-Path -LiteralPath $destination `
                -PathType Leaf -ErrorAction Stop
        } catch {
            Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
                -Category 'fixture_io_unavailable' `
                -Message 'No se pudo observar Temp/Incoming durante T1.'
        }
        $sample = [ordered]@{
            schema = 'ese.v91.i05.t1-h3-sample/v1'
            sample_number = ++$sampleNumber
            captured_at_utc = Get-LabUtcTimestamp
            elapsed_seconds =
                [Math]::Round(([DateTime]::UtcNow - $started).TotalSeconds, 3)
            api_available = $true
            kad_connected = $false
            kad2_connected = $false
            kad6_running = [bool]$statusNow.kad6_running
            ipv6_nonloopback_socket_count = 0
            exact_ipv4_peer_connection_count = $exact.Count
            nonloopback_established_count =
                $establishedNonLoopback.Count
            forbidden_established_count = $forbidden.Count
            observed_local_ephemeral_ports = @($exact |
                ForEach-Object { [int]$_.LocalPort } |
                Sort-Object -Unique)
            route_interface_id = Get-LabInterfaceId `
                -Id ([string]$Lan.adapter.InterfaceGuid) `
                -Name ([string]$Lan.adapter.Name) `
                -Description ([string]$Lan.adapter.InterfaceDescription)
            part_count = $part.Count
            part_bytes = if ($part.Count -eq 1) {
                [Int64]$part[0].Length
            } else { $null }
            destination_exists =
                [bool]$destinationExists
        }
        Add-Content -LiteralPath $SamplesPath `
            -Value ($sample | ConvertTo-Json -Depth 8 -Compress) `
            -Encoding utf8
        if ([bool]$sample.destination_exists) { break }
        Start-Sleep -Milliseconds `
            $containmentWatchdogIntervalMilliseconds
    } while ([DateTime]::UtcNow -lt $deadline)
    try {
        $destinationExists = Test-Path -LiteralPath $destination `
            -PathType Leaf -ErrorAction Stop
    } catch {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'fixture_io_unavailable' `
            -Message 'No se pudo verificar el destino final.'
    }
    if (-not $destinationExists) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'transfer_timeout' `
            -Message 'La transferencia no termino dentro de 7200 segundos.'
    }
    try {
        $containmentFinal = Get-I05ScopedContainmentInventory `
            -Plan $ContainmentPlan -Stage armed `
            -Path $ContainmentPlan.inventory_verified_path
    } catch {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'firewall_containment_changed' `
            -Message 'No se pudo cerrar la evidencia firewall containment.'
    }
    if ([int]$containmentFinal.present_count -ne 10 -or
        [string]$containmentFinal.state_sha256 -cne
            [string]$ContainmentPlan.state_armed_sha256) {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'firewall_containment_changed' `
            -Message 'El containment firewall no fue estable hasta completar.'
    }
    $ContainmentPlan.inventory_verified_sha256 =
        [string]$containmentFinal.sha256
    $ContainmentPlan.state_verified_sha256 =
        [string]$containmentFinal.state_sha256
    $containmentVerificationCount++
    $ContainmentPlan.verification_count =
        $containmentVerificationCount
    if (-not $sawExactIPv4) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'missing_exact_peer_socket' `
            -Message 'No se observo el socket IPv4 exacto H3->H1.'
    }
    $item = Get-Item -LiteralPath $destination
    if ([Int64]$item.Length -ne $fixtureBytes) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'file_size_mismatch' `
            -Message 'El destino no mide exactamente 4 GiB.'
    }
    $verification = & $FixtureVerifier -Mode Verify `
        -SeedPath $FixtureSeed -FixturePath $destination `
        -ReportPath $FixtureReportPath |
        Select-Object -Last 1
    if ([string]$verification.status -cne 'VERIFIED' -or
        [Int64]$verification.fixture.bytes -ne $fixtureBytes -or
        ([string]$verification.fixture.sha256).ToLowerInvariant() -cne
            $fixtureSha256 -or
        ([string]$verification.fixture.ed2k).ToUpperInvariant() -cne
            $fixtureEd2k) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'file_identity_mismatch' `
            -Message (
                'El calculo local SHA-256/ED2K del destino no coincide.'
            )
    }
    $tuples = @($tupleRecords.Values | Sort-Object local_port)
    $socketProof = [ordered]@{
        schema = 'ese.v91.i05.t1-socket-proof/v1'
        case_id = 'V91-I05'
        candidate_pid = [int]$Process.Id
        source_ipv4_sha256 = Get-LabStringSha256 -Value $SourceIPv4
        downloader_ipv4_sha256 = Get-LabStringSha256 `
            -Value $Lan.local_ipv4.ToString()
        remote_port = $expectedSourceTcpPort
        observed_tuples = $tuples
        unique_tuple_count = $tuples.Count
        stable_tuple = if ($tuples.Count -eq 1) { $tuples[0] } else { $null }
        forbidden_established_count = $forbiddenEstablishedCount
        sample_count = $sampleNumber
        watchdog_interval_ms =
            $containmentWatchdogIntervalMilliseconds
        watchdog_violations = $forbiddenEstablishedCount
        engine_watchdog_samples = $engineWatchdogSamples
        engine_watchdog_exact_filter_checks = $engineWatchdogSamples
        containment_verification_count =
            $containmentVerificationCount
        created_at_utc = Get-LabUtcTimestamp
    }
    Write-LabJson -Value $socketProof -Path $SocketProofPath | Out-Null
    return [pscustomobject][ordered]@{
        path = $destination
        bytes = [Int64]$item.Length
        sha256 = ([string]$verification.fixture.sha256).ToLowerInvariant()
        ed2k = ([string]$verification.fixture.ed2k).ToUpperInvariant()
        local_identity_method = 'local-streaming-sha256-ed2k-md4'
        calculation_report_path = $FixtureReportPath
        calculation_report_sha256 =
            Get-LabSha256 -Path $FixtureReportPath
        saw_exact_ipv4 = $sawExactIPv4
        allowed_local_ports = @($tuples |
            ForEach-Object { [int]$_.local_port } |
            Sort-Object -Unique)
        socket_proof_path = $SocketProofPath
        socket_proof_sha256 = Get-LabSha256 -Path $SocketProofPath
        unique_tuple_count = $tuples.Count
        stable_tuple = if ($tuples.Count -eq 1) { $tuples[0] } else { $null }
        forbidden_established_count = $forbiddenEstablishedCount
        sample_count = $sampleNumber
        watchdog_interval_ms =
            $containmentWatchdogIntervalMilliseconds
        watchdog_violations = $forbiddenEstablishedCount
        engine_watchdog_samples = $engineWatchdogSamples
        engine_watchdog_exact_filter_checks = $engineWatchdogSamples
        containment_verification_count =
            $containmentVerificationCount
        started_at_utc = $started.ToString('o')
        completed_at_utc = Get-LabUtcTimestamp
    }
}

function Get-I05EtwLossEvidence {
    param([switch]$StopOwnedSession)
    if (-not ('V91I05EtwTraceQuery' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class V91I05EtwTraceQuery {
    [StructLayout(LayoutKind.Sequential)]
    private struct WNODE_HEADER {
        public UInt32 BufferSize; public UInt32 ProviderId;
        public UInt64 HistoricalContext; public Int64 TimeStamp;
        public Guid Guid; public UInt32 ClientContext; public UInt32 Flags;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_TRACE_PROPERTIES {
        public WNODE_HEADER Wnode; public UInt32 BufferSize;
        public UInt32 MinimumBuffers; public UInt32 MaximumBuffers;
        public UInt32 MaximumFileSize; public UInt32 LogFileMode;
        public UInt32 FlushTimer; public UInt32 EnableFlags;
        public Int32 AgeLimit; public UInt32 NumberOfBuffers;
        public UInt32 FreeBuffers; public UInt32 EventsLost;
        public UInt32 BuffersWritten; public UInt32 LogBuffersLost;
        public UInt32 RealTimeBuffersLost; public IntPtr LoggerThreadId;
        public UInt32 LogFileNameOffset; public UInt32 LoggerNameOffset;
    }
    public sealed class Result {
        public UInt32 ErrorCode; public UInt32 EventsLost;
        public UInt32 LogBuffersLost; public UInt32 RealTimeBuffersLost;
        public UInt32 BuffersWritten;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    private static extern UInt32 ControlTrace(
        UInt64 sessionHandle, string sessionName, IntPtr properties,
        UInt32 controlCode);
    private static Result Control(string sessionName, UInt32 controlCode) {
        int size = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
        const int loggerNameCapacityChars = 1024;
        const int logFileNameCapacityChars = 32768;
        int loggerNameCapacityBytes =
            loggerNameCapacityChars * sizeof(char);
        int logFileNameCapacityBytes =
            logFileNameCapacityChars * sizeof(char);
        byte[] name = Encoding.Unicode.GetBytes(sessionName + "\0");
        if (name.Length > loggerNameCapacityBytes) {
            throw new ArgumentOutOfRangeException("sessionName");
        }
        int total = checked(
            size + loggerNameCapacityBytes + logFileNameCapacityBytes);
        IntPtr buffer = Marshal.AllocHGlobal(total);
        try {
            Marshal.Copy(new byte[total], 0, buffer, total);
            EVENT_TRACE_PROPERTIES value = new EVENT_TRACE_PROPERTIES();
            value.Wnode.BufferSize = (UInt32)total;
            value.Wnode.Flags = 0x00020000;
            value.LoggerNameOffset = (UInt32)size;
            value.LogFileNameOffset =
                (UInt32)(size + loggerNameCapacityBytes);
            Marshal.StructureToPtr(value, buffer, false);
            Marshal.Copy(name, 0, IntPtr.Add(buffer, size), name.Length);
            UInt32 error = ControlTrace(
                0, sessionName, buffer, controlCode);
            Result result = new Result(); result.ErrorCode = error;
            if (error == 0) {
                value = (EVENT_TRACE_PROPERTIES)Marshal.PtrToStructure(
                    buffer, typeof(EVENT_TRACE_PROPERTIES));
                result.EventsLost = value.EventsLost;
                result.LogBuffersLost = value.LogBuffersLost;
                result.RealTimeBuffersLost = value.RealTimeBuffersLost;
                result.BuffersWritten = value.BuffersWritten;
            }
            return result;
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    public static Result Query(string sessionName) {
        return Control(sessionName, 0);
    }
    public static Result Stop(string sessionName) {
        return Control(sessionName, 1);
    }
}
'@
    }
    $query = if ($StopOwnedSession) {
        [V91I05EtwTraceQuery]::Stop('PktMon')
    } else {
        [V91I05EtwTraceQuery]::Query('PktMon')
    }
    $buffersLost = [UInt64]$query.LogBuffersLost +
        [UInt64]$query.RealTimeBuffersLost
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-pktmon-loss/v1'
        case_id = 'V91-I05'
        available = [UInt32]$query.ErrorCode -eq 0
        error_code = [UInt32]$query.ErrorCode
        events_lost = [UInt64]$query.EventsLost
        log_buffers_lost = [UInt64]$query.LogBuffersLost
        realtime_buffers_lost = [UInt64]$query.RealTimeBuffersLost
        buffers_lost = $buffersLost
        buffers_written = [UInt64]$query.BuffersWritten
        proof_stage = if ($StopOwnedSession) {
            'ControlTrace(EVENT_TRACE_CONTROL_STOP)-final'
        } else {
            'ControlTrace(EVENT_TRACE_CONTROL_QUERY)-live'
        }
        proved_zero = [UInt32]$query.ErrorCode -eq 0 -and
            [UInt64]$query.EventsLost -eq 0 -and $buffersLost -eq 0
    }
}

function Get-I05PacketEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SourceIPv4,
        [Parameter(Mandatory = $true)][string]$DownloaderIPv4,
        [Parameter(Mandatory = $true)][int[]]$AllowedLocalPorts
    )
    if (-not ('V91I05PcapAnalyzer' -as [type])) {
        Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

public static class V91I05PcapAnalyzer {
    public sealed class Result {
        public bool Valid;
        public string[] Errors;
        public long Blocks;
        public long Sections;
        public long Interfaces;
        public string[] InterfaceNames;
        public long IEEE80211Packets;
        public long IPv4PeerPackets;
        public long IPv4PhysicalInterfacePackets;
        public long IPv6PeerPackets;
        public long RejectedPeerTuplePackets;
        public long ThirdPartyPeerPackets;
        public long RequestPartsI64;
        public long CompressedPart32;
        public long SendingPartI64;
        public long CompressedPartI64;
        public long InvalidFixtureI64Frames;
        public long FixtureHashFrames;
        public string[] FixtureHashFrameSignatures;
        public long TruncatedIPv4PeerPackets;
        public int[] AllowedLocalPorts;
        public string Method;
    }
    private sealed class Iface {
        public ushort LinkType;
        public string Name;
    }
    private sealed class Flow {
        public bool HasNext;
        public uint Next;
        public byte[] Tail = new byte[0];
    }
    private sealed class Work {
        public Result R = new Result();
        public List<string> Errors = new List<string>();
        public List<string> Names = new List<string>();
        public Dictionary<uint,Iface> Ifaces =
            new Dictionary<uint,Iface>();
        public Dictionary<string,Flow> Flows =
            new Dictionary<string,Flow>();
        public Dictionary<string,long> Signatures =
            new Dictionary<string,long>();
        public string H1;
        public string H3;
        public HashSet<int> AllowedPorts = new HashSet<int>();
        public byte[] Hash;
    }
    private static ushort U16(byte[] b, int o, bool le) {
        if (o < 0 || o + 2 > b.Length) throw new InvalidDataException("u16");
        return le ? (ushort)(b[o] | (b[o+1] << 8)) :
            (ushort)((b[o] << 8) | b[o+1]);
    }
    private static uint U32(byte[] b, int o, bool le) {
        if (o < 0 || o + 4 > b.Length) throw new InvalidDataException("u32");
        if (le) return (uint)(b[o] | (b[o+1] << 8) |
            (b[o+2] << 16) | (b[o+3] << 24));
        return ((uint)b[o] << 24) | ((uint)b[o+1] << 16) |
            ((uint)b[o+2] << 8) | b[o+3];
    }
    private static ushort BE16(byte[] b, int o) {
        return (ushort)((b[o] << 8) | b[o+1]);
    }
    private static uint BE32(byte[] b, int o) {
        return ((uint)b[o] << 24) | ((uint)b[o+1] << 16) |
            ((uint)b[o+2] << 8) | b[o+3];
    }
    private static byte[] ReadExact(Stream s, int n) {
        byte[] b = new byte[n]; int o = 0;
        while (o < n) {
            int r = s.Read(b, o, n-o);
            if (r <= 0) throw new EndOfStreamException();
            o += r;
        }
        return b;
    }
    private static byte[] Hex(string value) {
        byte[] result = new byte[value.Length/2];
        for (int i=0; i<result.Length; i++)
            result[i] = Convert.ToByte(value.Substring(i*2,2),16);
        return result;
    }
    private static string V4(byte[] b, int o) {
        return b[o]+"."+b[o+1]+"."+b[o+2]+"."+b[o+3];
    }
    private static string V6(byte[] b, int o) {
        byte[] value = new byte[16];
        Array.Copy(b,o,value,0,16);
        return new IPAddress(value).ToString().ToLowerInvariant();
    }
    private static bool PortIn(int value) {
        return value==7862 || value==7962 ||
            value==7872 || value==7972;
    }
    private static bool HashAt(byte[] b, int o, byte[] hash) {
        if (o < 0 || o + hash.Length > b.Length) return false;
        for (int i=0;i<hash.Length;i++)
            if (b[o+i] != hash[i]) return false;
        return true;
    }
    private static bool Try80211(
        byte[] p, out int ip, out int family) {
        ip=0; family=0;
        if (p.Length<32) return false;
        int fc0=p[0], fc1=p[1];
        if ((fc0&0x0c)!=0x08) return false;
        int subtype=(fc0>>4)&0x0f;
        int header=24;
        if ((fc1&0x03)==0x03) header+=6;
        bool qos=(subtype&0x08)!=0;
        if (qos) header+=2;
        if (qos && (fc1&0x80)!=0) header+=4;
        if (header+8>p.Length ||
            p[header]!=0xaa || p[header+1]!=0xaa ||
            p[header+2]!=0x03 || p[header+3]!=0x00 ||
            p[header+4]!=0x00 || p[header+5]!=0x00)
            return false;
        int ether=BE16(p,header+6);
        if (ether==0x0800) family=4;
        else if (ether==0x86DD) family=6;
        else return false;
        ip=header+8;
        return true;
    }
    private static void ScanFrames(
        Work w, byte[] b, bool requestDirection, bool responseDirection) {
        for (int i=0; i+22<=b.Length; i++) {
            if (b[i] != 0xC5) continue;
            uint length = U32(b,i+1,true);
            byte opcode = b[i+5];
            if (!HashAt(b,i+6,w.Hash)) continue;
            w.R.FixtureHashFrames++;
            string signature=opcode.ToString("X2")+":"+length;
            if (!w.Signatures.ContainsKey(signature))
                w.Signatures[signature]=0;
            w.Signatures[signature]++;
            if (requestDirection && opcode==0xA3 && length==65)
                w.R.RequestPartsI64++;
            else if (responseDirection && opcode==0x40 &&
                length>=25 && length<=16777216)
                w.R.CompressedPart32++;
            else if (responseDirection && opcode==0xA2 &&
                length>=33 && length<=16777216)
                w.R.SendingPartI64++;
            else if (responseDirection && opcode==0xA1 &&
                length>=29 && length<=16777216)
                w.R.CompressedPartI64++;
            else if (opcode==0xA1 || opcode==0xA2 || opcode==0xA3)
                w.R.InvalidFixtureI64Frames++;
        }
    }
    private static void AnalyzePacket(
        Work w, byte[] p, Iface iface, uint originalLength) {
        int ip=0; int family=0;
        bool ieee80211=false;
        if (iface.LinkType==1) {
            if (p.Length<14) return;
            int ether=BE16(p,12); ip=14;
            while (ether==0x8100 || ether==0x88A8) {
                if (ip+4>p.Length) return;
                ether=BE16(p,ip+2); ip+=4;
            }
            if (ether==0x0800) family=4;
            else if (ether==0x86DD) family=6;
            else if (Try80211(p,out ip,out family)) ieee80211=true;
            else return;
        } else if (iface.LinkType==105) {
            if (!Try80211(p,out ip,out family)) return;
            ieee80211=true;
        } else if (iface.LinkType==101) {
            if (p.Length<1) return;
            family=p[0]>>4;
        } else return;
        if (ieee80211) w.R.IEEE80211Packets++;

        string src, dst; int proto; int transport;
        int wireTransport;
        if (family==4) {
            if (ip+20>p.Length || (p[ip]>>4)!=4) return;
            int ihl=(p[ip]&15)*4;
            if (ihl<20 || ip+ihl>p.Length) return;
            int total=BE16(p,ip+2);
            int fragment=BE16(p,ip+6);
            if ((fragment&0x1fff)!=0) return;
            proto=p[ip+9]; src=V4(p,ip+12); dst=V4(p,ip+16);
            transport=ip+ihl; wireTransport=Math.Max(0,total-ihl);
        } else if (family==6) {
            if (ip+40>p.Length || (p[ip]>>4)!=6) return;
            int ipv6Payload=BE16(p,ip+4);
            proto=p[ip+6]; src=V6(p,ip+8); dst=V6(p,ip+24);
            transport=ip+40; int extensions=0;
            for (int n=0; proto!=6 && proto!=17 && n<8; n++) {
                int bytes; int next;
                if (proto==0 || proto==43 || proto==60) {
                    if (transport+2>p.Length) return;
                    next=p[transport]; bytes=(p[transport+1]+1)*8;
                } else if (proto==44) {
                    if (transport+8>p.Length) return;
                    if ((BE16(p,transport+2)&0xfff8)!=0) return;
                    next=p[transport]; bytes=8;
                } else if (proto==51) {
                    if (transport+2>p.Length) return;
                    next=p[transport]; bytes=(p[transport+1]+2)*4;
                } else return;
                if (bytes<=0 || transport+bytes>p.Length) return;
                transport+=bytes; extensions+=bytes; proto=next;
            }
            wireTransport=Math.Max(0,ipv6Payload-extensions);
        } else return;
        if ((proto!=6 && proto!=17) || transport+4>p.Length) return;
        int sport=BE16(p,transport), dport=BE16(p,transport+2);
        if (family==6) {
            if (PortIn(sport) || PortIn(dport)) w.R.IPv6PeerPackets++;
            return;
        }
        bool request = proto==6 && src==w.H3 && dst==w.H1 &&
            dport==7862 && w.AllowedPorts.Contains(sport);
        bool response = proto==6 && src==w.H1 && dst==w.H3 &&
            sport==7862 && w.AllowedPorts.Contains(dport);
        bool peerPort = proto==6 &&
            (sport==7862 || dport==7862 ||
             sport==7962 || dport==7962);
        if (peerPort && !request && !response) {
            bool expectedHosts =
                (src==w.H3 && dst==w.H1) ||
                (src==w.H1 && dst==w.H3);
            if (expectedHosts) w.R.RejectedPeerTuplePackets++;
            else w.R.ThirdPartyPeerPackets++;
        }
        if (!request && !response) return;
        w.R.IPv4PeerPackets++;
        // The caller proves physical ownership from InterfaceGuid -> PktMon
        // component mapping. IDB aliases are deliberately not trusted.
        w.R.IPv4PhysicalInterfacePackets++;
        if (proto!=6 || transport+20>p.Length) return;
        int tcpHeader=((p[transport+12]>>4)&15)*4;
        if (tcpHeader<20 || transport+tcpHeader>p.Length) return;
        int capturedPayload=Math.Max(0,p.Length-(transport+tcpHeader));
        int wirePayload=Math.Max(0,wireTransport-tcpHeader);
        if (capturedPayload<wirePayload) w.R.TruncatedIPv4PeerPackets++;
        byte[] payload=new byte[capturedPayload];
        Array.Copy(p,transport+tcpHeader,payload,0,capturedPayload);
        string key=src+"|"+sport+"|"+dst+"|"+dport;
        Flow flow;
        if (!w.Flows.TryGetValue(key,out flow)) {
            flow=new Flow(); w.Flows[key]=flow;
        }
        uint seq=BE32(p,transport+4);
        byte[] combined=payload;
        if (flow.HasNext && flow.Next==seq && flow.Tail.Length>0) {
            combined=new byte[flow.Tail.Length+payload.Length];
            Array.Copy(flow.Tail,0,combined,0,flow.Tail.Length);
            Array.Copy(payload,0,combined,flow.Tail.Length,payload.Length);
        }
        ScanFrames(w,combined,request,response);
        bool complete=capturedPayload>=wirePayload;
        if (complete) {
            int keep=Math.Min(64,combined.Length);
            flow.Tail=new byte[keep];
            if (keep>0) Array.Copy(
                combined,combined.Length-keep,flow.Tail,0,keep);
            uint advance=(uint)wirePayload;
            byte flags=p[transport+13];
            if ((flags&0x02)!=0) advance++;
            if ((flags&0x01)!=0) advance++;
            flow.Next=seq+advance; flow.HasNext=true;
        } else {
            flow.Tail=new byte[0]; flow.HasNext=false;
        }
    }
    public static Result Analyze(
        string path, string h1, string h3, int[] allowedLocalPorts) {
        Work w=new Work(); w.H1=h1; w.H3=h3;
        if (allowedLocalPorts==null || allowedLocalPorts.Length==0)
            throw new ArgumentException("allowedLocalPorts");
        foreach (int port in allowedLocalPorts) {
            if (port<=0 || port>65535 ||
                port==7862 || port==7872 ||
                port==7911 || port==7912 ||
                port==7962 || port==7972 ||
                port==8011 || port==8012)
                throw new ArgumentException("allowedLocalPorts");
            w.AllowedPorts.Add(port);
        }
        w.R.AllowedLocalPorts =
            new List<int>(w.AllowedPorts).ToArray();
        w.Hash=Hex("796A95E75DF8E78D54A57CDEA1FEDE84");
        bool little=true;
        try {
            using (FileStream fs=new FileStream(
                path,FileMode.Open,FileAccess.Read,FileShare.Read,
                1048576,FileOptions.SequentialScan)) {
                while (fs.Position<fs.Length) {
                    long offset=fs.Position;
                    byte[] head=ReadExact(fs,8);
                    bool section=head[0]==0x0A && head[1]==0x0D &&
                        head[2]==0x0D && head[3]==0x0A;
                    uint type, length;
                    byte[] rest;
                    if (section) {
                        byte[] magic=ReadExact(fs,4);
                        if (magic[0]==0x4D && magic[1]==0x3C &&
                            magic[2]==0x2B && magic[3]==0x1A) little=true;
                        else if (magic[0]==0x1A && magic[1]==0x2B &&
                            magic[2]==0x3C && magic[3]==0x4D) little=false;
                        else throw new InvalidDataException(
                            "bad section byte-order magic");
                        length=U32(head,4,little); type=0x0A0D0D0A;
                        if (length<28 || (length%4)!=0 ||
                            length>16777216) throw new InvalidDataException(
                            "bad section length");
                        byte[] tail=ReadExact(fs,(int)length-12);
                        rest=new byte[tail.Length+4];
                        Array.Copy(magic,0,rest,0,4);
                        Array.Copy(tail,0,rest,4,tail.Length);
                        w.Ifaces.Clear(); w.R.Sections++;
                    } else {
                        type=U32(head,0,little);
                        length=U32(head,4,little);
                        if (length<12 || (length%4)!=0 ||
                            length>16777216) throw new InvalidDataException(
                            "bad block length");
                        rest=ReadExact(fs,(int)length-8);
                    }
                    if (U32(rest,rest.Length-4,little)!=length)
                        throw new InvalidDataException(
                            "block trailing length mismatch");
                    w.R.Blocks++;
                    if (type==1) {
                        if (rest.Length<12)
                            throw new InvalidDataException("short IDB");
                        Iface f=new Iface(); f.LinkType=U16(rest,0,little);
                        f.Name="";
                        int o=8, end=rest.Length-4;
                        while (o+4<=end) {
                            ushort code=U16(rest,o,little);
                            ushort n=U16(rest,o+2,little); o+=4;
                            if (code==0) break;
                            if (o+n>end) throw new InvalidDataException(
                                "IDB option overflow");
                            if (code==2) f.Name=Encoding.UTF8.GetString(rest,o,n);
                            o+=(n+3)&~3;
                        }
                        uint id=(uint)w.Ifaces.Count; w.Ifaces[id]=f;
                        w.R.Interfaces++;
                        if (!w.Names.Contains(f.Name)) w.Names.Add(f.Name);
                    } else if (type==6) {
                        if (rest.Length<24)
                            throw new InvalidDataException("short EPB");
                        uint id=U32(rest,0,little);
                        Iface f;
                        if (!w.Ifaces.TryGetValue(id,out f))
                            throw new InvalidDataException(
                                "EPB unknown interface");
                        uint cap=U32(rest,12,little);
                        uint original=U32(rest,16,little);
                        if (cap>1048576 || 20+cap>rest.Length-4)
                            throw new InvalidDataException(
                                "EPB payload overflow");
                        byte[] packet=new byte[cap];
                        Array.Copy(rest,20,packet,0,(int)cap);
                        AnalyzePacket(w,packet,f,original);
                    }
                    if (fs.Position<=offset)
                        throw new InvalidDataException("parser did not advance");
                }
            }
        } catch (Exception ex) { w.Errors.Add(ex.Message); }
        w.R.Valid=w.Errors.Count==0 && w.R.Sections>0 &&
            w.R.Interfaces>0;
        w.R.Errors=w.Errors.ToArray();
        w.R.InterfaceNames=w.Names.ToArray();
        List<string> signatures=new List<string>();
        foreach (KeyValuePair<string,long> item in w.Signatures)
            signatures.Add(item.Key+"="+item.Value);
        signatures.Sort(StringComparer.Ordinal);
        w.R.FixtureHashFrameSignatures=signatures.ToArray();
        w.R.Method="streaming-pcapng; PID-watchdog-derived H1/H3 tuple " +
            "allowlist (not direct PCAP PID attribution); bounded " +
            "sequence-aware TCP header reassembly; C5 frame length/opcode/" +
            "fixture-ED2K validation; physical ownership from external " +
            "InterfaceGuid/PktMon component proof; process-scoped firewall " +
            "containment attribution guard; end-to-end SHA-256";
        return w.R;
    }
}
'@
    }
    return [V91I05PcapAnalyzer]::Analyze(
        $Path, $SourceIPv4, $DownloaderIPv4, $AllowedLocalPorts)
}

function Complete-I05Capture {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$SourceIPv4,
        [Parameter(Mandatory = $true)][string]$DownloaderIPv4,
        [Parameter(Mandatory = $true)][object]$Adapter,
        [Parameter(Mandatory = $true)][string]$InterfaceId,
        [Parameter(Mandatory = $true)][int]$CandidatePid,
        [Parameter(Mandatory = $true)][int[]]$AllowedLocalPorts,
        [Parameter(Mandatory = $true)][object]$ContainmentEvidence
    )
    @(& pktmon.exe counters 2>&1) |
        Set-Content -LiteralPath $State.counters_path -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw 'PktMon counters fallo antes del cierre.'
    }
    @(& logman.exe query -ets PktMon 2>&1) |
        Set-Content -LiteralPath $State.session_before_stop -Encoding utf8
    $beforeStopExit = $LASTEXITCODE
    $beforeStopText =
        Get-Content -LiteralPath $State.session_before_stop -Raw
    if ($beforeStopExit -ne 0 -or
        $beforeStopText.IndexOf(
            ([IO.Path]::GetFullPath([string]$State.etl_path)),
            [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw (
            'La sesion PktMon activa no demuestra el ETL propio; ' +
            'se rechaza detenerla.'
        )
    }
    $loss = Get-I05EtwLossEvidence -StopOwnedSession
    Write-LabJson -Value $loss -Path $State.loss_path | Out-Null
    if (-not [bool]$loss.proved_zero) {
        throw (
            'El STOP ETW final no demuestra EventsLost/' +
            'LogBuffersLost/RealTimeBuffersLost=0.'
        )
    }
    @(& pktmon.exe filter list 2>&1) |
        Set-Content -LiteralPath $State.filters_before_reset -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo inventariar PktMon antes del reset.'
    }
    Assert-I05PktMonFilterRowsExact `
        -ExpectedLines @(Get-Content -LiteralPath $State.filters_armed) `
        -ActualLines @(Get-Content -LiteralPath $State.filters_before_reset)
    $pktmonReset = @(& pktmon.exe stop 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw (
            'El STOP ETW fue valido, pero PktMon no reseteo su estado ' +
            "interno: $($pktmonReset -join ' ')"
        )
    }
    $State.started = $false
    $State.session_owned = $false
    @(& logman.exe query -ets PktMon 2>&1) |
        Set-Content -LiteralPath $State.session_after -Encoding utf8
    if ($LASTEXITCODE -eq 0) {
        throw 'La sesion ETW PktMon sigue activa.'
    }
    if (-not (Test-Path -LiteralPath $State.etl_path -PathType Leaf)) {
        throw 'Falta el ETL PktMon.'
    }
    $etlBytes = [Int64](Get-Item -LiteralPath $State.etl_path).Length
    $limitBytes = [Int64]$captureFileSizeMiB * 1MB
    if ($etlBytes -le 0 -or $etlBytes -ge $limitBytes) {
        throw 'El ETL alcanzo el limite circular o esta vacio.'
    }
    $remove = Invoke-I05Pktmon -Arguments @('filter', 'remove') `
        -LogPath $State.command_log
    if ($remove.exit_code -ne 0) {
        throw 'No se pudo retirar el conjunto exacto de filtros propios.'
    }
    @(& pktmon.exe filter list 2>&1) |
        Set-Content -LiteralPath $State.filters_after -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo verificar el inventario PktMon restaurado.'
    }
    $before = (Get-Content -LiteralPath $State.filters_before -Raw).Trim()
    $after = (Get-Content -LiteralPath $State.filters_after -Raw).Trim()
    if ($before -cne $after) {
        throw 'El inventario PktMon final difiere del inicial vacio.'
    }
    $State.component_post = Get-I05PktMonMappingSnapshot `
        -Adapter $Adapter -Path $State.component_post_raw_path `
        -LogPath $State.command_log
    $mappingKey = Get-I05PktMonMappingKey -Mapping $State.component_pre
    foreach ($mapping in @(
        $State.component_armed, $State.component_post
    )) {
        if ((Get-I05PktMonMappingKey -Mapping $mapping) -cne $mappingKey) {
            throw 'El mapping PktMon GUID/Id no fue estable pre/armed/post.'
        }
    }

    foreach ($stage in @('pre', 'armed', 'post')) {
        $mapping = $State.("component_$stage")
        $compact = [ordered]@{
            schema = 'ese.v91.i05.t1-component-inventory/v1'
            case_id = 'V91-I05'
            stage = $stage
            raw_bytes = [Int64]$mapping.inventory_bytes
            raw_sha256 = [string]$mapping.inventory_sha256
            mapping_key_sha256 = [string]$mapping.mapping_key_sha256
            primary_id = [int]$mapping.primary_id
            secondary_id = [int]$mapping.secondary_id
            interface_guid_sha256 = Get-LabStringSha256 `
                -Value ([string]$mapping.interface_guid)
        }
        Write-LabJson -Value $compact `
            -Path $State.("component_${stage}_compact_path") | Out-Null
    }
    $componentMapping = [ordered]@{
        schema = 'ese.v91.i05.t1-component-mapping/v1'
        case_id = 'V91-I05'
        source = 'pktmon list --json Components[].Properties[].Value'
        interface_guid = [string]$State.component_pre.interface_guid
        interface_guid_sha256 = Get-LabStringSha256 `
            -Value ([string]$State.component_pre.interface_guid)
        interface_index = [int]$State.component_pre.interface_index
        mac_address_sha256 = Get-LabStringSha256 `
            -Value ([string]$State.component_pre.mac_address)
        primary_id = [int]$State.component_pre.primary_id
        secondary_id = [int]$State.component_pre.secondary_id
        conversion_component_ids =
            @($State.component_pre.conversion_component_ids)
        mapping_key_sha256 =
            [string]$State.component_pre.mapping_key_sha256
        unique_guid_component_match = $true
        optional_if_index_correlated =
            [bool]$State.component_pre.if_index_correlated
        optional_if_index_present =
            [bool]$State.component_pre.if_index_property_present
        optional_mac_correlated =
            [bool]$State.component_pre.mac_correlated
        optional_mac_present =
            [bool]$State.component_pre.mac_property_present
        stable_pre_armed_post = $true
        inventories = [ordered]@{
            pre_raw_sha256 =
                [string]$State.component_pre.inventory_sha256
            armed_raw_sha256 =
                [string]$State.component_armed.inventory_sha256
            post_raw_sha256 =
                [string]$State.component_post.inventory_sha256
        }
    }
    $componentMappingPath = Write-LabJson -Value $componentMapping `
        -Path $State.component_mapping_path

    $conversionResults = [System.Collections.Generic.List[object]]::new()
    foreach ($componentId in @(
        $State.component_pre.conversion_component_ids
    )) {
        $candidatePcap = Join-Path (
            Split-Path -Parent $State.etl_path
        ) ("v91-i05-t1-component-$componentId.pcapng")
        if (Test-Path -LiteralPath $candidatePcap) {
            throw "Ya existe el PCAPNG component-scoped $componentId."
        }
        $convert = Invoke-I05Pktmon -Arguments @(
            'etl2pcap', $State.etl_path, '--out', $candidatePcap,
            '--component-id', [string]$componentId
        ) -LogPath $State.command_log
        if ($convert.exit_code -ne 0 -or
            -not (Test-Path -LiteralPath $candidatePcap -PathType Leaf)) {
            throw "Fallo etl2pcap --component-id $componentId."
        }
        $candidateWire = Get-I05PacketEvidence -Path $candidatePcap `
            -SourceIPv4 $SourceIPv4 -DownloaderIPv4 $DownloaderIPv4 `
            -AllowedLocalPorts $AllowedLocalPorts
        $conversionResults.Add([pscustomobject][ordered]@{
            component_id = [int]$componentId
            path = $candidatePcap
            bytes = [Int64](Get-Item -LiteralPath $candidatePcap).Length
            sha256 = Get-LabSha256 -Path $candidatePcap
            parser_valid = [bool]$candidateWire.Valid
            exact_peer_flow = [bool]$candidateWire.Valid -and
                [Int64]$candidateWire.IPv4PeerPackets -gt 0
            exact_peer_packets =
                [Int64]$candidateWire.IPv4PeerPackets
            rejected_peer_tuple_packets =
                [Int64]$candidateWire.RejectedPeerTuplePackets
            third_party_peer_packets =
                [Int64]$candidateWire.ThirdPartyPeerPackets
            wire = $candidateWire
        })
    }
    foreach ($candidate in @($conversionResults)) {
        if (-not [bool]$candidate.parser_valid) {
            Assert-I05WireEvidence -Wire $candidate.wire
        }
    }
    $winner = Select-I05UniqueComponentConversion `
        -Results $conversionResults.ToArray()
    $wire = $winner.wire
    $State.pcapng_path = [string]$winner.path
    $State.conversion_results = @($conversionResults)
    Assert-I05WireEvidence -Wire $wire
    foreach ($candidate in @($conversionResults)) {
        if ([int]$candidate.component_id -ne
            [int]$winner.component_id) {
            Remove-Item -LiteralPath ([string]$candidate.path) -Force `
                -ErrorAction Stop
        }
    }
    $wireDocument = [ordered]@{
        schema = 'ese.v91.i05.t1-pcap-analysis/v1'
        case_id = 'V91-I05'
        parser_valid = [bool]$wire.Valid
        errors = @($wire.Errors)
        conversion_component_id = [int]$winner.component_id
        allowed_local_ports = @($AllowedLocalPorts | Sort-Object -Unique)
        exact_peer_packets = [Int64]$wire.IPv4PeerPackets
        ieee80211_packets = [Int64]$wire.IEEE80211Packets
        rejected_peer_tuple_packets =
            [Int64]$wire.RejectedPeerTuplePackets
        third_party_peer_packets =
            [Int64]$wire.ThirdPartyPeerPackets
        ipv6_peer_packets = [Int64]$wire.IPv6PeerPackets
        requestparts_i64 = [Int64]$wire.RequestPartsI64
        compressedpart_32 = [Int64]$wire.CompressedPart32
        sendingpart_i64 = [Int64]$wire.SendingPartI64
        compressedpart_i64 = [Int64]$wire.CompressedPartI64
        invalid_fixture_i64_frames =
            [Int64]$wire.InvalidFixtureI64Frames
        fixture_hash_frames = [Int64]$wire.FixtureHashFrames
        fixture_hash_frame_signatures =
            @($wire.FixtureHashFrameSignatures)
        truncated_ipv4_peer_packets =
            [Int64]$wire.TruncatedIPv4PeerPackets
        candidate_pid = $CandidatePid
        candidate_pid_role = 'socket-watchdog-context-only'
        pcap_pid_attributed = $false
        tuple_allowlist_pid_observed = $true
        attribution_guard = 'process-scoped-firewall-containment'
        physical_component_guid_match = $true
        component_mapping_sha256 =
            Get-LabSha256 -Path $componentMappingPath
        method = [string]$wire.Method
    }
    $wirePath = Write-LabJson -Value $wireDocument -Path (
        Join-Path (Split-Path -Parent $State.pcapng_path) `
            'pcap-analysis.json')
    $filterSummaryPath = Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i05.t1-pktmon-filter/v1'
        case_id = 'V91-I05'
        filters = @($State.filters)
        before_bytes =
            [Int64](Get-Item -LiteralPath $State.filters_before).Length
        before_sha256 = Get-LabSha256 -Path $State.filters_before
        armed_bytes =
            [Int64](Get-Item -LiteralPath $State.filters_armed).Length
        armed_sha256 = Get-LabSha256 -Path $State.filters_armed
        before_reset_bytes =
            [Int64](Get-Item -LiteralPath $State.filters_before_reset).Length
        before_reset_sha256 =
            Get-LabSha256 -Path $State.filters_before_reset
        active_inventory_rows_exact = $true
        after_bytes =
            [Int64](Get-Item -LiteralPath $State.filters_after).Length
        after_sha256 = Get-LabSha256 -Path $State.filters_after
        restored_exactly = $true
        third_party_containment = $ContainmentEvidence
    }) -Path (Join-Path (Split-Path -Parent $State.etl_path) `
        'pktmon-filter.json')
    $conversionSummary = @($conversionResults | ForEach-Object {
        [ordered]@{
            component_id = [int]$_.component_id
            bytes = [Int64]$_.bytes
            sha256 = [string]$_.sha256
            parser_valid = [bool]$_.parser_valid
            exact_peer_flow = [bool]$_.exact_peer_flow
            retained = [int]$_.component_id -eq [int]$winner.component_id
        }
    })
    $statusSummaryPath = Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i05.t1-pktmon-status/v1'
        case_id = 'V91-I05'
        primary_component_id = [int]$State.component_pre.primary_id
        secondary_component_id = [int]$State.component_pre.secondary_id
        converted_component_id = [int]$winner.component_id
        conversion_hit_count = 1
        conversion_results = $conversionSummary
        command_log_bytes =
            [Int64](Get-Item -LiteralPath $State.command_log).Length
        command_log_sha256 = Get-LabSha256 -Path $State.command_log
        counters_bytes =
            [Int64](Get-Item -LiteralPath $State.counters_path).Length
        counters_sha256 = Get-LabSha256 -Path $State.counters_path
        session_stopped = $true
        filters_restored = $true
    }) -Path (Join-Path (Split-Path -Parent $State.etl_path) `
        'pktmon-status.json')
    return [pscustomobject][ordered]@{
        backend = 'pktmon'
        status = 'PASS'
        pcap_path_relative = 'evidence\' + (
            Split-Path -Leaf $State.pcapng_path)
        pcap_sha256 = Get-LabSha256 -Path $State.pcapng_path
        pcap_bytes =
            [Int64](Get-Item -LiteralPath $State.pcapng_path).Length
        etl_bytes = $etlBytes
        etl_below_circular_limit = $true
        ipv4_peer_packets = [Int64]$wire.IPv4PeerPackets
        rejected_peer_tuple_packets =
            [Int64]$wire.RejectedPeerTuplePackets
        third_party_peer_packets =
            [Int64]$wire.ThirdPartyPeerPackets
        physical_interface = $true
        physical_component_guid_match = $true
        ipv6_peer_packets = [Int64]$wire.IPv6PeerPackets
        requestparts_i64 = [Int64]$wire.RequestPartsI64
        compressedpart_32 = [Int64]$wire.CompressedPart32
        sendingpart_i64 = [Int64]$wire.SendingPartI64
        compressedpart_i64 = [Int64]$wire.CompressedPartI64
        sending_i64 = [Int64]$wire.SendingPartI64
        compressed_i64 = [Int64]$wire.CompressedPartI64
        capture_complete = $true
        packet_loss_detected = $false
        etw_loss_proved_zero = $true
        etw_events_lost = [UInt64]$loss.events_lost
        etw_buffers_lost = [UInt64]$loss.buffers_lost
        filters_restored = $true
        etw_session_absent = $true
        interface_id = $InterfaceId
        primary_component_id = [int]$State.component_pre.primary_id
        converted_component_id = [int]$winner.component_id
        conversion_hit_count = 1
        component_mapping_sha256 =
            Get-LabSha256 -Path $componentMappingPath
        mapping_key_sha256 =
            [string]$State.component_pre.mapping_key_sha256
        packet_size = $capturePacketSize
        filter_scope_exact = $true
        etl_loss_proved_zero = $true
        etl_below_file_limit = $true
        pcap_parsed = [bool]$wire.Valid
        tuple_exact = [Int64]$wire.IPv4PeerPackets -gt 0
        candidate_pid = $CandidatePid
        candidate_pid_role = 'socket-watchdog-context-only'
        pcap_pid_attributed = $false
        tuple_allowlist_pid_observed = $true
        process_scoped_containment = $true
        ed2k_framing_valid =
            [Int64]$wire.RequestPartsI64 -gt 0 -and
            ([Int64]$wire.CompressedPart32 +
                [Int64]$wire.SendingPartI64 +
                [Int64]$wire.CompressedPartI64) -gt 0
        allowed_opcodes_only =
            [Int64]$wire.InvalidFixtureI64Frames -eq 0
        filters_absent_after = $true
        etw_session_absent_after = $true
        filter_inventory_restored = $true
        analysis_path_relative = 'evidence\pcap-analysis.json'
        analysis_sha256 = Get-LabSha256 -Path $wirePath
        analysis_method = [string]$wire.Method
        component_mapping_path = $componentMappingPath
        component_mapping_path_relative =
            'evidence\component-mapping.json'
        filter_summary_path = $filterSummaryPath
        status_summary_path = $statusSummaryPath
    }
}

function New-I05CompactEvidenceBundle {
    param(
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][object]$CaptureState,
        [Parameter(Mandatory = $true)][object]$CaptureResult,
        [Parameter(Mandatory = $true)][object]$ContainmentPlan,
        [Parameter(Mandatory = $true)][string]$SamplesPath,
        [Parameter(Mandatory = $true)][string]$SocketProofPath,
        [Parameter(Mandatory = $true)][string]$FileIntegrityPath
    )
    $stage = Join-Path $EvidenceRoot (
        'bundle-stage-' + $Nonce.Substring(0, 8))
    $zipPath = Join-Path $EvidenceRoot 'V91-I05-H3-EVIDENCE.zip'
    if ((Test-Path -LiteralPath $stage) -or
        (Test-Path -LiteralPath $zipPath)) {
        throw 'Ya existe una salida de evidence bundle H3.'
    }
    $null = New-Item -ItemType Directory -Path $stage
    try {
        $sources = [ordered]@{
            'pcap-analysis.json' = Join-Path $EvidenceRoot `
                'pcap-analysis.json'
            'component-mapping.json' =
                [string]$CaptureState.component_mapping_path
            'component-inventory-pre.json' =
                [string]$CaptureState.component_pre_compact_path
            'component-inventory-armed.json' =
                [string]$CaptureState.component_armed_compact_path
            'component-inventory-post.json' =
                [string]$CaptureState.component_post_compact_path
            'pktmon-filter.json' =
                [string]$CaptureResult.filter_summary_path
            'pktmon-loss.json' = [string]$CaptureState.loss_path
            'pktmon-status.json' =
                [string]$CaptureResult.status_summary_path
            'socket-proof.json' = $SocketProofPath
            'file-integrity.json' = $FileIntegrityPath
        }
        foreach ($entry in $sources.GetEnumerator()) {
            if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
                throw "Falta evidencia compacta '$($entry.Key)'."
            }
            $item = Get-Item -LiteralPath $entry.Value
            if ([Int64]$item.Length -le 1 -or
                [Int64]$item.Length -gt 131072L) {
                throw (
                    "La evidencia '$($entry.Key)' no es compacta: " +
                    $item.Length + ' bytes.'
                )
            }
            Copy-Item -LiteralPath $entry.Value `
                -Destination (Join-Path $stage $entry.Key)
        }

        $manifestEntries = @($sources.Keys | Sort-Object |
            ForEach-Object {
                $path = Join-Path $stage $_
                [ordered]@{
                    path = [string]$_
                    bytes = [Int64](Get-Item -LiteralPath $path).Length
                    sha256 = Get-LabSha256 -Path $path
                }
            })
        $retained = [ordered]@{
            etl = [string]$CaptureState.etl_path
            pcapng = [string]$CaptureState.pcapng_path
            transfer_samples = $SamplesPath
            pktmon_log = [string]$CaptureState.command_log
            pktmon_filters_before_reset =
                [string]$CaptureState.filters_before_reset
            component_inventory_pre_raw =
                [string]$CaptureState.component_pre_raw_path
            component_inventory_armed_raw =
                [string]$CaptureState.component_armed_raw_path
            component_inventory_post_raw =
                [string]$CaptureState.component_post_raw_path
            firewall_containment_spec =
                [string]$ContainmentPlan.spec_path
            firewall_containment_inventory_before =
                [string]$ContainmentPlan.inventory_before_path
            firewall_containment_inventory_armed =
                [string]$ContainmentPlan.inventory_armed_path
            firewall_containment_inventory_verified =
                [string]$ContainmentPlan.inventory_verified_path
        }
        $retainedRaw = @($retained.GetEnumerator() | ForEach-Object {
            if (-not (Test-Path -LiteralPath $_.Value -PathType Leaf)) {
                throw "Falta retained_raw '$($_.Key)'."
            }
            $full = [IO.Path]::GetFullPath([string]$_.Value)
            $rootPrefix = [IO.Path]::GetFullPath($RunRoot).
                TrimEnd('\', '/') + '\'
            if (-not $full.StartsWith(
                    $rootPrefix,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "retained_raw '$($_.Key)' escapa de RunRoot."
            }
            [ordered]@{
                kind = [string]$_.Key
                path_relative = $full.Substring(
                    $rootPrefix.Length).Replace('\', '/')
                bytes = [Int64](Get-Item -LiteralPath $full).Length
                sha256 = Get-LabSha256 -Path $full
            }
        })
        $manifest = [ordered]@{
            schema = 'ese.v91.i05.t1-evidence-manifest/v1'
            case_id = 'V91-I05'
            nonce = $Nonce
            created_at_utc = Get-LabUtcTimestamp
            entries = $manifestEntries
            retained_raw = $retainedRaw
        }
        $manifestPath = Write-LabJson -Value $manifest `
            -Path (Join-Path $stage 'manifest.json')
        $manifestSha256 = Get-LabSha256 -Path $manifestPath

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory(
            $stage, $zipPath,
            [IO.Compression.CompressionLevel]::Optimal, $false)
        $zipItem = Get-Item -LiteralPath $zipPath
        if ([Int64]$zipItem.Length -le 1 -or
            [Int64]$zipItem.Length -gt 524288L) {
            throw (
                'El evidence bundle comprimido supera 512 KiB: ' +
                $zipItem.Length + ' bytes.'
            )
        }
        $expectedEntries = @(
            'manifest.json'
            $sources.Keys
        ) | Sort-Object
        $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            $actualEntries = @($archive.Entries |
                ForEach-Object { $_.FullName.Replace('\', '/') } |
                Sort-Object)
            if (($actualEntries -join "`n") -cne
                ($expectedEntries -join "`n")) {
                throw 'La allowlist del evidence ZIP no es exacta.'
            }
        } finally {
            $archive.Dispose()
        }
        $bytes = [IO.File]::ReadAllBytes($zipPath)
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i05.t1-evidence-bundle/v1'
            encoding = 'base64'
            bytes = $bytes.Length
            sha256 = Get-I05BytesSha256 -Bytes $bytes
            manifest_sha256 = $manifestSha256
            content_base64 = [Convert]::ToBase64String($bytes)
            path = $zipPath
        }
    } finally {
        if (Test-Path -LiteralPath $stage -PathType Container) {
            Remove-Item -LiteralPath $stage -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
    }
}

if ($env:ESE_V91_I05_LIBRARY_ONLY -ceq '1') {
    return
}

try {
    Write-I05BootProgress -Stage 'administrator'
    Assert-I05Administrator
    Write-I05BootProgress -Stage 'required_files'
    foreach ($required in @(
        $configPath, $preparePath, $contractPath, $cleanupPath, $archivePath,
        $baseManifestPath, $fixtureVerifierPath
    )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Falta el archivo requerido: $required"
        }
    }
    if (Test-Path -LiteralPath $activePath -PathType Leaf) {
        throw (
            'Ya existe ACTIVE-V91-I05-T1.json. Ejecute primero ' +
            'STOP-V91-I05-DOWNLOADER.cmd.'
        )
    }
    if (Test-Path -LiteralPath $latestReadyPath -PathType Leaf) {
        throw 'Existe un READY anterior sin marcador activo; retirelo manualmente.'
    }
    $configRaw = Get-Content -LiteralPath $configPath -Raw
    $config = $configRaw | ConvertFrom-Json
    Write-I05BootProgress -Stage 'config_loaded'
    Assert-I05ExactString -Value $config.schema `
        -Expected 'ese.v91.i05.t1-config/v1' -Label 'CONFIG schema'
    Assert-I05ExactString -Value $config.case_id `
        -Expected 'V91-I05' -Label 'CONFIG case_id'
    Assert-I05ExactString -Value $config.status `
        -Expected 'ARMED' -Label 'CONFIG status'
    $nonce = [string](Get-I05RequiredProperty -InputObject $config `
        -Name 'nonce' -Context 'CONFIG')
    if ($nonce -notmatch '^[0-9a-f]{32}$') {
        throw 'CONFIG.nonce no es 32hex lowercase.'
    }
    Enter-I05SingleInstance -RunNonce $nonce
    Write-I05BootProgress -Stage 'config_identity'
    foreach ($staleOperatorMarker in @(
        $latestFailurePath, $latestErrorPath
    )) {
        if (Test-Path -LiteralPath $staleOperatorMarker -PathType Leaf) {
            Remove-Item -LiteralPath $staleOperatorMarker -Force
        }
    }
    $created = [DateTimeOffset]::Parse([string]$config.created_at_utc)
    $expires = [DateTimeOffset]::Parse([string]$config.expires_at_utc)
    $now = [DateTimeOffset]::UtcNow
    if ($created -gt $now.AddMinutes(5) -or $expires -le $now -or
        $expires -le $created) {
        throw 'CONFIG esta caducado o tiene fechas incoherentes.'
    }

    Assert-I05ExactString -Value $config.candidate.version `
        -Expected $expectedVersion -Label 'candidate.version'
    Assert-I05ExactString -Value $config.candidate.commit `
        -Expected $expectedCommit -Label 'candidate.commit'
    if ([bool]$config.candidate.dirty) {
        throw 'CONFIG exige un candidato dirty.'
    }
    Assert-I05ExactString -Value $config.candidate.emule_sha256 `
        -Expected $expectedEmuleSha256 -Label 'candidate.emule_sha256'
    Assert-I05ExactString -Value $config.candidate.ese_server_sha256 `
        -Expected $expectedEseServerSha256 `
        -Label 'candidate.ese_server_sha256'
    Assert-I05ExactString -Value $config.candidate.build_info_sha256 `
        -Expected $expectedBuildInfoSha256 `
        -Label 'candidate.build_info_sha256'
    Assert-I05ExactString -Value $config.candidate.zip_sha256 `
        -Expected $expectedArchiveSha256 -Label 'candidate.zip_sha256'
    if ([Int64]$config.candidate.zip_bytes -ne $expectedArchiveBytes) {
        throw 'candidate.zip_bytes no coincide.'
    }

    if ([int]$config.source.tcp_port -ne $expectedSourceTcpPort -or
        [int]$config.source.udp_port -ne $expectedSourceUdpPort -or
        [int]$config.source.web_port -ne $expectedSourceWebPort) {
        throw 'Los puertos H1 del CONFIG no coinciden con el contrato.'
    }
    if ([int]$config.ipv6_probe.port -ne $expectedProbePort -or
        -not [bool]$config.ipv6_probe.required -or
        [string]$config.ipv6_probe.protocol -cne 'TCP') {
        throw 'El probe IPv6 del CONFIG no coincide con el contrato.'
    }
    if ([int]$config.downloader.tcp_port -ne $tcpPort -or
        [int]$config.downloader.udp_port -ne $udpPort -or
        [int]$config.downloader.web_port -ne $webPort -or
        [Int64]$config.downloader.min_free_bytes -ne $minimumFreeBytes -or
        [string]$config.downloader.filesystem -cne 'NTFS') {
        throw 'El bloque downloader del CONFIG no coincide con H3.'
    }
    if ([string]$config.coordination.transport -cne 'lan-tcp-v1' -or
        [int]$config.coordination.control_port -ne $controlPort -or
        -not [bool]$config.coordination.single_stream -or
        [int]$config.coordination.maximum_frame_bytes -ne
            $maximumControlDocumentBytes) {
        throw 'La coordinacion LAN TCP del CONFIG no coincide.'
    }
    if ([int]$config.policy.ipv6_mode -ne 0 -or
        -not [bool]$config.policy.os_ipv6_binding_required -or
        [string]$config.policy.data_family -cne 'IPv4' -or
        [string]$config.policy.forbidden_interface_pattern -cne
            $forbiddenInterfacePattern -or
        -not [bool]$config.policy.packet_capture_required) {
        throw 'La politica formal I05 del CONFIG no coincide.'
    }
    foreach ($name in @(
        'kad2_enabled', 'kad6_enabled', 'third_party_peers_allowed'
    )) {
        $property = $config.policy.PSObject.Properties[$name]
        if ($null -eq $property -or $property.Value -isnot [bool] -or
            [bool]$property.Value) {
            throw "CONFIG.policy.$name debe ser booleano false."
        }
    }
    foreach ($name in @(
        'direct_link_only', 'third_party_sources_forbidden'
    )) {
        $property = $config.policy.PSObject.Properties[$name]
        if ($null -eq $property -or $property.Value -isnot [bool] -or
            -not [bool]$property.Value) {
            throw "CONFIG.policy.$name debe ser booleano true."
        }
    }
    if ([int]$config.policy.kad_network_mask -ne 0 -or
        [string]$config.policy.discovery -cne 'direct-link-only') {
        throw 'CONFIG no exige Kad off y discovery direct-link-only.'
    }

    $sourceIPv4Address = Convert-I05IPAddress `
        -Value ([string]$config.source.ipv4_address) `
        -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Label 'source.ipv4_address'
    $sourceIPv4 = $sourceIPv4Address.ToString()
    if ((Get-LabAddressClass -Address $sourceIPv4) -ne 'private-v4') {
        throw 'source.ipv4_address debe ser IPv4 privada.'
    }
    Assert-I05ExactString -Value $config.source.ipv4_sha256 `
        -Expected (Get-LabStringSha256 -Value $sourceIPv4) `
        -Label 'source.ipv4_sha256'
    $sourceHostId = ([string]$config.source.host_id_sha256).
        ToLowerInvariant()
    if ($sourceHostId -notmatch '^[0-9a-f]{64}$') {
        throw 'source.host_id_sha256 no es un SHA-256 canonico.'
    }
    $localHostId = Get-I05HostIdSha256
    if ($sourceHostId -ceq $localHostId) {
        throw 'H1 y H3 resuelven al mismo MachineGuid; T1 exige dos equipos.'
    }
    $localSourceMatches = @(Get-NetIPAddress -AddressFamily IPv4 `
        -ErrorAction Stop | Where-Object {
            ([string]$_.IPAddress) -eq $sourceIPv4
        })
    if ($localSourceMatches.Count -ne 0) {
        throw 'La IPv4 declarada para H1 pertenece en realidad a H3.'
    }
    Assert-I05ExactString -Value $config.ipv6_probe.source_interface_id `
        -Expected ([string]$config.source.interface_id) `
        -Label 'H1 IPv4/IPv6 source_interface_id'

    $probeRemote = Convert-I05IPAddress `
        -Value ([string]$config.ipv6_probe.address) `
        -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
        -Label 'ipv6_probe.address'
    $probeCanonical = $probeRemote.ToString().Split('%')[0].ToLowerInvariant()
    $probeClass = Get-LabAddressClass -Address $probeCanonical
    if ($probeClass -notin @('linklocal-v6', 'ula-v6', 'global-v6')) {
        throw "Clase IPv6 de probe no admitida: $probeClass"
    }
    Assert-I05ExactString -Value $config.ipv6_probe.address_class `
        -Expected $probeClass -Label 'ipv6_probe.address_class'
    Assert-I05ExactString -Value $config.ipv6_probe.address_sha256 `
        -Expected (Get-LabStringSha256 -Value $probeCanonical) `
        -Label 'ipv6_probe.address_sha256'
    $requestLine = "V91-I05-PROBE $nonce"
    $responseLine = "V91-I05-PROBE-OK $nonce"
    Assert-I05ExactString -Value $config.ipv6_probe.request_line `
        -Expected $requestLine -Label 'ipv6_probe.request_line'
    Assert-I05ExactString -Value $config.ipv6_probe.response_line `
        -Expected $responseLine -Label 'ipv6_probe.response_line'
    Assert-I05ExactString -Value $config.ipv6_probe.challenge_sha256 `
        -Expected (Get-LabStringSha256 -Value $requestLine) `
        -Label 'ipv6_probe.challenge_sha256'

    Write-I05BootProgress -Stage 'candidate_hash'
    $archiveItem = Get-Item -LiteralPath $archivePath -Force
    if (($archiveItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        [Int64]$archiveItem.Length -ne $expectedArchiveBytes -or
        (Get-LabSha256 -Path $archivePath) -cne
            $expectedArchiveSha256) {
        throw 'El ZIP RC3 completo no coincide en bytes/SHA-256.'
    }
    Write-I05BootProgress -Stage 'candidate_hash_ok'
    $baseManifest = Get-Content -LiteralPath $baseManifestPath -Raw |
        ConvertFrom-Json
    Assert-I05ExactString -Value $baseManifest.schema `
        -Expected 'ese.v91.i05-remote-base/v1' `
        -Label 'I05-BASE-MANIFEST schema'
    Assert-I05ExactString -Value (
        ([string]$baseManifest.candidate.archive_sha256).ToLowerInvariant()
    ) -Expected $expectedArchiveSha256 `
        -Label 'I05-BASE-MANIFEST archive_sha256'
    if ([Int64]$baseManifest.candidate.archive_bytes -ne
            $expectedArchiveBytes -or
        [string]$baseManifest.measurement.topology -cne 'T1' -or
        [string]$baseManifest.measurement.transport_family -cne 'IPv4' -or
        [string]$baseManifest.measurement.application_ipv6_mode -cne 'Off' -or
        -not [bool]$baseManifest.measurement.
            windows_ipv6_stack_must_remain_enabled -or
        -not [bool]$baseManifest.measurement.
            preflight_ipv6_lan_probe_required) {
        throw 'I05-BASE-MANIFEST no conserva el contrato T1/RC3.'
    }

    Write-I05BootProgress -Stage 'storage_context'
    $storage = Get-I05StorageContext
    Write-I05BootProgress -Stage 'lan_context'
    $lan = Get-I05PhysicalLanContext -SourceIPv4 $sourceIPv4Address
    $interfaceText = '{0}|{1}' -f $lan.adapter.Name,
        $lan.adapter.InterfaceDescription
    if ($interfaceText -match $forbiddenInterfacePattern) {
        throw 'La ruta LAN seleccionada usa una interfaz prohibida.'
    }
    $interfaceId = Get-LabInterfaceId -Id ([string]$lan.adapter.InterfaceGuid) `
        -Name ([string]$lan.adapter.Name) `
        -Description ([string]$lan.adapter.InterfaceDescription)
    Assert-I05ExactString `
        -Value ([string]$config.downloader.expected_ipv4_address) `
        -Expected $lan.local_ipv4.ToString() `
        -Label 'downloader.expected_ipv4_address'
    Assert-I05ExactString `
        -Value ([string]$config.downloader.expected_ipv4_sha256) `
        -Expected (Get-LabStringSha256 `
            -Value $lan.local_ipv4.ToString()) `
        -Label 'downloader.expected_ipv4_sha256'
    Assert-I05ExactString `
        -Value ([string]$config.coordination.h1_address_sha256) `
        -Expected (Get-LabStringSha256 -Value $sourceIPv4) `
        -Label 'coordination.h1_address_sha256'
    Assert-I05ExactString `
        -Value ([string]$config.coordination.h3_address_sha256) `
        -Expected (Get-LabStringSha256 `
            -Value $lan.local_ipv4.ToString()) `
        -Label 'coordination.h3_address_sha256'
    Write-I05BootProgress -Stage 'effective_route'
    $effectiveRoute = Get-I05EffectiveRouteEvidence `
        -RemoteIPv4 $sourceIPv4
    if ([int]$effectiveRoute.interface_index -ne
            [int]$lan.adapter.ifIndex -or
        [string]$effectiveRoute.source_address -cne
            $lan.local_ipv4.ToString() -or
        [string]$effectiveRoute.next_hop -cne '0.0.0.0') {
        throw 'Find-NetRoute no elige la IPv4/NIC fisica on-link esperada.'
    }

    Write-I05BootProgress -Stage 'ipv6_probe'
    $probe = Invoke-I05IPv6Probe -Lan $lan `
        -RemoteAddress $probeRemote -RemotePort $expectedProbePort `
        -RequestLine $requestLine -ResponseLine $responseLine
    if ([string]$probe.remote_address -cne $probeCanonical) {
        throw 'El RemoteEndPoint del probe no coincide con H1.'
    }

    Write-I05BootProgress -Stage 'port_inventory'
    Assert-I05PortAvailable -Protocol TCP -Port $tcpPort
    Assert-I05PortAvailable -Protocol UDP -Port $udpPort
    Assert-I05PortAvailable -Protocol TCP -Port $webPort
    Assert-I05PortAvailable -Protocol TCP -Port $controlPort

    Write-I05BootProgress -Stage 'run_materialization'
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $runRoot = Join-Path $kitRoot (
        "runs\v91-i05-h3-$($nonce.Substring(0,8))-$stamp")
    if (Test-Path -LiteralPath $runRoot) {
        throw "La salida timestamped ya existe: $runRoot"
    }
    $evidenceRoot = New-LabDirectory -Path (Join-Path $runRoot 'evidence')
    $nodesRoot = Join-Path $runRoot 'nodes'
    $packagePath = Join-Path $runRoot 'pinned-rc3-package'
    $exactPackage = Expand-I05ExactCandidateZip -ZipPath $archivePath `
        -Destination $packagePath
    $candidate = $exactPackage.candidate

    & $preparePath -NodeRole B -SourcePackage $packagePath `
        -OutputRoot $nodesRoot -RunId 'v91-i05-t1' -PortOffset 3300
    $nodePath = Join-Path $nodesRoot 'v91-i05-t1-b'
    $emulePath = Join-Path $nodePath 'emule.exe'
    if ((Get-LabSha256 -Path $emulePath) -cne $expectedEmuleSha256) {
        throw 'El emule.exe copiado al perfil ya no coincide con RC3.'
    }

    # The real IPv6 probe above must precede this write.
    $preferencesPath = Set-I05DownloaderPreferences -Node $nodePath
    $preferencesHash = Get-LabSha256 -Path $preferencesPath
    $configHash = Get-LabStringSha256 -Value $configRaw

    $firewallName = "eSE-V91-I05-H3-$nonce"
    $firewallDisplayName = "eSE V91 I05 H3 $nonce"
    $controlFirewallName = "eSE-V91-I05-H3-Control-$nonce"
    $controlFirewallDisplayName = "eSE V91 I05 H3 Control $nonce"
    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath -PathType Leaf)) {
        throw 'No se pudo identificar powershell.exe para la regla de control.'
    }
    $firewallByName = @(Get-I05FirewallRulesByExactName `
        -Name @($firewallName))
    $firewallByDisplay = @(Get-I05FirewallRulesByExactDisplayName `
        -DisplayName $firewallDisplayName)
    if ($firewallByName.Count -ne 0 -or
        $firewallByDisplay.Count -ne 0) {
        throw 'Ya existe una regla firewall con el nonce I05.'
    }
    $firewallProfile = Get-I05FirewallProfile `
        -Profile $lan.network_profile
    $null = Assert-I05WindowsFirewallEnforced
    $containmentPlan = New-I05ContainmentPlan -Nonce $nonce `
        -Program $emulePath -SourceIPv4 $sourceIPv4 `
        -Profile 'Any' -EvidenceRoot $evidenceRoot
    $containmentPlan.enforcement_check_count = 1
    $containmentSpecDocument = [ordered]@{
        schema = 'ese.v91.i05.t1-firewall-containment-spec/v1'
        case_id = 'V91-I05'
        nonce = $nonce
        created_at_utc = Get-LabUtcTimestamp
        scope = 'exact-ten-nonce-program-rules-only'
        canonical_algorithm =
            'UTF8-no-BOM; ordinal role sort; LF join; no trailing LF'
        rule_count = [int]$containmentPlan.rule_count
        rule_names_sha256 =
            [string]$containmentPlan.rule_names_sha256
        spec_sha256 = [string]$containmentPlan.spec_sha256
        canonical_rules = @($containmentPlan.canonical_rules)
        rule_specs = @($containmentPlan.rules)
    }
    Write-LabJson -Value $containmentSpecDocument `
        -Path $containmentPlan.spec_path | Out-Null
    $containmentPlan.spec_document_sha256 =
        Get-LabSha256 -Path $containmentPlan.spec_path
    $containmentBefore = Get-I05ScopedContainmentInventory `
        -Plan $containmentPlan -Stage before `
        -Path $containmentPlan.inventory_before_path
    if ([int]$containmentBefore.present_count -ne 0 -or
        [int]$containmentBefore.absent_count -ne 10) {
        throw 'Ya existe una regla nonce-scoped del plan containment.'
    }
    $containmentPlan.inventory_before_sha256 =
        [string]$containmentBefore.sha256
    $containmentPlan.state_before_sha256 =
        [string]$containmentBefore.state_sha256
    $capturePrefix = 'ese-i05-' + $nonce.Substring(0, 8)
    $capturePlan = [ordered]@{
        backend = 'pktmon'
        started = $false
        filters = @(
            "$capturePrefix-v4-data", "$capturePrefix-v6-src-tcp",
            "$capturePrefix-v6-dst-tcp", "$capturePrefix-v6-src-udp",
            "$capturePrefix-v6-dst-udp"
        )
        filters_before =
            Join-Path $evidenceRoot 'pktmon-filters-before.txt'
        filters_armed =
            Join-Path $evidenceRoot 'pktmon-filters-armed.txt'
        filters_before_reset =
            Join-Path $evidenceRoot 'pktmon-filters-before-reset.txt'
        filters_after =
            Join-Path $evidenceRoot 'pktmon-filters-after.txt'
        etl_path = Join-Path $evidenceRoot 'v91-i05-t1-packets.etl'
        pcapng_path =
            Join-Path $evidenceRoot 'v91-i05-t1-packets.pcapng'
        command_log = Join-Path $evidenceRoot 'pktmon.log'
        component_pre_raw_path =
            Join-Path $evidenceRoot 'pktmon-components-pre.raw.json'
        component_armed_raw_path =
            Join-Path $evidenceRoot 'pktmon-components-armed.raw.json'
        component_post_raw_path =
            Join-Path $evidenceRoot 'pktmon-components-post.raw.json'
    }
    $mutations = [ordered]@{
        peer_firewall = 'NOT_STARTED'
        control_firewall = 'NOT_STARTED'
        containment_firewall = 'NOT_STARTED'
        pktmon_filters = 'NOT_STARTED'
        pktmon_session = 'NOT_STARTED'
        candidate_process = 'NOT_STARTED'
    }
    $hostIdHash = Get-I05HostIdSha256
    $ownershipCreatedAt = Get-LabUtcTimestamp
    $sessionPath = Join-Path $evidenceRoot `
        'downloader-session-private.json'
    $privateSession = [ordered]@{
        schema = 'ese.v91.i05.t1-h3-private-session/v1'
        case_id = 'V91-I05'
        nonce = $nonce
        created_at_utc = $ownershipCreatedAt
        updated_at_utc = $ownershipCreatedAt
        ownership_state = 'PREPARED'
        config_path = $configPath
        config_sha256 = $configHash
        run_root = $runRoot
        node_path = $nodePath
        emule_path = $emulePath
        preferences_path = $preferencesPath
        preferences_sha256 = $preferencesHash
        process_id = 0
        process_started_at_utc = $null
        process_not_before_utc = $ownershipCreatedAt
        process_arguments = @(
            '--portable', '--ignoreinstances', '--headless',
            "--metrics-port=$webPort", "--tcp-port=$tcpPort",
            "--udp-port=$udpPort"
        )
        source_ipv4_address = $sourceIPv4
        source_host_id_sha256 = $sourceHostId
        downloader_host_id_sha256 = $hostIdHash
        source_ipv6_probe_address = $probeCanonical
        downloader_ipv4_address = $lan.local_ipv4.ToString()
        downloader_ipv6_probe_address = $probe.local_address
        interface_alias = [string]$lan.adapter.Name
        interface_index = [int]$lan.adapter.ifIndex
        interface_guid = ([Guid]$lan.adapter.InterfaceGuid).
            ToString('D').ToLowerInvariant()
        interface_mac = Convert-I05MacCanonical `
            -Value ([string]$lan.adapter.MacAddress)
        interface_id = $interfaceId
        firewall_rule_name = $firewallName
        firewall_display_name = $firewallDisplayName
        firewall_profile = $firewallProfile
        control_firewall_rule_name = $controlFirewallName
        control_firewall_display_name = $controlFirewallDisplayName
        control_program = $powershellPath
        control_port = $controlPort
        control_listener_process_id = $PID
        containment = $containmentPlan
        capture_intent_path =
            Join-Path $evidenceRoot 'pktmon-intent-private.json'
        capture = $capturePlan
        mutations = Copy-I05MutationState -State $mutations
        candidate = [ordered]@{
            version = $expectedVersion
            commit = $expectedCommit
            emule_sha256 = $expectedEmuleSha256
            ese_server_sha256 = $expectedEseServerSha256
            build_info_sha256 = $expectedBuildInfoSha256
            zip_sha256 = $expectedArchiveSha256
            zip_bytes = $expectedArchiveBytes
        }
    }
    $active = [ordered]@{
        schema = 'ese.v91.i05.t1-active-h3/v2'
        case_id = 'V91-I05'
        nonce = $nonce
        created_at_utc = $ownershipCreatedAt
        updated_at_utc = $ownershipCreatedAt
        run_root = $runRoot
        session_path = $sessionPath
        ready_path = Join-Path $runRoot 'READY-V91-I05-T1.json'
        process_id = 0
        process_started_at_utc = $null
        process_not_before_utc = $ownershipCreatedAt
        emule_path = $emulePath
        process_arguments = @($privateSession.process_arguments)
        firewall_rule_name = $firewallName
        firewall_display_name = $firewallDisplayName
        control_firewall_rule_name = $controlFirewallName
        control_firewall_display_name = $controlFirewallDisplayName
        control_program = $powershellPath
        control_port = $controlPort
        control_listener_process_id = $PID
        containment = $containmentPlan
        capture_intent_path =
            Join-Path $evidenceRoot 'pktmon-intent-private.json'
        interface_alias = [string]$lan.adapter.Name
        downloader_ipv4_address = $lan.local_ipv4.ToString()
        source_ipv4_address = $sourceIPv4
        capture = $capturePlan
        capture_state = 'PLANNED'
        capture_pcapng_path = $null
        capture_pcap_sha256 = $null
        capture_analysis_sha256 = $null
        mutations = Copy-I05MutationState -State $mutations
        config_sha256 = $configHash
        candidate_zip_path = $archivePath
        candidate_zip_sha256 = $expectedArchiveSha256
        candidate_zip_bytes = $expectedArchiveBytes
    }
    Save-I05OwnershipDocuments -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath

    $phase = 'peer_firewall'
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource peer_firewall `
        -State PENDING
    New-NetFirewallRule -Name $firewallName `
        -DisplayName $firewallDisplayName -Direction Inbound -Action Allow `
        -Enabled True -Profile $firewallProfile -Protocol TCP `
        -LocalPort $tcpPort -LocalAddress $lan.local_ipv4.ToString() `
        -RemoteAddress $sourceIPv4 -Program $emulePath `
        -InterfaceAlias ([string]$lan.adapter.Name) `
        -EdgeTraversalPolicy Block | Out-Null
    $firewallCreated = $true
    $null = Assert-I05FirewallRule -Name $firewallName `
        -DisplayName $firewallDisplayName -Program $emulePath `
        -InterfaceAlias ([string]$lan.adapter.Name) `
        -LocalAddress $lan.local_ipv4.ToString() `
        -RemoteAddress $sourceIPv4

    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource peer_firewall `
        -State OWNED
    $phase = 'containment_firewall'
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource containment_firewall `
        -State PENDING
    Install-I05ContainmentRules -Plan $containmentPlan
    $containmentArmed = Get-I05ScopedContainmentInventory `
        -Plan $containmentPlan -Stage armed `
        -Path $containmentPlan.inventory_armed_path
    if ([int]$containmentArmed.present_count -ne 10 -or
        [int]$containmentArmed.absent_count -ne 0) {
        throw 'El containment firewall no quedo armado exactamente.'
    }
    $containmentPlan.inventory_armed_sha256 =
        [string]$containmentArmed.sha256
    $containmentPlan.state_armed_sha256 =
        [string]$containmentArmed.state_sha256
    $containmentPlan.armed_at_utc = Get-LabUtcTimestamp
    $containmentCreated = $true
    $privateSession.containment = $containmentPlan
    $active.containment = $containmentPlan
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource containment_firewall `
        -State OWNED
    $phase = 'control_firewall'
    $controlByName = @(Get-I05FirewallRulesByExactName `
        -Name @($controlFirewallName))
    $controlByDisplay = @(Get-I05FirewallRulesByExactDisplayName `
        -DisplayName $controlFirewallDisplayName)
    if ($controlByName.Count -ne 0 -or
        $controlByDisplay.Count -ne 0) {
        throw 'Ya existe la regla firewall de control I05.'
    }
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource control_firewall `
        -State PENDING
    New-NetFirewallRule -Name $controlFirewallName `
        -DisplayName $controlFirewallDisplayName `
        -Direction Inbound -Action Allow -Enabled True `
        -Profile $firewallProfile -Protocol TCP -LocalPort $controlPort `
        -LocalAddress $lan.local_ipv4.ToString() `
        -RemoteAddress $sourceIPv4 -Program $powershellPath `
        -InterfaceAlias ([string]$lan.adapter.Name) `
        -EdgeTraversalPolicy Block | Out-Null
    $controlFirewallCreated = $true
    $null = Assert-I05FirewallRule -Name $controlFirewallName `
        -DisplayName $controlFirewallDisplayName -Program $powershellPath `
        -InterfaceAlias ([string]$lan.adapter.Name) `
        -LocalAddress $lan.local_ipv4.ToString() `
        -RemoteAddress $sourceIPv4 -LocalPort $controlPort
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource control_firewall `
        -State OWNED
    $controlListener = New-Object Net.Sockets.TcpListener(
        $lan.local_ipv4, $controlPort)
    $controlListener.Server.ExclusiveAddressUse = $true
    $controlListener.Start(1)

    $phase = 'pktmon_arm'
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource pktmon_filters `
        -State PENDING
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource pktmon_session `
        -State PENDING
    $capture = Start-I05Capture -Evidence $evidenceRoot `
        -Nonce $nonce -SourceIPv4 $sourceIPv4 -Adapter $lan.adapter
    $privateSession.capture = $capture
    $active.capture = $capture
    $active.capture_state = 'ARMED'
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource pktmon_filters `
        -State OWNED
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource pktmon_session `
        -State OWNED

    $phase = 'candidate_start'
    $processNotBefore = Get-LabUtcTimestamp
    $privateSession.process_not_before_utc = $processNotBefore
    $active.process_not_before_utc = $processNotBefore
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource candidate_process `
        -State PENDING
    $process = Start-Process -FilePath $emulePath -ArgumentList @(
        '--portable', '--ignoreinstances', '--headless',
        "--metrics-port=$webPort", "--tcp-port=$tcpPort",
        "--udp-port=$udpPort"
    ) -WorkingDirectory $nodePath -WindowStyle Hidden -PassThru
    $processId = $process.Id
    $process.Refresh()
    $privateSession.process_id = $processId
    $privateSession.process_started_at_utc =
        $process.StartTime.ToUniversalTime().ToString('o')
    $privateSession.ownership_state = 'RUNNING'
    $active.process_id = $processId
    $active.process_started_at_utc =
        $privateSession.process_started_at_utc
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource candidate_process `
        -State OWNED

    $status = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        Start-Sleep -Milliseconds 400
        $process.Refresh()
        if ($process.HasExited) {
            Throw-I05ClassifiedFailure `
                -Classification PRODUCT_INVARIANT `
                -Category 'candidate_process_exit' `
                -Message (
                    "El downloader termino con codigo $($process.ExitCode)."
                )
        }
        try {
            $status = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$webPort/api/status" `
                -TimeoutSec 2
        } catch {}
    } while ($null -eq $status -and [DateTime]::UtcNow -lt $deadline)
    if ($null -eq $status) {
        Throw-I05ClassifiedFailure `
            -Classification PRODUCT_INVARIANT `
            -Category 'candidate_api_unavailable' `
            -Message "La API local no respondio en TCP/$webPort."
    }
    $peerListenerDeadline = [DateTime]::UtcNow.AddSeconds(30)
    $startupPeerListeners = @()
    do {
        $startupTcp = @(Get-I05CandidateTcpConnections `
            -ProcessId $processId)
        $startupPeerListeners = @($startupTcp | Where-Object {
            [string]$_.State -eq 'Listen' -and
            [int]$_.LocalPort -eq $tcpPort
        })
        if ($startupPeerListeners.Count -gt 0) { break }
        $process.Refresh()
        if ($process.HasExited) {
            Throw-I05ClassifiedFailure `
                -Classification PRODUCT_INVARIANT `
                -Category 'candidate_process_exit' `
                -Message (
                    'El downloader termino esperando su listener peer.'
                )
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $peerListenerDeadline)
    if ($startupPeerListeners.Count -eq 0) {
        Throw-I05ClassifiedFailure `
            -Classification PRODUCT_INVARIANT `
            -Category 'candidate_peer_listener_missing' `
            -Message (
                'El candidato no abrio su listener peer en 30 segundos.'
            )
    }
    foreach ($name in @(
        'kad_connected', 'kad6_running', 'kad6_connected'
    )) {
        Assert-I05StrictBooleanFalse -InputObject $status -Name $name `
            -Context 'API initial'
    }
    $status = Assert-I05RuntimeIPv4Only `
        -ProcessId $processId -Lan $lan -Preferences $preferencesPath
    $apiLanDenial = Assert-I05LanApiForbidden -Lan $lan

    $initialTcp = @(Get-I05CandidateTcpConnections `
        -ProcessId $processId)
    $tcpListeners = @($initialTcp | Where-Object {
        [string]$_.State -eq 'Listen'
    })
    $peerListeners = @($tcpListeners | Where-Object LocalPort -eq $tcpPort)
    $apiListeners = @($tcpListeners | Where-Object LocalPort -eq $webPort)
    if ($peerListeners.Count -lt 1 -or
        @($peerListeners | Where-Object {
            [string]$_.LocalAddress -match ':'
        }).Count -ne 0) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_peer_listener' `
            -Message 'IPv6Mode=0 no produjo un listener peer IPv4 puro.'
    }
    if ($apiListeners.Count -lt 1 -or
        @($apiListeners | Where-Object {
            -not (Test-I05ApiListenerAllowedByIPv4Profile `
                -Connection $_)
        }).Count -ne 0) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_api_binding' `
            -Message 'La API no usa el listener IPv4 nativo esperado.'
    }
    $udpEndpoints = @(Get-I05CandidateUdpEndpoints `
        -ProcessId $processId)
    if (@($udpEndpoints | Where-Object {
            [int]$_.LocalPort -eq $udpPort -and
            [string]$_.LocalAddress -match ':'
        }).Count -ne 0) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_ipv6_udp' `
            -Message 'IPv6Mode=0 dejo un endpoint UDP IPv6 del peer.'
    }

    Invoke-I05CandidateApi -Uri (
        "http://127.0.0.1:$webPort/api/network/connect?ed2k=0&kad=0"
    ) -TimeoutSec 10 -Context 'network disconnect' | Out-Null
    Start-Sleep -Seconds 2
    $status = Invoke-I05CandidateApi `
        -Uri "http://127.0.0.1:$webPort/api/status" `
        -TimeoutSec 3 -Context 'READY status'
    foreach ($name in @(
        'kad_connected', 'kad6_running', 'kad6_connected'
    )) {
        Assert-I05StrictBooleanFalse -InputObject $status -Name $name `
            -Context 'API READY'
    }
    $readyTcp = @(Get-I05CandidateTcpConnections `
        -ProcessId $processId)
    $nonLoopbackV6 = @($readyTcp | Where-Object {
            [string]$_.RemoteAddress -match ':' -and
            [string]$_.RemoteAddress -ne '::1'
        })
    if ($nonLoopbackV6.Count -ne 0) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_ipv6_socket' `
            -Message (
                'El downloader abrio una conexion IPv6 no-loopback en READY.'
            )
    }
    $readyThirdParties = @($readyTcp | Where-Object {
            [string]$_.State -eq 'Established' -and
            [string]$_.RemoteAddress -notin @(
                '', '0.0.0.0', '::', '127.0.0.1', '::1'
            )
        })
    if ($readyThirdParties.Count -ne 0) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'unexpected_peer_socket' `
            -Message 'READY no esta limpio de conexiones peer de terceros.'
    }

    $v9 = Invoke-I05CandidateApi `
        -Uri "http://127.0.0.1:$webPort/api/ese/v9" `
        -TimeoutSec 5 -Context 'READY v9'
    $safeStatus = ConvertTo-LabSanitizedValue -InputObject $status `
        -RedactAddresses
    $safeV9 = ConvertTo-LabSanitizedValue -InputObject $v9 `
        -RedactAddresses
    Write-LabJson -Value $safeStatus `
        -Path (Join-Path $evidenceRoot 'status-ready.json') | Out-Null
    Write-LabJson -Value $safeV9 `
        -Path (Join-Path $evidenceRoot 'v9-ready.json') | Out-Null

    $readyAt = [DateTimeOffset]::UtcNow
    $intentHash = Get-LabSha256 -Path $capture.intent_path
    $privateSession.ownership_state = 'READY'
    $privateSession.capture = $capture
    $active.capture = $capture
    Save-I05OwnershipDocuments -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath

    $ready = [ordered]@{
        schema = 'ese.v91.i05.t1-ready/v1'
        case_id = 'V91-I05'
        status = 'READY'
        nonce = $nonce
        created_at_utc = $readyAt.ToString('o')
        ready_at_utc = $readyAt.ToString('o')
        expires_at_utc = $expires.ToUniversalTime().ToString('o')
        candidate = [ordered]@{
            version = $expectedVersion
            commit = $expectedCommit
            dirty = $false
            emule_sha256 = $expectedEmuleSha256
            ese_server_sha256 = $expectedEseServerSha256
            build_info_sha256 = $expectedBuildInfoSha256
            zip_sha256 = $expectedArchiveSha256
            zip_bytes = $expectedArchiveBytes
        }
        host = [ordered]@{
            role = 'H3'
            host_id_sha256 = $hostIdHash
            source_host_id_sha256 = $sourceHostId
            physical_windows = $true
        }
        storage = [ordered]@{
            filesystem = $storage.filesystem
            free_bytes = $storage.free_bytes
            minimum_free_bytes = $minimumFreeBytes
            run_root_sha256 = Get-LabStringSha256 -Value $runRoot
        }
        network = [ordered]@{
            ipv4 = [ordered]@{
                address = $lan.local_ipv4.ToString()
                address_sha256 =
                    Get-LabStringSha256 -Value $lan.local_ipv4.ToString()
                class = 'private-v4'
                prefix_length = $lan.prefix_length
                interface_id = $interfaceId
                physical = $true
                status = 'Up'
                source_on_link = $true
                next_hop = '0.0.0.0'
                source_address_sha256 =
                    Get-LabStringSha256 `
                        -Value $lan.local_ipv4.ToString()
            }
            ipv6_probe = [ordered]@{
                success = $true
                family = 'IPv6'
                local_address_sha256 =
                    Get-LabStringSha256 -Value $probe.local_address
                source_address_sha256 =
                    Get-LabStringSha256 -Value $probeCanonical
                source_port = $expectedProbePort
                local_ephemeral_port = $probe.local_ephemeral_port
                challenge_sha256 =
                    Get-LabStringSha256 -Value $requestLine
                response_sha256 =
                    Get-LabStringSha256 -Value $responseLine
                interface_id = $interfaceId
                completed_at_utc = $probe.completed_at_utc
            }
            ipv6_binding_enabled = $true
        }
        node = [ordered]@{
            process_id = $processId
            emule_sha256 = $expectedEmuleSha256
            tcp_port = $tcpPort
            udp_port = $udpPort
            web_port = $webPort
            ipv6_mode = 0
            kad_network_mask = 0
            kad_connected = $false
            kad2_connected = $false
            kad6_running = $false
            kad6_connected = $false
            tcp_listener_owned = $true
            api_ipv4_only = $true
            api_lan_access_denied = [bool]$apiLanDenial.denied
            api_lan_denial_mode = [string]$apiLanDenial.mode
            api_lan_http_status = [int]$apiLanDenial.http_status
        }
        firewall = [ordered]@{
            rule_name = $firewallName
            nonce_scoped = $true
            program_scoped = $true
            peer_scoped = $true
            interface_scoped = $true
            local_port = $tcpPort
            remote_address_sha256 =
                Get-LabStringSha256 -Value $sourceIPv4
        }
        capture = [ordered]@{
            backend = 'pktmon'
            arm_status = 'ARMED'
            fail_closed = $true
            intent_sha256 = $intentHash
            packet_size = $capturePacketSize
            etl_path_sha256 =
                Get-LabStringSha256 -Value ([string]$capture.etl_path)
            component_mapping = [ordered]@{
                interface_guid_sha256 = Get-LabStringSha256 `
                    -Value ([string]$capture.component_pre.interface_guid)
                primary_id = [int]$capture.component_pre.primary_id
                secondary_ids = @(
                    if ([int]$capture.component_pre.secondary_id -gt 0) {
                        [int]$capture.component_pre.secondary_id
                    }
                )
                mapping_key_sha256 =
                    [string]$capture.component_pre.mapping_key_sha256
                mapping_sha256 =
                    [string]$capture.component_pre.mapping_key_sha256
                inventories = [ordered]@{
                    pre_sha256 =
                        [string]$capture.component_pre.inventory_sha256
                    armed_sha256 =
                        [string]$capture.component_armed.inventory_sha256
                }
            }
        }
        coordination = [ordered]@{
            transport = 'lan-tcp-v1'
            address = $lan.local_ipv4.ToString()
            address_sha256 = Get-LabStringSha256 `
                -Value $lan.local_ipv4.ToString()
            port = $controlPort
            remote_address_sha256 =
                Get-LabStringSha256 -Value $sourceIPv4
            challenge_sha256 = Get-LabStringSha256 `
                -Value ("V91-I05-COMMAND $nonce")
            single_use = $true
        }
        fixture = [ordered]@{
            name = $fixtureName
            bytes = $fixtureBytes
            sha256 = $fixtureSha256
            ed2k_hash = $fixtureEd2k
        }
        evidence = [ordered]@{
            config_sha256 = $configHash
            private_session_sha256 = Get-LabSha256 -Path $sessionPath
            status_ready = 'evidence\status-ready.json'
            v9_ready = 'evidence\v9-ready.json'
        }
    }
    $runReadyPath = Join-Path $runRoot 'READY-V91-I05-T1.json'
    $active.ready_path = $runReadyPath
    $active.capture_intent_path = $capture.intent_path
    Save-I05OwnershipDocuments -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath
    $runReadyPath = Write-LabJson -Value $ready -Path $runReadyPath
    Copy-Item -LiteralPath $runReadyPath -Destination $latestReadyPath

    $readyText = Join-Path $runRoot 'READY-V91-I05-T1.txt'
    Write-LabText -Path $readyText -Value ((@(
        'V91-I05 H3 DOWNLOADER READY'
        "nonce=$nonce"
        "process_id=$processId"
        "tcp_port=$tcpPort"
        "udp_port=$udpPort"
        "web_port=$webPort"
        "ready_json=$latestReadyPath"
        "run_root=$runRoot"
        ''
        'IPv6 de Windows sigue activo y el probe fisico ha pasado.'
        'eSE esta en IPv6Mode=0. PktMon esta ARMED.'
        'No cierre eMule; use STOP-V91-I05-DOWNLOADER.cmd al terminar.'
    ) -join "`r`n") + "`r`n")
    Write-Host "V91-I05 H3 READY: $latestReadyPath" `
        -ForegroundColor Green
    Write-Host (
        "Esperando a H1 por la LAN fisica $($lan.local_ipv4):$controlPort..."
    ) -ForegroundColor Cyan

    $accept = $controlListener.BeginAcceptTcpClient($null, $null)
    while (-not $accept.AsyncWaitHandle.WaitOne(500)) {
        $process.Refresh()
        if ($process.HasExited) {
            Throw-I05ClassifiedFailure `
                -Classification PRODUCT_INVARIANT `
                -Category 'candidate_process_exit' `
                -Message 'El downloader termino esperando el canal H1.'
        }
        if ([DateTimeOffset]::UtcNow -ge $expires) {
            throw 'CONFIG caduco antes de recibir COMMAND.'
        }
    }
    $controlClient = $controlListener.EndAcceptTcpClient($accept)
    $controlClient.NoDelay = $true
    $controlClient.Client.SetSocketOption(
        [Net.Sockets.SocketOptionLevel]::Socket,
        [Net.Sockets.SocketOptionName]::KeepAlive, $true)
    $remoteControl = [Net.IPEndPoint]$controlClient.Client.RemoteEndPoint
    $localControl = [Net.IPEndPoint]$controlClient.Client.LocalEndPoint
    if ($remoteControl.Address.ToString() -cne $sourceIPv4 -or
        $localControl.Address.ToString() -cne $lan.local_ipv4.ToString() -or
        [int]$localControl.Port -ne $controlPort) {
        throw 'El canal de control no usa el par IPv4 fisico H1/H3 exacto.'
    }
    $controlStream = $controlClient.GetStream()
    $commandWait = $expires - [DateTimeOffset]::UtcNow
    if ($commandWait.TotalSeconds -lt 300) {
        throw 'CONFIG no deja al menos 300 s para preparar H1 y recibir COMMAND.'
    }
    $commandWaitMilliseconds = [int][Math]::Min(
        2147483000,
        [Math]::Ceiling($commandWait.TotalMilliseconds))
    $controlStream.ReadTimeout = $commandWaitMilliseconds
    $controlStream.WriteTimeout = 30000
    $readyWireHash = Send-I05ControlDocument -Stream $controlStream `
        -Type READY -Nonce $nonce -Path $runReadyPath
    $commandPath = Join-Path $runRoot 'COMMAND-V91-I05-T1.json'
    $commandRecord = Receive-I05ControlDocument -Stream $controlStream `
        -Type COMMAND -Nonce $nonce -Destination $commandPath
    $linkContract = Assert-I05Command `
        -Command $commandRecord.document -Config $config -Nonce $nonce
    Confirm-I05ReceivedDocument -Stream $controlStream -Type COMMAND `
        -Nonce $nonce -Sha256 $commandRecord.sha256
    $controlStream.ReadTimeout = 30000

    $controlListener.Stop()
    $controlListener = $null
    $controlRules = @(Get-NetFirewallRule -PolicyStore ActiveStore `
        -Name $controlFirewallName -ErrorAction Stop)
    if ($controlRules.Count -ne 1 -or
        [string]$controlRules[0].DisplayName -cne
            $controlFirewallDisplayName) {
        throw 'La regla de control dejo de ser propia/unica.'
    }
    $null = Assert-I05FirewallRule -Name $controlFirewallName `
        -DisplayName $controlFirewallDisplayName -Program $powershellPath `
        -InterfaceAlias ([string]$lan.adapter.Name) `
        -LocalAddress $lan.local_ipv4.ToString() `
        -RemoteAddress $sourceIPv4 -LocalPort $controlPort
    # Keep the exact nonce-owned H1->H3 rule for the established coordination
    # stream. The listener is already closed, so no second client can enter;
    # removing this allow rule here can tear down the stream before STARTED.
    # Formal cleanup removes and proves absence of the rule.

    $phase = 'direct_injection'
    try {
        $directDelivery = Send-I05Ed2kLink -Process $process `
            -Link $linkContract.direct_link
        $queue = Wait-I05QueueOwnership -Process $process -Node $nodePath
    } catch {
        if ($_.Exception.Data.Contains('i05_classification')) {
            throw
        }
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'direct_link_injection' `
            -Message $_.Exception.Message
    }
    $startedAt = [DateTimeOffset]::UtcNow
    $started = [ordered]@{
        schema = 'ese.v91.i05.t1-started/v1'
        case_id = 'V91-I05'
        status = 'STARTED'
        nonce = $nonce
        created_at_utc = $startedAt.ToString('o')
        command_sha256 = $commandRecord.sha256
        candidate = $ready.candidate
        node = [ordered]@{
            process_id = $processId
            emule_sha256 = $expectedEmuleSha256
            ipv6_mode = 0
            kad_network_mask = 0
            kad_connected = $false
            kad2_connected = $false
            kad6_running = $false
            kad6_connected = $false
        }
        injection = [ordered]@{
            delivery_count = 1
            direct_injected = [bool]$directDelivery.accepted
            queue_owned_after_direct = $true
            direct_link_sha256 = $linkContract.direct_link_sha256
            queue_observed_at_utc = $queue.observed_at_utc
        }
        capture = [ordered]@{
            backend = 'pktmon'
            status = 'ARMED'
            intent_sha256 = $intentHash
        }
    }
    $startedPath = Write-LabJson -Value $started -Path (
        Join-Path $runRoot 'STARTED-V91-I05-T1.json')
    $startedWireHash = Send-I05ControlDocument -Stream $controlStream `
        -Type STARTED -Nonce $nonce -Path $startedPath
    Write-Host 'V91-I05 H3 STARTED: transferencia en curso.' `
        -ForegroundColor Green

    $phase = 'direct_transfer'
    $samplesPath = Join-Path $evidenceRoot 'transfer-samples.jsonl'
    $socketProofPath = Join-Path $evidenceRoot 'socket-proof.json'
    $fixtureCalculationReportPath = Join-Path $evidenceRoot `
        'file-integrity-calculation.raw.json'
    $transfer = Wait-I05TransferComplete -Process $process -Lan $lan `
        -SourceIPv4 $sourceIPv4 -Preferences $preferencesPath `
        -Node $nodePath -SamplesPath $samplesPath `
        -SocketProofPath $socketProofPath `
        -FixtureVerifier $fixtureVerifierPath `
        -FixtureSeed (Join-Path $packagePath 'ffmpeg.exe') `
        -FixtureReportPath $fixtureCalculationReportPath `
        -ControlClient $controlClient `
        -ContainmentPlan $containmentPlan
    $privateSession.containment = $containmentPlan
    $active.containment = $containmentPlan
    Save-I05OwnershipDocuments -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath
    $finalStatus = Assert-I05RuntimeIPv4Only -ProcessId $processId `
        -Lan $lan -Preferences $preferencesPath
    $safeFinalStatus = ConvertTo-LabSanitizedValue `
        -InputObject $finalStatus -RedactAddresses
    $finalStatusPath = Write-LabJson -Value $safeFinalStatus `
        -Path (Join-Path $evidenceRoot 'status-final.json')
    $finalRoute = Get-I05EffectiveRouteEvidence `
        -RemoteIPv4 $sourceIPv4
    if ([int]$finalRoute.interface_index -ne [int]$lan.adapter.ifIndex -or
        [string]$finalRoute.source_address -cne
            $lan.local_ipv4.ToString() -or
        [string]$finalRoute.next_hop -cne '0.0.0.0') {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'physical_route_changed' `
            -Message 'La ruta efectiva final ya no es la LAN fisica on-link.'
    }
    if ([string]$containmentPlan.state_verified_sha256 -cne
            [string]$containmentPlan.state_armed_sha256 -or
        [int]$containmentPlan.verification_count -lt 1 -or
        [int]$transfer.watchdog_violations -ne 0 -or
        [int]$transfer.sample_count -lt 1 -or
        [int]$transfer.engine_watchdog_samples -ne
            [int]$transfer.engine_watchdog_exact_filter_checks -or
        [int]$transfer.engine_watchdog_exact_filter_checks -ne
            [int]$transfer.sample_count) {
        Throw-I05ClassifiedFailure -Classification LAB_BLOCKED `
            -Category 'firewall_containment_evidence' `
            -Message 'La evidencia containment no esta cerrada/exacta.'
    }
    $containmentForWire = [ordered]@{
        schema = 'ese.v91.i05.t1-firewall-containment/v1'
        rule_count = [int]$containmentPlan.rule_count
        rule_names_sha256 =
            [string]$containmentPlan.rule_names_sha256
        spec_sha256 = [string]$containmentPlan.spec_sha256
        spec_document_sha256 =
            [string]$containmentPlan.spec_document_sha256
        inventory_before_sha256 =
            [string]$containmentPlan.inventory_before_sha256
        inventory_armed_sha256 =
            [string]$containmentPlan.inventory_armed_sha256
        inventory_verified_sha256 =
            [string]$containmentPlan.inventory_verified_sha256
        state_before_sha256 =
            [string]$containmentPlan.state_before_sha256
        state_armed_sha256 =
            [string]$containmentPlan.state_armed_sha256
        state_verified_sha256 =
            [string]$containmentPlan.state_verified_sha256
        direct_link_only = $true
        third_party_sources_forbidden = $true
        exact_rules_armed = $true
        third_party_bytes_impossible = $true
        watchdog_interval_ms =
            $containmentWatchdogIntervalMilliseconds
        watchdog_samples = [int]$transfer.sample_count
        watchdog_violations = [int]$transfer.watchdog_violations
        verification_count =
            [int]$containmentPlan.verification_count
        inventory_scope = 'exact-ten-nonce-program-rules-only'
        profile_scope = 'Any'
        firewall_service_running = $true
        firewall_profiles_enabled = $true
        firewall_profile_count = 3
        firewall_profiles_sha256 = Get-LabStringSha256 -Value (
            "Domain=true`nPrivate=true`nPublic=true")
        engine_watchdog_samples =
            [int]$transfer.engine_watchdog_samples
        engine_watchdog_exact_filter_checks =
            [int]$transfer.engine_watchdog_exact_filter_checks
        canonical_rules = @($containmentPlan.canonical_rules)
    }
    $phase = 'pktmon_complete'
    $captureResult = Complete-I05Capture -State $capture `
        -SourceIPv4 $sourceIPv4 `
        -DownloaderIPv4 $lan.local_ipv4.ToString() `
        -Adapter $lan.adapter `
        -InterfaceId $interfaceId `
        -CandidatePid $processId `
        -AllowedLocalPorts $transfer.allowed_local_ports `
        -ContainmentEvidence $containmentForWire
    $captureCompleted = $true
    $active.capture_state = 'COMPLETED'
    $active.capture_pcapng_path = $capture.pcapng_path
    $active.capture_pcap_sha256 = $captureResult.pcap_sha256
    $active.capture_analysis_sha256 = $captureResult.analysis_sha256
    $privateSession.capture = $capture
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource pktmon_session `
        -State COMPLETED
    Set-I05MutationState -ActiveDocument $active `
        -ActiveDocumentPath $activePath -SessionDocument $privateSession `
        -SessionDocumentPath $sessionPath -Resource pktmon_filters `
        -State REMOVED

    $pktmonStatus = Get-Content -LiteralPath `
        ([string]$captureResult.status_summary_path) -Raw |
        ConvertFrom-Json
    $pktmonStatus | Add-Member -NotePropertyName `
        candidate_status_ready_sha256 -NotePropertyValue (
            Get-LabSha256 -Path (Join-Path $evidenceRoot 'status-ready.json'))
    $pktmonStatus | Add-Member -NotePropertyName `
        candidate_status_final_sha256 -NotePropertyValue (
            Get-LabSha256 -Path $finalStatusPath)
    $pktmonStatus | Add-Member -NotePropertyName etl_bytes `
        -NotePropertyValue (
            [Int64](Get-Item -LiteralPath $capture.etl_path).Length)
    $pktmonStatus | Add-Member -NotePropertyName etl_sha256 `
        -NotePropertyValue (Get-LabSha256 -Path $capture.etl_path)
    $pktmonStatus | Add-Member -NotePropertyName pcapng_bytes `
        -NotePropertyValue (
            [Int64](Get-Item -LiteralPath $capture.pcapng_path).Length)
    $pktmonStatus | Add-Member -NotePropertyName pcapng_sha256 `
        -NotePropertyValue (Get-LabSha256 -Path $capture.pcapng_path)
    $pktmonStatus | Add-Member -NotePropertyName transfer_samples_bytes `
        -NotePropertyValue (
            [Int64](Get-Item -LiteralPath $samplesPath).Length)
    $pktmonStatus | Add-Member -NotePropertyName transfer_samples_sha256 `
        -NotePropertyValue (Get-LabSha256 -Path $samplesPath)
    $pktmonStatus | Add-Member -NotePropertyName candidate_networks `
        -NotePropertyValue ([ordered]@{
            kad_connected = $false
            kad2_connected = $false
            kad6_running = $false
            kad6_connected = $false
        })
    Write-LabJson -Value $pktmonStatus `
        -Path ([string]$captureResult.status_summary_path) | Out-Null
    $runPrefix = [IO.Path]::GetFullPath($runRoot).TrimEnd('\', '/') + '\'
    $destinationFull = [IO.Path]::GetFullPath([string]$transfer.path)
    if (-not $destinationFull.StartsWith(
            $runPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'El destino verificado escapa de RunRoot.'
    }
    $fileIntegrity = [ordered]@{
        schema = 'ese.v91.i05.t1-file-integrity/v1'
        case_id = 'V91-I05'
        name = $fixtureName
        name_sha256 = Get-LabStringSha256 -Value $fixtureName
        path_relative = $destinationFull.Substring(
            $runPrefix.Length).Replace('\', '/')
        bytes = [Int64]$transfer.bytes
        sha256 = [string]$transfer.sha256
        ed2k = [string]$transfer.ed2k
        method = [string]$transfer.local_identity_method
        calculation_report_sha256 =
            [string]$transfer.calculation_report_sha256
        calculated_at_utc = Get-LabUtcTimestamp
    }
    $fileIntegrityPath = Write-LabJson -Value $fileIntegrity `
        -Path (Join-Path $evidenceRoot 'file-integrity.json')
    $phase = 'evidence_bundle'
    $bundleResult = New-I05CompactEvidenceBundle -RunRoot $runRoot `
        -EvidenceRoot $evidenceRoot -Nonce $nonce `
        -CaptureState $capture -CaptureResult $captureResult `
        -ContainmentPlan $containmentPlan `
        -SamplesPath $samplesPath -SocketProofPath $socketProofPath `
        -FileIntegrityPath $fileIntegrityPath
    $bundleForWire = [ordered]@{
        schema = [string]$bundleResult.schema
        encoding = [string]$bundleResult.encoding
        bytes = [int]$bundleResult.bytes
        sha256 = [string]$bundleResult.sha256
        manifest_sha256 = [string]$bundleResult.manifest_sha256
        content_base64 = [string]$bundleResult.content_base64
    }
    $captureForWire = [ordered]@{
        backend = 'pktmon'
        status = 'PASS'
        pcap_path_relative = $captureResult.pcap_path_relative
        pcap_sha256 = $captureResult.pcap_sha256
        pcap_bytes = $captureResult.pcap_bytes
        etl_bytes = $captureResult.etl_bytes
        interface_id = $captureResult.interface_id
        packet_size = $captureResult.packet_size
        physical_interface = $true
        primary_component_id = $captureResult.primary_component_id
        converted_component_id = $captureResult.converted_component_id
        conversion_hit_count = 1
        component_mapping_sha256 =
            $captureResult.component_mapping_sha256
        mapping_key_sha256 = $captureResult.mapping_key_sha256
        physical_component_guid_match = $true
        ipv4_peer_packets = $captureResult.ipv4_peer_packets
        rejected_peer_tuple_packets = 0
        third_party_peer_packets = 0
        ipv6_peer_packets = 0
        requestparts_i64 = $captureResult.requestparts_i64
        compressedpart_32 = $captureResult.compressedpart_32
        sendingpart_i64 = $captureResult.sendingpart_i64
        compressedpart_i64 = $captureResult.compressedpart_i64
        sending_i64 = $captureResult.sending_i64
        compressed_i64 = $captureResult.compressed_i64
        capture_complete = $true
        packet_loss_detected = $false
        tuple_exact = $true
        filter_scope_exact = $true
        etl_loss_proved_zero = $true
        etl_below_file_limit = $true
        pcap_parsed = $true
        candidate_pid = $processId
        candidate_pid_role = 'socket-watchdog-context-only'
        pcap_pid_attributed = $false
        tuple_allowlist_pid_observed = $true
        process_scoped_containment = $true
        ed2k_framing_valid = $true
        allowed_opcodes_only = $true
        etw_loss_proved_zero = $true
        filters_restored = $true
        filters_absent_after = $true
        etw_session_absent_after = $true
        filter_inventory_restored = $true
        analysis_sha256 = $captureResult.analysis_sha256
    }
    $completeAt = [DateTimeOffset]::UtcNow
    $complete = [ordered]@{
        schema = 'ese.v91.i05.t1-complete/v1'
        case_id = 'V91-I05'
        status = 'PASS'
        nonce = $nonce
        created_at_utc = $completeAt.ToString('o')
        candidate = $ready.candidate
        file = [ordered]@{
            name = $fixtureName
            destination_bytes = $transfer.bytes
            destination_sha256 = $transfer.sha256
            ed2k = $transfer.ed2k
            ed2k_source = 'local-streaming-calculation'
            integrity_sha256 = Get-LabSha256 -Path $fileIntegrityPath
            calculation_report_sha256 =
                $transfer.calculation_report_sha256
            complete = $true
        }
        node = [ordered]@{
            process_id = $processId
            emule_sha256 = $expectedEmuleSha256
            ipv6_mode = 0
            kad_network_mask = 0
            kad_connected = $false
            kad2_connected = $false
            kad6_running = $false
            kad6_connected = $false
            windows_ipv6_binding_enabled = $true
            api_responsive = $true
            tcp_listener_owned = $true
        }
        route = [ordered]@{
            family = 'IPv4'
            physical = $true
            on_link = $true
            interface_id = $interfaceId
            source_address_sha256 = Get-LabStringSha256 `
                -Value $lan.local_ipv4.ToString()
            remote_address_sha256 =
                Get-LabStringSha256 -Value $sourceIPv4
            next_hop = $finalRoute.next_hop
            destination_prefix = $finalRoute.destination_prefix
        }
        socket_proof = [ordered]@{
            sha256 = $transfer.socket_proof_sha256
            candidate_pid = $processId
            observed_ephemeral_ports =
                @($transfer.allowed_local_ports | Sort-Object -Unique)
            unique_tuple_count = $transfer.unique_tuple_count
            stable_tuple = $transfer.stable_tuple
            forbidden_tuple_count = 0
            forbidden_established_count = 0
            sample_count = $transfer.sample_count
        }
        capture = $captureForWire
        containment = $containmentForWire
        evidence_bundle = $bundleForWire
        evidence = [ordered]@{
            command_sha256 = $commandRecord.sha256
            started_sha256 = Get-LabSha256 -Path $startedPath
            samples_sha256 = Get-LabSha256 -Path $samplesPath
            sample_count = $transfer.sample_count
        }
    }
    $completePath = Write-LabJson -Value $complete -Path (
        Join-Path $runRoot 'COMPLETE-V91-I05-T1.json')
    $process.Refresh()
    if ($process.HasExited) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_process_exit' `
            -Message 'El candidato termino antes de publicar COMPLETE.'
    }
    $completeWireHash = Send-I05ControlDocument -Stream $controlStream `
        -Type COMPLETE -Nonce $nonce -Path $completePath
    Write-Host 'V91-I05 H3 COMPLETE PASS; esperando STOP de H1.' `
        -ForegroundColor Green

    $stopPath = Join-Path $runRoot 'STOP-V91-I05-T1.json'
    $stopRecord = Receive-I05ControlDocument -Stream $controlStream `
        -Type STOP -Nonce $nonce -Destination $stopPath
    $stop = $stopRecord.document
    Assert-I05ExactString -Value $stop.schema `
        -Expected 'ese.v91.i05.t1-stop/v1' -Label 'STOP schema'
    Assert-I05ExactString -Value $stop.case_id `
        -Expected 'V91-I05' -Label 'STOP case_id'
    Assert-I05ExactString -Value $stop.status `
        -Expected 'STOP' -Label 'STOP status'
    Assert-I05ExactString -Value $stop.nonce `
        -Expected $nonce -Label 'STOP nonce'
    Assert-I05ExactString -Value $stop.reason `
        -Expected 'completed' -Label 'STOP reason'
    foreach ($property in @(
        'version', 'commit', 'emule_sha256', 'ese_server_sha256',
        'build_info_sha256', 'zip_sha256', 'zip_bytes'
    )) {
        Assert-I05ExactString -Value $stop.candidate.$property `
            -Expected $ready.candidate.$property `
            -Label "STOP candidate.$property"
    }
    if ([bool]$stop.candidate.dirty) {
        throw 'STOP candidate.dirty debe ser false.'
    }
    Confirm-I05ReceivedDocument -Stream $controlStream -Type STOP `
        -Nonce $nonce -Sha256 $stopRecord.sha256
    $process.Refresh()
    if ($process.HasExited) {
        Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
            -Category 'candidate_process_exit' `
            -Message 'El candidato termino antes del cleanup formal.'
    }
    $cleanupResult = & $cleanupPath
    if ([string]$cleanupResult.status -cne 'CLEANUP_COMPLETE') {
        throw 'El cleanup H3 devolvio error.'
    }
    $cleanupInvoked = $true
    $cleanupDocumentPath = Join-Path $runRoot 'CLEANUP-V91-I05-T1.json'
    if (-not (Test-Path -LiteralPath $cleanupDocumentPath -PathType Leaf)) {
        throw 'El cleanup H3 no escribio CLEANUP.'
    }
    $cleanupWireHash = Send-I05ControlDocument -Stream $controlStream `
        -Type CLEANUP -Nonce $nonce -Path $cleanupDocumentPath
    $controlStream.Dispose()
    $controlStream = $null
    $controlClient.Close()
    $controlClient = $null
    Write-Host 'V91-I05 H3 CLEANUP confirmado por H1.' `
        -ForegroundColor Green
    Exit-I05SingleInstance
} catch {
    $failureException = $_.Exception
    $message = $failureException.Message
    $classification = if (
        $failureException.Data.Contains('i05_classification')
    ) {
        [string]$failureException.Data['i05_classification']
    } else { 'LAB_BLOCKED' }
    $category = if ($failureException.Data.Contains('i05_category')) {
        [string]$failureException.Data['i05_category']
    } else { [string]$phase }
    try {
        if ($null -ne $controlListener) { $controlListener.Stop() }
    } catch {}
    $cleanupRequired =
        (Test-Path -LiteralPath $activePath -PathType Leaf) -or
        $firewallCreated -or $controlFirewallCreated -or
        $containmentCreated -or
        $processId -gt 0 -or
        ($null -ne $capture -and [bool]$capture.started)
    # Notify H1 while the nonce-owned physical control channel is still
    # intact.  Cleanup removes that channel's firewall rule, so waiting until
    # afterwards could leave H1 blocked until its two-hour transfer timeout.
    # The wire document truthfully reports that cleanup has not started yet;
    # the final local FAILURE below is rewritten with the completed outcome.
    $failureDelivered = $false
    if ($null -ne $controlStream -and
        $nonce -match '^[0-9a-f]{32}$') {
        try {
            $pendingFailure = [ordered]@{
                schema = 'ese.v91.i05.t1-failure/v1'
                case_id = 'V91-I05'
                status = $classification
                nonce = $nonce
                created_at_utc = Get-LabUtcTimestamp
                phase = [string]$phase
                category = $category
                message_sha256 = Get-LabStringSha256 -Value (
                    Protect-LabText -Value $message -RedactAddresses)
                candidate = [ordered]@{
                    version = $expectedVersion
                    commit = $expectedCommit
                    dirty = $false
                    emule_sha256 = $expectedEmuleSha256
                    zip_sha256 = $expectedArchiveSha256
                    zip_bytes = $expectedArchiveBytes
                }
                cleanup = [ordered]@{
                    attempted = $false
                    complete = $false
                    status = 'NOT_ATTEMPTED'
                    error_sha256 = $null
                }
            }
            $pendingFailurePath = Write-LabJson -Value $pendingFailure `
                -Path (Join-Path $runRoot `
                    'evidence\FAILURE-PENDING-V91-I05-T1.json')
            $controlStream.ReadTimeout = 30000
            $controlStream.WriteTimeout = 30000
            $null = Send-I05ControlDocument -Stream $controlStream `
                -Type FAILURE -Nonce $nonce -Path $pendingFailurePath
            $failureDelivered = $true
        } catch {
            # A final delivery is retried after cleanup. Local evidence is
            # always authoritative for the unattended agent.
        }
    }
    $centralCleanupError = $null
    $cleanupAttempted = $false
    if (-not $cleanupInvoked -and
        (Test-Path -LiteralPath $activePath -PathType Leaf) -and
        (Test-Path -LiteralPath $cleanupPath -PathType Leaf)) {
        $cleanupAttempted = $true
        try {
            $cleanupFallback = & $cleanupPath
            if ([string]$cleanupFallback.status -ne 'CLEANUP_COMPLETE') {
                throw 'cleanup no devolvio CLEANUP_COMPLETE'
            }
            $cleanupInvoked = $true
        } catch {
            $centralCleanupError = $_.Exception.Message
        }
    }
    if (-not $cleanupInvoked -and $cleanupRequired -and
        -not (Test-Path -LiteralPath $activePath -PathType Leaf)) {
        $centralCleanupError =
            'ACTIVE formal ausente; no se tocan recursos sin ownership.'
    }
    $cleanupComplete = [bool]$cleanupInvoked -or -not $cleanupRequired
    $cleanupAttemptedForReport =
        [bool]$cleanupAttempted -or [bool]$cleanupInvoked
    $failurePath = $null
    $safeMessage = Protect-LabText -Value $message -RedactAddresses
    try {
        $failure = [ordered]@{
            schema = 'ese.v91.i05.t1-failure/v1'
            case_id = 'V91-I05'
            status = $classification
            nonce = $nonce
            created_at_utc = Get-LabUtcTimestamp
            phase = [string]$phase
            category = $category
            message_sha256 = Get-LabStringSha256 -Value $safeMessage
            candidate = [ordered]@{
                version = $expectedVersion
                commit = $expectedCommit
                dirty = $false
                emule_sha256 = $expectedEmuleSha256
                zip_sha256 = $expectedArchiveSha256
                zip_bytes = $expectedArchiveBytes
            }
            cleanup = [ordered]@{
                attempted = $cleanupAttemptedForReport
                complete = [bool]$cleanupInvoked
                status = if (-not $cleanupAttemptedForReport -and
                    -not $cleanupRequired) {
                    'NOT_ATTEMPTED'
                } elseif ($cleanupInvoked) {
                    'CLEANUP_COMPLETE'
                } elseif ($cleanupAttempted) {
                    'FAILED'
                } else {
                    'NOT_ATTEMPTED'
                }
                error_sha256 = if ($centralCleanupError) {
                    Get-LabStringSha256 -Value (
                        Protect-LabText -Value $centralCleanupError `
                            -RedactAddresses)
                } else { $null }
            }
        }
        $null = Write-LabJson -Value $failure -Path $latestFailurePath
        [IO.File]::WriteAllLines(
            $latestErrorPath,
            [string[]]@(
                "status=$classification",
                "phase=$phase",
                "category=$category",
                "message=$safeMessage"
            ),
            (New-Object Text.UTF8Encoding($false)))
        if ($runRoot -and (Test-Path -LiteralPath $runRoot)) {
            $failurePath = Write-LabJson -Value $failure `
                -Path (Join-Path $runRoot 'evidence\FAILURE-V91-I05-T1.json')
        }
    } catch {}
    if (-not $failureDelivered -and
        $null -ne $controlStream -and $failurePath -and
        $nonce -match '^[0-9a-f]{32}$') {
        try {
            $controlStream.ReadTimeout = 30000
            $controlStream.WriteTimeout = 30000
            $null = Send-I05ControlDocument -Stream $controlStream `
                -Type FAILURE -Nonce $nonce -Path $failurePath
        } catch {
            # FAILURE is best-effort; local evidence and cleanup remain primary.
        }
    }
    try {
        if ($null -ne $controlStream) { $controlStream.Dispose() }
    } catch {}
    try {
        if ($null -ne $controlClient) { $controlClient.Close() }
    } catch {}
    Exit-I05SingleInstance
    Write-Host 'ERROR AL PREPARAR V91-I05 H3' `
        -ForegroundColor White -BackgroundColor DarkRed
    Write-Host $message -ForegroundColor Red
    exit 1
}
