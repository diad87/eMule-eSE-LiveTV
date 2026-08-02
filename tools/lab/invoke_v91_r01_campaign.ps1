[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HomeProfile,
    [Parameter(Mandatory = $true)][string]$HotspotProfile,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AgentIPv4,
    [ValidateRange(1024, 65535)][int]$AgentPort = 8015,
    [string]$TokenDpapiPath = (
        "$env:LOCALAPPDATA\eSE-Lab-Controller\smallframe-token.dpapi"),
    [string]$ServerInterfaceAlias = 'Ethernet',
    [string]$LaptopWifiInterfaceAlias = 'Wi-Fi',
    [ValidateRange(1024, 65533)][int]$ServerPort = 51901,
    [ValidateRange(1024, 65534)][int]$ProbePort = 51902,
    [ValidateRange(1024, 65535)][int]$CandidateTcpPort = 51662,
    [ValidateRange(1024, 65535)][int]$CandidateUdpPort = 51672,
    [ValidateRange(1024, 65535)][int]$CandidateWebPort = 51711,
    [string]$MobileServerAddress = '',
    [Parameter(Mandatory = $true)][string]$CandidatePackagePath,
    [Parameter(Mandatory = $true)][string]$CandidateZipPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory = $true)][string]$RemoteCandidateZipPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedH3SidSha256,
    [Parameter(Mandatory = $true)][switch]$DisposableH3AccountConfirmed,
    [string]$OutputRoot = '',
    [ValidateRange(300, 1200)][int]$TimeoutSeconds = 600,
    [ValidateRange(60, 300)][int]$CleanupGraceSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'v91_r01_upnp.ps1')

$parsedAgentIPv4 = $null
if (-not [Net.IPAddress]::TryParse($AgentIPv4, [ref]$parsedAgentIPv4) -or
    $parsedAgentIPv4.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork -or
    $parsedAgentIPv4.Equals([Net.IPAddress]::Any)) {
    throw 'AgentIPv4 must be an explicit, usable IPv4 literal.'
}
$AgentIPv4 = $parsedAgentIPv4.ToString()

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $PSScriptRoot '..\..\lab-runs\v91-r01'
}
$controller = Join-Path $PSScriptRoot 'control_ese_lab_smallframe_agent.ps1'
$remoteRunner = Join-Path $PSScriptRoot 'run_v91_r01_remote.ps1'
$serverRunner = Join-Path $PSScriptRoot 'run_v91_r01_server.ps1'
$watchdogRunner = Join-Path $PSScriptRoot 'run_v91_r01_wifi_watchdog.ps1'
foreach ($path in @($controller, $remoteRunner, $serverRunner,
        $watchdogRunner,
        (Join-Path $CandidatePackagePath 'emule.exe'),
        (Join-Path $CandidatePackagePath 'ese-server.exe'),
        (Join-Path $CandidatePackagePath 'BUILD_INFO.txt'),
        $CandidateZipPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing required R01 input: $path"
    }
}
if ($ServerPort -eq $ProbePort) {
    throw 'ServerPort and ProbePort must be distinct.'
}
$allCampaignPorts = @(
    $ServerPort, $ProbePort, $CandidateTcpPort, $CandidateUdpPort,
    $CandidateWebPort)
if (@($allCampaignPorts | Select-Object -Unique).Count -ne
        $allCampaignPorts.Count) {
    throw 'All R01 server, probe and candidate ports must be distinct.'
}
if (-not $DisposableH3AccountConfirmed) {
    throw 'Formal R01 requires an explicitly confirmed disposable H3 lab account.'
}
$ExpectedH3SidSha256 = $ExpectedH3SidSha256.ToLowerInvariant()
if ([string]::IsNullOrWhiteSpace($HomeProfile) -or
    [string]::IsNullOrWhiteSpace($HotspotProfile) -or
    [string]::Equals($HomeProfile.Trim(), $HotspotProfile.Trim(),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'HomeProfile and HotspotProfile must identify two non-empty, different saved WLAN profiles.'
}

function Get-R01TextSha256 {
    param([Parameter(Mandatory = $true)][string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) |
                ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

function Get-R01StreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($Stream) | ForEach-Object {
                    $_.ToString('x2')
                }) -join '')
    } finally { $sha.Dispose() }
}

function Assert-R01NoReparsePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowMissingLeaf
    )
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    if (-not (Test-Path -LiteralPath $cursor)) {
        if (-not $AllowMissingLeaf) {
            throw "Required path is missing: $full"
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "R01 rejects reparse-point path component: $cursor"
        }
        $parent = [IO.Path]::GetDirectoryName($cursor.TrimEnd('\'))
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) {
            break
        }
        $cursor = $parent
    }
    return $full
}

function Test-R01SafeRelativePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or
        [IO.Path]::IsPathRooted($Path) -or $Path.Contains(':') -or
        $Path.Contains([char]0)) { return $false }
    $normalized = $Path.Replace('\', '/')
    if ($normalized.StartsWith('/') -or $normalized.EndsWith('/')) {
        return $false
    }
    $parts = @($normalized.Split('/'))
    return ($parts.Count -gt 0 -and @($parts | Where-Object {
                [string]::IsNullOrWhiteSpace($_) -or $_ -in @('.', '..')
            }).Count -eq 0)
}

function Get-R01PackageFileCensus {
    param([Parameter(Mandatory = $true)][string]$Root)
    $rootFull = (Assert-R01NoReparsePath -Path $Root).TrimEnd('\')
    $prefix = $rootFull + '\'
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($rootFull)
    $files = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force `
                -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "R01 package tree contains a reparse point: $($item.FullName)"
            }
            $full = [IO.Path]::GetFullPath([string]$item.FullName)
            if (-not $full.StartsWith(
                    $prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'R01 package census escaped its root.'
            }
            if ($item.PSIsContainer) {
                $queue.Enqueue($full)
                continue
            }
            $relative = $full.Substring($prefix.Length).Replace('\', '/')
            if (-not (Test-R01SafeRelativePath -Path $relative) -or
                -not $seen.Add($relative)) {
                throw "Invalid, duplicate or case-colliding package path '$relative'."
            }
            $files.Add([pscustomobject][ordered]@{
                    relative_path = $relative
                    full_path = $full
                })
        }
    }
    return @($files | Sort-Object relative_path)
}

function Get-R01PackageManifestCanonical {
    param([Parameter(Mandatory = $true)]$Files)
    [string[]]$lines = @($Files | ForEach-Object {
            "{0}`t{1}`t{2}" -f [string]$_.relative_path,
                [Int64]$_.bytes, ([string]$_.sha256).ToLowerInvariant()
        })
    [Array]::Sort($lines, [StringComparer]::Ordinal)
    return $lines -join "`n"
}

function Test-R01OverlayAdapter {
    param([Parameter(Mandatory = $true)]$Adapter)
    $text = @(
        [string]$Adapter.Name, [string]$Adapter.InterfaceAlias,
        [string]$Adapter.InterfaceDescription) -join ' '
    return $text -match (
        '(?i)tailscale|wireguard|cloudflare|warp|zerotier|openvpn|' +
        'hyper-v|vethernet|loopback|tunnel|tap|vpn|hamachi')
}

function Get-R01ZipPackageEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)]$Candidate
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $packageRoot = (Assert-R01NoReparsePath `
        -Path ([string]$Candidate.package_path)).TrimEnd('\')
    $zipFull = Assert-R01NoReparsePath -Path $ZipPath
    $census = @(Get-R01PackageFileCensus -Root $packageRoot)
    if ($census.Count -lt 3) {
        throw 'Candidate package manifest is unexpectedly small.'
    }

    # Every loose-package file and the ZIP stay open without write/delete share
    # for the whole comparison. The evidence therefore describes one immutable
    # byte snapshot, not a sequence of racy path reads.
    $packageStreams = [Collections.Generic.List[IO.FileStream]]::new()
    $packageEntries = [Collections.Generic.List[object]]::new()
    $packageByPath = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $zipStream = $null
    $archive = $null
    try {
        foreach ($file in $census) {
            $stream = [IO.File]::Open(
                [string]$file.full_path, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $packageStreams.Add($stream)
            $hash = Get-R01StreamSha256 -Stream $stream
            $stream.Position = 0
            $entry = [pscustomobject][ordered]@{
                relative_path = [string]$file.relative_path
                bytes = [Int64]$stream.Length
                sha256 = $hash
            }
            if ($packageByPath.ContainsKey([string]$entry.relative_path)) {
                throw "Duplicate/case-colliding package path '$($entry.relative_path)'."
            }
            $packageByPath.Add([string]$entry.relative_path, $entry)
            $packageEntries.Add($entry)
        }
        foreach ($required in @(
                @{ path = 'emule.exe'; hash = [string]$Candidate.emule_sha256 },
                @{ path = 'ese-server.exe'; hash = [string]$Candidate.ese_server_sha256 },
                @{ path = 'BUILD_INFO.txt'; hash = [string]$Candidate.build_info_sha256 }
            )) {
            if (-not $packageByPath.ContainsKey($required.path) -or
                [string]$packageByPath[$required.path].sha256 -cne
                    ([string]$required.hash).ToLowerInvariant()) {
                throw "Candidate identity mismatch for '$($required.path)'."
            }
        }

        $zipStream = [IO.File]::Open(
            $zipFull, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        $zipHash = Get-R01StreamSha256 -Stream $zipStream
        $zipBytes = [Int64]$zipStream.Length
        $zipStream.Position = 0
        $archive = [IO.Compression.ZipArchive]::new(
            $zipStream, [IO.Compression.ZipArchiveMode]::Read, $true)
        $allEntries = @($archive.Entries)
        foreach ($candidateEntry in $allEntries) {
            $normalizedName = ([string]$candidateEntry.FullName).Replace('\', '/')
            $trimmed = $normalizedName.TrimEnd('/')
            $attributeBits = [BitConverter]::ToUInt32(
                [BitConverter]::GetBytes(
                    [int]$candidateEntry.ExternalAttributes), 0)
            $unixType = (($attributeBits -shr 16) -band 0xF000)
            if ([string]::IsNullOrWhiteSpace($trimmed) -or
                -not (Test-R01SafeRelativePath -Path $trimmed) -or
                $unixType -eq 0xA000) {
                throw "Unsafe ZIP entry '$normalizedName'."
            }
        }
        $zipFiles = @($allEntries | Where-Object {
                -not ([string]$_.FullName).EndsWith('/') -and
                -not ([string]$_.FullName).EndsWith('\')
            })
        $markers = @($zipFiles | Where-Object {
                [IO.Path]::GetFileName(
                    ([string]$_.FullName).Replace('\', '/')) -ceq
                    'BUILD_INFO.txt'
            })
        if ($markers.Count -ne 1) {
            throw 'ZIP must contain exactly one BUILD_INFO.txt root marker.'
        }
        $markerName = ([string]$markers[0].FullName).Replace('\', '/')
        $rootPrefix = $markerName.Substring(
            0, $markerName.Length - 'BUILD_INFO.txt'.Length)
        $zipByPath = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($zipEntry in $zipFiles) {
            $entryName = ([string]$zipEntry.FullName).Replace('\', '/')
            if (-not $entryName.StartsWith(
                    $rootPrefix, [StringComparison]::Ordinal)) {
                throw "ZIP entry is outside the candidate root: $entryName"
            }
            $relative = $entryName.Substring($rootPrefix.Length)
            if (-not (Test-R01SafeRelativePath -Path $relative) -or
                $zipByPath.ContainsKey($relative)) {
                throw "Invalid, duplicate or case-colliding ZIP path '$relative'."
            }
            $entryStream = $zipEntry.Open()
            try { $hash = Get-R01StreamSha256 -Stream $entryStream }
            finally { $entryStream.Dispose() }
            $zipByPath.Add($relative, [pscustomobject][ordered]@{
                    relative_path = $relative
                    zip_entry = $entryName
                    bytes = [Int64]$zipEntry.Length
                    sha256 = $hash
                })
        }
        if ($zipByPath.Count -ne $packageByPath.Count) {
            throw ('ZIP/package file count differs: ZIP={0}, package={1}.' -f
                $zipByPath.Count, $packageByPath.Count)
        }
        foreach ($relative in $packageByPath.Keys) {
            if (-not $zipByPath.ContainsKey($relative)) {
                throw "ZIP is missing package file '$relative'."
            }
            $packageEntry = $packageByPath[$relative]
            $zipEntry = $zipByPath[$relative]
            if ([Int64]$zipEntry.bytes -ne [Int64]$packageEntry.bytes -or
                [string]$zipEntry.sha256 -cne [string]$packageEntry.sha256) {
                throw "ZIP/package mismatch for '$relative'."
            }
        }
        $canonical = Get-R01PackageManifestCanonical -Files $packageEntries
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.package-zip-binding/v3'
            zip_root_prefix = $rootPrefix
            zip_sha256 = $zipHash
            zip_bytes = $zipBytes
            file_count = $packageEntries.Count
            manifest_sha256 = Get-R01TextSha256 -Text $canonical
            exact_file_set = $true
            exact_bytes_and_sha256 = $true
            locked_snapshot = $true
            reparse_free = $true
            files = @($packageEntries)
        }
    } finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($null -ne $zipStream) { $zipStream.Dispose() }
        foreach ($stream in $packageStreams) { $stream.Dispose() }
    }
}

function Get-R01IPv4Class {
    param([Parameter(Mandatory = $true)][string]$Address)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) { return 'invalid' }
    $bytes = $parsed.GetAddressBytes()
    if ($bytes[0] -eq 10 -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) { return 'private' }
    if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and
        $bytes[1] -le 127) { return 'shared-cgnat' }
    if ($bytes[0] -eq 127) { return 'loopback' }
    if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return 'link-local' }
    $special =
        $bytes[0] -eq 0 -or $bytes[0] -ge 224 -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and $bytes[2] -eq 0) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and $bytes[2] -eq 2) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 31 -and $bytes[2] -eq 196) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 52 -and $bytes[2] -eq 193) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 88 -and $bytes[2] -eq 99) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 175 -and $bytes[2] -eq 48) -or
        ($bytes[0] -eq 198 -and $bytes[1] -in 18, 19) -or
        ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and $bytes[2] -eq 100) -or
        ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113)
    if ($special) {
        return 'special'
    }
    return 'global'
}

function Get-R01PortBaseline {
    param(
        [Parameter(Mandatory = $true)][int[]]$TcpPorts,
        [int[]]$UdpPorts = @()
    )
    # Enumerate first and filter locally: an empty result is legitimate, while
    # a CIM/provider failure remains terminating and can never mean "free".
    $tcpRows = @(Get-NetTCPConnection -ErrorAction Stop)
    $udpRows = @(Get-NetUDPEndpoint -ErrorAction Stop)
    $evidence = [Collections.Generic.List[object]]::new()
    foreach ($port in $TcpPorts) {
        $owners = @($tcpRows | Where-Object { [int]$_.LocalPort -eq $port } |
                Select-Object -ExpandProperty OwningProcess -Unique)
        $evidence.Add([pscustomobject][ordered]@{
                protocol = 'TCP'; port = $port
                available = $owners.Count -eq 0; owner_count = $owners.Count
            })
    }
    foreach ($port in $UdpPorts) {
        $owners = @($udpRows | Where-Object { [int]$_.LocalPort -eq $port } |
                Select-Object -ExpandProperty OwningProcess -Unique)
        $evidence.Add([pscustomobject][ordered]@{
                protocol = 'UDP'; port = $port
                available = $owners.Count -eq 0; owner_count = $owners.Count
            })
    }
    return @($evidence)
}

function Get-R01OwnedFirewallEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Group,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][int]$LocalPort,
        [Parameter(Mandatory = $true)][string]$InterfaceAlias,
        [Parameter(Mandatory = $true)][string]$Program
    )
    $rules = @(Get-NetFirewallRule -Name $Name -ErrorAction Stop)
    if ($rules.Count -ne 1) { throw 'Nonce firewall rule is not unique.' }
    $rule = $rules[0]
    $ports = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $addresses = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $applications = @(
        $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $interfaces = @(
        $rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
    if ($ports.Count -ne 1 -or $addresses.Count -ne 1 -or
        $applications.Count -ne 1 -or $interfaces.Count -ne 1) {
        throw 'Nonce firewall rule does not have one exact filter tuple.'
    }
    $port = $ports[0]
    $address = $addresses[0]
    $application = $applications[0]
    $interface = $interfaces[0]
    if ([string]$rule.DisplayName -cne $Name -or
        [string]$rule.Group -cne $Group -or
        [string]$rule.Direction -cne 'Inbound' -or
        [string]$rule.Action -cne 'Allow' -or
        [string]$rule.Enabled -cne 'True' -or
        [string]$rule.Profile -cne 'Any' -or
        [string]$port.Protocol -cne 'TCP' -or
        [string]$port.LocalPort -cne [string]$LocalPort -or
        [string]$address.LocalAddress -cne $LocalAddress -or
        [string]$address.RemoteAddress -cne 'Any' -or
        [string]$application.Program -ine $Program -or
        [string]$interface.InterfaceAlias -ine $InterfaceAlias) {
        throw 'Nonce firewall rule no longer matches its exact owned tuple.'
    }
    return [pscustomobject][ordered]@{
        name = $Name; group = $Group; local_address = $LocalAddress
        local_port = $LocalPort; interface_alias = $InterfaceAlias
        program = [IO.Path]::GetFullPath($Program)
    }
}

function Get-R01FirewallRulesByNameFailClosed {
    param([Parameter(Mandatory = $true)][string]$Name)
    return @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
            [string]$_.Name -ceq $Name
        })
}

function Remove-R01OwnedFirewallRule {
    param([Parameter(Mandatory = $true)]$Owned)
    $null = Get-R01OwnedFirewallEvidence -Name $Owned.name `
        -Group $Owned.group -LocalAddress $Owned.local_address `
        -LocalPort ([int]$Owned.local_port) `
        -InterfaceAlias $Owned.interface_alias -Program $Owned.program
    Get-NetFirewallRule -Name $Owned.name -ErrorAction Stop |
        Remove-NetFirewallRule -ErrorAction Stop
    return @(Get-R01FirewallRulesByNameFailClosed `
        -Name $Owned.name).Count -eq 0
}

function Get-R01LocalProcessIdentity {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )
    $Process.Refresh()
    if ($Process.HasExited) { throw 'Process exited before identity capture.' }
    $path = [IO.Path]::GetFullPath([string]$Process.Path)
    if ($path -ine [IO.Path]::GetFullPath($ExpectedPath)) {
        throw 'Process path differs from the expected executable.'
    }
    $null = Assert-R01NoReparsePath -Path $path
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { $sha = Get-R01StreamSha256 -Stream $stream }
    finally { $stream.Dispose() }
    return [pscustomobject][ordered]@{
        pid = [int]$Process.Id
        start_time_utc = $Process.StartTime.ToUniversalTime().ToString('o')
        executable_path_sha256 =
            Get-R01TextSha256 -Text $path.ToLowerInvariant()
        executable_sha256 = $sha
    }
}

function Test-R01LocalProcessIdentity {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )
    try {
        $actual = Get-R01LocalProcessIdentity -Process $Process `
            -ExpectedPath $ExpectedPath
        return ([int]$actual.pid -eq [int]$Expected.pid -and
            [string]$actual.start_time_utc -ceq [string]$Expected.start_time_utc -and
            [string]$actual.executable_path_sha256 -ceq
                [string]$Expected.executable_path_sha256 -and
            [string]$actual.executable_sha256 -ceq
                [string]$Expected.executable_sha256)
    } catch { return $false }
}

function Get-R01UpnpBackendEvidence {
    param([Parameter(Mandatory = $true)]$Backend)
    $kind = [string]$Backend.kind
    if ($kind -ceq 'com') {
        return [pscustomobject][ordered]@{
            kind = 'com'
            formal_eligible = $false
            local_address = ''
            gateway_address = ''
            control_uri = ''
            service_type = ''
            identity_sha256 = Get-R01TextSha256 -Text (
                'ese.v91.r01-upnp-backend/v1|com|unbound')
        }
    }
    if ($kind -cne 'soap') { throw 'Unknown R01 UPnP backend identity.' }
    $localAddress = [string]$Backend.local_address
    $gatewayAddress = [string]$Backend.gateway_address
    $controlUri = [Uri]([string]$Backend.control_uri)
    $serviceType = [string]$Backend.service_type
    $localIp = $null
    $gatewayIp = $null
    if (-not [Net.IPAddress]::TryParse($localAddress, [ref]$localIp) -or
        $localIp.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
        -not [Net.IPAddress]::TryParse($gatewayAddress, [ref]$gatewayIp) -or
        $gatewayIp.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
        $serviceType -cnotmatch
            '^urn:schemas-upnp-org:service:(WANIP|WANPPP)Connection:[0-9]+$') {
        throw 'SOAP backend identity is incomplete or invalid.'
    }
    Assert-R01UpnpHttpUri -Uri $controlUri `
        -GatewayAddress $gatewayAddress
    $canonical = 'ese.v91.r01-upnp-backend/v1|soap|{0}|{1}|{2}|{3}' -f
        $localIp.ToString(), $gatewayIp.ToString(),
        $controlUri.AbsoluteUri, $serviceType
    return [pscustomobject][ordered]@{
        kind = 'soap'
        formal_eligible = $true
        local_address = $localIp.ToString()
        gateway_address = $gatewayIp.ToString()
        control_uri = $controlUri.AbsoluteUri
        service_type = $serviceType
        identity_sha256 = Get-R01TextSha256 -Text $canonical
    }
}

function Add-R01OwnedUpnpMapping {
    param(
        [Parameter(Mandatory = $true)]$Backend,
        [Parameter(Mandatory = $true)][int]$ExternalPort,
        [Parameter(Mandatory = $true)][int]$InternalPort,
        [Parameter(Mandatory = $true)][string]$InternalClient,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if ($Description -notmatch '^eR01-[SPF]-[0-9a-f]{24}$' -or
        $Description.Length -gt 32) {
        throw 'UPnP ownership description does not satisfy the R01 contract.'
    }
    $backendEvidence = Get-R01UpnpBackendEvidence -Backend $Backend
    $existing = Get-R01UpnpMapping -Backend $Backend `
        -ExternalPort $ExternalPort
    if ($null -ne $existing) {
        throw "TCP UPnP port $ExternalPort already has a mapping."
    }
    # Register the complete cleanup tuple before the first router mutation.
    # Even if Add succeeds remotely and its response/readback fails locally,
    # catch/finally can later re-read and delete only this exact mapping.
    $cleanupCandidate = [pscustomobject][ordered]@{
        external_port = $ExternalPort
        internal_port = $InternalPort
        internal_client = $InternalClient
        protocol = 'TCP'
        description = $Description
        external_address = ''
        backend = [string]$Backend.kind
        backend_identity_sha256 = [string]$backendEvidence.identity_sha256
    }
    $script:mappingCleanupCandidates.Add($cleanupCandidate)
    $created = $null
    $addError = ''
    try {
        $created = Add-R01UpnpMapping -Backend $Backend `
            -ExternalPort $ExternalPort -InternalPort $InternalPort `
            -InternalClient $InternalClient -Description $Description
    } catch { $addError = $_.Exception.Message }
    $currentReadComplete = $true
    try {
        $current = Get-R01UpnpMapping -Backend $Backend `
            -ExternalPort $ExternalPort
    } catch {
        $current = $null
        $currentReadComplete = $false
    }
    $valid = $null -ne $created -and $null -ne $current -and
        [string]$created.Description -ceq $Description -and
        [string]$created.InternalClient -ceq $InternalClient -and
        [int]$created.InternalPort -eq $InternalPort -and
        [bool]$created.Enabled -and
        [string]$current.Description -ceq $Description -and
        [string]$current.InternalClient -ceq $InternalClient -and
        [int]$current.InternalPort -eq $InternalPort -and
        [bool]$current.Enabled
    if (-not $valid) {
        $ownedCurrent = $null -ne $current -and
            [string]$current.Description -ceq $Description -and
            [string]$current.InternalClient -ceq $InternalClient -and
            [int]$current.InternalPort -eq $InternalPort -and
            [bool]$current.Enabled
        $rollbackAttempted = $false
        $rollbackComplete = $currentReadComplete -and $null -eq $current
        if ($ownedCurrent) {
            $rollbackAttempted = $true
            try {
                Remove-R01UpnpMapping -Backend $Backend `
                    -ExternalPort $ExternalPort
                $rollbackReadComplete = $true
                try {
                    $afterRollback = Get-R01UpnpMapping -Backend $Backend `
                        -ExternalPort $ExternalPort
                } catch {
                    $afterRollback = $null
                    $rollbackReadComplete = $false
                }
                $rollbackComplete = $rollbackReadComplete -and
                    $null -eq $afterRollback
            } catch { $rollbackComplete = $false }
        }
        $script:mappingLifecycleEvidence.Add([pscustomobject][ordered]@{
                external_port = $ExternalPort
                protocol = 'TCP'
                backend = [string]$Backend.kind
                backend_identity_sha256 =
                    [string]$backendEvidence.identity_sha256
                phase = 'add_validation_failed'
                add_error = $addError
                exact_owned_mapping_observed = $ownedCurrent
                rollback_attempted = $rollbackAttempted
                rollback_complete = $rollbackComplete
            })
        throw (
            "Router did not return the owned TCP mapping $ExternalPort; " +
            "rollback_complete=$rollbackComplete.")
    }
    $script:mappingLifecycleEvidence.Add([pscustomobject][ordered]@{
            external_port = $ExternalPort
            protocol = 'TCP'
            backend = [string]$Backend.kind
            backend_identity_sha256 =
                [string]$backendEvidence.identity_sha256
            phase = 'owned_mapping_created'
            add_error = ''
            exact_owned_mapping_observed = $true
            rollback_attempted = $false
            rollback_complete = $null
        })
    $cleanupCandidate.external_address = [string]$created.ExternalIPAddress
    return $cleanupCandidate
}

function Remove-R01OwnedUpnpMapping {
    param(
        [Parameter(Mandatory = $true)]$Backend,
        [Parameter(Mandatory = $true)]$Owned
    )
    $result = [ordered]@{
        resolved = $false
        deleted = $false
        foreign_preserved = $false
        phase = 'owned_mapping_remove_failed'
    }
    $backendEvidence = $null
    try {
        $backendEvidence = Get-R01UpnpBackendEvidence -Backend $Backend
        if ([string]$Owned.backend -cne [string]$Backend.kind) {
            throw 'UPnP backend identity changed before cleanup.'
        }
        if ([string]$Owned.protocol -cne 'TCP') {
            throw 'UPnP owned mapping protocol changed before cleanup.'
        }
        if ([string]$Owned.backend_identity_sha256 -cne
            [string]$backendEvidence.identity_sha256) {
            throw 'UPnP backend endpoint changed before cleanup.'
        }
        $current = Get-R01UpnpMapping -Backend $Backend `
            -ExternalPort ([int]$Owned.external_port)
        if ($null -eq $current) {
            $result.resolved = $true
            $result.phase = 'owned_mapping_absent'
        } elseif (
            [string]$current.Description -ceq [string]$Owned.description -and
            [string]$current.InternalClient -ceq
                [string]$Owned.internal_client -and
            [int]$current.InternalPort -eq [int]$Owned.internal_port -and
            [bool]$current.Enabled) {
            Remove-R01UpnpMapping -Backend $Backend `
                -ExternalPort ([int]$Owned.external_port)
            $remainingReadComplete = $true
            try {
                $remaining = Get-R01UpnpMapping -Backend $Backend `
                    -ExternalPort ([int]$Owned.external_port)
            } catch {
                $remaining = $null
                $remainingReadComplete = $false
            }
            if ($remainingReadComplete -and $null -eq $remaining) {
                $result.resolved = $true
                $result.deleted = $true
                $result.phase = 'owned_mapping_removed'
            } elseif ($remainingReadComplete -and
                ([string]$remaining.Description -cne
                    [string]$Owned.description -or
                [string]$remaining.InternalClient -cne
                    [string]$Owned.internal_client -or
                [int]$remaining.InternalPort -ne
                    [int]$Owned.internal_port -or
                -not [bool]$remaining.Enabled)) {
                $result.resolved = $true
                $result.deleted = $true
                $result.foreign_preserved = $true
                $result.phase = 'foreign_mapping_observed_after_delete'
            }
        } else {
            $result.resolved = $true
            $result.foreign_preserved = $true
            $result.phase = 'foreign_mapping_preserved'
        }
    } catch {}
    $script:mappingLifecycleEvidence.Add([pscustomobject][ordered]@{
            external_port = [int]$Owned.external_port
            protocol = 'TCP'
            backend = [string]$Backend.kind
            backend_identity_sha256 = if ($null -ne $backendEvidence) {
                [string]$backendEvidence.identity_sha256
            } else { '' }
            phase = [string]$result.phase
            rollback_complete = [bool]$result.resolved
            deleted = [bool]$result.deleted
            foreign_preserved = [bool]$result.foreign_preserved
        })
    return [pscustomobject]$result
}

function Test-R01TransitionEvidence {
    param(
        [Parameter(Mandatory = $true)]$Remote,
        [Parameter(Mandatory = $true)]$Server
    )
    try {
        $initial = $Remote.topology.initial
        $mobile = $Remote.topology.mobile
        $probe = $Remote.topology.mobile_public_probe
        $oldSocket = $Remote.session.initial_socket
        $initialGuid = ([string]$initial.interface_guid).Trim('{}')
        $mobileGuid = ([string]$mobile.interface_guid).Trim('{}')
        $initialWlan = [string]$initial.wlan_profile_sha256
        $mobileWlan = [string]$mobile.wlan_profile_sha256
        $initialNla = [string]$initial.connection_profile.name_sha256
        $mobileNla = [string]$mobile.connection_profile.name_sha256
        $probeLocal = [string]$probe.local_address
        $oldLocal = [string]$oldSocket.local_address
        $mobileOwnsProbeAddress = @($mobile.addresses | Where-Object {
                [string]$_.family -ceq 'IPv4' -and
                -not [bool]$_.skip_as_source -and
                [string]$_.address -ceq $probeLocal
            }).Count -eq 1
        $initialOwnsOldAddress = @($initial.addresses | Where-Object {
                [string]$_.family -ceq 'IPv4' -and
                -not [bool]$_.skip_as_source -and
                [string]$_.address -ceq $oldLocal
            }).Count -eq 1
        return (
            -not [string]::IsNullOrWhiteSpace($initialGuid) -and
            $initialGuid -ieq $mobileGuid -and
            [bool]$initial.profile_matches_expected -and
            [bool]$mobile.profile_matches_expected -and
            [bool]$initial.hardware_interface -and
            [bool]$mobile.hardware_interface -and
            -not [bool]$initial.virtual -and -not [bool]$mobile.virtual -and
            -not [bool]$initial.overlay -and -not [bool]$mobile.overlay -and
            [string]$initial.status -ceq 'Up' -and
            [string]$mobile.status -ceq 'Up' -and
            $initialWlan -match '^[0-9a-f]{64}$' -and
            $mobileWlan -match '^[0-9a-f]{64}$' -and
            $initialWlan -cne $mobileWlan -and
            $initialNla -match '^[0-9a-f]{64}$' -and
            $mobileNla -match '^[0-9a-f]{64}$' -and
            $initialNla -cne $mobileNla -and
            [string]$probe.status -ceq 'PASS' -and
            [bool]$probe.physical_nonvirtual -and
            [bool]$probe.selected_route.valid -and
            -not [bool]$probe.selected_route.overlay -and
            ([string]$probe.interface_guid).Trim('{}') -ieq $mobileGuid -and
            -not [string]::IsNullOrWhiteSpace($probeLocal) -and
            -not [string]::IsNullOrWhiteSpace($oldLocal) -and
            $probeLocal -cne $oldLocal -and $mobileOwnsProbeAddress -and
            $initialOwnsOldAddress -and
            [string]$Server.topology_probe.status -ceq 'PASS' -and
            (Get-R01IPv4Class -Address (
                [string]$Server.topology_probe.remote_address)) -ceq
                'global' -and
            -not [string]::IsNullOrWhiteSpace(
                [string]$Server.initial.remote_address) -and
            [string]$Server.topology_probe.remote_address -cne
                [string]$Server.initial.remote_address -and
            [bool]$Remote.topology.initial_selected_route.valid -and
            [bool]$Remote.topology.mobile_selected_route.valid -and
            -not [bool]$Remote.topology.initial_selected_route.overlay -and
            -not [bool]$Remote.topology.mobile_selected_route.overlay
        )
    } catch { return $false }
}

function Test-R01ExactProbeBinding {
    param(
        [Parameter(Mandatory = $true)]$RemoteProbe,
        [Parameter(Mandatory = $true)]$ServerProbe,
        [Parameter(Mandatory = $true)][string]$ServerListenAddress,
        [Parameter(Mandatory = $true)][AllowEmptyString()]
        [string]$ExpectedProbeAddress,
        [Parameter(Mandatory = $true)][int]$ExpectedProbePort,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce
    )
    try {
        $expectedAddress = $null
        $remoteAddress = $null
        $selectedRouteAddress = $null
        $serverListen = $null
        $serverLocal = $null
        if (-not [Net.IPAddress]::TryParse(
                $ExpectedProbeAddress, [ref]$expectedAddress) -or
            $expectedAddress.AddressFamily -ne
                [Net.Sockets.AddressFamily]::InterNetwork -or
            -not [Net.IPAddress]::TryParse(
                [string]$RemoteProbe.remote_address, [ref]$remoteAddress) -or
            -not [Net.IPAddress]::TryParse(
                [string]$RemoteProbe.selected_route.remote_address,
                [ref]$selectedRouteAddress) -or
            -not [Net.IPAddress]::TryParse(
                $ServerListenAddress, [ref]$serverListen) -or
            -not [Net.IPAddress]::TryParse(
                [string]$ServerProbe.local_address, [ref]$serverLocal)) {
            return $false
        }
        $remoteAt = [DateTimeOffset]::MinValue
        $serverAt = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse(
                [string]$RemoteProbe.at_utc, [ref]$remoteAt) -or
            -not [DateTimeOffset]::TryParse(
                [string]$ServerProbe.accepted_at_utc, [ref]$serverAt)) {
            return $false
        }
        $timeDeltaSeconds = [Math]::Abs(
            ($remoteAt.ToUniversalTime() -
                $serverAt.ToUniversalTime()).TotalSeconds)
        $nonceSha256 = Get-R01TextSha256 -Text $ExpectedNonce
        return (
            [string]$RemoteProbe.schema -ceq
                'ese.v91.r01-mobile-probe/v1' -and
            [string]$ServerProbe.schema -ceq
                'ese.v91.r01-server-probe/v1' -and
            [string]$RemoteProbe.status -ceq 'PASS' -and
            [string]$ServerProbe.status -ceq 'PASS' -and
            $expectedAddress.Equals($remoteAddress) -and
            $expectedAddress.Equals($selectedRouteAddress) -and
            $serverListen.Equals($serverLocal) -and
            [int]$RemoteProbe.remote_port -eq $ExpectedProbePort -and
            [int]$ServerProbe.local_port -eq $ExpectedProbePort -and
            [int]$RemoteProbe.local_port -ge 1 -and
            [int]$RemoteProbe.local_port -le 65535 -and
            [int]$ServerProbe.remote_port -ge 1 -and
            [int]$ServerProbe.remote_port -le 65535 -and
            [string]$RemoteProbe.nonce_sha256 -ceq $nonceSha256 -and
            [string]$ServerProbe.nonce_sha256 -ceq $nonceSha256 -and
            $timeDeltaSeconds -le 20.0)
    } catch { return $false }
}

function Test-R01EvidenceBinding {
    param(
        [Parameter(Mandatory = $true)]$Remote,
        [Parameter(Mandatory = $true)]$Server,
        [Parameter(Mandatory = $true)]$ExpectedCandidate,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce,
        [Parameter(Mandatory = $true)][AllowEmptyString()]
        [string]$ExpectedProbeAddress,
        [Parameter(Mandatory = $true)][int]$ExpectedServerPort,
        [Parameter(Mandatory = $true)][int]$ExpectedProbePort,
        [Parameter(Mandatory = $true)][int]$ExpectedCandidateTcpPort
    )
    try {
        return [string]$Remote.schema -ceq 'ese.v91.r01-remote/v4' -and
            [string]$Server.schema -ceq
                'ese.v91.r01-controlled-server/v1' -and
            [string]$Remote.case_id -ceq 'V91-R01' -and
            [string]$Server.case_id -ceq 'V91-R01' -and
            [string]$Remote.nonce -ceq $ExpectedNonce -and
            [string]$Server.nonce -ceq $ExpectedNonce -and
            [string]$Remote.candidate.version -ceq
                [string]$ExpectedCandidate.version -and
            [string]$Remote.candidate.commit -ceq
                [string]$ExpectedCandidate.commit -and
            -not [bool]$Remote.candidate.dirty -and
            [string]$Remote.candidate.emule_sha256 -ceq
                [string]$ExpectedCandidate.emule_sha256 -and
            [string]$Remote.candidate.ese_server_sha256 -ceq
                [string]$ExpectedCandidate.ese_server_sha256 -and
            [string]$Remote.candidate.build_info_sha256 -ceq
                [string]$ExpectedCandidate.build_info_sha256 -and
            [string]$Remote.candidate.zip_sha256 -ceq
                [string]$ExpectedCandidate.zip_sha256 -and
            [Int64]$Remote.candidate.zip_bytes -eq
                [Int64]$ExpectedCandidate.zip_bytes -and
            [string]$Remote.candidate.package_manifest_sha256 -ceq
                [string]$ExpectedCandidate.package_manifest_sha256 -and
            [int]$Remote.candidate.package_manifest_file_count -eq
                [int]$ExpectedCandidate.package_manifest_file_count -and
            [string]$Remote.candidate.remote_package_binding.remote_zip_sha256 `
                -ceq [string]$ExpectedCandidate.zip_sha256 -and
            [Int64]$Remote.candidate.remote_package_binding.remote_zip_bytes `
                -eq [Int64]$ExpectedCandidate.zip_bytes -and
            [string]$Remote.candidate.remote_package_binding.manifest_sha256 `
                -ceq [string]$ExpectedCandidate.package_manifest_sha256 -and
            [int]$Remote.candidate.remote_package_binding.manifest_file_count `
                -eq [int]$ExpectedCandidate.package_manifest_file_count -and
            [bool]$Remote.candidate.remote_package_binding.
                extracted_file_set_exact -and
            [bool]$Remote.candidate.remote_package_binding.
                extracted_bytes_and_sha256_exact -and
            [string]$Remote.candidate.remote_package_binding.schema -ceq
                'ese.v91.r01-remote-package-binding/v2' -and
            [bool]$Remote.candidate.remote_package_binding.locked_zip_snapshot -and
            [bool]$Remote.candidate.remote_package_binding.reparse_free -and
            [int]$Remote.candidate.remote_package_binding.post_extract_file_count `
                -eq [int]$ExpectedCandidate.package_manifest_file_count -and
            [string]$Remote.account_registry_preflight.sid_sha256 -ceq
                [string]$ExpectedCandidate.h3_sid_sha256 -and
            [bool]$Remote.account_registry_preflight.disposable_account_confirmed -and
            [bool]$Remote.account_registry_preflight.emule_autostart_absent -and
            @($Remote.port_preflight).Count -eq 3 -and
            @($Remote.port_preflight | Where-Object {
                    -not [bool]$_.available
                }).Count -eq 0 -and
            [string]$Remote.candidate.process_identity.schema -ceq
                'ese.v91.r01-process-identity/v1' -and
            [int]$Remote.candidate.process_identity.pid -eq
                [int]$Remote.candidate.process_id -and
            [string]$Remote.candidate.process_identity.executable_sha256 -ceq
                [string]$ExpectedCandidate.emule_sha256 -and
            [string]$Remote.candidate.process_identity.start_time_utc -ceq
                [string]$Remote.session.initial_socket.process_start_time_utc -and
            [string]$Remote.candidate.process_identity.executable_path_sha256 `
                -ceq [string]$Remote.session.initial_socket.executable_path_sha256 -and
            [string]$Remote.candidate.process_identity.executable_sha256 -ceq
                [string]$Remote.session.initial_socket.executable_sha256 -and
            [int]$Remote.session.server_port -eq $ExpectedServerPort -and
            [int]$Remote.session.candidate_tcp_port -eq
                $ExpectedCandidateTcpPort -and
            [int]$Remote.topology.mobile_public_probe.remote_port -eq
                $ExpectedProbePort -and
            [int]$Server.server_port -eq $ExpectedServerPort -and
            [int]$Server.probe_port -eq $ExpectedProbePort -and
            [int]$Server.initial.advertised_tcp_port -eq
                $ExpectedCandidateTcpPort -and
            (Test-R01ExactProbeBinding `
                -RemoteProbe $Remote.topology.mobile_public_probe `
                -ServerProbe $Server.topology_probe `
                -ServerListenAddress ([string]$Server.listen_address) `
                -ExpectedProbeAddress $ExpectedProbeAddress `
                -ExpectedProbePort $ExpectedProbePort `
                -ExpectedNonce $ExpectedNonce) -and
            (Test-R01TransitionEvidence -Remote $Remote -Server $Server)
    } catch { return $false }
}

function Test-R01AggregatePass {
    param(
        [Parameter(Mandatory = $true)]$Remote,
        [Parameter(Mandatory = $true)]$Server,
        [Parameter(Mandatory = $true)]$ExpectedCandidate,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce,
        [Parameter(Mandatory = $true)][AllowEmptyString()]
        [string]$ExpectedProbeAddress,
        [Parameter(Mandatory = $true)][int]$ExpectedServerPort,
        [Parameter(Mandatory = $true)][int]$ExpectedProbePort,
        [Parameter(Mandatory = $true)][int]$ExpectedCandidateTcpPort
    )
    return (Test-R01EvidenceBinding -Remote $Remote -Server $Server `
            -ExpectedCandidate $ExpectedCandidate `
            -ExpectedNonce $ExpectedNonce `
            -ExpectedProbeAddress $ExpectedProbeAddress `
            -ExpectedServerPort $ExpectedServerPort `
            -ExpectedProbePort $ExpectedProbePort `
            -ExpectedCandidateTcpPort $ExpectedCandidateTcpPort) -and
        [string]$Remote.status -ceq 'REMOTE_PASS' -and
        [string]$Server.status -ceq 'SERVER_PASS' -and
        [bool]$Remote.process_preflight.baseline_zero -and
        [bool]$Remote.candidate.same_pid_before_after -and
        [string]$Remote.candidate.process_identity.start_time_utc -ceq
            [string]$Remote.session.reconnected_socket.process_start_time_utc -and
        [string]$Remote.candidate.process_identity.executable_path_sha256 -ceq
            [string]$Remote.session.reconnected_socket.executable_path_sha256 -and
        [string]$Remote.candidate.process_identity.executable_sha256 -ceq
            [string]$Remote.session.reconnected_socket.executable_sha256 -and
        [bool]$Remote.topology.mobile_topology_validated -and
        [bool]$Remote.session.old_endpoint_expired -and
        [bool]$Remote.cleanup.home_restored -and
        [string]$Remote.cleanup.final_profile_mode -ceq 'home_restored' -and
        [bool]$Remote.cleanup.node_removed -and
        [bool]$Remote.cleanup.account_registry_unchanged -and
        -not [bool]$Remote.cleanup.cleanup_incident -and
        [bool]$Remote.cleanup.wifi_watchdog_safe -and
        [bool]$Server.same_client_identity -and
        [bool]$Server.different_observed_remote -and
        [string]$Server.mobile.remote_address -ceq
            [string]$Server.topology_probe.remote_address
}

function Test-R01ProductFailureProven {
    param(
        [Parameter(Mandatory = $true)]$Remote,
        [Parameter(Mandatory = $true)]$Server,
        [Parameter(Mandatory = $true)]$ExpectedCandidate,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce,
        [Parameter(Mandatory = $true)][AllowEmptyString()]
        [string]$ExpectedProbeAddress,
        [Parameter(Mandatory = $true)][int]$ExpectedServerPort,
        [Parameter(Mandatory = $true)][int]$ExpectedProbePort,
        [Parameter(Mandatory = $true)][int]$ExpectedCandidateTcpPort
    )
    return (Test-R01EvidenceBinding -Remote $Remote -Server $Server `
            -ExpectedCandidate $ExpectedCandidate `
            -ExpectedNonce $ExpectedNonce `
            -ExpectedProbeAddress $ExpectedProbeAddress `
            -ExpectedServerPort $ExpectedServerPort `
            -ExpectedProbePort $ExpectedProbePort `
            -ExpectedCandidateTcpPort $ExpectedCandidateTcpPort) -and
        [string]$Remote.status -ceq 'REMOTE_FAIL' -and
        [bool]$Remote.product_failure_proven -and
        [string]$Remote.failure_category -ceq 'PRODUCT' -and
        [bool]$Server.fixture_valid_for_product_adjudication
}

function Get-R01AggregateStatus {
    param(
        [AllowNull()]$Remote,
        [AllowNull()]$Server,
        [Parameter(Mandatory = $true)]$ExpectedCandidate,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce,
        [Parameter(Mandatory = $true)][AllowEmptyString()]
        [string]$ExpectedProbeAddress,
        [Parameter(Mandatory = $true)][int]$ExpectedServerPort,
        [Parameter(Mandatory = $true)][int]$ExpectedProbePort,
        [Parameter(Mandatory = $true)][int]$ExpectedCandidateTcpPort,
        [Parameter(Mandatory = $true)][bool]$CleanupComplete,
        [AllowEmptyString()][string]$ControllerFailure = ''
    )
    if ($null -ne $Remote -and $null -ne $Server -and
        (Test-R01ProductFailureProven -Remote $Remote -Server $Server `
            -ExpectedCandidate $ExpectedCandidate `
            -ExpectedNonce $ExpectedNonce `
            -ExpectedProbeAddress $ExpectedProbeAddress `
            -ExpectedServerPort $ExpectedServerPort `
            -ExpectedProbePort $ExpectedProbePort `
            -ExpectedCandidateTcpPort $ExpectedCandidateTcpPort)) {
        return 'FAIL'
    }
    if (-not [string]::IsNullOrWhiteSpace($ControllerFailure) -or
        -not $CleanupComplete -or $null -eq $Remote -or $null -eq $Server) {
        return 'BLOCKED'
    }
    if (Test-R01AggregatePass -Remote $Remote -Server $Server `
            -ExpectedCandidate $ExpectedCandidate `
            -ExpectedNonce $ExpectedNonce `
            -ExpectedProbeAddress $ExpectedProbeAddress `
            -ExpectedServerPort $ExpectedServerPort `
            -ExpectedProbePort $ExpectedProbePort `
            -ExpectedCandidateTcpPort $ExpectedCandidateTcpPort) {
        return 'PASS'
    }
    return 'BLOCKED'
}

function Assert-R01PublicResultPrivacy {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [string[]]$SensitiveValues = @()
    )
    $root = @($Value.PSObject.Properties.Name | Sort-Object)
    $expectedRoot = @(
        'candidate', 'case_id', 'checks', 'completed_at_utc',
        'private_aggregate', 'schema', 'status') | Sort-Object
    $candidateNames = @($Value.candidate.PSObject.Properties.Name | Sort-Object)
    $expectedCandidate = @(
        'build_info_sha256', 'commit', 'emule_sha256', 'version',
        'zip_bytes', 'zip_sha256') | Sort-Object
    $checkNames = @($Value.checks.PSObject.Properties.Name | Sort-Object)
    $privateNames = @(
        $Value.private_aggregate.PSObject.Properties.Name | Sort-Object)
    $completed = [DateTimeOffset]::MinValue
    $completedValid = [DateTimeOffset]::TryParse(
        [string]$Value.completed_at_utc, [ref]$completed) -and
        $completed.Offset -eq [TimeSpan]::Zero
    if (($root -join "`n") -cne ($expectedRoot -join "`n") -or
        ($candidateNames -join "`n") -cne
            ($expectedCandidate -join "`n") -or
        ($checkNames -join ',') -cne
            'cleanup_complete,cleanup_incident,product_failure_proven' -or
        ($privateNames -join ',') -cne 'bytes,sha256' -or
        [string]$Value.schema -cne 'ese.v91.r01-public-result/v1' -or
        [string]$Value.case_id -cne 'V91-R01' -or
        [string]$Value.status -cnotin @('PASS', 'FAIL', 'BLOCKED') -or
        -not $completedValid -or
        [string]$Value.candidate.version -cnotmatch
            '^[A-Za-z0-9._+-]{1,64}$' -or
        [string]$Value.candidate.commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Value.candidate.emule_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Value.candidate.build_info_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        [string]$Value.candidate.zip_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [Int64]$Value.candidate.zip_bytes -lt 1 -or
        [string]$Value.private_aggregate.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [Int64]$Value.private_aggregate.bytes -lt 1) {
        throw 'R01 public result violated its exact allowlist.'
    }
    foreach ($property in $Value.checks.PSObject.Properties) {
        if (-not ($property.Value -is [bool])) {
            throw 'R01 public checks must be strict booleans.'
        }
    }
    if ([string]$Value.status -ceq 'PASS' -and (
            -not [bool]$Value.checks.cleanup_complete -or
            [bool]$Value.checks.cleanup_incident -or
            [bool]$Value.checks.product_failure_proven)) {
        throw 'R01 public PASS has incoherent checks.'
    }
    if ([string]$Value.status -ceq 'FAIL' -and
        -not [bool]$Value.checks.product_failure_proven) {
        throw 'R01 public FAIL is not product-proven.'
    }
    $json = $Value | ConvertTo-Json -Depth 8 -Compress
    foreach ($sensitive in @($SensitiveValues | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            } | Select-Object -Unique)) {
        $text = [string]$sensitive
        if ($json.IndexOf($text, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $json.IndexOf((Get-R01TextSha256 -Text $text),
                [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw 'R01 public result contains a sensitive value or digest.'
        }
    }
    return $true
}

function New-R01PublicResult {
    param(
        [Parameter(Mandatory = $true)]$Aggregate,
        [Parameter(Mandatory = $true)]$Candidate,
        [Parameter(Mandatory = $true)][string]$PrivateAggregatePath,
        [Parameter(Mandatory = $true)][bool]$CleanupComplete,
        [Parameter(Mandatory = $true)][bool]$CleanupIncident,
        [Parameter(Mandatory = $true)][bool]$ProductFailureProven,
        [string[]]$SensitiveValues = @()
    )
    $item = Get-Item -LiteralPath $PrivateAggregatePath -ErrorAction Stop
    $value = [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-public-result/v1'
        case_id = 'V91-R01'; status = [string]$Aggregate.status
        completed_at_utc = [string]$Aggregate.completed_at_utc
        candidate = [pscustomobject][ordered]@{
            version = [string]$Candidate.version
            commit = ([string]$Candidate.commit).ToLowerInvariant()
            emule_sha256 = ([string]$Candidate.emule_sha256).ToLowerInvariant()
            build_info_sha256 =
                ([string]$Candidate.build_info_sha256).ToLowerInvariant()
            zip_sha256 = ([string]$Candidate.zip_sha256).ToLowerInvariant()
            zip_bytes = [Int64]$Candidate.zip_bytes
        }
        checks = [pscustomobject][ordered]@{
            product_failure_proven = $ProductFailureProven
            cleanup_complete = $CleanupComplete
            cleanup_incident = $CleanupIncident
        }
        private_aggregate = [pscustomobject][ordered]@{
            bytes = [Int64]$item.Length
            sha256 = (Get-FileHash -LiteralPath $item.FullName `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $null = Assert-R01PublicResultPrivacy -Value $value `
        -SensitiveValues $SensitiveValues
    return $value
}

function Invoke-R01CooperativeRemoteCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$ControllerPath,
        [Parameter(Mandatory = $true)][string]$AgentAddress,
        [Parameter(Mandatory = $true)][int]$AgentListenPort,
        [Parameter(Mandatory = $true)][string]$TokenPath,
        [Parameter(Mandatory = $true)][string]$RemoteJobId,
        [Parameter(Mandatory = $true)][DateTimeOffset]$AutonomousDeadline,
        [Parameter(Mandatory = $true)][int]$GraceSeconds,
        [Parameter(Mandatory = $true)][string]$RunDirectory,
        [Parameter(Mandatory = $true)][string]$ResultOutputPath
    )
    $evidence = [ordered]@{
        schema = 'ese.v91.r01-cooperative-cleanup/v1'
        job_id = $RemoteJobId
        cancel_attempted = $false
        cancel_acknowledged = $false
        terminal_state_observed = $false
        terminal_state = ''
        result_collected = $false
        forced_stop_used = $false
        attempts = 0
        last_error = ''
        completed_at_utc = ''
    }
    $graceDeadline = [DateTimeOffset]::UtcNow.AddSeconds($GraceSeconds)
    $autonomousCleanupDeadline = $AutonomousDeadline.AddSeconds(60)
    $deadline = if ($graceDeadline -gt $autonomousCleanupDeadline) {
        $graceDeadline
    } else { $autonomousCleanupDeadline }
    do {
        $evidence.attempts++
        $jobState = $null
        try {
            $jobState = & $ControllerPath -Command job `
                -AgentIPv4 $AgentAddress -Port $AgentListenPort `
                -TokenDpapiPath $TokenPath -JobId $RemoteJobId `
                -TimeoutMilliseconds 3000
            if ([string]$jobState.state -in @(
                    'COMPLETE', 'ERROR', 'STOPPED')) {
                $evidence.terminal_state_observed = $true
                $evidence.terminal_state = [string]$jobState.state
                break
            }
        } catch { $evidence.last_error = $_.Exception.Message }
        if (-not $evidence.cancel_acknowledged) {
            $evidence.cancel_attempted = $true
            try {
                $cancel = & $ControllerPath -Command cancel `
                    -AgentIPv4 $AgentAddress -Port $AgentListenPort `
                    -TokenDpapiPath $TokenPath -JobId $RemoteJobId `
                    -TimeoutMilliseconds 3000
                $evidence.cancel_acknowledged =
                    [string]$cancel.state -ceq 'CANCEL_SIGNALLED'
            } catch { $evidence.last_error = $_.Exception.Message }
        }
        Start-Sleep -Seconds 1
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    if ($evidence.terminal_state_observed) {
        try {
            & $ControllerPath -Command download -AgentIPv4 $AgentAddress `
                -Port $AgentListenPort -TokenDpapiPath $TokenPath `
                -RemotePath "jobs/$RemoteJobId/result.json" `
                -OutputPath $ResultOutputPath `
                -TimeoutMilliseconds 5000 | Out-Null
            $evidence.result_collected =
                Test-Path -LiteralPath $ResultOutputPath -PathType Leaf
        } catch { $evidence.last_error = $_.Exception.Message }
        foreach ($name in @('stdout.log', 'stderr.log', 'status.json')) {
            try {
                & $ControllerPath -Command download `
                    -AgentIPv4 $AgentAddress -Port $AgentListenPort `
                    -TokenDpapiPath $TokenPath `
                    -RemotePath "jobs/$RemoteJobId/$name" `
                    -OutputPath (Join-Path $RunDirectory "remote-$name") `
                    -TimeoutMilliseconds 5000 | Out-Null
            } catch {}
        }
    }
    $evidence.completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    return [pscustomobject]$evidence
}

$runId = [Guid]::NewGuid().ToString('N')
$jobId = [Guid]::NewGuid().ToString('N')
$nonce = [Guid]::NewGuid().ToString('N')
$runRoot = Join-Path ([IO.Path]::GetFullPath($OutputRoot)) $runId
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
$manifestPath = Join-Path $runRoot 'manifest.json'
$serverRequestPath = Join-Path $runRoot 'server-request.json'
$remoteRequestPath = Join-Path $runRoot 'remote-request.json'
$packageManifestPath = Join-Path $runRoot 'package-manifest.json'
$remoteResultPath = Join-Path $runRoot 'remote-result.json'
$aggregatePath = Join-Path $runRoot 'aggregate-result.json'
$serverStdout = Join-Path $runRoot 'server-stdout.log'
$serverStderr = Join-Path $runRoot 'server-stderr.log'
$candidateInfo = Get-LabCandidateInfo -PackagePath $CandidatePackagePath `
    -ExpectedCommit $ExpectedCommit
$candidateHash = [string]$candidateInfo.emule_sha256
$zipPackageEvidence = Get-R01ZipPackageEvidence `
    -ZipPath $CandidateZipPath -Candidate $candidateInfo
$zipHash = [string]$zipPackageEvidence.zip_sha256
$zipBytes = [Int64]$zipPackageEvidence.zip_bytes
[IO.File]::WriteAllText($packageManifestPath,
    ($zipPackageEvidence | ConvertTo-Json -Depth 10),
    [Text.UTF8Encoding]::new($false))
$expectedCandidate = [pscustomobject][ordered]@{
    version = [string]$candidateInfo.version
    commit = [string]$candidateInfo.commit
    dirty = $false
    emule_sha256 = $candidateHash
    ese_server_sha256 = [string]$candidateInfo.ese_server_sha256
    build_info_sha256 = [string]$candidateInfo.build_info_sha256
    zip_sha256 = $zipHash
    zip_bytes = $zipBytes
    package_manifest_sha256 =
        [string]$zipPackageEvidence.manifest_sha256
    package_manifest_file_count = [int]$zipPackageEvidence.file_count
    h3_sid_sha256 = $ExpectedH3SidSha256
}

$serverProcess = $null
$serverProcessIdentity = $null
$serverProcessTerminal = $false
$upnpBackend = $null
$upnpBackendEvidence = $null
$ownedMappings = [Collections.Generic.List[object]]::new()
$mappingCleanupCandidates = [Collections.Generic.List[object]]::new()
$mappingLifecycleEvidence = [Collections.Generic.List[object]]::new()
$resolvedMappingKeys = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
$ownedFirewallRules = [Collections.Generic.List[object]]::new()
$firewallGroup = "eSE R01 Lab $nonce"
$deletedMappingCount = 0
$removedFirewallRuleCount = 0
$controllerFailure = ''
$remoteResult = $null
$serverResult = $null
$localAddress = ''
$publicAddress = ''
$adapter = $null
$job = $null
$powershellPath = Join-Path $env:SystemRoot `
    'System32\WindowsPowerShell\v1.0\powershell.exe'
$remoteJobLaunchAttempted = $false
$remoteJobStarted = $false
$remoteCleanupEvidence = $null
$agentPreflightEvidence = $null
$controllerPortBaseline = @()
$runnerDeadlineSeconds = $TimeoutSeconds - $CleanupGraceSeconds
if ($runnerDeadlineSeconds -lt 180) {
    throw 'TimeoutSeconds must exceed CleanupGraceSeconds by at least 180.'
}
$remoteAutonomousDeadline = $null

try {
    $pingT0 = [DateTimeOffset]::UtcNow
    $agentPing = & $controller -Command ping -AgentIPv4 $AgentIPv4 `
        -Port $AgentPort -TokenDpapiPath $TokenDpapiPath
    $pingT1 = [DateTimeOffset]::UtcNow
    $agentUtc = [DateTimeOffset]::MinValue
    if ([string]$agentPing.schema -cne 'ese.lab.smallframe-ping/v2' -or
        [int]$agentPing.protocol -lt 2 -or
        @($agentPing.capabilities) -notcontains 'cooperative_cancel' -or
        [string]$agentPing.state -cne 'IDLE' -or
        -not [DateTimeOffset]::TryParse([string]$agentPing.utc_now,
            [ref]$agentUtc)) {
        throw ('H3 agent preflight requires protocol v2, IDLE state, ' +
            'cooperative_cancel and a valid UTC timestamp.')
    }
    $offsetMinimumMs = ($agentUtc - $pingT1).TotalMilliseconds
    $offsetMaximumMs = ($agentUtc - $pingT0).TotalMilliseconds
    $clockBoundMs = [Math]::Max([Math]::Abs($offsetMinimumMs),
        [Math]::Abs($offsetMaximumMs))
    $agentPreflightEvidence = [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-agent-preflight/v1'
        ping_schema = [string]$agentPing.schema
        protocol = [int]$agentPing.protocol
        state = [string]$agentPing.state
        capabilities = @($agentPing.capabilities)
        controller_t0_utc = $pingT0.ToString('o')
        agent_utc = $agentUtc.ToString('o')
        controller_t1_utc = $pingT1.ToString('o')
        round_trip_ms = [Math]::Round(
            ($pingT1 - $pingT0).TotalMilliseconds, 3)
        clock_offset_interval_ms = @(
            [Math]::Round($offsetMinimumMs, 3),
            [Math]::Round($offsetMaximumMs, 3))
        maximum_absolute_clock_offset_ms = [Math]::Round($clockBoundMs, 3)
        clock_bound_pass = $clockBoundMs -le 1000
        mutation_allowed = $clockBoundMs -le 1000
    }
    if ($clockBoundMs -gt 1000) {
        throw ('H3/controller clock offset bound exceeds 1 second; ' +
            'R01 timestamps cannot be cross-adjudicated.')
    }
    $controllerProcesses = @(Get-Process -ErrorAction Stop)
    if (@($controllerProcesses | Where-Object {
                [string]$_.ProcessName -ieq 'emule'
            }).Count -gt 0) {
        throw 'R01 refuses to start while an eMule process is running on H1.'
    }
    $adapter = Get-NetAdapter -Name $ServerInterfaceAlias -ErrorAction Stop
    if (-not $adapter.HardwareInterface -or $adapter.Virtual -or
        (Test-R01OverlayAdapter -Adapter $adapter) -or
        [string]$adapter.Status -cne 'Up') {
        throw 'R01 controlled server requires one active physical H1 NIC.'
    }
    $localAddresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex `
            -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
                -not $_.SkipAsSource -and $_.AddressState -eq 'Preferred' -and
                (Get-R01IPv4Class -Address $_.IPAddress) -in
                    @('private', 'global')
            })
    if ($localAddresses.Count -ne 1) {
        throw 'Expected exactly one usable IPv4 on the H1 server NIC.'
    }
    $localAddress = [string]$localAddresses[0].IPAddress
    $serverDefaultRoutes = @(Get-NetRoute `
            -InterfaceIndex ([int]$adapter.ifIndex) -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_.NextHop) -and
            [string]$_.NextHop -cne '0.0.0.0'
        } | Sort-Object RouteMetric)
    if ($serverDefaultRoutes.Count -lt 1) {
        throw 'Selected H1 server NIC has no explicit IPv4 gateway.'
    }
    $gatewayAddress = [string]$serverDefaultRoutes[0].NextHop
    $controllerPortBaseline = @(Get-R01PortBaseline `
        -TcpPorts @($ServerPort, $ProbePort))
    if (@($controllerPortBaseline | Where-Object {
                -not [bool]$_.available
            }).Count -ne 0) {
        throw 'R01 controlled server/probe ports are not clean before mutation.'
    }

    foreach ($definition in @(
        @{ port = $ServerPort; suffix = 'SERVER' },
        @{ port = $ProbePort; suffix = 'PROBE' }
    )) {
        $ruleName = "eSE-R01-$nonce-$($definition.suffix)"
        if (@(Get-R01FirewallRulesByNameFailClosed `
                -Name $ruleName).Count -ne 0) {
            throw 'Nonce firewall rule name already exists before creation.'
        }
        $ownedRule = [pscustomobject][ordered]@{
            name = $ruleName; group = $firewallGroup
            local_address = $localAddress
            local_port = [int]$definition.port
            interface_alias = $ServerInterfaceAlias
            program = [IO.Path]::GetFullPath($powershellPath)
        }
        $ownedFirewallRules.Add($ownedRule)
        New-NetFirewallRule -Name $ruleName -DisplayName $ruleName `
            -Group $firewallGroup -Direction Inbound -Action Allow `
            -Enabled True -Profile Any -Protocol TCP `
            -LocalAddress $localAddress -LocalPort $definition.port `
            -InterfaceAlias $ServerInterfaceAlias `
            -Program $powershellPath | Out-Null
        $null = Get-R01OwnedFirewallEvidence -Name $ruleName `
            -Group $firewallGroup -LocalAddress $localAddress `
            -LocalPort ([int]$definition.port) `
            -InterfaceAlias $ServerInterfaceAlias -Program $powershellPath
    }

    [ordered]@{
        nonce = $nonce
        listen_address = $localAddress
        server_port = $ServerPort
        probe_port = $ProbePort
        expected_tcp_port = $CandidateTcpPort
        timeout_seconds = $TimeoutSeconds
    } | ConvertTo-Json | Set-Content -LiteralPath $serverRequestPath `
        -Encoding UTF8

    $serverArguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" ' +
        '-JobRequestPath "{1}"' -f $serverRunner, $serverRequestPath
    $serverProcess = Start-Process -FilePath $powershellPath `
        -ArgumentList $serverArguments -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $serverStdout `
        -RedirectStandardError $serverStderr
    $serverProcessIdentity = Get-R01LocalProcessIdentity `
        -Process $serverProcess -ExpectedPath $powershellPath
    $readyPath = Join-Path $runRoot 'server-ready.json'
    $readyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
    while (-not (Test-Path -LiteralPath $readyPath)) {
        $serverProcess.Refresh()
        if ($serverProcess.HasExited) {
            throw 'Controlled server exited before READY.'
        }
        if ([DateTimeOffset]::UtcNow -ge $readyDeadline) {
            throw 'Timed out waiting for controlled server READY.'
        }
        Start-Sleep -Milliseconds 100
    }

    # This IGD requires a live target socket before AddPortMapping. Bring up
    # the exact firewall/listener fixture first, then mutate the router.
    $upnpBackend = New-R01UpnpBackend -LocalAddress $localAddress `
        -GatewayAddress $gatewayAddress
    $upnpBackendEvidence = Get-R01UpnpBackendEvidence -Backend $upnpBackend
    if (-not [bool]$upnpBackendEvidence.formal_eligible) {
        throw 'Selected UPnP backend is not eligible for formal R01.'
    }
    foreach ($definition in @(
        @{ port = $ServerPort; suffix = 'SERVER' },
        @{ port = $ProbePort; suffix = 'PROBE' }
    )) {
        $description = Get-R01UpnpOwnershipDescription -Nonce $nonce `
            -Role $definition.suffix -ExternalPort $definition.port `
            -InternalPort $definition.port -InternalClient $localAddress
        $owned = Add-R01OwnedUpnpMapping -Backend $upnpBackend `
            -ExternalPort $definition.port -InternalPort $definition.port `
            -InternalClient $localAddress -Description $description
        $ownedMappings.Add($owned)
    }
    $reportedAddresses = @($ownedMappings | ForEach-Object external_address |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique)
    if (-not [string]::IsNullOrWhiteSpace($MobileServerAddress)) {
        $publicAddress = $MobileServerAddress
        if ($reportedAddresses.Count -gt 1) {
            throw 'UPnP mappings reported ambiguous external IPv4 addresses.'
        }
        if ($reportedAddresses.Count -eq 1) {
            $reportedIp = $null
            $suppliedIp = $null
            if (-not [Net.IPAddress]::TryParse(
                    [string]$reportedAddresses[0], [ref]$reportedIp) -or
                -not [Net.IPAddress]::TryParse(
                    $publicAddress, [ref]$suppliedIp) -or
                -not $reportedIp.Equals($suppliedIp)) {
                throw 'Supplied public IPv4 differs from the UPnP report.'
            }
        }
    } elseif ($reportedAddresses.Count -eq 1) {
        $publicAddress = [string]$reportedAddresses[0]
    } else {
        throw 'No unambiguous H1 public IPv4 was supplied or reported.'
    }
    if ((Get-R01IPv4Class -Address $publicAddress) -cne 'global') {
        throw 'Router endpoint is not a globally routable IPv4 address.'
    }

    [ordered]@{
        nonce = $nonce
        candidate_zip_path = $RemoteCandidateZipPath
        expected_emule_sha256 = $candidateHash
        expected_ese_server_sha256 = [string]$candidateInfo.ese_server_sha256
        expected_build_info_sha256 = [string]$candidateInfo.build_info_sha256
        expected_zip_sha256 = $zipHash
        expected_zip_bytes = $zipBytes
        expected_package_manifest_sha256 =
            [string]$zipPackageEvidence.manifest_sha256
        expected_package_manifest_file_count =
            [int]$zipPackageEvidence.file_count
        expected_account_sid_sha256 = $ExpectedH3SidSha256
        disposable_account_confirmed = $true
        candidate_commit = [string]$candidateInfo.commit
        candidate_version = [string]$candidateInfo.version
        home_profile = $HomeProfile
        hotspot_profile = $HotspotProfile
        wifi_interface_alias = $LaptopWifiInterfaceAlias
        initial_server_address = $localAddress
        mobile_server_address = $publicAddress
        server_port = $ServerPort
        topology_probe_port = $ProbePort
        tcp_port = $CandidateTcpPort
        udp_port = $CandidateUdpPort
        web_port = $CandidateWebPort
        runner_deadline_seconds = $runnerDeadlineSeconds
    } | ConvertTo-Json | Set-Content -LiteralPath $remoteRequestPath `
        -Encoding UTF8

    $remoteEntrypoint = "injected/$jobId/run_v91_r01_remote.ps1"
    $remoteWatchdog =
        "injected/$jobId/run_v91_r01_wifi_watchdog.ps1"
    $remotePackageManifest =
        "injected/$jobId/package-manifest.json"
    & $controller -Command upload -AgentIPv4 $AgentIPv4 -Port $AgentPort `
        -TokenDpapiPath $TokenDpapiPath -SourcePath $remoteRunner `
        -RemotePath $remoteEntrypoint | Out-Null
    & $controller -Command upload -AgentIPv4 $AgentIPv4 -Port $AgentPort `
        -TokenDpapiPath $TokenDpapiPath -SourcePath $watchdogRunner `
        -RemotePath $remoteWatchdog | Out-Null
    & $controller -Command upload -AgentIPv4 $AgentIPv4 -Port $AgentPort `
        -TokenDpapiPath $TokenDpapiPath -SourcePath $packageManifestPath `
        -RemotePath $remotePackageManifest | Out-Null
    $remoteJobLaunchAttempted = $true
    & $controller -Command run -AgentIPv4 $AgentIPv4 -Port $AgentPort `
        -TokenDpapiPath $TokenDpapiPath -JobId $jobId `
        -RemotePath $remoteEntrypoint `
        -JobRequestPath $remoteRequestPath | Out-Null
    $remoteJobStarted = $true
    $remoteAutonomousDeadline = [DateTimeOffset]::UtcNow.AddSeconds(
        $runnerDeadlineSeconds)

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        try {
            $job = & $controller -Command job -AgentIPv4 $AgentIPv4 `
                -Port $AgentPort -TokenDpapiPath $TokenDpapiPath -JobId $jobId
        } catch { continue }
        if ([string]$job.state -in @('COMPLETE', 'ERROR', 'STOPPED')) { break }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($null -eq $job -or
        [string]$job.state -notin @('COMPLETE', 'ERROR', 'STOPPED')) {
        throw 'Timed out waiting for the unattended laptop R01 job.'
    }
    & $controller -Command download -AgentIPv4 $AgentIPv4 -Port $AgentPort `
        -TokenDpapiPath $TokenDpapiPath `
        -RemotePath "jobs/$jobId/result.json" `
        -OutputPath $remoteResultPath | Out-Null
    foreach ($name in @('stdout.log', 'stderr.log', 'status.json')) {
        try {
            & $controller -Command download -AgentIPv4 $AgentIPv4 `
                -Port $AgentPort -TokenDpapiPath $TokenDpapiPath `
                -RemotePath "jobs/$jobId/$name" `
                -OutputPath (Join-Path $runRoot "remote-$name") | Out-Null
        } catch {}
    }
    $remoteResult = Get-Content -LiteralPath $remoteResultPath -Raw |
        ConvertFrom-Json
} catch {
    $controllerFailure = $_.Exception.Message
    # On an error path, release exact owned mappings before any potentially
    # long cooperative recovery wait can let the controlled listeners expire.
    if ($null -ne $upnpBackend) {
        foreach ($owned in @($mappingCleanupCandidates)) {
            $mappingKey = '{0}|{1}' -f [int]$owned.external_port,
                [string]$owned.backend_identity_sha256
            if (-not $resolvedMappingKeys.Contains($mappingKey)) {
                $resolution = Remove-R01OwnedUpnpMapping `
                    -Backend $upnpBackend -Owned $owned
                if ([bool]$resolution.resolved) {
                    $null = $resolvedMappingKeys.Add($mappingKey)
                    if ([bool]$resolution.deleted) {
                        $deletedMappingCount++
                    }
                }
            }
        }
    }
    if ($remoteJobLaunchAttempted) {
        if ($null -eq $remoteAutonomousDeadline) {
            $remoteAutonomousDeadline = [DateTimeOffset]::UtcNow.AddSeconds(
                $runnerDeadlineSeconds)
        }
        $remoteCleanupEvidence = Invoke-R01CooperativeRemoteCleanup `
            -ControllerPath $controller -AgentAddress $AgentIPv4 `
            -AgentListenPort $AgentPort -TokenPath $TokenDpapiPath `
            -RemoteJobId $jobId `
            -AutonomousDeadline $remoteAutonomousDeadline `
            -GraceSeconds $CleanupGraceSeconds -RunDirectory $runRoot `
            -ResultOutputPath $remoteResultPath
        if (Test-Path -LiteralPath $remoteResultPath -PathType Leaf) {
            try {
                $remoteResult = Get-Content -LiteralPath $remoteResultPath `
                    -Raw | ConvertFrom-Json
            } catch {}
        }
    }
} finally {
    # Keep both controlled listeners alive while deleting and re-reading the
    # mappings. Some IGDs couple mapping lifecycle to the target listener.
    if ($null -ne $upnpBackend) {
        foreach ($owned in @($mappingCleanupCandidates)) {
            $mappingKey = '{0}|{1}' -f [int]$owned.external_port,
                [string]$owned.backend_identity_sha256
            if (-not $resolvedMappingKeys.Contains($mappingKey)) {
                $resolution = Remove-R01OwnedUpnpMapping `
                    -Backend $upnpBackend -Owned $owned
                if ([bool]$resolution.resolved) {
                    $null = $resolvedMappingKeys.Add($mappingKey)
                    if ([bool]$resolution.deleted) {
                        $deletedMappingCount++
                    }
                }
            }
        }
    }
    try {
        [IO.File]::WriteAllText((Join-Path $runRoot 'stop-server.flag'),
            'stop', [Text.Encoding]::ASCII)
    } catch {}
    if ($null -ne $serverProcess) {
        try {
            $serverProcess.Refresh()
            if (-not $serverProcess.HasExited) {
                if (-not $serverProcess.WaitForExit(5000)) {
                    if ($null -eq $serverProcessIdentity -or
                        -not (Test-R01LocalProcessIdentity `
                            -Process $serverProcess `
                            -Expected $serverProcessIdentity `
                            -ExpectedPath $powershellPath)) {
                        throw 'Refusing to kill a server process with changed identity.'
                    }
                    $serverProcess.Kill()
                    $serverProcess.WaitForExit(10000) | Out-Null
                }
            }
            $serverProcess.Refresh()
            $serverProcessTerminal = $serverProcess.HasExited
        } catch { $serverProcessTerminal = $false }
    }
    foreach ($ownedRule in @($ownedFirewallRules)) {
        try {
            if (Remove-R01OwnedFirewallRule -Owned $ownedRule) {
                $removedFirewallRuleCount++
            }
        } catch {
        }
    }
}

$serverResultPath = Join-Path $runRoot 'server-result.json'
if ($null -eq $remoteResult -and
    (Test-Path -LiteralPath $remoteResultPath -PathType Leaf)) {
    try {
        $remoteResult = Get-Content -LiteralPath $remoteResultPath -Raw |
            ConvertFrom-Json
    } catch {}
}
if ($null -eq $serverResult -and
    (Test-Path -LiteralPath $serverResultPath -PathType Leaf)) {
    try {
        $serverResult = Get-Content -LiteralPath $serverResultPath -Raw |
            ConvertFrom-Json
    } catch {}
}
$mappingLifecycleSafe = $resolvedMappingKeys.Count -eq
    $mappingCleanupCandidates.Count
$formalMappingLifecycleComplete =
    $ownedMappings.Count -eq 2 -and
    $mappingCleanupCandidates.Count -eq 2 -and
    $deletedMappingCount -eq 2
$remoteRecoveryComplete = $null -eq $remoteCleanupEvidence -or
    ([bool]$remoteCleanupEvidence.terminal_state_observed -and
        [bool]$remoteCleanupEvidence.result_collected -and
        -not [bool]$remoteCleanupEvidence.forced_stop_used)
$cleanupSafe = $mappingLifecycleSafe -and
    $removedFirewallRuleCount -eq $ownedFirewallRules.Count -and
    $remoteRecoveryComplete -and $serverProcessTerminal
$adjudicationCleanupComplete = $cleanupSafe -and
    $formalMappingLifecycleComplete
$status = Get-R01AggregateStatus -Remote $remoteResult -Server $serverResult `
    -ExpectedCandidate $expectedCandidate -ExpectedNonce $nonce `
    -ExpectedProbeAddress $publicAddress `
    -ExpectedServerPort $ServerPort -ExpectedProbePort $ProbePort `
    -ExpectedCandidateTcpPort $CandidateTcpPort `
    -CleanupComplete $adjudicationCleanupComplete `
    -ControllerFailure $controllerFailure
$aggregate = [ordered]@{
    schema = 'ese.v91.r01-campaign/v1'
    case_id = 'V91-R01'
    nonce = $nonce
    status = $status
    run_id = $runId
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    failure = $controllerFailure
    candidate = [ordered]@{
        identity_basis = 'frozen package + ZIP contract'
        version = [string]$candidateInfo.version
        commit = [string]$candidateInfo.commit
        dirty = [string]$candidateInfo.dirty
        emule_sha256 = $candidateHash
        ese_server_sha256 = [string]$candidateInfo.ese_server_sha256
        build_info_sha256 = [string]$candidateInfo.build_info_sha256
        zip_sha256 = $zipHash
        zip_bytes = $zipBytes
        package_zip_binding = $zipPackageEvidence
    }
    topology = [ordered]@{
        id = 'T3'
        server_interface_guid = if ($null -ne $adapter) {
            [string]$adapter.InterfaceGuid
        } else { '' }
        server_interface_physical_nonvirtual = if ($null -ne $adapter) {
            [bool]$adapter.HardwareInterface -and -not [bool]$adapter.Virtual
        } else { $false }
        initial_server_address = $localAddress
        mobile_server_address = $publicAddress
        mobile_server_address_class = if ($publicAddress) {
            Get-R01IPv4Class -Address $publicAddress
        } else { 'unknown' }
        home_connection_profile_sha256 = if ($null -ne $remoteResult) {
            [string]$remoteResult.topology.home_connection_profile_sha256
        } else { $null }
        hotspot_connection_profile_sha256 = if ($null -ne $remoteResult) {
            [string]$remoteResult.topology.hotspot_connection_profile_sha256
        } else { $null }
        # Contractual I07 aliases: these are NLA connection-profile hashes,
        # never the requested netsh WLAN profile-name hashes.
        home_profile_sha256 = if ($null -ne $remoteResult) {
            [string]$remoteResult.topology.home_connection_profile_sha256
        } else { $null }
        hotspot_profile_sha256 = if ($null -ne $remoteResult) {
            [string]$remoteResult.topology.hotspot_connection_profile_sha256
        } else { $null }
        overlay_used_for_candidate_data = if ($null -ne $adapter) {
            Test-R01OverlayAdapter -Adapter $adapter
        } else { $true }
    }
    requested_home_wlan_profile_sha256 =
        Get-R01TextSha256 -Text $HomeProfile
    requested_hotspot_wlan_profile_sha256 =
        Get-R01TextSha256 -Text $HotspotProfile
    agent_preflight = $agentPreflightEvidence
    upnp_backend = $upnpBackendEvidence
    controller_port_baseline = $controllerPortBaseline
    remote = $remoteResult
    server = $serverResult
    cleanup = [ordered]@{
        owned_upnp_mapping_count = $ownedMappings.Count
        attempted_upnp_mapping_count = $mappingCleanupCandidates.Count
        resolved_upnp_cleanup_count = $resolvedMappingKeys.Count
        removed_upnp_mapping_count = $deletedMappingCount
        owned_firewall_rule_count = $ownedFirewallRules.Count
        removed_firewall_rule_count = $removedFirewallRuleCount
        mapping_lifecycle_safe = $mappingLifecycleSafe
        formal_mapping_lifecycle_complete =
            $formalMappingLifecycleComplete
        upnp_mapping_lifecycle = @($mappingLifecycleEvidence)
        remote_job_launch_attempted = $remoteJobLaunchAttempted
        remote_job_started = $remoteJobStarted
        cooperative_remote_recovery = $remoteCleanupEvidence
        remote_recovery_complete = $remoteRecoveryComplete
        server_process_terminal = $serverProcessTerminal
        server_process_identity = $serverProcessIdentity
        remote_cleanup_incident = if ($null -ne $remoteResult -and
            $null -ne $remoteResult.cleanup) {
            [bool]$remoteResult.cleanup.cleanup_incident
        } else { $true }
        incident = (-not $cleanupSafe) -or $null -eq $remoteResult -or
            [bool]$remoteResult.cleanup.cleanup_incident
        complete = $cleanupSafe
        adjudication_gate_complete = $adjudicationCleanupComplete
    }
}
$aggregate | ConvertTo-Json -Depth 16 |
    Set-Content -LiteralPath $aggregatePath -Encoding UTF8
$remoteProductFailureProven = $null -ne $remoteResult -and
    [bool]$remoteResult.product_failure_proven -and
    [string]$remoteResult.failure_category -ceq 'PRODUCT'
$overallCleanupIncident = (-not $cleanupSafe) -or
    $null -eq $remoteResult -or [bool]$remoteResult.cleanup.cleanup_incident
$publicResult = New-R01PublicResult -Aggregate ([pscustomobject]$aggregate) `
    -Candidate $expectedCandidate -PrivateAggregatePath $aggregatePath `
    -CleanupComplete $cleanupSafe `
    -CleanupIncident $overallCleanupIncident `
    -ProductFailureProven $remoteProductFailureProven `
    -SensitiveValues @(
        $AgentIPv4, $TokenDpapiPath, $ServerInterfaceAlias,
        $LaptopWifiInterfaceAlias, $HomeProfile, $HotspotProfile,
        $MobileServerAddress, $CandidatePackagePath, $CandidateZipPath,
        $RemoteCandidateZipPath, $OutputRoot, $ExpectedH3SidSha256,
        $runId, $jobId, $nonce, $runRoot, $localAddress, $publicAddress,
        $(if ($null -ne $adapter) { [string]$adapter.InterfaceGuid } else { '' }),
        $(if ($null -ne $upnpBackendEvidence) {
                [string]$upnpBackendEvidence.gateway_address
            } else { '' }),
        $(if ($null -ne $upnpBackendEvidence) {
                [string]$upnpBackendEvidence.control_uri
            } else { '' })
    )
$publicResultPath = Join-Path $runRoot 'public-result.json'
$publicResult | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $publicResultPath -Encoding UTF8
$manifest = [ordered]@{
    schema = 'ese.v91.r01-manifest/v1'
    run_id = $runId
    job_id = $jobId
    aggregate = $aggregatePath
    public_result = $publicResultPath
    candidate_sha256 = $candidateHash
    candidate_commit = [string]$candidateInfo.commit
    candidate_version = [string]$candidateInfo.version
    build_info_sha256 = [string]$candidateInfo.build_info_sha256
    zip_sha256 = $zipHash
    zip_bytes = $zipBytes
    expected_h3_sid_sha256 = $ExpectedH3SidSha256
    disposable_h3_account_confirmed = $true
    package_zip_binding = $zipPackageEvidence
    requested_home_wlan_profile_sha256 =
        Get-R01TextSha256 -Text $HomeProfile
    requested_hotspot_wlan_profile_sha256 =
        Get-R01TextSha256 -Text $HotspotProfile
    agent_preflight = $agentPreflightEvidence
    upnp_backend_identity_sha256 = if ($null -ne $upnpBackendEvidence) {
        [string]$upnpBackendEvidence.identity_sha256
    } else { '' }
    upnp_mapping_lifecycle = @($mappingLifecycleEvidence)
    cooperative_remote_recovery = $remoteCleanupEvidence
}
$manifest | ConvertTo-Json -Depth 16 |
    Set-Content -LiteralPath $manifestPath -Encoding UTF8
$publicResult
if ($status -ceq 'FAIL') { exit 1 }
if ($status -cne 'PASS') { exit 2 }
