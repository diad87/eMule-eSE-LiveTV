<#
.SYNOPSIS
Runs V91-D01 on two controlled physical Windows hosts.

.DESCRIPTION
Start the Coordinator role first and the Source role second with the
coordinator-issued RunNonce.  The two roles exchange nonce-scoped JSON files
through CoordinationRoot; media never traverses that directory.

The source owns one non-sparse file and listens only on IPv4.  The coordinator
uses a fresh Preferred profile, a same-host controlled minimal eD2K server,
Kad disabled, no third-party servers and exactly one explicit-hostname link
injection.  Formal PASS requires:

  * an observed direct native T1 or T2 topology on distinct physical hosts;
  * exact and stable controlled A+AAAA DNS answers;
  * a failed AAAA path and a working A path attributed to real PID sockets;
  * one lossless PktMon/ETW capture covering both target families;
  * exactly one post-baseline localhost telemetry event proving that the
    canonical A+AAAA set was resolved and simultaneously materialized;
  * an intact one-file transfer, responsive API/UI, isolation and clean
    rollback; and
  * unchanged extracted-package, ZIP and executable identities.

The product telemetry contract is GET /api/debug/source-resolutions:

  {
    "schema": "ese.debug.source-resolutions/v1",
    "sequence": 12,
    "events": [{
      "sequence": 12,
      "hostname_sha256": "...",
        "file_ed2k_hash": "...",
      "port": 9162,
      "resolver_result": "success",
      "resolved": {
        "ipv4_count": 1, "ipv6_count": 1,
        "endpoint_set_sha256": "..."
      },
      "materialized": {
        "ipv4_count": 1, "ipv6_count": 1,
        "endpoint_set_sha256": "...",
        "simultaneously_retained": true
      },
      "candidates": [{
        "family": "ipv4",
        "endpoint_sha256": "...",
        "outcome": "added",
        "source_origin": "hostname_link"
      }]
    }]
  }

Endpoint canonical bytes are family byte 4 or 6, address bytes in network
order, and the two-byte port in network order.  Entries are sorted
lexicographically and concatenated before SHA-256.

The summary deliberately separates fixture_status, observability_status and
product_status.  Exit codes are 0=PASS, 1=FAIL and 2=BLOCKED.
#>
[CmdletBinding()]
param(
    [ValidateSet('Coordinator', 'Source')][string]$Role = 'Coordinator',
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$PackageZipPath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)][string]$CoordinationRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedEmuleSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageZipSha256,
    [Parameter(Mandatory = $true)][string]$Hostname,
    [Parameter(Mandatory = $true)][string]$SourcePublicIPv4,
    [Parameter(Mandatory = $true)][string]$SourceLocalIPv4,
    [Parameter(Mandatory = $true)][string]$SourceIPv6,
    [Parameter(Mandatory = $true)][string]$CoordinatorPublicIPv4,
    [Parameter(Mandatory = $true)][string]$CoordinatorLocalIPv4,
    [Parameter(Mandatory = $true)][string]$CoordinatorIPv6,
    [Parameter(Mandatory = $true)][switch]$ControlledFixtureAcknowledged,
    [ValidateRange(1024, 65535)][int]$SourceTcpPort = 9162,
    [ValidateRange(1024, 65535)][int]$SourceUdpPort = 9172,
    [ValidateRange(1024, 65535)][int]$SourceWebPort = 9211,
    [ValidateRange(1024, 65535)][int]$DownloaderTcpPort = 9262,
    [ValidateRange(1024, 65535)][int]$DownloaderUdpPort = 9272,
    [ValidateRange(1024, 65535)][int]$DownloaderWebPort = 9311,
    [ValidateRange(1048576, 1073741824)]
    [Int64]$FileSizeBytes = 67108864,
    [ValidateRange(30, 900)][int]$PeerReadyTimeoutSeconds = 300,
    [ValidateRange(60, 3600)][int]$TransferTimeoutSeconds = 1200,
    [ValidateRange(250, 10000)]
    [int]$EndpointProbeTimeoutMilliseconds = 2500,
    [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunNonce = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'common.ps1')

$caseId = 'V91-D01'
$expectedEmuleHash = $ExpectedEmuleSha256.ToLowerInvariant()
$expectedZipHash = $ExpectedPackageZipSha256.ToLowerInvariant()
$canonicalHostname = $Hostname.Trim().Trim('[', ']').
    TrimEnd('.').ToLowerInvariant()
$webPassword = 'v91-d01-local-api'
$overlayPattern =
    '(?i)tailscale|wireguard|cloudflare|warp|zerotier|openvpn|' +
    'hyper-v|vethernet|loopback|tunnel|tap|vpn|hamachi'

function Convert-D01Address {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$Family,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse(
        $Value.Trim('[', ']').Split('%')[0], [ref]$parsed
    ) -or $parsed.AddressFamily -ne $Family -or
        ($Family -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and
            $parsed.IsIPv4MappedToIPv6)) {
        throw "$Name is not an address in the required family: '$Value'"
    }
    return $parsed
}

function Get-D01NormalizedIp {
    param([Parameter(Mandatory = $true)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse(
        $Address.Trim('[', ']').Split('%')[0], [ref]$parsed
    )) {
        return $Address
    }
    if ($parsed.IsIPv4MappedToIPv6) {
        return $parsed.MapToIPv4().ToString()
    }
    return $parsed.ToString()
}

function Test-D01Administrator {
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

function Get-D01MachineId {
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

function New-D01ClockAnchor {
    $frequency = [Diagnostics.Stopwatch]::Frequency
    $qpcBefore = [Diagnostics.Stopwatch]::GetTimestamp()
    $utcTicks = [DateTime]::UtcNow.Ticks
    $qpcAfter = [Diagnostics.Stopwatch]::GetTimestamp()
    $midpoint = [Int64][Math]::Round(
        ([decimal]$qpcBefore + [decimal]$qpcAfter) / 2,
        [MidpointRounding]::AwayFromZero
    )
    $unixNanoseconds = [Int64](
        ([decimal]$utcTicks - [decimal]621355968000000000L) * 100
    )
    $uncertaintyNanoseconds = [Int64][Math]::Ceiling(
        [double](
            ([decimal]($qpcAfter - $qpcBefore) * 1000000000) /
            [decimal]$frequency / 2
        )
    ) + 100L
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-clock-anchor/v1'
        clock_domain = 'windows-query-performance-counter'
        anchor_id = [Guid]::NewGuid().ToString('N')
        qpc_frequency = [Int64]$frequency
        anchor_qpc_ticks = $midpoint
        anchor_epoch_unix_ns = $unixNanoseconds
        anchor_uncertainty_ns = $uncertaintyNanoseconds
        generated_at_utc = Get-LabUtcTimestamp
    }
}

function Get-D01ClockObservation {
    param(
        [Parameter(Mandatory = $true)][object]$Anchor,
        [Parameter(Mandatory = $true)][Int64]$QpcStart,
        [Parameter(Mandatory = $true)][Int64]$QpcEnd
    )

    if ($QpcEnd -lt $QpcStart -or
        [Int64]$Anchor.qpc_frequency -le 0) {
        throw 'Invalid QPC observation interval'
    }
    $midpoint = [Int64][Math]::Round(
        ([decimal]$QpcStart + [decimal]$QpcEnd) / 2,
        [MidpointRounding]::AwayFromZero
    )
    $deltaNanoseconds = [decimal](
        ([decimal]($midpoint - [Int64]$Anchor.anchor_qpc_ticks) *
            1000000000) / [decimal][Int64]$Anchor.qpc_frequency
    )
    $epochNanoseconds = [Int64][Math]::Round(
        [decimal][Int64]$Anchor.anchor_epoch_unix_ns + $deltaNanoseconds,
        [MidpointRounding]::AwayFromZero
    )
    $intervalUncertainty = [Int64][Math]::Ceiling(
        [double](
            ([decimal]($QpcEnd - $QpcStart) * 1000000000) /
            [decimal][Int64]$Anchor.qpc_frequency / 2
        )
    )
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-clock-observation/v1'
        clock_domain = [string]$Anchor.clock_domain
        anchor_id = [string]$Anchor.anchor_id
        qpc_frequency = [Int64]$Anchor.qpc_frequency
        qpc_start_ticks = $QpcStart
        qpc_end_ticks = $QpcEnd
        qpc_midpoint_ticks = $midpoint
        epoch_unix_ns = $epochNanoseconds
        uncertainty_ns =
            [Int64]$Anchor.anchor_uncertainty_ns + $intervalUncertainty
    }
}

function Write-D01JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -Force
    }
    $temporary = Join-Path $parent (
        '.{0}.{1}.tmp' -f (Split-Path -Leaf $Path),
        [Guid]::NewGuid().ToString('N')
    )
    try {
        [IO.File]::WriteAllText(
            $temporary,
            ($Value | ConvertTo-Json -Depth 48),
            (New-Object Text.UTF8Encoding($false))
        )
        [IO.File]::Move($temporary, $Path)
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Add-D01JsonLine {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    Add-Content -LiteralPath $Path -Encoding utf8 -Value (
        $Value | ConvertTo-Json -Depth 32 -Compress
    )
}

function Wait-D01JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [AllowEmptyString()][string]$StopPath = ''
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($StopPath -and
            (Test-Path -LiteralPath $StopPath -PathType Leaf)) {
            try {
                return [pscustomobject]@{
                    kind = 'stop'
                    value = Get-Content -LiteralPath $StopPath -Raw |
                        ConvertFrom-Json -ErrorAction Stop
                }
            } catch {}
        }
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try {
                return [pscustomobject]@{
                    kind = 'value'
                    value = Get-Content -LiteralPath $Path -Raw |
                        ConvertFrom-Json -ErrorAction Stop
                }
            } catch {}
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Get-D01DirectoryManifest {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $root = Get-LabFullPath -Path $RootPath
    $entries = New-Object 'Collections.Generic.List[object]'
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
        $entry = [pscustomobject][ordered]@{
            relative_path = $relative
            bytes = [Int64]$file.Length
            sha256 = $sha256
        }
        $entries.Add($entry)
        $null = $canonical.Append($relative)
        $null = $canonical.Append([char]0)
        $null = $canonical.Append([string][Int64]$file.Length)
        $null = $canonical.Append([char]0)
        $null = $canonical.Append($sha256)
        $null = $canonical.Append("`n")
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-extracted-package-manifest/v2'
        root_directory_name = Split-Path -Leaf $root
        file_count = $entries.Count
        total_bytes = $totalBytes
        manifest_sha256 =
            Get-LabStringSha256 -Value $canonical.ToString()
        files = @($entries)
    }
}

function Get-D01ZipManifest {
    param([Parameter(Mandatory = $true)][string]$ZipPath)

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = Get-LabFullPath -Path $ZipPath
    if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) {
        throw "Candidate ZIP is missing: $zip"
    }
    $archive = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        $rawEntries = @(
            $archive.Entries | Where-Object {
                -not [string]::IsNullOrEmpty($_.Name)
            }
        )
        if ($rawEntries.Count -eq 0) {
            throw 'Candidate ZIP contains no files'
        }
        $firstParts = @(
            $rawEntries | ForEach-Object {
                ([string]$_.FullName).Replace('\', '/').Split('/')[0]
            } | Sort-Object -Unique
        )
        $stripPrefix = ''
        if ($firstParts.Count -eq 1 -and
            @($rawEntries | Where-Object {
                ([string]$_.FullName).Replace('\', '/').IndexOf('/') -lt 0
            }).Count -eq 0) {
            $stripPrefix = $firstParts[0] + '/'
        }

        $items = New-Object 'Collections.Generic.List[object]'
        foreach ($entry in $rawEntries) {
            $relative = ([string]$entry.FullName).Replace('\', '/')
            if ($stripPrefix -and $relative.StartsWith(
                $stripPrefix, [StringComparison]::Ordinal
            )) {
                $relative = $relative.Substring($stripPrefix.Length)
            }
            $stream = $entry.Open()
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $hash = ([BitConverter]::ToString(
                    $sha.ComputeHash($stream)
                )).Replace('-', '').ToLowerInvariant()
            } finally {
                $sha.Dispose()
                $stream.Dispose()
            }
            $items.Add([pscustomobject][ordered]@{
                relative_path = $relative
                bytes = [Int64]$entry.Length
                sha256 = $hash
            })
        }
        $orderedItems = @($items | Sort-Object relative_path)
        $canonical = New-Object Text.StringBuilder
        $totalBytes = 0L
        foreach ($item in $orderedItems) {
            $totalBytes += [Int64]$item.bytes
            $null = $canonical.Append([string]$item.relative_path)
            $null = $canonical.Append([char]0)
            $null = $canonical.Append([string][Int64]$item.bytes)
            $null = $canonical.Append([char]0)
            $null = $canonical.Append([string]$item.sha256)
            $null = $canonical.Append("`n")
        }
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-zip-manifest/v2'
            zip_name = Split-Path -Leaf $zip
            zip_bytes = [Int64](Get-Item -LiteralPath $zip).Length
            zip_sha256 = Get-LabSha256 -Path $zip
            stripped_common_prefix = $stripPrefix
            file_count = $orderedItems.Count
            total_uncompressed_bytes = $totalBytes
            manifest_sha256 =
                Get-LabStringSha256 -Value $canonical.ToString()
            files = $orderedItems
        }
    } finally {
        $archive.Dispose()
    }
}

function Get-D01CandidateIdentity {
    $candidate = Get-LabCandidateInfo -PackagePath $PackagePath `
        -ExpectedCommit $Commit
    $directory = Get-D01DirectoryManifest -RootPath $candidate.package_path
    $zip = Get-D01ZipManifest -ZipPath $PackageZipPath
    $zipMatchesDirectory =
        $zip.file_count -eq $directory.file_count -and
        $zip.total_uncompressed_bytes -eq $directory.total_bytes -and
        $zip.manifest_sha256 -eq $directory.manifest_sha256
    return [pscustomobject][ordered]@{
        candidate = $candidate
        extracted_manifest = $directory
        zip_manifest = $zip
        emule_sha256_matches =
            $candidate.emule_sha256 -eq $expectedEmuleHash
        zip_sha256_matches = $zip.zip_sha256 -eq $expectedZipHash
        zip_matches_extracted_directory = $zipMatchesDirectory
        exact = $candidate.emule_sha256 -eq $expectedEmuleHash -and
            $zip.zip_sha256 -eq $expectedZipHash -and
            $zipMatchesDirectory
    }
}

function Get-D01EndpointBytes {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $familyByte = if ($Address.AddressFamily -eq
        [Net.Sockets.AddressFamily]::InterNetwork) { [byte]4 } else { [byte]6 }
    $addressBytes = $Address.GetAddressBytes()
    $result = New-Object byte[] (1 + $addressBytes.Length + 2)
    $result[0] = $familyByte
    [Array]::Copy($addressBytes, 0, $result, 1, $addressBytes.Length)
    $result[$result.Length - 2] = [byte](($Port -shr 8) -band 0xff)
    $result[$result.Length - 1] = [byte]($Port -band 0xff)
    return $result
}

function Get-D01BytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash($Bytes)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-D01CanonicalEndpointEvidence {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress[]]$Addresses,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $entries = @(
        foreach ($address in $Addresses) {
            $bytes = Get-D01EndpointBytes -Address $address -Port $Port
            [pscustomobject][ordered]@{
                family = if ($address.AddressFamily -eq
                    [Net.Sockets.AddressFamily]::InterNetwork) {
                    'IPv4'
                } else { 'IPv6' }
                endpoint_sha256 = Get-D01BytesSha256 -Bytes $bytes
                canonical_hex = [BitConverter]::ToString($bytes).
                    Replace('-', '').ToLowerInvariant()
                bytes = $bytes
            }
        }
    )
    $sorted = @($entries | Sort-Object canonical_hex)
    $stream = New-Object IO.MemoryStream
    try {
        foreach ($entry in $sorted) {
            $stream.Write($entry.bytes, 0, $entry.bytes.Length)
        }
        $setBytes = $stream.ToArray()
    } finally {
        $stream.Dispose()
    }
    return [pscustomobject][ordered]@{
        algorithm =
            'family-byte(4|6)||address-network-bytes||port-big-endian; ' +
            'lexicographic-entry-sort; concatenation; sha256'
        port = $Port
        endpoint_set_sha256 = Get-D01BytesSha256 -Bytes $setBytes
        endpoints = @(
            $sorted | Select-Object family, endpoint_sha256, canonical_hex
        )
    }
}

function Get-D01AdapterEvidence {
    param(
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex `
        -ErrorAction Stop
    $isVirtual = $false
    if ($adapter.PSObject.Properties.Name -contains 'Virtual') {
        $isVirtual = [bool]$adapter.Virtual
    }
    $overlayLike = ([string]$adapter.Name) -match $overlayPattern -or
        ([string]$adapter.InterfaceDescription) -match $overlayPattern
    $physical = [bool]$adapter.HardwareInterface -and -not $isVirtual -and
        -not $overlayLike -and [string]$adapter.Status -eq 'Up'
    return [pscustomobject][ordered]@{
        context = $Context
        interface_index = [int]$adapter.InterfaceIndex
        interface_id = Get-LabInterfaceId `
            -Id ([string]$adapter.InterfaceGuid) `
            -Name ([string]$adapter.Name) `
            -Description ([string]$adapter.InterfaceDescription)
        status = [string]$adapter.Status
        hardware_interface = [bool]$adapter.HardwareInterface
        virtual = $isVirtual
        overlay_or_vpn_like = $overlayLike
        physical_nonvirtual = $physical
    }
}

function Get-D01NetworkPrefix {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][int]$PrefixLength
    )

    $parsed = [Net.IPAddress]::Parse($Address.Split('%')[0])
    $bytes = $parsed.GetAddressBytes()
    if ($PrefixLength -lt 0 -or
        $PrefixLength -gt ($bytes.Length * 8)) {
        throw "Invalid prefix length $PrefixLength for $Address"
    }
    $remaining = $PrefixLength
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        if ($remaining -ge 8) {
            $remaining -= 8
            continue
        }
        if ($remaining -le 0) {
            $bytes[$index] = 0
        } else {
            $mask = [byte](0xff -band (0xff -shl (8 - $remaining)))
            $bytes[$index] = [byte]($bytes[$index] -band $mask)
            $remaining = 0
        }
    }
    return '{0}/{1}' -f (New-Object Net.IPAddress -ArgumentList (, $bytes)),
        $PrefixLength
}

function Get-D01AssignedAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$Family,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $familyName = if ($Family -eq
        [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
    $normalized = Get-D01NormalizedIp -Address $Address
    $item = Get-NetIPAddress -AddressFamily $familyName `
        -ErrorAction SilentlyContinue | Where-Object {
            (Get-D01NormalizedIp -Address ([string]$_.IPAddress)) -eq
                $normalized -and [string]$_.AddressState -eq 'Preferred'
        } | Select-Object -First 1
    if ($null -eq $item) {
        throw "$Context is not a Preferred address assigned on this host"
    }
    $adapter = Get-D01AdapterEvidence `
        -InterfaceIndex ([int]$item.InterfaceIndex) -Context $Context
    return [pscustomobject][ordered]@{
        address = $normalized
        address_class = Get-LabAddressClass -Address $normalized
        interface_index = [int]$item.InterfaceIndex
        prefix_length = [int]$item.PrefixLength
        network_prefix = Get-D01NetworkPrefix `
            -Address $normalized -PrefixLength ([int]$item.PrefixLength)
        adapter = $adapter
    }
}

function Get-D01RouteEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][string]$Context
    )

    try {
        $route = Find-NetRoute -RemoteIPAddress $RemoteAddress `
            -ErrorAction Stop | Select-Object -First 1
        if ($null -eq $route) { throw 'Find-NetRoute returned no route' }
        $adapter = Get-D01AdapterEvidence `
            -InterfaceIndex ([int]$route.InterfaceIndex) -Context $Context
        $source = Get-D01NormalizedIp -Address ([string]$route.IPAddress)
        $nextHop = Get-D01NormalizedIp -Address ([string]$route.NextHop)
        $onLink = $nextHop -in @('0.0.0.0', '::')
        return [pscustomobject][ordered]@{
            available = $true
            remote_address = Get-D01NormalizedIp -Address $RemoteAddress
            source_address = $source
            source_class = Get-LabAddressClass -Address $source
            interface_index = [int]$route.InterfaceIndex
            next_hop = $nextHop
            next_hop_class = if ($onLink) {
                'on-link'
            } else {
                Get-LabAddressClass -Address $nextHop
            }
            on_link = $onLink
            adapter = $adapter
            error = $null
        }
    } catch {
        return [pscustomobject][ordered]@{
            available = $false
            remote_address = Get-D01NormalizedIp -Address $RemoteAddress
            source_address = ''
            source_class = 'invalid'
            interface_index = $null
            next_hop = ''
            next_hop_class = 'unknown'
            on_link = $false
            adapter = $null
            error = $_.Exception.Message
        }
    }
}

function Get-D01IsolationEvidence {
    $overlays = @(
        Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
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
        active_overlay_or_vpn_adapters = $overlays
        active_overlay_or_vpn_count = $overlays.Count
        proxy_environment_variable_names_set = $setProxyEnvironmentNames
        proxy_environment_variable_count = $setProxyEnvironmentNames.Count
        strict_isolation_valid =
            $overlays.Count -eq 0 -and $setProxyEnvironmentNames.Count -eq 0
    }
}

function Get-D01FirewallRuleEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [ValidateSet('Allow', 'Block')]
        [Parameter(Mandatory = $true)][string]$ExpectedAction,
        [Parameter(Mandatory = $true)][string]$ExpectedLocalAddress,
        [Parameter(Mandatory = $true)][string[]]$ExpectedRemoteAddress,
        [Parameter(Mandatory = $true)][int]$ExpectedLocalPort,
        [Parameter(Mandatory = $true)][string]$ExpectedRemotePort,
        [Parameter(Mandatory = $true)][string]$ExpectedProgram,
        [Parameter(Mandatory = $true)][string]$ExpectedProfile
    )

    $rules = @(
        Get-NetFirewallRule -DisplayName $DisplayName `
            -ErrorAction SilentlyContinue
    )
    $ports = @()
    $addresses = @()
    $applications = @()
    if ($rules.Count -eq 1) {
        $ports = @(
            $rules[0] | Get-NetFirewallPortFilter `
                -ErrorAction SilentlyContinue
        )
        $addresses = @(
            $rules[0] | Get-NetFirewallAddressFilter `
                -ErrorAction SilentlyContinue
        )
        $applications = @(
            $rules[0] | Get-NetFirewallApplicationFilter `
                -ErrorAction SilentlyContinue
        )
    }
    $localAddresses = @(
        if ($addresses.Count -eq 1) {
            $addresses[0].LocalAddress |
                ForEach-Object { [string]$_ }
        }
    )
    $remoteAddresses = @(
        if ($addresses.Count -eq 1) {
            $addresses[0].RemoteAddress |
                ForEach-Object { [string]$_ }
        }
    )
    $expectedRemoteAddresses = @(
        $ExpectedRemoteAddress |
            ForEach-Object { [string]$_ } |
            Sort-Object -Unique
    )
    $actualRemoteAddresses = @(
        $remoteAddresses | Sort-Object -Unique
    )
    $remoteAddressesMatch =
        $expectedRemoteAddresses.Count -gt 0 -and
        $actualRemoteAddresses.Count -eq
            $expectedRemoteAddresses.Count -and
        @(Compare-Object `
            -ReferenceObject $expectedRemoteAddresses `
            -DifferenceObject $actualRemoteAddresses).Count -eq 0
    $programMatches = if ($ExpectedProgram -eq 'Any') {
        $applications.Count -eq 1 -and
        [string]$applications[0].Program -eq 'Any'
    } else {
        $applications.Count -eq 1 -and
        [IO.Path]::GetFullPath([string]$applications[0].Program) -eq
            [IO.Path]::GetFullPath($ExpectedProgram)
    }
    $exact = $rules.Count -eq 1 -and $ports.Count -eq 1 -and
        $addresses.Count -eq 1 -and $programMatches -and
        [string]$rules[0].Direction -eq 'Inbound' -and
        [string]$rules[0].Action -eq $ExpectedAction -and
        [string]$rules[0].Enabled -eq 'True' -and
        [string]$rules[0].Profile -eq $ExpectedProfile -and
        [string]$ports[0].Protocol -eq 'TCP' -and
        [string]$ports[0].LocalPort -eq [string]$ExpectedLocalPort -and
        [string]$ports[0].RemotePort -eq $ExpectedRemotePort -and
        $localAddresses.Count -eq 1 -and
        $localAddresses[0] -eq $ExpectedLocalAddress -and
        $remoteAddressesMatch
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        display_name = $DisplayName
        rule_count = $rules.Count
        action = if ($rules.Count -eq 1) {
            [string]$rules[0].Action
        } else { '' }
        direction = if ($rules.Count -eq 1) {
            [string]$rules[0].Direction
        } else { '' }
        enabled = $rules.Count -eq 1 -and
            [string]$rules[0].Enabled -eq 'True'
        profile = if ($rules.Count -eq 1) {
            [string]$rules[0].Profile
        } else { '' }
        protocol = if ($ports.Count -eq 1) {
            [string]$ports[0].Protocol
        } else { '' }
        local_port = if ($ports.Count -eq 1) {
            [string]$ports[0].LocalPort
        } else { '' }
        remote_port = if ($ports.Count -eq 1) {
            [string]$ports[0].RemotePort
        } else { '' }
        local_addresses = $localAddresses
        remote_addresses = $remoteAddresses
        program = if ($applications.Count -eq 1) {
            [string]$applications[0].Program
        } else { '' }
        exact = $exact
    }
}

function Assert-D01OutputLocation {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$CandidateRoot
    )

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $packagePrefix = [IO.Path]::GetFullPath($CandidateRoot).TrimEnd('\') + '\'
    if (($full + '\').StartsWith(
        $packagePrefix, [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Label must not be inside the candidate package"
    }
    return $full
}

function Test-D01PortsFree {
    param([Parameter(Mandatory = $true)][int[]]$Ports)

    foreach ($port in $Ports) {
        if (Get-NetTCPConnection -State Listen -LocalPort $port `
            -ErrorAction SilentlyContinue) {
            throw "TCP port $port is already listening"
        }
        if (Get-NetUDPEndpoint -LocalPort $port `
            -ErrorAction SilentlyContinue) {
            throw "UDP port $port is already in use"
        }
    }
}

function Get-D01Md5Text {
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

function Set-D01IsolatedPreferences {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][int]$IPv6Mode,
        [AllowEmptyString()][string]$IPv6BindAddress = '',
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][string]$IncomingPath,
        [Parameter(Mandatory = $true)][string]$TempPath,
        [switch]$SourceProfile
    )

    $config = Join-Path $NodePath 'config'
    $preferences = Join-Path $config 'preferences.ini'
    foreach ($identityName in @(
        'preferences.dat', 'cryptkey.dat', 'clients.met'
    )) {
        $identityPath = Join-Path $config $identityName
        if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
            Remove-Item -LiteralPath $identityPath -Force -ErrorAction Stop
        }
    }
    foreach ($entry in ([ordered]@{
        Port = [string]$TcpPort
        UDPPort = [string]$UdpPort
        Autoconnect = '0'
        NetworkED2K = '0'
        NetworkKademlia = '0'
        AutoConnectStaticOnly = '1'
        Reconnect = '0'
        Serverlist = '0'
        UpdateNotifyTestClient = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        FilterBadIPs = '0'
        FilterServersByIP = '0'
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
    if ($SourceProfile) {
        foreach ($entry in ([ordered]@{
            MaxUpload = '512'
            UploadCapacityNew = '1024'
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
        Password = Get-D01Md5Text -Value $webPassword
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

    foreach ($name in @(
        'server.met', 'server_met.old', 'server_met.download',
        'server_met.old.bak', 'staticservers.dat', 'nodes.dat',
        'nodes_v6.dat', 'bootstrap.dat'
    )) {
        $path = Join-Path $config $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
    [IO.File]::WriteAllText(
        (Join-Path $config 'shareddir.dat'), '',
        (New-Object Text.UTF8Encoding($false))
    )
    foreach ($runtimeLog in @(
        Get-ChildItem -LiteralPath $NodePath -Recurse -File -Filter '*.log' `
            -ErrorAction SilentlyContinue
    )) {
        Remove-Item -LiteralPath $runtimeLog.FullName -Force `
            -ErrorAction Stop
    }
    return [pscustomobject][ordered]@{
        preferences_path = $preferences
        preferences_sha256 = Get-LabSha256 -Path $preferences
        ipv6_mode = $IPv6Mode
        ipv6_bind_address = $IPv6BindAddress
        network_ed2k = $false
        network_kad = $false
        proxy_enabled = $false
        web_allowed_ips = @('127.0.0.1')
        inherited_server_and_kad_files_removed = $true
        fresh_identity = $true
    }
}

function Enable-D01ControlledEd2kProfile {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ServerAddress,
        [Parameter(Mandatory = $true)][int]$ServerPort,
        [Parameter(Mandatory = $true)][string]$Nonce
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
    $static = Join-Path $NodePath 'config\staticservers.dat'
    $line = '{0}:{1},0,eSE-D01-{2}' -f $ServerAddress, $ServerPort, $Nonce
    [IO.File]::WriteAllText(
        $static, ($line + "`r`n"),
        (New-Object Text.UnicodeEncoding($false, $true))
    )
    return [pscustomobject][ordered]@{
        endpoint = "$ServerAddress`:$ServerPort"
        endpoint_scope = 'same-host assigned physical IPv4'
        staticservers_sha256 = Get-LabSha256 -Path $static
        preferences_sha256 = Get-LabSha256 -Path $preferences
        network_ed2k = $true
        network_kad = $false
        auto_connect_static_only = $true
        third_party_server_files_removed = $true
    }
}

function Wait-D01Api {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before API startup (exit $($Process.ExitCode))"
        }
        try {
            return Invoke-RestMethod `
                -Uri "http://127.0.0.1:$Port/api/status" -TimeoutSec 2
        } catch {}
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "API on localhost port $Port did not become ready"
}

function Wait-D01Listener {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [switch]$RequireIPv4Only
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
            $v6Listeners = @($listeners | Where-Object {
                (Get-D01NormalizedIp -Address ([string]$_.LocalAddress)).
                    Contains(':')
            })
            if (-not $RequireIPv4Only -or $v6Listeners.Count -eq 0) {
                return [pscustomobject][ordered]@{
                    process_id = $Process.Id
                    ipv4_only = $v6Listeners.Count -eq 0
                    listeners = @(
                        $listeners | ForEach-Object {
                            [pscustomobject][ordered]@{
                                local_address = Get-D01NormalizedIp `
                                    -Address ([string]$_.LocalAddress)
                                local_port = [int]$_.LocalPort
                                owning_process = [int]$_.OwningProcess
                            }
                        }
                    )
                }
            }
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($RequireIPv4Only) {
        throw "An IPv4-only PID-owned listener on port $Port did not become ready"
    }
    throw "PID-owned listener on port $Port did not become ready"
}

function Test-D01ApiIsolation {
    param(
        [AllowNull()][object]$Data,
        [switch]$AllowControlledEd2k
    )

    if ($null -eq $Data) { return $false }
    $names = @($Data.PSObject.Properties.Name)
    $ed2kValid = if ($AllowControlledEd2k) {
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
        [int]$Data.kad_running_mask -eq 0 -and $ed2kValid
}

function Get-D01ApiProbe {
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
        isolation_valid = Test-D01ApiIsolation -Data $data `
            -AllowControlledEd2k:$AllowControlledEd2k
        error = $errorText
        data = $data
    }
}

function Initialize-D01UiProbe {
    if ('V91D01UiProbeV2' -as [type]) { return }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91D01UiProbeV2 {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam,
        uint flags, uint timeout, out IntPtr result);
}
'@
}

function Get-D01UiProbe {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    Initialize-D01UiProbe
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $present = $false
    $responsive = $false
    try {
        $Process.Refresh()
        if (-not $Process.HasExited -and
            $Process.MainWindowHandle -ne [IntPtr]::Zero) {
            $present = $true
            $result = [IntPtr]::Zero
            $sent = [V91D01UiProbeV2]::SendMessageTimeout(
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

function Stop-D01OwnedProcess {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [AllowEmptyString()][string]$ExpectedPath = ''
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
    $pathOwned = $true
    if ($ExpectedPath) {
        try {
            $pathOwned = [IO.Path]::GetFullPath($actual.Path) -eq
                [IO.Path]::GetFullPath($ExpectedPath)
        } catch { $pathOwned = $false }
    }
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
        if (-not $graceful) {
            Stop-Process -Id $actual.Id -Force -ErrorAction Stop
            $null = $actual.WaitForExit(10000)
        }
    } catch {}
    return [pscustomobject]@{
        stopped = $null -eq (
            Get-Process -Id $actual.Id -ErrorAction SilentlyContinue
        )
        path_owned = $true
        graceful = $graceful
        process_id = $actual.Id
    }
}

function Get-D01ClassicSession {
    param([Parameter(Mandatory = $true)][int]$Port)

    $encoded = [Uri]::EscapeDataString($webPassword)
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
    throw "Classic WebServer login failed on localhost port $Port"
}

function Get-D01SharedLink {
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

function Send-D01Ed2kLink {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Link
    )

    if (-not ('V91D01CopyDataV2' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91D01CopyDataV2 {
    [StructLayout(LayoutKind.Sequential)]
    public struct COPYDATASTRUCT {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint msg, IntPtr wParam, ref COPYDATASTRUCT lParam,
        uint flags, uint timeout, out IntPtr result);
}
'@
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $handle = [IntPtr]::Zero
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'Downloader exited before the sole ED2K link injection'
        }
        $handle = $Process.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($handle -eq [IntPtr]::Zero) {
        throw 'Downloader main window handle was unavailable'
    }

    $pointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Link)
    try {
        $payload = New-Object V91D01CopyDataV2+COPYDATASTRUCT
        $payload.dwData = [IntPtr]12000
        $payload.cbData = ($Link.Length + 1) * 2
        $payload.lpData = $pointer
        $result = [IntPtr]::Zero
        $sent = [V91D01CopyDataV2]::SendMessageTimeout(
            $handle, 0x004A, [IntPtr]::Zero, [ref]$payload,
            2, 5000, [ref]$result
        )
        if ($sent -eq [IntPtr]::Zero) {
            throw "WM_COPYDATA timed out or failed (Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
        }
        return [pscustomobject][ordered]@{
            injected_at_utc = Get-LabUtcTimestamp
            process_id = $Process.Id
            link_sha256 = Get-LabStringSha256 -Value $Link
            send_message_timeout_ms = 5000
            one_injection = $true
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
    }
}

function New-D01FixtureFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Int64]$Bytes
    )

    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None
    )
    $rng = $null
    try {
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        $buffer = New-Object byte[] (1MB)
        [Int64]$remaining = $Bytes
        while ($remaining -gt 0) {
            $rng.GetBytes($buffer)
            $count = [int][Math]::Min([Int64]$buffer.Length, $remaining)
            $stream.Write($buffer, 0, $count)
            $remaining -= $count
        }
        $stream.Flush($true)
    } finally {
        if ($null -ne $rng) { $rng.Dispose() }
        $stream.Dispose()
    }
    $item = Get-Item -LiteralPath $Path
    return [pscustomobject][ordered]@{
        bytes = [Int64]$item.Length
        sha256 = Get-LabSha256 -Path $Path
        generation = 'fully materialized CSPRNG bytes; non-sparse'
    }
}

function Test-D01TcpEndpoint {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds
    )

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $client = New-Object Net.Sockets.TcpClient($Address.AddressFamily)
    $connected = $false
    $timedOut = $false
    $errorText = $null
    try {
        $task = $client.ConnectAsync($Address, $Port)
        if (-not $task.Wait($TimeoutMilliseconds)) {
            $timedOut = $true
        } elseif ($task.IsFaulted) {
            $errorText = $task.Exception.GetBaseException().Message
        } else {
            $connected = $client.Connected
        }
    } catch {
        $errorText = $_.Exception.GetBaseException().Message
    } finally {
        $watch.Stop()
        $client.Dispose()
    }
    return [pscustomobject][ordered]@{
        address = $Address.ToString()
        family = if ($Address.AddressFamily -eq
            [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
        port = $Port
        connected = $connected
        timed_out = $timedOut
        duration_ms = [Int64]$watch.ElapsedMilliseconds
        error = $errorText
    }
}

function Get-D01TargetConnections {
    param(
        [ValidateRange(0, 2147483647)][int]$ProcessId = 0,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddresses,
        [ValidateRange(0, 65535)][int]$RemotePort = 0
    )

    $normalizedTargets = @(
        $RemoteAddresses | ForEach-Object {
            Get-D01NormalizedIp -Address $_
        }
    )
    $connections = if ($ProcessId -gt 0 -and $RemotePort -gt 0) {
        @(
            Get-NetTCPConnection -OwningProcess $ProcessId `
                -RemotePort $RemotePort -ErrorAction SilentlyContinue
        )
    } elseif ($ProcessId -gt 0) {
        @(
            Get-NetTCPConnection -OwningProcess $ProcessId `
                -ErrorAction SilentlyContinue
        )
    } elseif ($RemotePort -gt 0) {
        @(
            Get-NetTCPConnection -RemotePort $RemotePort `
                -ErrorAction SilentlyContinue
        )
    } else {
        @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    }
    return @(
        $connections |
            Where-Object {
                (Get-D01NormalizedIp -Address ([string]$_.RemoteAddress)) -in
                    $normalizedTargets
            } | ForEach-Object {
                $remote = Get-D01NormalizedIp `
                    -Address ([string]$_.RemoteAddress)
                $local = Get-D01NormalizedIp `
                    -Address ([string]$_.LocalAddress)
                $assigned = Get-NetIPAddress -ErrorAction SilentlyContinue |
                    Where-Object {
                        (Get-D01NormalizedIp `
                            -Address ([string]$_.IPAddress)) -eq $local
                    } | Select-Object -First 1
                $adapter = $null
                if ($null -ne $assigned) {
                    try {
                        $adapter = Get-D01AdapterEvidence `
                            -InterfaceIndex ([int]$assigned.InterfaceIndex) `
                            -Context 'target-process-socket'
                    } catch {}
                }
                [pscustomobject][ordered]@{
                    captured_at_utc = Get-LabUtcTimestamp
                    owning_process = [int]$_.OwningProcess
                    state = [string]$_.State
                    family = if ($remote.Contains(':')) { 'IPv6' } else { 'IPv4' }
                    local_address = $local
                    local_port = [int]$_.LocalPort
                    remote_address = $remote
                    remote_port = [int]$_.RemotePort
                    local_address_assigned = $null -ne $assigned
                    adapter = $adapter
                    physical_nonvirtual = $null -ne $adapter -and
                        [bool]$adapter.physical_nonvirtual
                }
            }
    )
}

function Get-D01IncomingConnections {
    param(
        [ValidateRange(0, 2147483647)][int]$ProcessId = 0,
        [Parameter(Mandatory = $true)][int]$LocalPort
    )

    $connections = if ($ProcessId -gt 0) {
        @(
            Get-NetTCPConnection -OwningProcess $ProcessId `
                -LocalPort $LocalPort -ErrorAction SilentlyContinue
        )
    } else {
        @(
            Get-NetTCPConnection -LocalPort $LocalPort `
                -ErrorAction SilentlyContinue
        )
    }
    return @(
        $connections |
            Where-Object { [string]$_.State -ne 'Listen' } |
            ForEach-Object {
                $local = Get-D01NormalizedIp `
                    -Address ([string]$_.LocalAddress)
                $assigned = Get-NetIPAddress -ErrorAction SilentlyContinue |
                    Where-Object {
                        (Get-D01NormalizedIp `
                            -Address ([string]$_.IPAddress)) -eq $local
                    } | Select-Object -First 1
                $adapter = $null
                if ($null -ne $assigned) {
                    try {
                        $adapter = Get-D01AdapterEvidence `
                            -InterfaceIndex ([int]$assigned.InterfaceIndex) `
                            -Context 'source-inverse-socket'
                    } catch {}
                }
                [pscustomobject][ordered]@{
                    captured_at_utc = Get-LabUtcTimestamp
                    owning_process = [int]$_.OwningProcess
                    state = [string]$_.State
                    local_address = $local
                    local_port = [int]$_.LocalPort
                    remote_address = Get-D01NormalizedIp `
                        -Address ([string]$_.RemoteAddress)
                    remote_port = [int]$_.RemotePort
                    local_address_assigned = $null -ne $assigned
                    adapter = $adapter
                    physical_nonvirtual = $null -ne $adapter -and
                        [bool]$adapter.physical_nonvirtual
                }
            }
    )
}

function Get-D01DnsEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedA,
        [Parameter(Mandatory = $true)][string]$ExpectedAAAA,
        [Parameter(Mandatory = $true)][string]$Stage
    )

    $addresses = @([Net.Dns]::GetHostAddresses($Name))
    $answers = @(
        $addresses | ForEach-Object {
            [pscustomobject][ordered]@{
                family = if ($_.AddressFamily -eq
                    [Net.Sockets.AddressFamily]::InterNetwork) {
                    'IPv4'
                } else { 'IPv6' }
                address = Get-D01NormalizedIp -Address $_.ToString()
                address_class = Get-LabAddressClass -Address $_.ToString()
            }
        } | Sort-Object family, address -Unique
    )
    $a = @($answers | Where-Object family -eq 'IPv4' |
        Select-Object -ExpandProperty address)
    $aaaa = @($answers | Where-Object family -eq 'IPv6' |
        Select-Object -ExpandProperty address)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-controlled-dns/v2'
        captured_at_utc = Get-LabUtcTimestamp
        stage = $Stage
        resolver = 'System.Net.Dns.GetHostAddresses'
        hostname = $Name
        expected = [ordered]@{ A = $ExpectedA; AAAA = $ExpectedAAAA }
        answers = $answers
        exact_controlled_answer_set = $a.Count -eq 1 -and
            $aaaa.Count -eq 1 -and $a[0] -eq $ExpectedA -and
            $aaaa[0] -eq $ExpectedAAAA
    }
}

function Get-D01TelemetrySnapshot {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Int64]$AfterSequence = -1
    )

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $data = $null
    $errorText = $null
    try {
        $uri = "http://127.0.0.1:$Port/api/debug/source-resolutions"
        if ($AfterSequence -ge 0) {
            $uri += '?after=' + [string]$AfterSequence
        }
        $data = Invoke-RestMethod -Uri $uri -TimeoutSec 2
    } catch {
        $errorText = $_.Exception.Message
    } finally {
        $watch.Stop()
    }
    $contractValid = $false
    if ($null -ne $data) {
        $names = @($data.PSObject.Properties.Name)
        $contractValid =
            [string]$data.schema -eq
                'ese.debug.source-resolutions/v1' -and
            $names -contains 'sequence' -and
            $names -contains 'events' -and
            [Int64]$data.sequence -ge 0
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        available = $null -ne $data
        duration_ms = [Int64]$watch.ElapsedMilliseconds
        after_sequence = $AfterSequence
        contract_valid = $contractValid
        error = $errorText
        data = $data
    }
}

function Test-D01NoRawTelemetryFields {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $true }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $true }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            if ([string]$key -in @(
                'hostname', 'address', 'ip', 'ip_address', 'endpoint'
            )) {
                return $false
            }
            if (-not (Test-D01NoRawTelemetryFields -Value $Value[$key])) {
                return $false
            }
        }
        return $true
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) {
            if (-not (Test-D01NoRawTelemetryFields -Value $item)) {
                return $false
            }
        }
        return $true
    }
    foreach ($property in $Value.PSObject.Properties) {
        if ([string]$property.Name -in @(
            'hostname', 'address', 'ip', 'ip_address', 'endpoint'
        )) {
            return $false
        }
        if (-not (Test-D01NoRawTelemetryFields -Value $property.Value)) {
            return $false
        }
    }
    return $true
}

function Get-D01TelemetryVerdict {
    param(
        [Parameter(Mandatory = $true)][object]$Snapshot,
        [Parameter(Mandatory = $true)][Int64]$BaselineSequence,
        [Parameter(Mandatory = $true)][string]$HostnameSha256,
        [Parameter(Mandatory = $true)][string]$FileEd2kHash,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][object]$CanonicalEndpoints
    )

    $newEvents = @()
    if ($Snapshot.available -and $Snapshot.contract_valid) {
        $newEvents = @(
            @($Snapshot.data.events) | Where-Object {
                [Int64]$_.sequence -gt $BaselineSequence
            } | Sort-Object { [Int64]$_.sequence }
        )
    }
    $event = if ($newEvents.Count -eq 1) { $newEvents[0] } else { $null }
    $candidateEvidence = @()
    if ($null -ne $event) { $candidateEvidence = @($event.candidates) }
    $expectedEndpointHashes = @(
        $CanonicalEndpoints.endpoints |
            Select-Object -ExpandProperty endpoint_sha256 |
            Sort-Object -Unique
    )
    $actualEndpointHashes = @(
        $candidateEvidence |
            Select-Object -ExpandProperty endpoint_sha256 |
            ForEach-Object { ([string]$_).ToLowerInvariant() } |
            Sort-Object -Unique
    )
    $candidateFamilies = @(
        $candidateEvidence |
            Select-Object -ExpandProperty family |
            ForEach-Object { [string]$_ } |
            Sort-Object -Unique
    )
    $candidateOutcomesValid = $candidateEvidence.Count -eq 2 -and
        @($candidateEvidence | Where-Object {
            [string]$_.outcome -notin @('added', 'merged_existing') -or
            [string]$_.source_origin -ne 'hostname_link'
        }).Count -eq 0
    $eventFieldsMatch = $null -ne $event -and
        ([string]$event.hostname_sha256).ToLowerInvariant() -eq
            $HostnameSha256 -and
        ([string]$event.file_ed2k_hash).ToLowerInvariant() -eq
            $FileEd2kHash.ToLowerInvariant() -and
        [int]$event.port -eq $Port -and
        [string]$event.resolver_result -eq 'success'
    $resolvedMatch = $null -ne $event -and
        [int]$event.resolved.ipv4_count -eq 1 -and
        [int]$event.resolved.ipv6_count -eq 1 -and
        ([string]$event.resolved.endpoint_set_sha256).ToLowerInvariant() -eq
            $CanonicalEndpoints.endpoint_set_sha256
    $materializedMatch = $null -ne $event -and
        [int]$event.materialized.ipv4_count -eq 1 -and
        [int]$event.materialized.ipv6_count -eq 1 -and
        ([string]$event.materialized.endpoint_set_sha256).ToLowerInvariant() -eq
            $CanonicalEndpoints.endpoint_set_sha256 -and
        [bool]$event.materialized.simultaneously_retained
    $candidateSetMatch =
        ($expectedEndpointHashes -join ',') -eq
            ($actualEndpointHashes -join ',') -and
        ($candidateFamilies -join ',') -eq 'ipv4,ipv6' -and
        $candidateOutcomesValid
    $privacyValid = $null -ne $event -and
        (Test-D01NoRawTelemetryFields -Value $event)
    return [pscustomobject][ordered]@{
        baseline_sequence = $BaselineSequence
        snapshot_sequence = if ($Snapshot.available) {
            [Int64]$Snapshot.data.sequence
        } else { $null }
        new_event_count = $newEvents.Count
        exactly_one_new_event = $newEvents.Count -eq 1
        event_sequence = if ($null -ne $event) {
            [Int64]$event.sequence
        } else { $null }
        event_fields_match = $eventFieldsMatch
        resolved_set_match = $resolvedMatch
        materialized_set_match = $materializedMatch
        candidate_set_match = $candidateSetMatch
        raw_sensitive_fields_absent = $privacyValid
        expected_endpoint_set_sha256 =
            $CanonicalEndpoints.endpoint_set_sha256
        expected_endpoint_hashes = $expectedEndpointHashes
        event = $event
        product_contract_pass = $eventFieldsMatch -and $resolvedMatch -and
            $materializedMatch -and $candidateSetMatch -and $privacyValid
        observability_contract_pass = $Snapshot.available -and
            $Snapshot.contract_valid -and $newEvents.Count -eq 1
    }
}

function Get-D01AdjudicationStatus {
    param(
        [Parameter(Mandatory = $true)][bool]$CaseArmed,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'BLOCKED')][string]$FixtureStatus,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'BLOCKED')][string]$ObservabilityStatus,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)][int]$ProductFailureCount
    )

    $productStatus = if (-not $CaseArmed) {
        'NOT_EVALUATED'
    } elseif ($ProductFailureCount -gt 0) {
        'FAIL'
    } elseif ($FixtureStatus -eq 'PASS' -and
        $ObservabilityStatus -eq 'PASS') {
        'PASS'
    } else {
        'NOT_EVALUATED'
    }
    $formalStatus = if ($productStatus -eq 'FAIL') {
        'FAIL'
    } elseif ($FixtureStatus -ne 'PASS' -or
        $ObservabilityStatus -ne 'PASS') {
        'BLOCKED'
    } elseif ($productStatus -eq 'PASS') {
        'PASS'
    } else {
        'FAIL'
    }
    return [pscustomobject][ordered]@{
        product_status = $productStatus
        formal_status = $formalStatus
    }
}

function Get-D01OptionalProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$DefaultValue = $null
    )

    if ($null -eq $InputObject) { return $DefaultValue }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $DefaultValue }
    return $property.Value
}

function Start-D01ControlledEd2kServer {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedClientAddress,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][ref]$PublishedOwner,
        [ValidateSet(
            '', 'owner-published', 'listener-published',
            'listener-started', 'powershell-published',
            'script-configured', 'async-published'
        )][string]$FaultInjectionPhase = ''
    )

    $state = New-Object `
        'Collections.Concurrent.ConcurrentDictionary[string,object]'
    $state['phase'] = 'owner-published'
    $state['stop_requested'] = $false
    $state['logged_in'] = $false
    $state['reply_sent'] = $false
    $state['error'] = ''
    $state['frames_received'] = 0
    $state['listen_port'] = 0
    $state['high_id'] = [uint32]0x01000001
    $state['listen_address'] = $ListenAddress
    $state['expected_client_address'] = $ExpectedClientAddress
    $owner = [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-controlled-server-owner/v1'
        owner_id = [Guid]::NewGuid().ToString('N')
        phase = 'owner-published'
        listener = $null
        port = 0
        state = $state
        powershell = $null
        async = $null
        evidence_path = $EvidencePath
        started_at_utc = $null
        start_error = $null
        start_rollback = $null
        stop_attempts = 0
        listener_stopped = $false
        client_closed = $false
        powershell_stop_requested = $false
        end_invoke_called = $false
        powershell_disposed = $false
        async_completed = $false
    }
    $PublishedOwner.Value = $owner

    try {
        if ($FaultInjectionPhase -eq 'owner-published') {
            throw 'Injected controlled-server failure after owner publication'
        }
        $listenIp = [Net.IPAddress]::Parse($ListenAddress)
        if ($listenIp.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
            [Net.IPAddress]::IsLoopback($listenIp)) {
            throw 'Controlled eD2K server requires assigned non-loopback IPv4'
        }
        $listener = New-Object Net.Sockets.TcpListener($listenIp, 0)
        $owner.listener = $listener
        $owner.phase = 'listener-published'
        $state['phase'] = 'listener-published'
        $listener.Server.ExclusiveAddressUse = $true
        if ($FaultInjectionPhase -eq 'listener-published') {
            throw 'Injected controlled-server failure after listener publication'
        }
        $listener.Start(1)
        $port = [int]([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $owner.port = $port
        $owner.phase = 'listener-started'
        $state['phase'] = 'listening'
        $state['listen_port'] = $port
        if ($FaultInjectionPhase -eq 'listener-started') {
            throw 'Injected controlled-server failure after listener start'
        }

    $serverBody = {
        param(
            $Listener, $State, $ResultPath, $RunNonceValue,
            $AllowedClientAddress
        )

        function Read-ExactD01 {
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
                    throw "Controlled server stream closed after $offset/$Count bytes"
                }
                $offset += $read
            }
            return $buffer
        }

        function Send-D01Frame {
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
        try {
            $State['phase'] = 'accepting'
            $client = $Listener.AcceptTcpClient()
            $State['client'] = $client
            $remote = [Net.IPEndPoint]$client.Client.RemoteEndPoint
            if ($remote.Address.ToString() -ne $AllowedClientAddress) {
                throw "Unexpected controlled-server client $remote"
            }
            $State['accepted_remote'] = $remote.ToString()
            $stream = $client.GetStream()
            $stream.ReadTimeout = 30000
            $header = Read-ExactD01 -Stream $stream -Count 6
            $packetLength = [BitConverter]::ToUInt32($header, 1)
            if ($header[0] -ne 0xE3 -or $header[5] -ne 0x01 -or
                $packetLength -lt 23 -or $packetLength -gt 1048576) {
                throw (
                    'Expected OP_EDONKEYPROT:OP_LOGINREQUEST; ' +
                    "protocol=0x$('{0:X2}' -f $header[0]) " +
                    "opcode=0x$('{0:X2}' -f $header[5]) length=$packetLength"
                )
            }
            $payload = Read-ExactD01 -Stream $stream `
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
            Send-D01Frame -Stream $stream -Opcode 0x40 `
                -Payload ([BitConverter]::GetBytes([uint32]0x01000001))
            $State['reply_sent'] = $true
            $State['logged_in'] = $true
            $State['phase'] = 'connected'
            $State['login_at_utc'] = $loginAt
            $stream.ReadTimeout = 2000
            $nextStatus = [DateTime]::UtcNow.AddSeconds(10)
            while (-not [bool]$State['stop_requested']) {
                if ($stream.DataAvailable) {
                    $nextHeader = Read-ExactD01 -Stream $stream -Count 6
                    $nextLength = [BitConverter]::ToUInt32($nextHeader, 1)
                    if ($nextLength -lt 1 -or $nextLength -gt 16777216) {
                        throw "Invalid client frame length $nextLength"
                    }
                    if ($nextLength -gt 1) {
                        $null = Read-ExactD01 -Stream $stream `
                            -Count ([int]$nextLength - 1)
                    }
                    $State['frames_received'] =
                        [int]$State['frames_received'] + 1
                    $State['last_client_opcode'] = [int]$nextHeader[5]
                } elseif ([DateTime]::UtcNow -ge $nextStatus) {
                    Send-D01Frame -Stream $stream -Opcode 0x34 `
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
            if ($null -ne $stream) { try { $stream.Dispose() } catch {} }
            if ($null -ne $client) { try { $client.Dispose() } catch {} }
            try { $Listener.Stop() } catch {}
            if ([string]$State['phase'] -ne 'error') {
                $State['phase'] = 'stopped'
            }
            $result = [ordered]@{
                schema = 'ese.v91.d01-controlled-ed2k-server/v2'
                run_nonce = $RunNonceValue
                listen_address = [string]$State['listen_address']
                listen_port = [int]$State['listen_port']
                high_id = [uint32]$State['high_id']
                login_at_utc = $loginAt
                stopped_at_utc = [DateTime]::UtcNow.ToString('o')
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
                accepted_remote = if (
                    $State.ContainsKey('accepted_remote')
                ) {
                    [string]$State['accepted_remote']
                } else { '' }
                frames_received = [int]$State['frames_received']
                error = [string]$State['error']
            }
            [IO.File]::WriteAllText(
                $ResultPath, ($result | ConvertTo-Json -Depth 16),
                (New-Object Text.UTF8Encoding($false))
            )
        }
    }

        $powershell = [PowerShell]::Create()
        $owner.powershell = $powershell
        $owner.phase = 'powershell-published'
        $state['phase'] = 'powershell-published'
        if ($FaultInjectionPhase -eq 'powershell-published') {
            throw 'Injected controlled-server failure after PowerShell publication'
        }
        $null = $powershell.AddScript($serverBody.ToString())
        $null = $powershell.AddArgument($listener)
        $null = $powershell.AddArgument($state)
        $null = $powershell.AddArgument($EvidencePath)
        $null = $powershell.AddArgument($Nonce)
        $null = $powershell.AddArgument($ExpectedClientAddress)
        $owner.phase = 'script-configured'
        $state['phase'] = 'script-configured'
        if ($FaultInjectionPhase -eq 'script-configured') {
            throw 'Injected controlled-server failure after script configuration'
        }
        $async = $powershell.BeginInvoke()
        $owner.async = $async
        $owner.phase = 'async-published'
        $state['phase'] = 'accepting'
        if ($FaultInjectionPhase -eq 'async-published') {
            throw 'Injected controlled-server failure after async publication'
        }
        $owner.started_at_utc = Get-LabUtcTimestamp
        $owner.phase = 'running'
        return $owner
    } catch {
        $owner.start_error = $_.Exception.Message
        $owner.phase = 'start-failed'
        $state['phase'] = 'start-failed'
        $rollback = Stop-D01ControlledEd2kServer -Server $owner
        $owner.start_rollback = $rollback
        throw (
            "Controlled eD2K server construction failed: " +
            "$($owner.start_error); rollback_stopped=$($rollback.stopped)"
        )
    }
}

function Wait-D01ControlledEd2kLogin {
    param(
        [Parameter(Mandatory = $true)][object]$Server,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$ExpectedTcpPort
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
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
                    client_local_address = Get-D01NormalizedIp `
                        -Address ([string]$connections[0].LocalAddress)
                    client_local_port = [int]$connections[0].LocalPort
                    login_payload_sha256 =
                        [string]$Server.state['login_payload_sha256']
                    advertised_tcp_port =
                        [int]$Server.state['login_advertised_tcp_port']
                    assigned_high_id = [uint32]$Server.state['high_id']
                    same_host_physical_server = $true
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Timed out proving the controlled same-host eD2K login'
}

function Stop-D01ControlledEd2kServer {
    param([AllowNull()][object]$Server)

    if ($null -eq $Server) {
        return [pscustomobject][ordered]@{
            stopped = $true
            error = $null
            evidence = $null
            ownership = [ordered]@{
                owner_published = $false
                all_owned_resources_released = $true
            }
        }
    }
    $errors = New-Object 'Collections.Generic.List[string]'
    $state = if ($null -ne $Server.PSObject.Properties['state']) {
        $Server.state
    } else { $null }
    $listener = if (
        $null -ne $Server.PSObject.Properties['listener']
    ) { $Server.listener } else { $null }
    $powershell = if (
        $null -ne $Server.PSObject.Properties['powershell']
    ) { $Server.powershell } else { $null }
    $async = if ($null -ne $Server.PSObject.Properties['async']) {
        $Server.async
    } else { $null }
    if ($null -ne $Server.PSObject.Properties['stop_attempts']) {
        $Server.stop_attempts = [int]$Server.stop_attempts + 1
    }

    if ($null -ne $state) {
        try { $state['stop_requested'] = $true } catch {
            $errors.Add("stop flag: $($_.Exception.Message)")
        }
        if ($state.ContainsKey('client')) {
            try {
                $state['client'].Close()
                if ($null -ne
                    $Server.PSObject.Properties['client_closed']) {
                    $Server.client_closed = $true
                }
            } catch {
                $errors.Add("client close: $($_.Exception.Message)")
            }
        }
    }
    if ($null -ne $listener) {
        try {
            $listener.Stop()
            if ($null -ne
                $Server.PSObject.Properties['listener_stopped']) {
                $Server.listener_stopped = $true
            }
        } catch {
            $errors.Add("listener stop: $($_.Exception.Message)")
        }
    } elseif ($null -ne
        $Server.PSObject.Properties['listener_stopped']) {
        $Server.listener_stopped = $true
    }

    $asyncCompleted = $null -eq $async
    if ($null -ne $async) {
        try {
            $asyncCompleted = [bool]$async.IsCompleted
            if (-not $asyncCompleted) {
                $asyncCompleted = $async.AsyncWaitHandle.WaitOne(
                    [TimeSpan]::FromSeconds(10)
                )
            }
        } catch {
            if ($null -ne
                $Server.PSObject.Properties['async_completed']) {
                $asyncCompleted = [bool]$Server.async_completed
            }
            if (-not $asyncCompleted) {
                $errors.Add("async wait: $($_.Exception.Message)")
            }
        }
        if (-not $asyncCompleted -and $null -ne $powershell) {
            try {
                $powershell.Stop()
                if ($null -ne $Server.PSObject.Properties[
                    'powershell_stop_requested'
                ]) {
                    $Server.powershell_stop_requested = $true
                }
                $asyncCompleted = $async.AsyncWaitHandle.WaitOne(
                    [TimeSpan]::FromSeconds(5)
                )
            } catch {
                $errors.Add("PowerShell stop: $($_.Exception.Message)")
            }
        }
    }
    if ($null -ne $powershell -and $null -ne $async -and
        $asyncCompleted -and
        (
            $null -eq $Server.PSObject.Properties['end_invoke_called'] -or
            -not [bool]$Server.end_invoke_called
        )) {
        try {
            $null = $powershell.EndInvoke($async)
        } catch {
            $stopRequested = $null -ne $state -and
                $state.ContainsKey('stop_requested') -and
                [bool]$state['stop_requested']
            if (-not $stopRequested) {
                $errors.Add("EndInvoke: $($_.Exception.Message)")
            }
        } finally {
            if ($null -ne
                $Server.PSObject.Properties['end_invoke_called']) {
                $Server.end_invoke_called = $true
            }
        }
    }
    if ($null -ne $powershell -and
        (
            $null -eq $Server.PSObject.Properties['powershell_disposed'] -or
            -not [bool]$Server.powershell_disposed
        )) {
        try {
            $powershell.Dispose()
            if ($null -ne
                $Server.PSObject.Properties['powershell_disposed']) {
                $Server.powershell_disposed = $true
            }
        } catch {
            $errors.Add("PowerShell dispose: $($_.Exception.Message)")
        }
    } elseif ($null -eq $powershell -and $null -ne
        $Server.PSObject.Properties['powershell_disposed']) {
        $Server.powershell_disposed = $true
    }
    if ($null -ne $Server.PSObject.Properties['async_completed']) {
        $Server.async_completed = $asyncCompleted
    }
    if ($null -ne $state -and $errors.Count -eq 0) {
        try { $state['phase'] = 'stopped' } catch {}
    }

    $evidence = $null
    $evidencePath = if (
        $null -ne $Server.PSObject.Properties['evidence_path']
    ) { [string]$Server.evidence_path } else { '' }
    if ($evidencePath -and
        (Test-Path -LiteralPath $evidencePath -PathType Leaf)) {
        try {
            $evidence = Get-Content -LiteralPath $evidencePath -Raw |
                ConvertFrom-Json -ErrorAction Stop
        } catch {
            $errors.Add("evidence read: $($_.Exception.Message)")
        }
    }
    $listenerReleased = $null -eq $listener -or
        (
            $null -ne $Server.PSObject.Properties['listener_stopped'] -and
            [bool]$Server.listener_stopped
        )
    $powershellReleased = $null -eq $powershell -or
        (
            $null -ne $Server.PSObject.Properties['powershell_disposed'] -and
            [bool]$Server.powershell_disposed
        )
    $allReleased = $listenerReleased -and $powershellReleased -and
        $asyncCompleted
    return [pscustomobject][ordered]@{
        stopped = $allReleased
        error = if ($errors.Count -eq 0) {
            $null
        } else { $errors -join '; ' }
        evidence = $evidence
        ownership = [ordered]@{
            owner_published = $true
            owner_id = if (
                $null -ne $Server.PSObject.Properties['owner_id']
            ) { [string]$Server.owner_id } else { '' }
            phase = if ($null -ne
                $Server.PSObject.Properties['phase']) {
                [string]$Server.phase
            } else { '' }
            stop_attempts = if ($null -ne
                $Server.PSObject.Properties['stop_attempts']) {
                [int]$Server.stop_attempts
            } else { 1 }
            listener_published = $null -ne $listener
            listener_released = $listenerReleased
            client_released = $null -eq $state -or
                -not $state.ContainsKey('client') -or
                (
                    $null -ne
                        $Server.PSObject.Properties['client_closed'] -and
                    [bool]$Server.client_closed
                ) -or $asyncCompleted
            powershell_published = $null -ne $powershell
            powershell_released = $powershellReleased
            async_published = $null -ne $async
            async_completed = $asyncCompleted
            all_owned_resources_released = $allReleased
        }
    }
}

function Invoke-D01Pktmon {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
    )

    $process = $null
    $timedOut = $false
    $stdout = ''
    $stderr = ''
    $exitCode = 9009
    try {
        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName =
            (Get-Command pktmon.exe -ErrorAction Stop).Source
        $quoted = foreach ($argumentValue in $Arguments) {
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
        $startInfo.Arguments = $quoted -join ' '
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'pktmon process did not start' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { $process.Kill() } catch {}
            $null = $process.WaitForExit(10000)
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($timedOut) {
            $exitCode = 1460
        } else {
            $exitCode = $process.ExitCode
        }
    } catch {
        $stderr += "`n" + $_.Exception.Message
        $exitCode = 9009
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
    Add-Content -LiteralPath $LogPath -Encoding utf8 -Value @(
        ('[{0}] pktmon {1}' -f (Get-LabUtcTimestamp),
            ($Arguments -join ' ')),
        $stdout, $stderr, "timed_out=$timedOut", "exit_code=$exitCode"
    )
    return [pscustomobject][ordered]@{
        exit_code = $exitCode
        timed_out = $timedOut
        stdout = $stdout
        stderr = $stderr
    }
}

function Get-D01EtwLossEvidence {
    if (-not ('V91D01EtwTraceQueryV2' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class V91D01EtwTraceQueryV2 {
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
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    private static extern UInt32 ControlTrace(
        UInt64 sessionHandle, string sessionName, IntPtr properties,
        UInt32 controlCode);
    public static Result Query(string sessionName) {
        int size = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
        byte[] name = Encoding.Unicode.GetBytes(sessionName + "\0");
        int total = size + name.Length + 2;
        IntPtr buffer = Marshal.AllocHGlobal(total);
        try {
            Marshal.Copy(new byte[total], 0, buffer, total);
            EVENT_TRACE_PROPERTIES p = new EVENT_TRACE_PROPERTIES();
            p.Wnode.BufferSize = (UInt32)total;
            p.Wnode.Flags = 0x00020000;
            p.LoggerNameOffset = (UInt32)size;
            Marshal.StructureToPtr(p, buffer, false);
            Marshal.Copy(name, 0, IntPtr.Add(buffer, size), name.Length);
            UInt32 error = ControlTrace(0, sessionName, buffer, 0);
            Result r = new Result();
            r.ErrorCode = error;
            if (error == 0) {
                p = (EVENT_TRACE_PROPERTIES)Marshal.PtrToStructure(
                    buffer, typeof(EVENT_TRACE_PROPERTIES));
                r.EventsLost = p.EventsLost;
                r.LogBuffersLost = p.LogBuffersLost;
                r.RealTimeBuffersLost = p.RealTimeBuffersLost;
                r.BuffersWritten = p.BuffersWritten;
            }
            return r;
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
'@
    }
    try {
        $query = [V91D01EtwTraceQueryV2]::Query('PktMon')
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
            error = $null
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

function Start-D01PacketCapture {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $prefix = 'ese-d01-' + $Nonce.Substring(0, 8)
    $state = [pscustomobject][ordered]@{
        available = $false
        start_attempted = $false
        started = $false
        capture_started_verified = $false
        session_owned = $false
        filters = @("$prefix-v4", "$prefix-v6")
        filter_scope = 'target-address-all-tcp-ports'
        expected_destination_port = $Port
        filters_applied_verified = $false
        filters_absent_verified = $false
        filter_inventory_restored_verified = $false
        etw_session_stopped_verified = $false
        etw_loss = $null
        etl_path = Join-Path $EvidencePath 'd01-packets.etl'
        pcapng_path = Join-Path $EvidencePath 'd01-packets.pcapng'
        text_path = Join-Path $EvidencePath 'd01-packets.txt'
        command_log = Join-Path $EvidencePath 'pktmon.log'
        filters_before_path =
            Join-Path $EvidencePath 'pktmon-filters-before.txt'
        filters_armed_path =
            Join-Path $EvidencePath 'pktmon-filters-armed.txt'
        filters_after_path =
            Join-Path $EvidencePath 'pktmon-filters-after.txt'
        counters_path = Join-Path $EvidencePath 'pktmon-counters.txt'
        error = $null
    }
    Write-D01JsonAtomic -Value ([ordered]@{
        schema = 'ese.v91.d01-pktmon-intent/v2'
        captured_at_utc = Get-LabUtcTimestamp
        run_nonce = $Nonce
        filters = $state.filters
        ipv4 = $IPv4
        ipv6 = $IPv6
        expected_destination_port = $Port
        capture_scope = 'both target addresses, TCP, all ports'
    }) -Path (Join-Path $EvidencePath 'pktmon-intent.json')
    if ($null -eq (Get-Command pktmon.exe -ErrorAction SilentlyContinue) -or
        $null -eq (Get-Command logman.exe -ErrorAction SilentlyContinue)) {
        $state.error = 'pktmon.exe or logman.exe is unavailable'
        return $state
    }
    @(& pktmon.exe filter list 2>&1) |
        Set-Content -LiteralPath $state.filters_before_path -Encoding utf8
    $beforeText = Get-Content -LiteralPath $state.filters_before_path -Raw
    if (@($state.filters | Where-Object {
        $beforeText.IndexOf(
            [string]$_, [StringComparison]::OrdinalIgnoreCase
        ) -ge 0
    }).Count -ne 0) {
        $state.error = 'A nonce-owned PktMon filter already exists'
        return $state
    }
    $sessionBefore = @(& logman.exe query -ets PktMon 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $state.error = 'An existing PktMon ETW session is active'
        return $state
    }
    try {
        $v4Result = Invoke-D01Pktmon -LogPath $state.command_log `
            -Arguments @(
                'filter', 'add', $state.filters[0], '-i', $IPv4,
                '-t', 'TCP'
            )
        if ($v4Result.exit_code -ne 0) {
            throw 'PktMon rejected the all-port IPv4/TCP filter'
        }
        $v6Result = Invoke-D01Pktmon -LogPath $state.command_log `
            -Arguments @(
                'filter', 'add', $state.filters[1], '-i', $IPv6,
                '-t', 'TCP'
            )
        if ($v6Result.exit_code -ne 0) {
            throw 'PktMon rejected the all-port IPv6/TCP filter'
        }
        @(& pktmon.exe filter list 2>&1) |
            Set-Content -LiteralPath $state.filters_armed_path -Encoding utf8
        $armed = Get-Content -LiteralPath $state.filters_armed_path -Raw
        $state.filters_applied_verified = @($state.filters | Where-Object {
            $armed.IndexOf(
                [string]$_, [StringComparison]::OrdinalIgnoreCase
            ) -lt 0
        }).Count -eq 0
        if (-not $state.filters_applied_verified) {
            throw 'PktMon did not list both exact run-owned filters'
        }
        $state.start_attempted = $true
        $startResult = Invoke-D01Pktmon -LogPath $state.command_log `
            -Arguments @(
                'start', '--capture', '--comp', 'nics', '--pkt-size', '0',
                '--file-name', $state.etl_path, '--file-size', '256'
            )
        $sessionAfterStart = @(& logman.exe query -ets PktMon 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $state.session_owned = $true
            $state.started = $true
            $state.capture_started_verified = $true
        }
        if ($startResult.exit_code -ne 0 -or -not $state.started) {
            throw 'PktMon capture could not be started and owned'
        }
        $state.available = $true
    } catch {
        $state.error = $_.Exception.Message
    }
    return $state
}

function Stop-D01PacketCapture {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)]
        [Collections.Generic.List[string]]$CleanupFailures
    )

    if ($null -eq (Get-Command pktmon.exe -ErrorAction SilentlyContinue) -or
        $null -eq (Get-Command logman.exe -ErrorAction SilentlyContinue)) {
        $CleanupFailures.Add(
            'pktmon/logman unavailable during capture cleanup'
        )
        return
    }
    try {
        @(& pktmon.exe counters 2>&1) |
            Set-Content -LiteralPath $State.counters_path -Encoding utf8
    } catch {
        $CleanupFailures.Add(
            "PktMon counters could not be retained: $($_.Exception.Message)"
        )
    }
    $sessionProbe = @(& logman.exe query -ets PktMon 2>&1)
    $sessionPresent = $LASTEXITCODE -eq 0
    if ($State.start_attempted -and $sessionPresent) {
        $State.session_owned = $true
        $State.started = $true
        $State.capture_started_verified = $true
    }
    if ($State.started) {
        $State.etw_loss = Get-D01EtwLossEvidence
        $stopResult = Invoke-D01Pktmon -LogPath $State.command_log `
            -Arguments @('stop')
        if ($stopResult.exit_code -ne 0) {
            $CleanupFailures.Add('PktMon stop returned failure')
        } else {
            $State.started = $false
        }
    }
    if (Test-Path -LiteralPath $State.etl_path -PathType Leaf) {
        $pcapResult = Invoke-D01Pktmon -LogPath $State.command_log `
            -Arguments @(
                'etl2pcap', $State.etl_path, '--out', $State.pcapng_path
            )
        if ($pcapResult.exit_code -ne 0) {
            $CleanupFailures.Add('PktMon ETL to PCAPNG conversion failed')
        }
        $textResult = Invoke-D01Pktmon -LogPath $State.command_log `
            -Arguments @(
                'etl2txt', $State.etl_path, '--out', $State.text_path,
                '--brief'
            )
        if ($textResult.exit_code -ne 0) {
            $CleanupFailures.Add('PktMon ETL to text conversion failed')
        }
    } else {
        $CleanupFailures.Add('PktMon ETL evidence is missing')
    }

    $inventory = @(& pktmon.exe filter list 2>&1)
    $inventoryText = $inventory -join "`n"
    foreach ($filter in @($State.filters)) {
        if ($inventoryText.IndexOf(
            [string]$filter, [StringComparison]::OrdinalIgnoreCase
        ) -ge 0) {
            $remove = Invoke-D01Pktmon -LogPath $State.command_log `
                -Arguments @('filter', 'remove', [string]$filter)
            if ($remove.exit_code -ne 0) {
                $CleanupFailures.Add(
                    "PktMon filter '$filter' could not be removed"
                )
            }
        }
    }
    @(& pktmon.exe filter list 2>&1) |
        Set-Content -LiteralPath $State.filters_after_path -Encoding utf8
    $afterText = Get-Content -LiteralPath $State.filters_after_path -Raw
    $State.filters_absent_verified = @($State.filters | Where-Object {
        $afterText.IndexOf(
            [string]$_, [StringComparison]::OrdinalIgnoreCase
        ) -ge 0
    }).Count -eq 0
    $beforeNormalized = (
        Get-Content -LiteralPath $State.filters_before_path -Raw
    ).Trim() -replace "`r`n", "`n"
    $afterNormalized = $afterText.Trim() -replace "`r`n", "`n"
    $State.filter_inventory_restored_verified =
        $beforeNormalized -ceq $afterNormalized
    if (-not $State.filters_absent_verified) {
        $CleanupFailures.Add('A run-owned PktMon filter remains')
    }
    if (-not $State.filter_inventory_restored_verified) {
        $CleanupFailures.Add(
            'PktMon filter inventory differs from its pre-run snapshot'
        )
    }
    $sessionAfter = @(& logman.exe query -ets PktMon 2>&1)
    $State.etw_session_stopped_verified = $LASTEXITCODE -ne 0
    if (-not $State.etw_session_stopped_verified) {
        $CleanupFailures.Add('PktMon ETW session remains active')
    }
}

function Get-D01ExpandedIPv6 {
    param([Parameter(Mandatory = $true)][Net.IPAddress]$Address)

    $bytes = $Address.GetAddressBytes()
    $groups = for ($index = 0; $index -lt 16; $index += 2) {
        '{0:x4}' -f (($bytes[$index] -shl 8) -bor $bytes[$index + 1])
    }
    return $groups -join ':'
}

function Read-D01PcapUInt16 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][bool]$LittleEndian
    )

    if ($Offset -lt 0 -or $Offset + 2 -gt $Bytes.Length) {
        throw 'PCAP read exceeded the available UInt16 bytes'
    }
    if ($LittleEndian) {
        return [uint16]([uint32]$Bytes[$Offset] +
            ([uint32]$Bytes[$Offset + 1] * 256))
    }
    return [uint16](([uint32]$Bytes[$Offset] * 256) +
        [uint32]$Bytes[$Offset + 1])
}

function Read-D01PcapUInt32 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][bool]$LittleEndian
    )

    if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) {
        throw 'PCAP read exceeded the available UInt32 bytes'
    }
    [uint64]$value = 0
    if ($LittleEndian) {
        for ($index = 3; $index -ge 0; $index--) {
            $value = ($value * 256) + [uint64]$Bytes[$Offset + $index]
        }
    } else {
        for ($index = 0; $index -lt 4; $index++) {
            $value = ($value * 256) + [uint64]$Bytes[$Offset + $index]
        }
    }
    return [uint32]$value
}

function Read-D01PcapUInt64 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][bool]$LittleEndian
    )

    if ($Offset -lt 0 -or $Offset + 8 -gt $Bytes.Length) {
        throw 'PCAP read exceeded the available UInt64 bytes'
    }
    [decimal]$value = 0
    if ($LittleEndian) {
        for ($index = 7; $index -ge 0; $index--) {
            $value = ($value * 256) + [decimal]$Bytes[$Offset + $index]
        }
    } else {
        for ($index = 0; $index -lt 8; $index++) {
            $value = ($value * 256) + [decimal]$Bytes[$Offset + $index]
        }
    }
    return [uint64]$value
}

function Convert-D01PcapTimestampToUnixNs {
    param(
        [Parameter(Mandatory = $true)][uint64]$RawTimestamp,
        [Parameter(Mandatory = $true)][byte]$Resolution,
        [Parameter(Mandatory = $true)][Int64]$OffsetSeconds
    )

    $binary = ($Resolution -band 0x80) -ne 0
    $exponent = [int]($Resolution -band 0x7f)
    [decimal]$denominator = 1
    for ($index = 0; $index -lt $exponent; $index++) {
        $denominator *= if ($binary) { 2 } else { 10 }
    }
    if ($denominator -le 0) {
        throw 'Invalid PCAP timestamp resolution'
    }
    $nanoseconds = (
        ([decimal]$RawTimestamp * [decimal]1000000000) / $denominator
    ) + ([decimal]$OffsetSeconds * [decimal]1000000000)
    if ($nanoseconds -lt [decimal][Int64]::MinValue -or
        $nanoseconds -gt [decimal][Int64]::MaxValue) {
        throw 'PCAP timestamp is outside Int64 Unix-nanosecond range'
    }
    return [Int64][Math]::Round(
        $nanoseconds, [MidpointRounding]::AwayFromZero
    )
}

function Convert-D01CapturedPacket {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Packet,
        [Parameter(Mandatory = $true)][uint16]$LinkType
    )

    $cursor = 0
    if ($LinkType -eq 1) {
        if ($Packet.Length -lt 14) {
            throw 'Truncated Ethernet packet in PCAP'
        }
        $etherType = ([uint16]$Packet[12] * 256) + $Packet[13]
        $cursor = 14
        while ($etherType -in @(0x8100, 0x88a8)) {
            if ($cursor + 4 -gt $Packet.Length) {
                throw 'Truncated VLAN header in PCAP'
            }
            $etherType = ([uint16]$Packet[$cursor + 2] * 256) +
                $Packet[$cursor + 3]
            $cursor += 4
        }
        if ($etherType -eq 0x0800) {
            $family = 'ipv4'
        } elseif ($etherType -eq 0x86dd) {
            $family = 'ipv6'
        } else {
            return $null
        }
    } elseif ($LinkType -eq 101) {
        if ($Packet.Length -lt 1) {
            throw 'Truncated raw-IP packet in PCAP'
        }
        $version = $Packet[0] -shr 4
        if ($version -eq 4) {
            $family = 'ipv4'
        } elseif ($version -eq 6) {
            $family = 'ipv6'
        } else {
            return $null
        }
    } else {
        throw "Unsupported PCAP link type $LinkType"
    }

    if ($family -eq 'ipv4') {
        if ($cursor + 20 -gt $Packet.Length -or
            ($Packet[$cursor] -shr 4) -ne 4) {
            throw 'Truncated or invalid IPv4 packet in PCAP'
        }
        $headerBytes = [int]($Packet[$cursor] -band 0x0f) * 4
        if ($headerBytes -lt 20 -or
            $cursor + $headerBytes + 20 -gt $Packet.Length) {
            throw 'Invalid IPv4 header length in PCAP'
        }
        $fragment = ([uint16]$Packet[$cursor + 6] * 256) +
            $Packet[$cursor + 7]
        if (($fragment -band 0x1fff) -ne 0) {
            return $null
        }
        if ($Packet[$cursor + 9] -ne 6) {
            return $null
        }
        $sourceAddress = '{0}.{1}.{2}.{3}' -f
            $Packet[$cursor + 12], $Packet[$cursor + 13],
            $Packet[$cursor + 14], $Packet[$cursor + 15]
        $destinationAddress = '{0}.{1}.{2}.{3}' -f
            $Packet[$cursor + 16], $Packet[$cursor + 17],
            $Packet[$cursor + 18], $Packet[$cursor + 19]
        $tcpOffset = $cursor + $headerBytes
    } else {
        if ($cursor + 40 -gt $Packet.Length -or
            ($Packet[$cursor] -shr 4) -ne 6) {
            throw 'Truncated or invalid IPv6 packet in PCAP'
        }
        $sourceBytes = New-Object byte[] 16
        $destinationBytes = New-Object byte[] 16
        [Array]::Copy($Packet, $cursor + 8, $sourceBytes, 0, 16)
        [Array]::Copy($Packet, $cursor + 24, $destinationBytes, 0, 16)
        $sourceAddress =
            (New-Object Net.IPAddress -ArgumentList (,$sourceBytes)).ToString()
        $destinationAddress =
            (New-Object Net.IPAddress -ArgumentList (,$destinationBytes)).
                ToString()
        $nextHeader = [int]$Packet[$cursor + 6]
        $tcpOffset = $cursor + 40
        for ($extensionCount = 0;
            $nextHeader -ne 6 -and $extensionCount -lt 8;
            $extensionCount++) {
            if ($nextHeader -in @(0, 43, 60)) {
                if ($tcpOffset + 2 -gt $Packet.Length) {
                    throw 'Truncated IPv6 extension header in PCAP'
                }
                $newNextHeader = [int]$Packet[$tcpOffset]
                $extensionBytes =
                    ([int]$Packet[$tcpOffset + 1] + 1) * 8
            } elseif ($nextHeader -eq 44) {
                if ($tcpOffset + 8 -gt $Packet.Length) {
                    throw 'Truncated IPv6 fragment header in PCAP'
                }
                $fragmentOffset =
                    (([int]$Packet[$tcpOffset + 2] * 256) +
                        $Packet[$tcpOffset + 3]) -band 0xfff8
                if ($fragmentOffset -ne 0) { return $null }
                $newNextHeader = [int]$Packet[$tcpOffset]
                $extensionBytes = 8
            } elseif ($nextHeader -eq 51) {
                if ($tcpOffset + 2 -gt $Packet.Length) {
                    throw 'Truncated IPv6 AH header in PCAP'
                }
                $newNextHeader = [int]$Packet[$tcpOffset]
                $extensionBytes =
                    ([int]$Packet[$tcpOffset + 1] + 2) * 4
            } else {
                return $null
            }
            if ($extensionBytes -le 0 -or
                $tcpOffset + $extensionBytes -gt $Packet.Length) {
                throw 'Invalid IPv6 extension length in PCAP'
            }
            $tcpOffset += $extensionBytes
            $nextHeader = $newNextHeader
        }
        if ($nextHeader -ne 6) { return $null }
    }

    if ($tcpOffset + 20 -gt $Packet.Length) {
        throw 'Truncated TCP header in PCAP'
    }
    $sourcePort = ([int]$Packet[$tcpOffset] * 256) +
        $Packet[$tcpOffset + 1]
    $destinationPort = ([int]$Packet[$tcpOffset + 2] * 256) +
        $Packet[$tcpOffset + 3]
    $sequenceNumber = [uint32](
        ([uint64]$Packet[$tcpOffset + 4] * 16777216) +
        ([uint64]$Packet[$tcpOffset + 5] * 65536) +
        ([uint64]$Packet[$tcpOffset + 6] * 256) +
        [uint64]$Packet[$tcpOffset + 7]
    )
    $flags = [int]$Packet[$tcpOffset + 13]
    return [pscustomobject][ordered]@{
        family = $family
        protocol = 'tcp'
        source_address = Get-D01NormalizedIp -Address $sourceAddress
        source_port = $sourcePort
        destination_address =
            Get-D01NormalizedIp -Address $destinationAddress
        destination_port = $destinationPort
        tcp_sequence_number = $sequenceNumber
        tcp_flags = $flags
        syn = ($flags -band 0x02) -ne 0
        ack = ($flags -band 0x10) -ne 0
        initial_syn = ($flags -band 0x02) -ne 0 -and
            ($flags -band 0x10) -eq 0
        five_tuple = 'tcp|{0}|{1}|{2}|{3}' -f
            (Get-D01NormalizedIp -Address $sourceAddress), $sourcePort,
            (Get-D01NormalizedIp -Address $destinationAddress),
            $destinationPort
    }
}

function Get-D01PcapNgTcpRecords {
    param([Parameter(Mandatory = $true)][string]$Path)

    $errors = New-Object 'Collections.Generic.List[string]'
    $records = New-Object 'Collections.Generic.List[object]'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            valid = $false
            errors = @('PCAPNG artifact is missing')
            records = @()
            section_count = 0
            interface_count = 0
        }
    }
    $bytes = [IO.File]::ReadAllBytes($Path)
    $offset = 0
    $sectionCount = 0
    $interfaces = @{}
    $interfaceCount = 0
    $littleEndian = $true
    while ($offset + 12 -le $bytes.Length) {
        try {
            $isSection = $bytes[$offset] -eq 0x0a -and
                $bytes[$offset + 1] -eq 0x0d -and
                $bytes[$offset + 2] -eq 0x0d -and
                $bytes[$offset + 3] -eq 0x0a
            if ($isSection) {
                if ($offset + 12 -gt $bytes.Length) {
                    throw 'Truncated PCAPNG section header'
                }
                $magic = @(
                    $bytes[$offset + 8], $bytes[$offset + 9],
                    $bytes[$offset + 10], $bytes[$offset + 11]
                ) -join '-'
                if ($magic -eq '77-60-43-26') {
                    $littleEndian = $true
                } elseif ($magic -eq '26-43-60-77') {
                    $littleEndian = $false
                } else {
                    throw 'Invalid PCAPNG byte-order magic'
                }
                $blockLength = [int](Read-D01PcapUInt32 -Bytes $bytes `
                    -Offset ($offset + 4) -LittleEndian $littleEndian)
                $interfaces = @{}
                $sectionCount++
                $blockType = [uint32]0x0a0d0d0a
            } else {
                if ($sectionCount -eq 0) {
                    throw 'PCAPNG data precedes its section header'
                }
                $blockType = Read-D01PcapUInt32 -Bytes $bytes `
                    -Offset $offset -LittleEndian $littleEndian
                $blockLength = [int](Read-D01PcapUInt32 -Bytes $bytes `
                    -Offset ($offset + 4) -LittleEndian $littleEndian)
            }
            if ($blockLength -lt 12 -or $blockLength % 4 -ne 0 -or
                $offset + $blockLength -gt $bytes.Length) {
                throw "Invalid PCAPNG block length $blockLength"
            }
            $trailingLength = Read-D01PcapUInt32 -Bytes $bytes `
                -Offset ($offset + $blockLength - 4) `
                -LittleEndian $littleEndian
            if ([uint32]$trailingLength -ne [uint32]$blockLength) {
                throw 'PCAPNG leading/trailing block lengths differ'
            }
            if ($blockType -eq 1) {
                if ($blockLength -lt 20) {
                    throw 'Truncated PCAPNG interface description'
                }
                $linkType = Read-D01PcapUInt16 -Bytes $bytes `
                    -Offset ($offset + 8) -LittleEndian $littleEndian
                [byte]$timestampResolution = 6
                [Int64]$timestampOffsetSeconds = 0
                $optionOffset = $offset + 16
                $optionEnd = $offset + $blockLength - 4
                while ($optionOffset + 4 -le $optionEnd) {
                    $optionCode = Read-D01PcapUInt16 -Bytes $bytes `
                        -Offset $optionOffset -LittleEndian $littleEndian
                    $optionLength = Read-D01PcapUInt16 -Bytes $bytes `
                        -Offset ($optionOffset + 2) `
                        -LittleEndian $littleEndian
                    $optionOffset += 4
                    if ($optionCode -eq 0) { break }
                    if ($optionOffset + $optionLength -gt $optionEnd) {
                        throw 'PCAPNG interface option exceeds its block'
                    }
                    if ($optionCode -eq 9 -and $optionLength -eq 1) {
                        $timestampResolution = $bytes[$optionOffset]
                    } elseif ($optionCode -eq 14 -and $optionLength -eq 8) {
                        $unsignedOffset = Read-D01PcapUInt64 -Bytes $bytes `
                            -Offset $optionOffset `
                            -LittleEndian $littleEndian
                        if ($unsignedOffset -le
                            [uint64][Int64]::MaxValue) {
                            $timestampOffsetSeconds =
                                [Int64]$unsignedOffset
                        } else {
                            $timestampOffsetSeconds = [Int64](
                                [decimal]$unsignedOffset -
                                [decimal]18446744073709551616
                            )
                        }
                    }
                    $optionOffset += [int](
                        [Math]::Ceiling($optionLength / 4.0) * 4
                    )
                }
                $interfaceId = $interfaces.Count
                $interfaces[$interfaceId] = [pscustomobject]@{
                    link_type = [uint16]$linkType
                    timestamp_resolution = $timestampResolution
                    timestamp_offset_seconds = $timestampOffsetSeconds
                }
                $interfaceCount++
            } elseif ($blockType -eq 6) {
                if ($blockLength -lt 32) {
                    throw 'Truncated PCAPNG enhanced packet block'
                }
                $interfaceId = [int](Read-D01PcapUInt32 -Bytes $bytes `
                    -Offset ($offset + 8) -LittleEndian $littleEndian)
                if (-not $interfaces.ContainsKey($interfaceId)) {
                    throw "PCAPNG packet references unknown interface $interfaceId"
                }
                $timestampHigh = Read-D01PcapUInt32 -Bytes $bytes `
                    -Offset ($offset + 12) -LittleEndian $littleEndian
                $timestampLow = Read-D01PcapUInt32 -Bytes $bytes `
                    -Offset ($offset + 16) -LittleEndian $littleEndian
                $capturedLength = [int](Read-D01PcapUInt32 -Bytes $bytes `
                    -Offset ($offset + 20) -LittleEndian $littleEndian)
                if ($capturedLength -lt 0 -or
                    $offset + 28 + $capturedLength -gt
                        $offset + $blockLength - 4) {
                    throw 'PCAPNG packet payload exceeds its block'
                }
                $packet = New-Object byte[] $capturedLength
                [Array]::Copy(
                    $bytes, $offset + 28, $packet, 0, $capturedLength
                )
                $decoded = Convert-D01CapturedPacket -Packet $packet `
                    -LinkType ([uint16]$interfaces[$interfaceId].link_type)
                if ($null -ne $decoded) {
                    $rawTimestamp =
                        ([uint64]$timestampHigh * [uint64]4294967296) +
                        [uint64]$timestampLow
                    $epochNanoseconds =
                        Convert-D01PcapTimestampToUnixNs `
                            -RawTimestamp $rawTimestamp `
                            -Resolution (
                                [byte]$interfaces[$interfaceId].
                                    timestamp_resolution
                            ) -OffsetSeconds (
                                [Int64]$interfaces[$interfaceId].
                                    timestamp_offset_seconds
                            )
                    $decoded | Add-Member -NotePropertyName `
                        packet_epoch_unix_ns -NotePropertyValue $epochNanoseconds
                    $decoded | Add-Member -NotePropertyName interface_id `
                        -NotePropertyValue $interfaceId
                    $decoded | Add-Member -NotePropertyName packet_index `
                        -NotePropertyValue ($records.Count + 1)
                    $records.Add($decoded)
                }
            }
            $offset += $blockLength
        } catch {
            $errors.Add(
                "PCAPNG offset ${offset}: $($_.Exception.Message)"
            )
            break
        }
    }
    if ($offset -ne $bytes.Length) {
        $errors.Add(
            "PCAPNG parser ended at $offset of $($bytes.Length) bytes"
        )
    }
    if ($sectionCount -eq 0) {
        $errors.Add('PCAPNG contains no section header')
    }
    return [pscustomobject][ordered]@{
        valid = $errors.Count -eq 0
        errors = $errors.ToArray()
        records = $records.ToArray()
        section_count = $sectionCount
        interface_count = $interfaceCount
    }
}

function Get-D01SocketSamplerEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$ClockAnchor,
        [Parameter(Mandatory = $true)][Int64]$MaximumUncertaintyNs
    )

    $errors = New-Object 'Collections.Generic.List[string]'
    $rows = New-Object 'Collections.Generic.List[object]'
    $sampleCount = 0
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            valid = $false
            errors = @('Socket sampler JSONL is missing')
            sample_count = 0
            rows = @()
        }
    }
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $Path) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $sample = $line | ConvertFrom-Json -ErrorAction Stop
            if ([string]$sample.schema -ne
                    'ese.v91.d01-target-socket-sample/v3' -or
                [string]$sample.clock.schema -ne
                    'ese.v91.d01-clock-observation/v1' -or
                [string]$sample.clock.anchor_id -ne
                    [string]$ClockAnchor.anchor_id -or
                [Int64]$sample.clock.qpc_frequency -ne
                    [Int64]$ClockAnchor.qpc_frequency) {
                throw 'Socket sample clock/schema contract mismatch'
            }
            $recomputed = Get-D01ClockObservation `
                -Anchor $ClockAnchor `
                -QpcStart ([Int64]$sample.clock.qpc_start_ticks) `
                -QpcEnd ([Int64]$sample.clock.qpc_end_ticks)
            if ([Int64]$recomputed.epoch_unix_ns -ne
                    [Int64]$sample.clock.epoch_unix_ns -or
                [Int64]$recomputed.uncertainty_ns -ne
                    [Int64]$sample.clock.uncertainty_ns -or
                [Int64]$sample.clock.uncertainty_ns -gt
                    $MaximumUncertaintyNs) {
                throw 'Socket sample epoch/QPC conversion is incoherent'
            }
            $sampleCount++
            foreach ($connection in @($sample.connections)) {
                $rows.Add([pscustomobject][ordered]@{
                    sample_number = [int]$sample.sample_number
                    epoch_unix_ns = [Int64]$sample.clock.epoch_unix_ns
                    uncertainty_ns = [Int64]$sample.clock.uncertainty_ns
                    qpc_midpoint_ticks =
                        [Int64]$sample.clock.qpc_midpoint_ticks
                    owning_process = [int]$connection.owning_process
                    state = [string]$connection.state
                    family = ([string]$connection.family).ToLowerInvariant()
                    local_address = Get-D01NormalizedIp `
                        -Address ([string]$connection.local_address)
                    local_port = [int]$connection.local_port
                    remote_address = Get-D01NormalizedIp `
                        -Address ([string]$connection.remote_address)
                    remote_port = [int]$connection.remote_port
                    local_address_assigned =
                        [bool]$connection.local_address_assigned
                    physical_nonvirtual =
                        [bool]$connection.physical_nonvirtual
                    adapter = $connection.adapter
                })
            }
        } catch {
            $errors.Add(
                "Socket sampler line ${lineNumber}: $($_.Exception.Message)"
            )
        }
    }
    if ($sampleCount -eq 0) {
        $errors.Add('Socket sampler contains no valid samples')
    }
    return [pscustomobject][ordered]@{
        valid = $errors.Count -eq 0
        errors = $errors.ToArray()
        sample_count = $sampleCount
        rows = $rows.ToArray()
    }
}

function Get-D01SynCorrelation {
    param(
        [Parameter(Mandatory = $true)][object]$Packet,
        [Parameter(Mandatory = $true)][object[]]$SamplerRows,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId,
        [Parameter(Mandatory = $true)][string]$ExpectedCoordinatorAddress,
        [Parameter(Mandatory = $true)][Int64]$ToleranceNs
    )

    $expectedLocal = Get-D01NormalizedIp `
        -Address $ExpectedCoordinatorAddress
    $packetTime = [Int64]$Packet.packet_epoch_unix_ns
    $nearRows = @(
        $SamplerRows | Where-Object {
            [Math]::Abs(
                [decimal]([Int64]$_.epoch_unix_ns - $packetTime)
            ) -le [decimal]$ToleranceNs
        }
    )
    $exactRows = @(
        $nearRows | Where-Object {
            [string]$_.family -eq [string]$Packet.family -and
            [string]$_.local_address -eq
                [string]$Packet.source_address -and
            [int]$_.local_port -eq [int]$Packet.source_port -and
            [string]$_.remote_address -eq
                [string]$Packet.destination_address -and
            [int]$_.remote_port -eq [int]$Packet.destination_port
        }
    )
    $foreignRows = @(
        $exactRows | Where-Object {
            [int]$_.owning_process -ne $CandidateProcessId
        }
    )
    $portReuseRows = @(
        $nearRows | Where-Object {
            [string]$_.family -eq [string]$Packet.family -and
            [string]$_.local_address -eq
                [string]$Packet.source_address -and
            [int]$_.local_port -eq [int]$Packet.source_port -and
            (
                [int]$_.owning_process -ne $CandidateProcessId -or
                [string]$_.remote_address -ne
                    [string]$Packet.destination_address -or
                [int]$_.remote_port -ne [int]$Packet.destination_port
            )
        }
    )
    $candidateRows = @(
        $exactRows | Where-Object {
            [int]$_.owning_process -eq $CandidateProcessId -and
            [bool]$_.local_address_assigned -and
            [bool]$_.physical_nonvirtual -and
            (
                [string]$Packet.family -ne 'ipv6' -or
                [string]$_.state -eq 'SynSent'
            )
        } | ForEach-Object {
            [pscustomobject]@{
                row = $_
                distance_ns = [Int64][Math]::Abs(
                    [decimal]([Int64]$_.epoch_unix_ns - $packetTime)
                )
            }
        } | Sort-Object distance_ns, {
            [int]$_.row.sample_number
        }
    )
    $minimumDistance = if ($candidateRows.Count -gt 0) {
        [Int64]$candidateRows[0].distance_ns
    } else { $null }
    $nearestRows = @()
    if ($candidateRows.Count -gt 0) {
        $nearestRows = @($candidateRows | Where-Object {
            [Int64]$_.distance_ns -eq $minimumDistance
        })
    }
    $foreignPacket =
        [string]$Packet.source_address -ne $expectedLocal
    $ambiguous = $nearestRows.Count -ne 1 -and
        $candidateRows.Count -gt 0
    $attributed = -not $foreignPacket -and
        $foreignRows.Count -eq 0 -and $portReuseRows.Count -eq 0 -and
        $nearestRows.Count -eq 1
    return [pscustomobject][ordered]@{
        packet_index = [int]$Packet.packet_index
        packet_epoch_unix_ns = $packetTime
        family = [string]$Packet.family
        five_tuple = [string]$Packet.five_tuple
        tcp_sequence_number = [uint32]$Packet.tcp_sequence_number
        tolerance_ns = $ToleranceNs
        candidate_process_id = $CandidateProcessId
        candidate_row_count = $candidateRows.Count
        exact_foreign_row_count = $foreignRows.Count
        port_reuse_row_count = $portReuseRows.Count
        foreign_packet = $foreignPacket
        ambiguous = $ambiguous
        unmatched = $candidateRows.Count -eq 0
        attributed = $attributed
        matched_distance_ns = if ($attributed) {
            [Int64]$nearestRows[0].distance_ns
        } else { $null }
        matched_sampler_row = if ($attributed) {
            $nearestRows[0].row
        } else { $null }
    }
}

function Get-D01PacketCaptureEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][Net.IPAddress]$IPv6,
        [Parameter(Mandatory = $true)][string]$CoordinatorIPv4,
        [Parameter(Mandatory = $true)]
        [Net.IPAddress]$CoordinatorIPv6,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$SocketSamplesPath,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId,
        [Parameter(Mandatory = $true)][object]$ClockAnchor,
        [Parameter(Mandatory = $true)][object]$ClockEndAnchor,
        [Parameter(Mandatory = $true)][Int64]$WindowStartEpochUnixNs,
        [Parameter(Mandatory = $true)][Int64]$WindowEndEpochUnixNs
    )

    if ($WindowEndEpochUnixNs -lt $WindowStartEpochUnixNs) {
        throw 'Invalid capture correlation window'
    }
    $correlationToleranceNs = [Int64]250000000
    $clockPrediction = Get-D01ClockObservation -Anchor $ClockAnchor `
        -QpcStart ([Int64]$ClockEndAnchor.anchor_qpc_ticks) `
        -QpcEnd ([Int64]$ClockEndAnchor.anchor_qpc_ticks)
    $clockDriftNs = [Int64](
        [Int64]$ClockEndAnchor.anchor_epoch_unix_ns -
        [Int64]$clockPrediction.epoch_unix_ns
    )
    $clockCoherent =
        [string]$ClockAnchor.clock_domain -eq
            [string]$ClockEndAnchor.clock_domain -and
        [Int64]$ClockAnchor.qpc_frequency -eq
            [Int64]$ClockEndAnchor.qpc_frequency -and
        [Math]::Abs([decimal]$clockDriftNs) -le [decimal]50000000 -and
        [Int64]$ClockAnchor.anchor_uncertainty_ns -le
            $correlationToleranceNs -and
        [Int64]$ClockEndAnchor.anchor_uncertainty_ns -le
            $correlationToleranceNs
    $pcap = Get-D01PcapNgTcpRecords -Path $State.pcapng_path
    $sampler = Get-D01SocketSamplerEvidence `
        -Path $SocketSamplesPath -ClockAnchor $ClockAnchor `
        -MaximumUncertaintyNs $correlationToleranceNs
    $sourceV4 = Get-D01NormalizedIp -Address $IPv4
    $sourceV6 = Get-D01NormalizedIp -Address $IPv6.ToString()
    $coordinatorV4 =
        Get-D01NormalizedIp -Address $CoordinatorIPv4
    $coordinatorV6 = Get-D01NormalizedIp `
        -Address $CoordinatorIPv6.ToString()
    $allTargetInitialSyns = @(
        @($pcap.records) | Where-Object {
            [bool]$_.initial_syn -and
            [string]$_.destination_address -in @($sourceV4, $sourceV6)
        }
    )
    $wrongPortSyns = @(
        $allTargetInitialSyns | Where-Object {
            [int]$_.destination_port -ne $Port
        }
    )
    $outOfWindowSyns = @(
        $allTargetInitialSyns | Where-Object {
            [Int64]$_.packet_epoch_unix_ns -lt
                $WindowStartEpochUnixNs -or
            [Int64]$_.packet_epoch_unix_ns -gt
                $WindowEndEpochUnixNs
        }
    )
    $eligibleSyns = @(
        $allTargetInitialSyns | Where-Object {
            [int]$_.destination_port -eq $Port -and
            [Int64]$_.packet_epoch_unix_ns -ge
                $WindowStartEpochUnixNs -and
            [Int64]$_.packet_epoch_unix_ns -le
                $WindowEndEpochUnixNs
        }
    )
    $correlations = @(
        foreach ($packet in $eligibleSyns) {
            $expectedCoordinator = if (
                [string]$packet.family -eq 'ipv4'
            ) { $coordinatorV4 } else { $coordinatorV6 }
            Get-D01SynCorrelation -Packet $packet `
                -SamplerRows @($sampler.rows) `
                -CandidateProcessId $CandidateProcessId `
                -ExpectedCoordinatorAddress $expectedCoordinator `
                -ToleranceNs $correlationToleranceNs
        }
    )
    $v4Correlations = @(
        $correlations | Where-Object { [string]$_.family -eq 'ipv4' }
    )
    $v6Correlations = @(
        $correlations | Where-Object { [string]$_.family -eq 'ipv6' }
    )
    $unattributed = @($correlations | Where-Object {
        -not [bool]$_.attributed
    })
    $correlationPass = $pcap.valid -and $sampler.valid -and
        $clockCoherent -and $wrongPortSyns.Count -eq 0 -and
        $outOfWindowSyns.Count -eq 0 -and
        $v4Correlations.Count -gt 0 -and
        $v6Correlations.Count -gt 0 -and
        @($v4Correlations | Where-Object {
            -not [bool]$_.attributed
        }).Count -eq 0 -and
        @($v6Correlations | Where-Object {
            -not [bool]$_.attributed
        }).Count -eq 0
    $artifacts = @()
    foreach ($path in @(
        $State.etl_path, $State.pcapng_path, $State.text_path
    )) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $item = Get-Item -LiteralPath $path
            $artifacts += [pscustomobject][ordered]@{
                name = $item.Name
                bytes = [Int64]$item.Length
                sha256 = Get-LabSha256 -Path $item.FullName
            }
        }
    }
    $lossless = $null -ne $State.etw_loss -and
        [bool]$State.etw_loss.proved_zero
    $filterScopeExact =
        [bool]$State.filters_applied_verified -and
        [string]$State.filter_scope -eq
            'target-address-all-tcp-ports' -and
        [int]$State.expected_destination_port -eq $Port
    return [pscustomobject][ordered]@{
        exact_filters_applied = $filterScopeExact
        capture_filter_scope = [string]$State.filter_scope
        all_target_tcp_ports_captured = $filterScopeExact
        tcp_port = $Port
        candidate_process_id = $CandidateProcessId
        correlation_tolerance_ns = $correlationToleranceNs
        correlation_window = [ordered]@{
            start_epoch_unix_ns = $WindowStartEpochUnixNs
            end_epoch_unix_ns = $WindowEndEpochUnixNs
        }
        clock_coherence = [ordered]@{
            valid = $clockCoherent
            drift_ns = $clockDriftNs
            start_anchor = $ClockAnchor
            end_anchor = $ClockEndAnchor
        }
        pcap_parser = $pcap
        socket_sampler = [ordered]@{
            valid = $sampler.valid
            errors = @($sampler.errors)
            sample_count = $sampler.sample_count
            row_count = @($sampler.rows).Count
        }
        etw_loss = $State.etw_loss
        etw_lossless = $lossless
        target_initial_syn_count = $allTargetInitialSyns.Count
        eligible_target_syn_count = $eligibleSyns.Count
        wrong_port_target_syn_count = $wrongPortSyns.Count
        out_of_window_target_syn_count = $outOfWindowSyns.Count
        unattributed_target_syn_count = $unattributed.Count
        ambiguous_target_syn_count = @($correlations | Where-Object {
            [bool]$_.ambiguous
        }).Count
        foreign_target_syn_count = @($correlations | Where-Object {
            [bool]$_.foreign_packet -or
            [int]$_.exact_foreign_row_count -gt 0
        }).Count
        port_reuse_target_syn_count = @($correlations | Where-Object {
            [int]$_.port_reuse_row_count -gt 0
        }).Count
        ipv4_exact_tuple_line_count = $v4Correlations.Count
        ipv6_exact_tuple_line_count = $v6Correlations.Count
        ipv4_exact_tuple_correlated =
            $v4Correlations.Count -gt 0 -and
            @($v4Correlations | Where-Object {
                -not [bool]$_.attributed
            }).Count -eq 0
        ipv6_exact_tuple_correlated =
            $v6Correlations.Count -gt 0 -and
            @($v6Correlations | Where-Object {
                -not [bool]$_.attributed
            }).Count -eq 0
        both_families_observed =
            $v4Correlations.Count -gt 0 -and $v6Correlations.Count -gt 0
        per_syn_correlations = $correlations
        correlation_pass = $correlationPass
        filter_inventory_restored =
            [bool]$State.filter_inventory_restored_verified
        etw_session_stopped =
            [bool]$State.etw_session_stopped_verified
        capture_started = [bool]$State.capture_started_verified
        artifacts = $artifacts
        capture_observability_pass =
            [bool]$State.available -and
            [bool]$State.capture_started_verified -and
            $filterScopeExact -and $lossless -and
            $pcap.valid -and $clockCoherent -and
            [bool]$State.filter_inventory_restored_verified -and
            [bool]$State.etw_session_stopped_verified -and
            $artifacts.Count -eq 3
    }
}

function Get-D01SourcePacketLinkEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [AllowNull()][object]$Observation,
        [Parameter(Mandatory = $true)][string]$SourceIPv4,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][object]$ClockAnchor,
        [Parameter(Mandatory = $true)][object]$ClockEndAnchor,
        [Parameter(Mandatory = $true)][Int64]$WindowStartEpochUnixNs,
        [Parameter(Mandatory = $true)][Int64]$WindowEndEpochUnixNs
    )

    if ($WindowEndEpochUnixNs -lt $WindowStartEpochUnixNs) {
        throw 'Invalid source capture correlation window'
    }
    $clockPrediction = Get-D01ClockObservation -Anchor $ClockAnchor `
        -QpcStart ([Int64]$ClockEndAnchor.anchor_qpc_ticks) `
        -QpcEnd ([Int64]$ClockEndAnchor.anchor_qpc_ticks)
    $clockDriftNs = [Int64](
        [Int64]$ClockEndAnchor.anchor_epoch_unix_ns -
        [Int64]$clockPrediction.epoch_unix_ns
    )
    $clockCoherent =
        [string]$ClockAnchor.clock_domain -eq
            [string]$ClockEndAnchor.clock_domain -and
        [Int64]$ClockAnchor.qpc_frequency -eq
            [Int64]$ClockEndAnchor.qpc_frequency -and
        [Math]::Abs([decimal]$clockDriftNs) -le [decimal]50000000 -and
        [Int64]$ClockAnchor.anchor_uncertainty_ns -le 250000000 -and
        [Int64]$ClockEndAnchor.anchor_uncertainty_ns -le 250000000
    $pcap = Get-D01PcapNgTcpRecords -Path $State.pcapng_path
    $normalizedSource = Get-D01NormalizedIp -Address $SourceIPv4
    $windowSyns = @(
        @($pcap.records) | Where-Object {
            [bool]$_.initial_syn -and [string]$_.family -eq 'ipv4' -and
            [string]$_.destination_address -eq $normalizedSource -and
            [int]$_.destination_port -eq $Port -and
            [Int64]$_.packet_epoch_unix_ns -ge
                $WindowStartEpochUnixNs -and
            [Int64]$_.packet_epoch_unix_ns -le
                $WindowEndEpochUnixNs
        }
    )
    $observationTupleValid = $false
    $matchingSyns = @()
    if ($null -ne $Observation) {
        try {
            $observationTupleValid =
                [string]$Observation.connection.state -eq 'Established' -and
                [string]$Observation.connection.local_address -eq
                    $normalizedSource -and
                [int]$Observation.connection.local_port -eq $Port -and
                [string]$Observation.connection.remote_address -notin
                    @('', '0.0.0.0', '::') -and
                [int]$Observation.connection.remote_port -gt 0
            if ($observationTupleValid) {
                $matchingSyns = @(
                    $windowSyns | Where-Object {
                        [string]$_.source_address -eq
                            [string]$Observation.connection.remote_address -and
                        [int]$_.source_port -eq
                            [int]$Observation.connection.remote_port
                    }
                )
            }
        } catch {
            $observationTupleValid = $false
            $matchingSyns = @()
        }
    }
    $distinctTuples = @(
        $windowSyns | ForEach-Object { [string]$_.five_tuple } |
            Sort-Object -Unique
    )
    $sequenceNumbers = @(
        $matchingSyns | ForEach-Object {
            [uint32]$_.tcp_sequence_number
        } | Sort-Object -Unique
    )
    $foreignSyns = if ($observationTupleValid) {
        @(
            $windowSyns | Where-Object {
                [string]$_.source_address -ne
                    [string]$Observation.connection.remote_address -or
                [int]$_.source_port -ne
                    [int]$Observation.connection.remote_port
            }
        )
    } else {
        @($windowSyns)
    }
    $filterScopeExact =
        [bool]$State.filters_applied_verified -and
        [string]$State.filter_scope -eq
            'target-address-all-tcp-ports' -and
        [int]$State.expected_destination_port -eq $Port
    $artifacts = @()
    foreach ($path in @(
        $State.etl_path, $State.pcapng_path, $State.text_path
    )) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $item = Get-Item -LiteralPath $path
            $artifacts += [pscustomobject][ordered]@{
                name = $item.Name
                bytes = [Int64]$item.Length
                sha256 = Get-LabSha256 -Path $item.FullName
            }
        }
    }
    $lossless = $null -ne $State.etw_loss -and
        [bool]$State.etw_loss.proved_zero
    $captureObservable =
        [bool]$State.available -and
        [bool]$State.capture_started_verified -and
        $filterScopeExact -and $lossless -and $pcap.valid -and
        $clockCoherent -and
        [bool]$State.filter_inventory_restored_verified -and
        [bool]$State.etw_session_stopped_verified -and
        $artifacts.Count -eq 3
    $linkValid = $pcap.valid -and $clockCoherent -and
        $observationTupleValid -and $windowSyns.Count -gt 0 -and
        $matchingSyns.Count -eq $windowSyns.Count -and
        $foreignSyns.Count -eq 0 -and $distinctTuples.Count -eq 1 -and
        $sequenceNumbers.Count -eq 1
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-source-packet-link/v1'
        capture_observability_pass = $captureObservable
        link_contract_pass = $linkValid
        filter_scope_exact = $filterScopeExact
        clock_coherence = [ordered]@{
            valid = $clockCoherent
            drift_ns = $clockDriftNs
        }
        correlation_window = [ordered]@{
            start_epoch_unix_ns = $WindowStartEpochUnixNs
            end_epoch_unix_ns = $WindowEndEpochUnixNs
        }
        incoming_target_initial_syn_count = $windowSyns.Count
        matching_inverse_initial_syn_count = $matchingSyns.Count
        foreign_or_additional_initial_syn_count = $foreignSyns.Count
        distinct_incoming_five_tuple_count = $distinctTuples.Count
        distinct_matching_sequence_count = $sequenceNumbers.Count
        matching_tcp_sequence_numbers = $sequenceNumbers
        matching_five_tuple = if ($distinctTuples.Count -eq 1) {
            $distinctTuples[0]
        } else { '' }
        pcap_parser = $pcap
        etw_loss = $State.etw_loss
        artifacts = $artifacts
    }
}

function Invoke-D01SourceRole {
    if (-not $RunNonce) {
        throw 'Source role requires the coordinator-issued RunNonce'
    }
    $nonce = $RunNonce.ToLowerInvariant()
    $candidateRoot = Get-LabFullPath -Path $PackagePath
    $outputPath = Assert-D01OutputLocation -Path $OutputRoot `
        -Label 'Source OutputRoot' -CandidateRoot $candidateRoot
    if (Test-Path -LiteralPath $outputPath) {
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Source OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $summaryPath = Join-Path $evidence 'summary.json'
    $coordinationBase = Assert-D01OutputLocation -Path $CoordinationRoot `
        -Label 'CoordinationRoot' -CandidateRoot $candidateRoot
    $coordination = Join-Path $coordinationBase "v91-d01-$nonce"
    $runPath = Join-Path $coordination 'run.json'
    $readyPath = Join-Path $coordination 'source-ready.json'
    $observePath = Join-Path $coordination 'observe.json'
    $observeAckPath = Join-Path $coordination 'source-observing.json'
    $observationPath = Join-Path $coordination 'source-observation.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $resultPath = Join-Path $coordination 'source-result.json'
    $socketSamplesPath = Join-Path $evidence 'incoming-sockets.jsonl'
    $healthSamplesPath = Join-Path $evidence 'health-samples.jsonl'
    $source = $null
    $sourceNode = ''
    $sourceExe = ''
    $firewallRuleV4 = 'eSE V91 D01 ' + $nonce + ' v4-allow'
    $firewallRuleV6Drop = 'eSE V91 D01 ' + $nonce + ' v6-drop'
    $firewallRulesCreated = $false
    $firewallRulesRemoved = $false
    $firewallEvidence = $null
    $runtimeError = $null
    $failureStage = 'preflight'
    $cleanupFailures = New-Object 'Collections.Generic.List[string]'
    $identityBefore = $null
    $identityAfter = $null
    $isolation = $null
    $topology = $null
    $preferences = $null
    $listenerEvidence = $null
    $fixture = $null
    $shared = $null
    $apiSamples = 0
    $apiUnavailable = 0
    $apiIsolationFailures = 0
    $uiSamples = 0
    $uiUnavailable = 0
    $uiUnresponsive = 0
    $inverseObservation = $null
    $inverseBaselineZero = $false
    $inverseUniqueKeys =
        New-Object 'Collections.Generic.HashSet[string]'
    $inverseActiveKeys =
        New-Object 'Collections.Generic.HashSet[string]'
    $inverseForeignKeys =
        New-Object 'Collections.Generic.HashSet[string]'
    $inverseAllConnectionKeys =
        New-Object 'Collections.Generic.HashSet[string]'
    $inverseAllowedRemoteAddresses = @()
    $inverseSeenCounts = @{}
    $inverseFirstSeenSample = @{}
    $inverseAmbiguityCount = 0
    $inverseGenerationCount = 0
    $sourceStopped = $false
    $nodeExeUnchanged = $false
    $candidateUnchanged = $false
    $startedAt = [DateTime]::UtcNow

    try {
        $identityBefore = Get-D01CandidateIdentity
        Write-LabJson -Value $identityBefore.extracted_manifest -Path (
            Join-Path $evidence 'package-manifest-before.json'
        ) | Out-Null
        Write-LabJson -Value $identityBefore.zip_manifest -Path (
            Join-Path $evidence 'zip-manifest-before.json'
        ) | Out-Null
        if (-not $identityBefore.exact) {
            throw 'Source package/ZIP identity does not match the exact candidate'
        }
        if (-not (Test-Path -LiteralPath $coordination -PathType Container)) {
            throw "Coordinator run directory is unavailable: $coordination"
        }
        $runWait = Wait-D01JsonFile -Path $runPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $runWait) {
            throw 'Timed out waiting for coordinator run.json'
        }
        $run = $runWait.value
        if ([string]$run.schema -ne 'ese.v91.d01-run/v2' -or
            [string]$run.case_id -ne $caseId -or
            [string]$run.run_nonce -ne $nonce -or
            [string]$run.candidate.commit -ne
                $identityBefore.candidate.commit -or
            [string]$run.candidate.emule_sha256 -ne
                $expectedEmuleHash -or
            [string]$run.candidate.package_zip_sha256 -ne
                $expectedZipHash -or
            [string]$run.candidate.extracted_manifest_sha256 -ne
                $identityBefore.extracted_manifest.manifest_sha256 -or
            [string]$run.candidate.zip_manifest_sha256 -ne
                $identityBefore.zip_manifest.manifest_sha256 -or
            [string]$run.fixture.hostname -ne $canonicalHostname -or
            [string]$run.fixture.source_public_ipv4 -ne
                $script:sourcePublicV4Text -or
            [string]$run.fixture.source_local_ipv4 -ne
                $script:sourceLocalV4Text -or
            [string]$run.fixture.source_ipv6 -ne
                $script:sourceV6Text -or
            [string]$run.fixture.coordinator_public_ipv4 -ne
                $script:coordinatorPublicV4Text -or
            [string]$run.fixture.coordinator_local_ipv4 -ne
                $script:coordinatorLocalV4Text -or
            [string]$run.fixture.coordinator_ipv6 -ne
                $script:coordinatorV6Text -or
            [int]$run.fixture.source_tcp_port -ne $SourceTcpPort -or
            [Int64]$run.fixture.file_size_bytes -ne $FileSizeBytes) {
            throw 'Source arguments/package do not exactly match run.json'
        }

        $isolation = Get-D01IsolationEvidence
        Write-LabJson -Value $isolation -Path (
            Join-Path $evidence 'isolation.json'
        ) | Out-Null
        if (-not $isolation.strict_isolation_valid) {
            throw 'Source has an active overlay/VPN adapter or proxy environment'
        }
        Test-D01PortsFree -Ports @(
            $SourceTcpPort, $SourceUdpPort, $SourceWebPort
        )
        $assignedV4 = Get-D01AssignedAddress `
            -Address $script:sourceLocalV4Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
            -Context 'source-local-ipv4'
        $assignedV6 = Get-D01AssignedAddress `
            -Address $script:sourceV6Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
            -Context 'source-public-ipv6'
        if (-not $assignedV4.adapter.physical_nonvirtual -or
            -not $assignedV6.adapter.physical_nonvirtual) {
            throw 'Source addresses are not assigned to physical native adapters'
        }
        if ([int]$assignedV4.interface_index -ne
            [int]$assignedV6.interface_index) {
            throw 'Source local IPv4 and public IPv6 are not on one physical adapter'
        }
        if ($script:sourcePublicV4Text -eq $script:sourceLocalV4Text -and
            $assignedV4.address_class -ne 'global-v4') {
            throw 'Direct T1 SourcePublicIPv4 must be a global assigned address'
        }
        $routeV4 = Get-D01RouteEvidence `
            -RemoteAddress $script:coordinatorPublicV4Text `
            -Context 'source-route-to-coordinator-ipv4'
        $routeV6 = Get-D01RouteEvidence `
            -RemoteAddress $script:coordinatorV6Text `
            -Context 'source-route-to-coordinator-ipv6'
        if (-not $routeV4.available -or -not $routeV6.available -or
            -not $routeV4.adapter.physical_nonvirtual -or
            -not $routeV6.adapter.physical_nonvirtual) {
            throw 'Source does not have native physical routes to coordinator'
        }
        $inverseAllowedRemoteAddresses = @(
            @(
                $script:coordinatorLocalV4Text,
                $script:coordinatorPublicV4Text,
                [string]$routeV4.next_hop
            ) | ForEach-Object {
                Get-D01NormalizedIp -Address ([string]$_)
            } | Where-Object {
                $_ -notin @('', '0.0.0.0', '::')
            } | Sort-Object -Unique
        )
        if ($inverseAllowedRemoteAddresses.Count -eq 0) {
            throw 'No controlled source-visible coordinator address was derived'
        }
        $topology = [pscustomobject][ordered]@{
            machine_id_sha256 = Get-D01MachineId
            source_local_ipv4 = $assignedV4
            source_public_ipv4 = $script:sourcePublicV4Text
            source_public_ipv4_is_nat =
                $script:sourcePublicV4Text -ne $script:sourceLocalV4Text
            source_ipv6 = $assignedV6
            route_to_coordinator_public_ipv4 = $routeV4
            route_to_coordinator_ipv6 = $routeV6
            allowed_inverse_remote_addresses =
                $inverseAllowedRemoteAddresses
            native_physical = $true
            overlay_vpn_proxy_absent = $true
        }
        Write-LabJson -Value $topology -Path (
            Join-Path $evidence 'topology.json'
        ) | Out-Null

        $failureStage = 'profile-setup'
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
            -SourcePackage $identityBefore.candidate.package_path `
            -OutputRoot $nodes -RunId "v91-d01-$nonce" -PortOffset 6100
        $sourceNode = Join-Path $nodes "v91-d01-$nonce-a"
        $sourceExe = Join-Path $sourceNode 'emule.exe'
        if ((Get-LabSha256 -Path $sourceExe) -ne $expectedEmuleHash) {
            throw 'Prepared source executable is not the exact candidate'
        }
        $incoming = New-LabDirectory -Path (Join-Path $sourceNode 'Incoming')
        $temp = New-LabDirectory -Path (Join-Path $sourceNode 'Temp')
        foreach ($directory in @($incoming, $temp)) {
            if (@(Get-ChildItem -LiteralPath $directory -Force).Count -ne 0) {
                throw "Prepared source transfer directory is not empty: $directory"
            }
        }
        $preferences = Set-D01IsolatedPreferences -NodePath $sourceNode `
            -IPv6Mode 0 -IPv6BindAddress $script:sourceV6Text `
            -WebPort $SourceWebPort -TcpPort $SourceTcpPort `
            -UdpPort $SourceUdpPort -IncomingPath $incoming `
            -TempPath $temp -SourceProfile
        $fileName = "v91-d01-$nonce.bin"
        $sourceFile = Join-Path $incoming $fileName
        $fixture = New-D01FixtureFile -Path $sourceFile -Bytes $FileSizeBytes
        $fixture | Add-Member -NotePropertyName file_name `
            -NotePropertyValue $fileName

        $failureStage = 'runtime-startup'
        Write-D01JsonAtomic -Value ([ordered]@{
            schema = 'ese.v91.d01-firewall-intent/v2'
            captured_at_utc = Get-LabUtcTimestamp
            rules = @(
                [ordered]@{
                    display_name = $firewallRuleV4
                    action = 'Allow'
                    program = $sourceExe
                    local_address = $script:sourceLocalV4Text
                    remote_addresses =
                        $inverseAllowedRemoteAddresses
                    local_port = $SourceTcpPort
                    protocol = 'TCP'
                },
                [ordered]@{
                    display_name = $firewallRuleV6Drop
                    action = 'Block'
                    program = 'Any'
                    local_address = $script:sourceV6Text
                    remote_address = $script:coordinatorV6Text
                    local_port = $SourceTcpPort
                    protocol = 'TCP'
                    purpose =
                        'silent controlled AAAA DROP preserving SynSent'
                }
            )
        }) -Path (Join-Path $evidence 'firewall-intent.json')
        New-NetFirewallRule -DisplayName $firewallRuleV4 -Direction Inbound `
            -Action Allow -Protocol TCP -Program $sourceExe `
            -LocalAddress $script:sourceLocalV4Text `
            -RemoteAddress $inverseAllowedRemoteAddresses `
            -LocalPort $SourceTcpPort -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName $firewallRuleV6Drop `
            -Direction Inbound -Action Block -Protocol TCP `
            -LocalAddress $script:sourceV6Text `
            -RemoteAddress $script:coordinatorV6Text `
            -LocalPort $SourceTcpPort -Profile Any | Out-Null
        $firewallRulesCreated = $true
        $firewallEvidence = [pscustomobject][ordered]@{
            ipv4_allow = Get-D01FirewallRuleEvidence `
                -DisplayName $firewallRuleV4 -ExpectedAction Allow `
                -ExpectedLocalAddress $script:sourceLocalV4Text `
                -ExpectedRemoteAddress $inverseAllowedRemoteAddresses `
                -ExpectedLocalPort $SourceTcpPort `
                -ExpectedRemotePort Any -ExpectedProgram $sourceExe `
                -ExpectedProfile Any
            ipv6_drop = Get-D01FirewallRuleEvidence `
                -DisplayName $firewallRuleV6Drop -ExpectedAction Block `
                -ExpectedLocalAddress $script:sourceV6Text `
                -ExpectedRemoteAddress $script:coordinatorV6Text `
                -ExpectedLocalPort $SourceTcpPort `
                -ExpectedRemotePort Any -ExpectedProgram Any `
                -ExpectedProfile Any
        }
        Write-LabJson -Value $firewallEvidence -Path (
            Join-Path $evidence 'firewall-armed.json'
        ) | Out-Null
        if (-not $firewallEvidence.ipv4_allow.exact -or
            -not $firewallEvidence.ipv6_drop.exact) {
            throw 'Source firewall allow/DROP rules are not exact'
        }

        $source = Start-Process -FilePath $sourceExe `
            -ArgumentList @(
                '--portable', '--ignoreinstances',
                "--metrics-port=$SourceWebPort",
                "--tcp-port=$SourceTcpPort",
                "--udp-port=$SourceUdpPort"
            ) -WorkingDirectory $sourceNode -PassThru -WindowStyle Hidden
        $listenerEvidence = Wait-D01Listener -Port $SourceTcpPort `
            -Process $source -RequireIPv4Only
        $startupApi = Wait-D01Api -Port $SourceWebPort -Process $source
        if (-not (Test-D01ApiIsolation -Data $startupApi)) {
            throw 'Source API shows NetLab, Kad or eD2K server activity'
        }
        if ((Get-LabSha256 -Path $source.Path) -ne $expectedEmuleHash) {
            throw 'Running source process is not the exact candidate'
        }
        $session = Get-D01ClassicSession -Port $SourceWebPort
        $shared = Get-D01SharedLink -Port $SourceWebPort `
            -Session $session -FileName $fileName -FileBytes $FileSizeBytes

        $ready = [ordered]@{
            schema = 'ese.v91.d01-source-ready/v3'
            case_id = $caseId
            run_nonce = $nonce
            generated_at_utc = Get-LabUtcTimestamp
            machine_id_sha256 = $topology.machine_id_sha256
            candidate = [ordered]@{
                commit = $identityBefore.candidate.commit
                emule_sha256 = $expectedEmuleHash
                package_zip_sha256 = $expectedZipHash
                extracted_manifest_sha256 =
                    $identityBefore.extracted_manifest.manifest_sha256
                zip_manifest_sha256 =
                    $identityBefore.zip_manifest.manifest_sha256
            }
            topology = $topology
            process = [ordered]@{
                process_id = $source.Id
                process_emule_sha256 = Get-LabSha256 -Path $source.Path
                listener = $listenerEvidence
                api_isolation_valid = $true
            }
            fixture = [ordered]@{
                file_name = $fileName
                file_bytes = $FileSizeBytes
                file_sha256 = $fixture.sha256
                ed2k_hash = $shared.ed2k_hash
                shared_link = $shared.link
                shared_link_sha256 =
                    Get-LabStringSha256 -Value $shared.link
            }
            preferences = $preferences
            firewall = [ordered]@{
                rules_created = $firewallRulesCreated
                exact = $firewallEvidence.ipv4_allow.exact -and
                    $firewallEvidence.ipv6_drop.exact
                ipv4_allow = $firewallEvidence.ipv4_allow
                ipv6_drop = $firewallEvidence.ipv6_drop
                AAAA_failure_mode = 'controlled silent inbound DROP'
            }
        }
        Write-D01JsonAtomic -Value $ready -Path $readyPath
        Write-Host (
            "V91-D01 source ready for coordinator nonce $nonce"
        ) -ForegroundColor Cyan

        $failureStage = 'observation-barrier'
        $observeWait = Wait-D01JsonFile -Path $observePath `
            -StopPath $stopPath `
            -TimeoutSeconds ($PeerReadyTimeoutSeconds + $TransferTimeoutSeconds)
        if ($null -eq $observeWait -or $observeWait.kind -eq 'stop') {
            throw 'Coordinator stopped or timed out before observation barrier'
        }
        $observe = $observeWait.value
        if ([string]$observe.schema -ne
                'ese.v91.d01-observe-command/v2' -or
            [string]$observe.case_id -ne $caseId -or
            [string]$observe.run_nonce -ne $nonce -or
            [string]$observe.candidate_commit -ne
                $identityBefore.candidate.commit -or
            [string]$observe.candidate_emule_sha256 -ne
                $expectedEmuleHash -or
            [int]$observe.downloader_process_id -le 0 -or
            [string]$observe.hostname_sha256 -ne
                (Get-LabStringSha256 -Value $canonicalHostname)) {
            throw 'Invalid coordinator observation command'
        }
        $baselineWaitStarted = [DateTime]::UtcNow
        $baselineWaitDeadline = $baselineWaitStarted.AddSeconds(
            [Math]::Max(
                1, [Math]::Min(120, $PeerReadyTimeoutSeconds - 5)
            )
        )
        $baselineSampleCount = 0
        do {
            $baselineSampleCount++
            $baselineIncoming = @(
                Get-D01IncomingConnections -ProcessId 0 `
                    -LocalPort $SourceTcpPort
            )
            if ($baselineIncoming.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $baselineWaitDeadline)
        $inverseBaselineZero = $baselineIncoming.Count -eq 0
        Write-D01JsonAtomic -Value ([ordered]@{
            schema = 'ese.v91.d01-source-observing/v4'
            case_id = $caseId
            run_nonce = $nonce
            generated_at_utc = Get-LabUtcTimestamp
            source_process_id = $source.Id
            source_process_emule_sha256 = Get-LabSha256 -Path $source.Path
            expected_downloader_process_id =
                [int]$observe.downloader_process_id
            all_processes_and_nonlisten_states_checked = $true
            allowed_source_visible_remote_addresses =
                $inverseAllowedRemoteAddresses
            baseline_established_connection_count =
                @($baselineIncoming | Where-Object {
                    [string]$_.state -eq 'Established'
                }).Count
            baseline_nonlisten_connection_count =
                $baselineIncoming.Count
            baseline_wait_sample_count = $baselineSampleCount
            baseline_wait_duration_ms = [Int64](
                ([DateTime]::UtcNow - $baselineWaitStarted).
                    TotalMilliseconds
            )
            baseline_zero = $inverseBaselineZero
        }) -Path $observeAckPath
        if (-not $inverseBaselineZero) {
            throw (
                'Source observation baseline contains a pre-existing ' +
                'non-listening socket'
            )
        }

        $failureStage = 'transfer-observation'
        $monitorStarted = [DateTime]::UtcNow
        $deadline = $monitorStarted.AddSeconds(
            $TransferTimeoutSeconds + 180
        )
        $nextHealth = [DateTime]::UtcNow
        $sampleNumber = 0
        $stopCommand = $null
        do {
            $source.Refresh()
            if ($source.HasExited) {
                throw "Source exited during transfer (exit $($source.ExitCode))"
            }
            $now = [DateTime]::UtcNow
            $connections = @(
                Get-D01IncomingConnections -ProcessId 0 `
                    -LocalPort $SourceTcpPort
            )
            Add-D01JsonLine -Path $socketSamplesPath -Value ([ordered]@{
                schema = 'ese.v91.d01-source-socket-sample/v2'
                sample_number = ++$sampleNumber
                captured_at_utc = Get-LabUtcTimestamp
                elapsed_ms = [Int64](
                    ($now - $monitorStarted).TotalMilliseconds
                )
                connections = $connections
            })
            $foreignInverseConnections = @(
                $connections | Where-Object {
                    [int]$_.owning_process -ne $source.Id -or
                    [string]$_.local_address -ne
                        $script:sourceLocalV4Text -or
                    [int]$_.local_port -ne $SourceTcpPort -or
                    -not [bool]$_.physical_nonvirtual -or
                    [string]$_.remote_address -notin
                        $inverseAllowedRemoteAddresses -or
                    [int]$_.remote_port -le 0
                }
            )
            foreach ($foreignConnection in $foreignInverseConnections) {
                $foreignKey = '{0}|{1}|{2}|{3}|{4}|{5}' -f
                    [int]$foreignConnection.owning_process,
                    [string]$foreignConnection.state,
                    [string]$foreignConnection.local_address,
                    [int]$foreignConnection.local_port,
                    [string]$foreignConnection.remote_address,
                    [int]$foreignConnection.remote_port
                $null = $inverseForeignKeys.Add($foreignKey)
            }
            foreach ($allowedConnection in @(
                $connections | Where-Object {
                    [int]$_.owning_process -eq $source.Id -and
                    [string]$_.local_address -eq
                        $script:sourceLocalV4Text -and
                    [int]$_.local_port -eq $SourceTcpPort -and
                    [bool]$_.physical_nonvirtual -and
                    [string]$_.remote_address -in
                        $inverseAllowedRemoteAddresses -and
                    [int]$_.remote_port -gt 0
                }
            )) {
                $allStateKey = '{0}|{1}|{2}|{3}|{4}' -f
                    [int]$allowedConnection.owning_process,
                    [string]$allowedConnection.local_address,
                    [int]$allowedConnection.local_port,
                    [string]$allowedConnection.remote_address,
                    [int]$allowedConnection.remote_port
                $null = $inverseAllConnectionKeys.Add($allStateKey)
            }
            if ($inverseForeignKeys.Count -gt 0) {
                $inverseAmbiguityCount =
                    [Math]::Max($inverseAmbiguityCount, 1)
            }
            if ($inverseAllConnectionKeys.Count -gt 1) {
                $inverseAmbiguityCount =
                    [Math]::Max($inverseAmbiguityCount, 1)
            }
            $established = @($connections | Where-Object {
                    [string]$_.state -eq 'Established' -and
                    [string]$_.local_address -eq
                        $script:sourceLocalV4Text -and
                    [int]$_.local_port -eq $SourceTcpPort -and
                    [int]$_.owning_process -eq $source.Id -and
                    [bool]$_.physical_nonvirtual -and
                    [string]$_.remote_address -in
                        $inverseAllowedRemoteAddresses -and
                    [int]$_.remote_port -gt 0
                })
            $currentInverseKeys =
                New-Object 'Collections.Generic.HashSet[string]'
            $connectionsByKey = @{}
            foreach ($establishedConnection in $established) {
                $inverseKey = '{0}|{1}|{2}|{3}|{4}' -f
                    [int]$establishedConnection.owning_process,
                    [string]$establishedConnection.local_address,
                    [int]$establishedConnection.local_port,
                    [string]$establishedConnection.remote_address,
                    [int]$establishedConnection.remote_port
                $null = $currentInverseKeys.Add($inverseKey)
                $connectionsByKey[$inverseKey] = $establishedConnection
            }
            foreach ($inverseKey in @($currentInverseKeys)) {
                if (-not $inverseActiveKeys.Contains($inverseKey) -and
                    $inverseUniqueKeys.Contains($inverseKey)) {
                    $inverseGenerationCount++
                    $inverseAmbiguityCount++
                }
                if ($inverseUniqueKeys.Add($inverseKey)) {
                    $inverseFirstSeenSample[$inverseKey] = $sampleNumber
                    $inverseSeenCounts[$inverseKey] = 0
                }
                $inverseSeenCounts[$inverseKey] =
                    [int]$inverseSeenCounts[$inverseKey] + 1
            }
            $inverseActiveKeys = $currentInverseKeys
            if ($inverseUniqueKeys.Count -gt 1) {
                $inverseAmbiguityCount =
                    [Math]::Max($inverseAmbiguityCount, 1)
            }
            if ($null -eq $inverseObservation -and
                $inverseUniqueKeys.Count -eq 1 -and
                $inverseAllConnectionKeys.Count -eq 1 -and
                $inverseAmbiguityCount -eq 0) {
                $onlyKey = @($inverseUniqueKeys)[0]
                if ($currentInverseKeys.Contains($onlyKey) -and
                    [int]$inverseSeenCounts[$onlyKey] -ge 2) {
                    $establishedConnection = $connectionsByKey[$onlyKey]
                    $inverseObservation = [pscustomobject][ordered]@{
                        schema = 'ese.v91.d01-source-observation/v4'
                        case_id = $caseId
                        run_nonce = $nonce
                        captured_at_utc = Get-LabUtcTimestamp
                        source_process_id = $source.Id
                        source_process_emule_sha256 =
                            Get-LabSha256 -Path $source.Path
                        connection = $establishedConnection
                        exact_inverse_pid_socket = $true
                        physical_adapter_proven = $true
                        baseline_zero = $inverseBaselineZero
                        baseline_established_connection_count = 0
                        baseline_nonlisten_connection_count = 0
                        all_processes_and_nonlisten_states_checked =
                            $true
                        allowed_source_visible_remote_addresses =
                            $inverseAllowedRemoteAddresses
                        source_visible_remote_address_allowed = $true
                        foreign_connection_count = 0
                        all_nonlisten_unique_socket_count = 1
                        new_socket_key_sha256 =
                            Get-LabStringSha256 -Value $onlyKey
                        first_seen_sample =
                            [int]$inverseFirstSeenSample[$onlyKey]
                        confirmed_sample = $sampleNumber
                        unique_new_socket_count = 1
                        ambiguity_count = 0
                        generation_count = 1
                        observation_window_started_at_utc =
                            $monitorStarted.ToString('o')
                        hairpin_nat_remote_address_not_assumed = $true
                    }
                    Write-D01JsonAtomic -Value $inverseObservation `
                        -Path $observationPath
                }
            }
            if ($now -ge $nextHealth) {
                $api = Get-D01ApiProbe -Port $SourceWebPort
                $ui = Get-D01UiProbe -Process $source
                $apiSamples++
                $uiSamples++
                if (-not $api.available) { $apiUnavailable++ }
                if ($api.available -and -not $api.isolation_valid) {
                    $apiIsolationFailures++
                }
                if (-not $ui.main_window_present) { $uiUnavailable++ }
                if ($ui.main_window_present -and
                    -not $ui.message_pump_responsive) {
                    $uiUnresponsive++
                }
                Add-D01JsonLine -Path $healthSamplesPath -Value ([ordered]@{
                    schema = 'ese.v91.d01-source-health-sample/v2'
                    captured_at_utc = Get-LabUtcTimestamp
                    api = $api
                    ui = $ui
                })
                $nextHealth = $now.AddSeconds(2)
            }
            if (Test-Path -LiteralPath $stopPath -PathType Leaf) {
                try {
                    $stopCommand = Get-Content -LiteralPath $stopPath -Raw |
                        ConvertFrom-Json -ErrorAction Stop
                    break
                } catch {}
            }
            if (($now - $monitorStarted).TotalSeconds -lt 20) {
                Start-Sleep -Milliseconds 50
            } else {
                Start-Sleep -Milliseconds 250
            }
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($null -eq $stopCommand) {
            throw 'Timed out waiting for coordinator stop command'
        }
        if ([string]$stopCommand.schema -ne
                'ese.v91.d01-stop-command/v2' -or
            [string]$stopCommand.case_id -ne $caseId -or
            [string]$stopCommand.run_nonce -ne $nonce -or
            [string]$stopCommand.candidate_commit -ne
                $identityBefore.candidate.commit -or
            [string]$stopCommand.candidate_emule_sha256 -ne
                $expectedEmuleHash) {
            throw 'Invalid coordinator stop command'
        }
    } catch {
        $runtimeError = $_.Exception.Message
    } finally {

        if ($null -ne $source) {
            $stopResult = Stop-D01OwnedProcess -Process $source `
                -ExpectedPath $sourceExe
            $sourceStopped = [bool]$stopResult.stopped
            if (-not $sourceStopped) {
                $cleanupFailures.Add('Source process remains running')
            }
        } else {
            $sourceStopped = $true
        }
        try {
            $rules = @(
                foreach ($displayName in @(
                    $firewallRuleV4, $firewallRuleV6Drop
                )) {
                    Get-NetFirewallRule -DisplayName $displayName `
                        -ErrorAction SilentlyContinue
                }
            )
            if ($rules.Count -gt 0) {
                $rules | Remove-NetFirewallRule -ErrorAction Stop
            }
            $remainingRules = @(
                foreach ($displayName in @(
                    $firewallRuleV4, $firewallRuleV6Drop
                )) {
                    Get-NetFirewallRule -DisplayName $displayName `
                        -ErrorAction SilentlyContinue
                }
            )
            $firewallRulesRemoved = $remainingRules.Count -eq 0
            if (-not $firewallRulesRemoved) {
                $cleanupFailures.Add(
                    'Temporary IPv4 allow or IPv6 DROP rule remains'
                )
            }
        } catch {
            $cleanupFailures.Add(
                "Firewall rollback failed: $($_.Exception.Message)"
            )
        }
        try {
            $identityAfter = Get-D01CandidateIdentity
            Write-LabJson -Value $identityAfter.extracted_manifest -Path (
                Join-Path $evidence 'package-manifest-after.json'
            ) | Out-Null
            Write-LabJson -Value $identityAfter.zip_manifest -Path (
                Join-Path $evidence 'zip-manifest-after.json'
            ) | Out-Null
            $candidateUnchanged = $null -ne $identityBefore -and
                $identityAfter.exact -and
                $identityAfter.extracted_manifest.manifest_sha256 -eq
                    $identityBefore.extracted_manifest.manifest_sha256 -and
                $identityAfter.zip_manifest.zip_sha256 -eq
                    $identityBefore.zip_manifest.zip_sha256
            if (-not $candidateUnchanged) {
                $cleanupFailures.Add('Source candidate package or ZIP changed')
            }
        } catch {
            $cleanupFailures.Add(
                "Source identity revalidation failed: $($_.Exception.Message)"
            )
        }
        if ($sourceExe -and
            (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
            $nodeExeUnchanged =
                (Get-LabSha256 -Path $sourceExe) -eq $expectedEmuleHash
        }
        if (-not $nodeExeUnchanged) {
            $cleanupFailures.Add('Prepared source executable changed')
        }
    }

    $healthObservabilityAvailable =
        $apiSamples -gt 0 -and $uiSamples -gt 0
    $sourceStatus = if ($null -eq $runtimeError -and
        $sourceStopped -and $firewallRulesRemoved -and
        $candidateUnchanged -and $nodeExeUnchanged -and
        $cleanupFailures.Count -eq 0) {
        'COMPLETE'
    } else { 'INCOMPLETE' }
    $result = [ordered]@{
        schema = 'ese.v91.d01-source-result/v2'
        case_id = $caseId
        run_nonce = $nonce
        generated_at_utc = Get-LabUtcTimestamp
        status = $sourceStatus
        runtime_error = $runtimeError
        failure_stage = $failureStage
        machine_id_sha256 = if ($null -ne $topology) {
            $topology.machine_id_sha256
        } else { Get-D01MachineId }
        candidate = [ordered]@{
            commit = if ($null -ne $identityBefore) {
                $identityBefore.candidate.commit
            } else { $Commit.ToLowerInvariant() }
            emule_sha256 = $expectedEmuleHash
            package_zip_sha256 = $expectedZipHash
            unchanged = $candidateUnchanged
            prepared_executable_unchanged = $nodeExeUnchanged
        }
        topology = $topology
        source_process_id = if ($null -ne $source) {
            $source.Id
        } else { $null }
        source_listener = $listenerEvidence
        fixture = if ($null -ne $shared) {
            [ordered]@{
                file_name = $fixture.file_name
                file_bytes = $fixture.bytes
                file_sha256 = $fixture.sha256
                ed2k_hash = $shared.ed2k_hash
            }
        } else { $fixture }
        inverse_socket_observation = $inverseObservation
        inverse_socket_observed = $null -ne $inverseObservation
        inverse_socket_baseline_zero = $inverseBaselineZero
        inverse_socket_baseline_all_nonlisten_states_checked = $true
        inverse_socket_allowed_remote_addresses =
            $inverseAllowedRemoteAddresses
        inverse_socket_foreign_connection_count =
            $inverseForeignKeys.Count
        inverse_socket_all_nonlisten_unique_count =
            $inverseAllConnectionKeys.Count
        inverse_socket_unique_new_count = $inverseUniqueKeys.Count
        inverse_socket_ambiguity_count = $inverseAmbiguityCount
        inverse_socket_generation_count =
            $inverseUniqueKeys.Count + $inverseGenerationCount
        health = [ordered]@{
            observability_available = $healthObservabilityAvailable
            api_sample_count = $apiSamples
            api_unavailable_count = $apiUnavailable
            api_isolation_failure_count = $apiIsolationFailures
            ui_sample_count = $uiSamples
            ui_unavailable_count = $uiUnavailable
            ui_unresponsive_count = $uiUnresponsive
        }
        cleanup = [ordered]@{
            source_process_stopped = $sourceStopped
            temporary_firewall_rules_created = $firewallRulesCreated
            temporary_firewall_rules_removed = $firewallRulesRemoved
            ipv4_allow_rule_name = $firewallRuleV4
            ipv6_drop_rule_name = $firewallRuleV6Drop
            firewall_armed_evidence = $firewallEvidence
            candidate_unchanged = $candidateUnchanged
            prepared_executable_unchanged = $nodeExeUnchanged
            dns_modified = $false
            hosts_modified = $false
            routes_modified = $false
            adapters_modified = $false
            overlay_vpn_modified = $false
            proxy_modified = $false
            failures = @($cleanupFailures)
        }
    }
    Write-LabJson -Value $result -Path $summaryPath | Out-Null
    try {
        if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            Write-D01JsonAtomic -Value $result -Path $resultPath
        }
    } catch {
        Write-Warning "Could not publish source-result.json: $($_.Exception.Message)"
    }
    Write-Host "V91-D01 source status: $sourceStatus" -ForegroundColor $(
        if ($sourceStatus -eq 'COMPLETE') { 'Green' } else { 'Yellow' }
    )
    if ($sourceStatus -eq 'COMPLETE') { return 0 }
    return 2
}

function Invoke-D01CoordinatorRole {
    if (-not $RunNonce) {
        $script:RunNonce = [Guid]::NewGuid().ToString('N')
    }
    $nonce = $RunNonce.ToLowerInvariant()
    $candidateRoot = Get-LabFullPath -Path $PackagePath
    $outputPath = Assert-D01OutputLocation -Path $OutputRoot `
        -Label 'Coordinator OutputRoot' -CandidateRoot $candidateRoot
    if (Test-Path -LiteralPath $outputPath) {
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Coordinator OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $captureEvidencePath =
        New-LabDirectory -Path (Join-Path $evidence 'capture')
    $apiEvidencePath = New-LabDirectory -Path (Join-Path $evidence 'api')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $summaryPath = Join-Path $evidence 'summary.json'
    $socketSamplesPath = Join-Path $evidence 'target-sockets.jsonl'
    $healthSamplesPath = Join-Path $evidence 'health-samples.jsonl'
    $telemetrySamplesPath =
        Join-Path $apiEvidencePath 'source-resolutions.jsonl'
    $coordinationBase = Assert-D01OutputLocation -Path $CoordinationRoot `
        -Label 'CoordinationRoot' -CandidateRoot $candidateRoot
    if (-not (Test-Path -LiteralPath $coordinationBase -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $coordinationBase -Force
    }
    $coordination = Join-Path $coordinationBase "v91-d01-$nonce"
    if (Test-Path -LiteralPath $coordination) {
        throw "Nonce-scoped CoordinationRoot already exists: $coordination"
    }
    $null = New-Item -ItemType Directory -Path $coordination
    $runPath = Join-Path $coordination 'run.json'
    $readyPath = Join-Path $coordination 'source-ready.json'
    $observePath = Join-Path $coordination 'observe.json'
    $observeAckPath = Join-Path $coordination 'source-observing.json'
    $sourceObservationPath =
        Join-Path $coordination 'source-observation.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $sourceResultPath = Join-Path $coordination 'source-result.json'

    $identityBefore = $null
    $identityAfter = $null
    $candidateUnchanged = $false
    $nodeExeUnchanged = $false
    $isolation = $null
    $coordinatorTopology = $null
    $topologyEvidence = $null
    $sourceReady = $null
    $sourceResult = $null
    $sourceObservation = $null
    $dnsInitial = $null
    $dnsFinal = $null
    $aProbe = $null
    $aaaaProbe = $null
    $preferences = $null
    $controlledProfile = $null
    $controlledServer = $null
    $controlledServerStop = $null
    $controlledLogin = $null
    $downloader = $null
    $downloaderNode = ''
    $downloaderExe = ''
    $destinationFile = ''
    $destinationBytes = 0L
    $destinationSha256 = ''
    $injection = $null
    $injectionCount = 0
    $baselineTelemetry = $null
    $finalTelemetry = $null
    $telemetryVerdict = $null
    $capture = $null
    $captureEvidence = $null
    $captureClockAnchor = $null
    $captureClockEndAnchor = $null
    [Int64]$captureWindowStartEpochUnixNs = 0
    [Int64]$captureWindowEndEpochUnixNs = 0
    $caseArmed = $false
    $runtimeError = $null
    $failureStage = 'preflight'
    $cleanupFailures = New-Object 'Collections.Generic.List[string]'
    $apiSamples = 0
    $apiUnavailable = 0
    $apiIsolationFailures = 0
    $uiSamples = 0
    $uiUnavailable = 0
    $uiUnresponsive = 0
    $socketSampleCount = 0
    $sawV4Socket = $false
    $sawV4Established = $false
    $sawV4Physical = $false
    $v4EstablishedEvidence = $null
    $coordinatorSocketBaselineZero = $false
    $sawV6Socket = $false
    $sawV6Established = $false
    $sawV6SynSent = $false
    $sawV6Physical = $false
    $v6SynSentEvidence = $null
    $v6ObservedStates = New-Object 'Collections.Generic.HashSet[string]'
    $sawForeignTargetSocket = $false
    $sawWrongPortTargetSocket = $false
    $unexpectedConnections = @()
    $transferCompleted = $false
    $productProcessExited = $false
    $startedAt = [DateTime]::UtcNow
    $transferStarted = $null
    $transferFinished = $null
    $stopPublished = $false

    try {
        $identityBefore = Get-D01CandidateIdentity
        Write-LabJson -Value $identityBefore.extracted_manifest -Path (
            Join-Path $evidence 'package-manifest-before.json'
        ) | Out-Null
        Write-LabJson -Value $identityBefore.zip_manifest -Path (
            Join-Path $evidence 'zip-manifest-before.json'
        ) | Out-Null
        if (-not $identityBefore.exact) {
            throw 'Coordinator package/ZIP identity is not the exact candidate'
        }
        $isolation = Get-D01IsolationEvidence
        Write-LabJson -Value $isolation -Path (
            Join-Path $evidence 'isolation.json'
        ) | Out-Null
        if (-not $isolation.strict_isolation_valid) {
            throw 'Coordinator has an active overlay/VPN adapter or proxy environment'
        }
        Test-D01PortsFree -Ports @(
            $DownloaderTcpPort, $DownloaderUdpPort, $DownloaderWebPort
        )
        $assignedV4 = Get-D01AssignedAddress `
            -Address $script:coordinatorLocalV4Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
            -Context 'coordinator-local-ipv4'
        $assignedV6 = Get-D01AssignedAddress `
            -Address $script:coordinatorV6Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
            -Context 'coordinator-public-ipv6'
        if (-not $assignedV4.adapter.physical_nonvirtual -or
            -not $assignedV6.adapter.physical_nonvirtual) {
            throw 'Coordinator addresses are not on physical native adapters'
        }
        if ([int]$assignedV4.interface_index -ne
            [int]$assignedV6.interface_index) {
            throw 'Coordinator IPv4 and IPv6 are not on one physical adapter'
        }
        if ($script:coordinatorPublicV4Text -eq
                $script:coordinatorLocalV4Text -and
            $assignedV4.address_class -ne 'global-v4') {
            throw 'Direct T1 CoordinatorPublicIPv4 must be globally routable'
        }
        $routeV4 = Get-D01RouteEvidence `
            -RemoteAddress $script:sourcePublicV4Text `
            -Context 'coordinator-route-to-source-ipv4'
        $routeV6 = Get-D01RouteEvidence `
            -RemoteAddress $script:sourceV6Text `
            -Context 'coordinator-route-to-source-ipv6'
        if (-not $routeV4.available -or -not $routeV6.available -or
            -not $routeV4.adapter.physical_nonvirtual -or
            -not $routeV6.adapter.physical_nonvirtual) {
            throw 'Coordinator lacks native physical routes to both DNS targets'
        }
        $coordinatorTopology = [pscustomobject][ordered]@{
            machine_id_sha256 = Get-D01MachineId
            coordinator_local_ipv4 = $assignedV4
            coordinator_public_ipv4 = $script:coordinatorPublicV4Text
            coordinator_public_ipv4_is_nat =
                $script:coordinatorPublicV4Text -ne
                    $script:coordinatorLocalV4Text
            coordinator_ipv6 = $assignedV6
            route_to_source_public_ipv4 = $routeV4
            route_to_source_ipv6 = $routeV6
            native_physical = $true
            overlay_vpn_proxy_absent = $true
        }
        Write-LabJson -Value $coordinatorTopology -Path (
            Join-Path $evidence 'coordinator-topology.json'
        ) | Out-Null
        $run = [ordered]@{
            schema = 'ese.v91.d01-run/v2'
            case_id = $caseId
            run_nonce = $nonce
            created_at_utc = Get-LabUtcTimestamp
            controlled_fixture_acknowledged = $true
            candidate = [ordered]@{
                commit = $identityBefore.candidate.commit
                emule_sha256 = $expectedEmuleHash
                ese_server_sha256 =
                    $identityBefore.candidate.ese_server_sha256
                build_info_sha256 =
                    $identityBefore.candidate.build_info_sha256
                package_zip_sha256 = $expectedZipHash
                extracted_manifest_sha256 =
                    $identityBefore.extracted_manifest.manifest_sha256
                zip_manifest_sha256 =
                    $identityBefore.zip_manifest.manifest_sha256
            }
            coordinator = $coordinatorTopology
            fixture = [ordered]@{
                hostname = $canonicalHostname
                hostname_sha256 =
                    Get-LabStringSha256 -Value $canonicalHostname
                source_public_ipv4 = $script:sourcePublicV4Text
                source_local_ipv4 = $script:sourceLocalV4Text
                source_ipv6 = $script:sourceV6Text
                coordinator_public_ipv4 =
                    $script:coordinatorPublicV4Text
                coordinator_local_ipv4 =
                    $script:coordinatorLocalV4Text
                coordinator_ipv6 = $script:coordinatorV6Text
                source_tcp_port = $SourceTcpPort
                source_udp_port = $SourceUdpPort
                source_web_port = $SourceWebPort
                downloader_tcp_port = $DownloaderTcpPort
                downloader_udp_port = $DownloaderUdpPort
                downloader_web_port = $DownloaderWebPort
                file_size_bytes = $FileSizeBytes
            }
        }
        Write-D01JsonAtomic -Value $run -Path $runPath
        Write-Host "V91-D01 RunNonce: $nonce" -ForegroundColor Cyan
        Write-Host (
            'Start Source role on Maria with this same RunNonce and ' +
            'the same fixture/candidate arguments.'
        ) -ForegroundColor Cyan

        $failureStage = 'source-ready'
        $readyWait = Wait-D01JsonFile -Path $readyPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $readyWait) {
            throw 'Timed out waiting for Maria source-ready.json'
        }
        $sourceReady = $readyWait.value
        if ([string]$sourceReady.schema -ne
                'ese.v91.d01-source-ready/v3' -or
            [string]$sourceReady.case_id -ne $caseId -or
            [string]$sourceReady.run_nonce -ne $nonce -or
            [string]$sourceReady.candidate.commit -ne
                $identityBefore.candidate.commit -or
            [string]$sourceReady.candidate.emule_sha256 -ne
                $expectedEmuleHash -or
            [string]$sourceReady.candidate.package_zip_sha256 -ne
                $expectedZipHash -or
            [string]$sourceReady.candidate.extracted_manifest_sha256 -ne
                $identityBefore.extracted_manifest.manifest_sha256 -or
            [string]$sourceReady.candidate.zip_manifest_sha256 -ne
                $identityBefore.zip_manifest.manifest_sha256 -or
            [Int64]$sourceReady.fixture.file_bytes -ne $FileSizeBytes -or
            [int]$sourceReady.process.process_id -le 0 -or
            -not [bool]$sourceReady.process.listener.ipv4_only -or
            -not [bool]$sourceReady.process.api_isolation_valid -or
            -not [bool]$sourceReady.firewall.rules_created -or
            -not [bool]$sourceReady.firewall.exact -or
            -not [bool]$sourceReady.firewall.ipv4_allow.exact -or
            -not [bool]$sourceReady.firewall.ipv6_drop.exact -or
            [string]$sourceReady.firewall.ipv6_drop.program -ne 'Any' -or
            [string]$sourceReady.firewall.ipv6_drop.remote_port -ne 'Any' -or
            [string]$sourceReady.firewall.ipv6_drop.profile -ne 'Any' -or
            [string]$sourceReady.firewall.AAAA_failure_mode -ne
                'controlled silent inbound DROP') {
            throw 'Maria source-ready evidence does not match the exact run'
        }
        if ([string]$sourceReady.machine_id_sha256 -eq
            [string]$coordinatorTopology.machine_id_sha256) {
            throw 'D01 requires two distinct physical machines'
        }
        $readyFirewallV4RemoteAddresses = @(
            @($sourceReady.firewall.ipv4_allow.remote_addresses) |
                ForEach-Object { [string]$_ } |
                Sort-Object -Unique
        )
        $readyTopologyAllowedRemoteAddresses = @(
            @($sourceReady.topology.allowed_inverse_remote_addresses) |
                ForEach-Object { [string]$_ } |
                Sort-Object -Unique
        )
        if ($readyTopologyAllowedRemoteAddresses.Count -eq 0 -or
            $readyFirewallV4RemoteAddresses.Count -ne
                $readyTopologyAllowedRemoteAddresses.Count -or
            @(Compare-Object `
                -ReferenceObject $readyTopologyAllowedRemoteAddresses `
                -DifferenceObject
                    $readyFirewallV4RemoteAddresses).Count -ne 0) {
            throw 'Maria IPv4 allow rule is not scoped to controlled peers'
        }

        $sourceTopology = $sourceReady.topology
        $samePhysicalV4Prefix =
            [string]$sourceTopology.source_local_ipv4.network_prefix -eq
                [string]$coordinatorTopology.
                    coordinator_local_ipv4.network_prefix
        $samePhysicalV6Prefix =
            [string]$sourceTopology.source_ipv6.network_prefix -eq
                [string]$coordinatorTopology.coordinator_ipv6.network_prefix
        $bilateralIpv6OnLink =
            [bool]$coordinatorTopology.route_to_source_ipv6.on_link -and
            [bool]$sourceTopology.route_to_coordinator_ipv6.on_link
        $t1 = $samePhysicalV4Prefix -and $samePhysicalV6Prefix -and
            $bilateralIpv6OnLink
        $nativeRoutedNextHopClasses = @(
            'linklocal-v6', 'ula-v6', 'global-v6'
        )
        $coordinatorV6NextHopClass =
            [string]$coordinatorTopology.
                route_to_source_ipv6.next_hop_class
        $sourceV6NextHopClass =
            [string]$sourceTopology.
                route_to_coordinator_ipv6.next_hop_class
        $t2Discriminator = -not $t1 -and
            $coordinatorV6NextHopClass -in $nativeRoutedNextHopClasses -and
            $sourceV6NextHopClass -in $nativeRoutedNextHopClasses
        $observedTopology = if ($t1) {
            'T1'
        } elseif ($t2Discriminator) { 'T2' } else { 'UNPROVEN' }
        $observedClass = if ($t1) {
            'T1-native-physical-same-prefix'
        } elseif ($t2Discriminator) {
            'T2-native-physical-routed-ipv6'
        } else {
            'UNPROVEN-native-topology'
        }
        $topologyValid =
            [bool]$coordinatorTopology.native_physical -and
            [bool]$sourceTopology.native_physical -and
            [bool]$coordinatorTopology.overlay_vpn_proxy_absent -and
            [bool]$sourceTopology.overlay_vpn_proxy_absent -and
            ($t1 -or $t2Discriminator)
        $topologyEvidence = [pscustomobject][ordered]@{
            observed_topology = $observedTopology
            observed_class = $observedClass
            accepted_topologies = @('T1', 'T2')
            distinct_machine_ids = $true
            coordinator = $coordinatorTopology
            source = $sourceTopology
            t1_direct_on_link = $t1
            t1_same_physical_ipv4_prefix = $samePhysicalV4Prefix
            t1_same_physical_ipv6_prefix = $samePhysicalV6Prefix
            t1_bilateral_ipv6_on_link = $bilateralIpv6OnLink
            t2_direct_native_discriminator = $t2Discriminator
            t2_coordinator_ipv6_next_hop_class =
                $coordinatorV6NextHopClass
            t2_source_ipv6_next_hop_class = $sourceV6NextHopClass
            nat_mapping_used_only_as_context = [ordered]@{
                source = $script:sourcePublicV4Text -ne
                    $script:sourceLocalV4Text
                coordinator = $script:coordinatorPublicV4Text -ne
                    $script:coordinatorLocalV4Text
            }
            no_overlay_vpn_proxy_data_plane = $true
            valid = $topologyValid
        }
        Write-LabJson -Value $topologyEvidence -Path (
            Join-Path $evidence 'topology.json'
        ) | Out-Null
        if (-not $topologyValid) {
            throw 'Observed topology is neither valid native T1 nor native T2'
        }

        $failureStage = 'dns-and-endpoint-fixture'
        $dnsInitial = Get-D01DnsEvidence -Name $canonicalHostname `
            -ExpectedA $script:sourcePublicV4Text `
            -ExpectedAAAA $script:sourceV6Text -Stage 'initial'
        Write-LabJson -Value $dnsInitial -Path (
            Join-Path $evidence 'dns-initial.json'
        ) | Out-Null
        if (-not $dnsInitial.exact_controlled_answer_set) {
            throw 'Controlled hostname does not resolve to exactly expected A+AAAA'
        }
        $aProbe = Test-D01TcpEndpoint -Address $script:sourcePublicV4Address `
            -Port $SourceTcpPort `
            -TimeoutMilliseconds $EndpointProbeTimeoutMilliseconds
        $aaaaProbe = Test-D01TcpEndpoint -Address $script:sourceV6Address `
            -Port $SourceTcpPort `
            -TimeoutMilliseconds $EndpointProbeTimeoutMilliseconds
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.d01-endpoint-probes/v2'
            captured_at_utc = Get-LabUtcTimestamp
            A = $aProbe
            AAAA = $aaaaProbe
        }) -Path (Join-Path $evidence 'endpoint-probes.json') | Out-Null
        if (-not $aProbe.connected) {
            throw 'Controlled A does not reach Maria source listener'
        }
        if ($aaaaProbe.connected -or -not $aaaaProbe.timed_out) {
            throw (
                'Controlled AAAA did not exhibit the required silent ' +
                'firewall DROP timeout'
            )
        }

        $failureStage = 'downloader-profile'
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
            -SourcePackage $identityBefore.candidate.package_path `
            -OutputRoot $nodes -RunId "v91-d01-$nonce" -PortOffset 6200
        $downloaderNode = Join-Path $nodes "v91-d01-$nonce-b"
        $downloaderExe = Join-Path $downloaderNode 'emule.exe'
        if ((Get-LabSha256 -Path $downloaderExe) -ne
            $expectedEmuleHash) {
            throw 'Prepared downloader executable is not exact candidate'
        }
        $incoming = New-LabDirectory `
            -Path (Join-Path $downloaderNode 'Incoming')
        $temp = New-LabDirectory -Path (Join-Path $downloaderNode 'Temp')
        foreach ($directory in @($incoming, $temp)) {
            if (@(Get-ChildItem -LiteralPath $directory -Force).Count -ne 0) {
                throw "Prepared downloader directory is not empty: $directory"
            }
        }
        $preferences = Set-D01IsolatedPreferences `
            -NodePath $downloaderNode -IPv6Mode 2 `
            -IPv6BindAddress $script:coordinatorV6Text `
            -WebPort $DownloaderWebPort -TcpPort $DownloaderTcpPort `
            -UdpPort $DownloaderUdpPort -IncomingPath $incoming `
            -TempPath $temp
        $controlledServer = Start-D01ControlledEd2kServer `
            -EvidencePath (
                Join-Path $evidence 'controlled-ed2k-server.json'
            ) -ListenAddress $script:coordinatorLocalV4Text `
            -ExpectedClientAddress $script:coordinatorLocalV4Text `
            -Nonce $nonce -PublishedOwner ([ref]$controlledServer)
        $controlledProfile = Enable-D01ControlledEd2kProfile `
            -NodePath $downloaderNode `
            -ServerAddress $script:coordinatorLocalV4Text `
            -ServerPort $controlledServer.port -Nonce $nonce
        $destinationFile = Join-Path $incoming `
            ([string]$sourceReady.fixture.file_name)

        $failureStage = 'downloader-startup'
        $downloader = Start-Process -FilePath $downloaderExe `
            -ArgumentList @(
                '--portable', '--ignoreinstances',
                "--metrics-port=$DownloaderWebPort",
                "--tcp-port=$DownloaderTcpPort",
                "--udp-port=$DownloaderUdpPort"
            ) -WorkingDirectory $downloaderNode -PassThru -WindowStyle Hidden
        $null = Wait-D01Listener -Port $DownloaderTcpPort `
            -Process $downloader
        $startupApi = Wait-D01Api -Port $DownloaderWebPort `
            -Process $downloader
        $controlledLogin = Wait-D01ControlledEd2kLogin `
            -Server $controlledServer -Process $downloader `
            -ExpectedTcpPort $DownloaderTcpPort
        $startupApi = Wait-D01Api -Port $DownloaderWebPort `
            -Process $downloader
        if (-not (Test-D01ApiIsolation -Data $startupApi `
            -AllowControlledEd2k)) {
            throw 'Downloader is not isolated on the controlled eD2K server'
        }
        if ((Get-LabSha256 -Path $downloader.Path) -ne
            $expectedEmuleHash) {
            throw 'Running downloader is not exact candidate'
        }

        $failureStage = 'observability-baseline'
        $baselineTelemetry = Get-D01TelemetrySnapshot `
            -Port $DownloaderWebPort
        Add-D01JsonLine -Path $telemetrySamplesPath `
            -Value $baselineTelemetry
        $baselineSequence = if (
            $baselineTelemetry.available -and
            $baselineTelemetry.contract_valid
        ) {
            [Int64]$baselineTelemetry.data.sequence
        } else { [Int64]0 }
        $captureClockAnchor = New-D01ClockAnchor
        Write-LabJson -Value $captureClockAnchor -Path (
            Join-Path $captureEvidencePath 'clock-anchor-start.json'
        ) | Out-Null
        $capture = Start-D01PacketCapture `
            -EvidencePath $captureEvidencePath -Nonce $nonce `
            -IPv4 $script:sourcePublicV4Text `
            -IPv6 $script:sourceV6Text -Port $SourceTcpPort
        Write-LabJson -Value $capture -Path (
            Join-Path $captureEvidencePath 'capture-start.json'
        ) | Out-Null
        Write-D01JsonAtomic -Value ([ordered]@{
            schema = 'ese.v91.d01-observe-command/v2'
            case_id = $caseId
            run_nonce = $nonce
            generated_at_utc = Get-LabUtcTimestamp
            candidate_commit = $identityBefore.candidate.commit
            candidate_emule_sha256 = $expectedEmuleHash
            downloader_process_id = $downloader.Id
            downloader_process_emule_sha256 =
                Get-LabSha256 -Path $downloader.Path
            hostname_sha256 =
                Get-LabStringSha256 -Value $canonicalHostname
            telemetry_baseline_sequence = $baselineSequence
            pktmon_started = [bool]$capture.started
        }) -Path $observePath
        $observeAckWait = Wait-D01JsonFile -Path $observeAckPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $observeAckWait) {
            throw 'Timed out waiting for source observation acknowledgement'
        }
        $observeAck = $observeAckWait.value
        $ackAllowedInverseAddresses = @(
            @($observeAck.allowed_source_visible_remote_addresses) |
                ForEach-Object {
                    Get-D01NormalizedIp -Address ([string]$_)
                } | Sort-Object -Unique
        )
        $readyAllowedInverseAddresses = @(
            @($sourceReady.topology.allowed_inverse_remote_addresses) |
                ForEach-Object {
                    Get-D01NormalizedIp -Address ([string]$_)
                } | Sort-Object -Unique
        )
        $allowedInverseAddressSetMatches =
            $ackAllowedInverseAddresses.Count -gt 0 -and
            $ackAllowedInverseAddresses.Count -eq
                $readyAllowedInverseAddresses.Count -and
            @(Compare-Object `
                -ReferenceObject $readyAllowedInverseAddresses `
                -DifferenceObject
                $ackAllowedInverseAddresses).Count -eq 0
        if ([string]$observeAck.schema -ne
                'ese.v91.d01-source-observing/v4' -or
            [string]$observeAck.case_id -ne $caseId -or
            [string]$observeAck.run_nonce -ne $nonce -or
            [int]$observeAck.source_process_id -ne
                [int]$sourceReady.process.process_id -or
            [int]$observeAck.expected_downloader_process_id -ne
                $downloader.Id -or
            -not [bool]$observeAck.
                all_processes_and_nonlisten_states_checked -or
            -not $allowedInverseAddressSetMatches -or
            -not [bool]$observeAck.baseline_zero -or
            [int]$observeAck.baseline_established_connection_count -ne 0 -or
            [int]$observeAck.baseline_nonlisten_connection_count -ne 0) {
            throw 'Invalid source observation acknowledgement'
        }

        $failureStage = 'product-transfer'
        $baseLink = [string]$sourceReady.fixture.shared_link
        if (-not $baseLink.StartsWith(
            'ed2k://|file|', [StringComparison]::OrdinalIgnoreCase
        ) -or -not $baseLink.EndsWith('|/')) {
            throw 'Source published an invalid ED2K file link'
        }
        $directLink = $baseLink +
            "|sources,$canonicalHostname`:$SourceTcpPort|/"
        $canonicalEndpoints = Get-D01CanonicalEndpointEvidence `
            -Addresses @(
                $script:sourcePublicV4Address,
                $script:sourceV6Address
            ) -Port $SourceTcpPort
        Write-LabJson -Value $canonicalEndpoints -Path (
            Join-Path $evidence 'canonical-endpoints.json'
        ) | Out-Null
        $coordinatorBaselineWaitStarted = [DateTime]::UtcNow
        $coordinatorBaselineWaitDeadline =
            $coordinatorBaselineWaitStarted.AddSeconds(
                [Math]::Max(
                    1, [Math]::Min(120, $PeerReadyTimeoutSeconds - 5)
                )
            )
        $coordinatorBaselineSampleCount = 0
        do {
            $coordinatorBaselineSampleCount++
            $coordinatorSocketBaseline = @(
                Get-D01TargetConnections -ProcessId 0 `
                    -RemoteAddresses @(
                        $script:sourcePublicV4Text,
                        $script:sourceV6Text
                    ) -RemotePort 0
            )
            if ($coordinatorSocketBaseline.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt
            $coordinatorBaselineWaitDeadline)
        $coordinatorSocketBaselineZero =
            $coordinatorSocketBaseline.Count -eq 0
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.d01-target-socket-baseline/v1'
            captured_at_utc = Get-LabUtcTimestamp
            candidate_process_id = $downloader.Id
            all_processes_checked = $true
            all_target_ports_checked = $true
            connection_count = $coordinatorSocketBaseline.Count
            baseline_zero = $coordinatorSocketBaselineZero
            baseline_wait_sample_count =
                $coordinatorBaselineSampleCount
            baseline_wait_duration_ms = [Int64](
                ([DateTime]::UtcNow -
                    $coordinatorBaselineWaitStarted).TotalMilliseconds
            )
            connections = $coordinatorSocketBaseline
        }) -Path (Join-Path $evidence 'target-socket-baseline.json') |
            Out-Null
        if (-not $coordinatorSocketBaselineZero) {
            throw 'A process has a pre-existing target socket before injection'
        }
        $caseArmed = [bool]$capture.available -and
            [bool]$capture.started -and
            [bool]$capture.filters_applied_verified
        if (-not $caseArmed) {
            throw 'External packet capture could not be armed exactly'
        }
        $injectionQpcStart = [Diagnostics.Stopwatch]::GetTimestamp()
        $transferStarted = [DateTime]::UtcNow
        $injection = Send-D01Ed2kLink -Process $downloader `
            -Link $directLink
        $injectionQpcEnd = [Diagnostics.Stopwatch]::GetTimestamp()
        $injectionClock = Get-D01ClockObservation `
            -Anchor $captureClockAnchor -QpcStart $injectionQpcStart `
            -QpcEnd $injectionQpcEnd
        $injection | Add-Member -NotePropertyName clock `
            -NotePropertyValue $injectionClock
        $captureWindowStartEpochUnixNs =
            [Int64]$injectionClock.epoch_unix_ns - [Int64]250000000
        $injectionCount = 1
        Write-LabJson -Value $injection -Path (
            Join-Path $evidence 'sole-link-injection.json'
        ) | Out-Null
        $deadline = $transferStarted.AddSeconds($TransferTimeoutSeconds)
        $nextHealth = [DateTime]::UtcNow
        $nextTelemetry = [DateTime]::UtcNow
        $completionObservedAt = $null
        do {
            $downloader.Refresh()
            if ($downloader.HasExited) {
                $productProcessExited = $true
                break
            }
            $now = [DateTime]::UtcNow
            $socketSampleQpcStart =
                [Diagnostics.Stopwatch]::GetTimestamp()
            $connections = @(
                Get-D01TargetConnections -ProcessId 0 `
                    -RemoteAddresses @(
                        $script:sourcePublicV4Text,
                        $script:sourceV6Text
                    ) -RemotePort 0
            )
            $socketSampleQpcEnd =
                [Diagnostics.Stopwatch]::GetTimestamp()
            $socketClock = Get-D01ClockObservation `
                -Anchor $captureClockAnchor `
                -QpcStart $socketSampleQpcStart `
                -QpcEnd $socketSampleQpcEnd
            foreach ($connection in $connections) {
                $connection | Add-Member -NotePropertyName sample_clock `
                    -NotePropertyValue $socketClock
            }
            $socketSampleCount++
            Add-D01JsonLine -Path $socketSamplesPath -Value ([ordered]@{
                schema = 'ese.v91.d01-target-socket-sample/v3'
                sample_number = $socketSampleCount
                captured_at_utc = Get-LabUtcTimestamp
                clock = $socketClock
                elapsed_ms = [Int64](
                    ($now - $transferStarted).TotalMilliseconds
                )
                connections = $connections
            })
            if (@($connections | Where-Object {
                [int]$_.remote_port -ne $SourceTcpPort
            }).Count -gt 0) {
                $sawWrongPortTargetSocket = $true
            }
            foreach ($connection in @($connections | Where-Object {
                [int]$_.owning_process -eq $downloader.Id -and
                [int]$_.remote_port -eq $SourceTcpPort
            })) {
                if ([string]$connection.remote_address -eq
                    $script:sourcePublicV4Text) {
                    $sawV4Socket = $true
                    if ([string]$connection.state -eq 'Established') {
                        $sawV4Established = $true
                        if ([bool]$connection.physical_nonvirtual) {
                            $sawV4Physical = $true
                            if ($null -eq $v4EstablishedEvidence) {
                                $v4EstablishedEvidence = $connection
                            }
                        }
                    }
                } elseif ([string]$connection.remote_address -eq
                    $script:sourceV6Text) {
                    $sawV6Socket = $true
                    $null = $v6ObservedStates.Add(
                        [string]$connection.state
                    )
                    if ([bool]$connection.physical_nonvirtual) {
                        $sawV6Physical = $true
                    }
                    if ([string]$connection.state -eq 'SynSent' -and
                        [bool]$connection.physical_nonvirtual -and
                        [string]$connection.local_address -eq
                            $script:coordinatorV6Text) {
                        $sawV6SynSent = $true
                        if ($null -eq $v6SynSentEvidence) {
                            $v6SynSentEvidence = $connection
                        }
                    }
                    if ([string]$connection.state -eq 'Established') {
                        $sawV6Established = $true
                    }
                }
            }
            if (@($connections | Where-Object {
                [int]$_.owning_process -ne $downloader.Id
            }).Count -gt 0) {
                $sawForeignTargetSocket = $true
            }
            if ($now -ge $nextHealth) {
                $api = Get-D01ApiProbe -Port $DownloaderWebPort `
                    -AllowControlledEd2k
                $ui = Get-D01UiProbe -Process $downloader
                $apiSamples++
                $uiSamples++
                if (-not $api.available) { $apiUnavailable++ }
                if ($api.available -and -not $api.isolation_valid) {
                    $apiIsolationFailures++
                }
                if (-not $ui.main_window_present) { $uiUnavailable++ }
                if ($ui.main_window_present -and
                    -not $ui.message_pump_responsive) {
                    $uiUnresponsive++
                }
                Add-D01JsonLine -Path $healthSamplesPath -Value ([ordered]@{
                    schema = 'ese.v91.d01-coordinator-health-sample/v2'
                    captured_at_utc = Get-LabUtcTimestamp
                    api = $api
                    ui = $ui
                })
                $nextHealth = $now.AddSeconds(2)
            }
            if ($now -ge $nextTelemetry) {
                $telemetrySample = Get-D01TelemetrySnapshot `
                    -Port $DownloaderWebPort `
                    -AfterSequence $baselineSequence
                Add-D01JsonLine -Path $telemetrySamplesPath `
                    -Value $telemetrySample
                if ($telemetrySample.available -and
                    $telemetrySample.contract_valid) {
                    $finalTelemetry = $telemetrySample
                }
                $nextTelemetry = $now.AddMilliseconds(500)
            }
            if (Test-Path -LiteralPath $destinationFile -PathType Leaf) {
                $destinationItem = Get-Item -LiteralPath $destinationFile
                if ([Int64]$destinationItem.Length -eq $FileSizeBytes) {
                    if ($null -eq $completionObservedAt) {
                        $completionObservedAt = $now
                    }
                    $hasTelemetryEvent = $null -ne $finalTelemetry -and
                        @($finalTelemetry.data.events).Count -gt 0
                    $hasInverse = Test-Path `
                        -LiteralPath $sourceObservationPath -PathType Leaf
                    if (($hasTelemetryEvent -and $hasInverse) -or
                        ($now - $completionObservedAt).TotalSeconds -ge 10) {
                        break
                    }
                }
            }
            if (($now - $transferStarted).TotalSeconds -lt 20) {
                Start-Sleep -Milliseconds 50
            } else {
                Start-Sleep -Milliseconds 250
            }
        } while ([DateTime]::UtcNow -lt $deadline)
        $transferFinished = [DateTime]::UtcNow
        if (Test-Path -LiteralPath $destinationFile -PathType Leaf) {
            $destinationBytes =
                [Int64](Get-Item -LiteralPath $destinationFile).Length
            if ($destinationBytes -eq $FileSizeBytes) {
                $destinationSha256 =
                    Get-LabSha256 -Path $destinationFile
                $transferCompleted = $destinationSha256 -eq
                    ([string]$sourceReady.fixture.file_sha256).
                        ToLowerInvariant()
            }
        }
        $finalTelemetry = Get-D01TelemetrySnapshot `
            -Port $DownloaderWebPort -AfterSequence $baselineSequence
        Add-D01JsonLine -Path $telemetrySamplesPath `
            -Value $finalTelemetry
        $telemetryVerdict = Get-D01TelemetryVerdict `
            -Snapshot $finalTelemetry `
            -BaselineSequence $baselineSequence `
            -HostnameSha256 (
                Get-LabStringSha256 -Value $canonicalHostname
            ) -FileEd2kHash ([string]$sourceReady.fixture.ed2k_hash) `
            -Port $SourceTcpPort `
            -CanonicalEndpoints $canonicalEndpoints
        Write-LabJson -Value $telemetryVerdict -Path (
            Join-Path $apiEvidencePath 'telemetry-verdict.json'
        ) | Out-Null
        if (Test-Path -LiteralPath $sourceObservationPath -PathType Leaf) {
            $sourceObservation =
                Get-Content -LiteralPath $sourceObservationPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
        }
        $dnsFinal = Get-D01DnsEvidence -Name $canonicalHostname `
            -ExpectedA $script:sourcePublicV4Text `
            -ExpectedAAAA $script:sourceV6Text -Stage 'final'
        Write-LabJson -Value $dnsFinal -Path (
            Join-Path $evidence 'dns-final.json'
        ) | Out-Null

        $allConnections = @(
            Get-NetTCPConnection -OwningProcess $downloader.Id `
                -ErrorAction SilentlyContinue
        )
        $unexpectedConnections = @(
            $allConnections | Where-Object {
                $remote = Get-D01NormalizedIp `
                    -Address ([string]$_.RemoteAddress)
                $remotePort = [int]$_.RemotePort
                $unspecified = $remote -in @('0.0.0.0', '::') -or
                    $remotePort -eq 0
                $loopbackApi = $remote -in @('127.0.0.1', '::1')
                $controlledScheduler =
                    $remote -eq $script:coordinatorLocalV4Text -and
                    $null -ne $controlledServer -and
                    $remotePort -eq [int]$controlledServer.port
                $controlledSource =
                    $remote -in @(
                        $script:sourcePublicV4Text,
                        $script:sourceV6Text
                    ) -and $remotePort -eq $SourceTcpPort
                -not (
                    $unspecified -or $loopbackApi -or
                    $controlledScheduler -or $controlledSource
                )
            } | ForEach-Object {
                [pscustomobject][ordered]@{
                    state = [string]$_.State
                    remote_address = Get-D01NormalizedIp `
                        -Address ([string]$_.RemoteAddress)
                    remote_port = [int]$_.RemotePort
                    owning_process = [int]$_.OwningProcess
                }
            }
        )
    } catch {
        $runtimeError = $_.Exception.Message
    } finally {

        if ($null -ne $capture) {
            try {
                $captureEndQpc = [Diagnostics.Stopwatch]::GetTimestamp()
                $captureEndClock = Get-D01ClockObservation `
                    -Anchor $captureClockAnchor `
                    -QpcStart $captureEndQpc -QpcEnd $captureEndQpc
                $captureWindowEndEpochUnixNs =
                    [Int64]$captureEndClock.epoch_unix_ns + [Int64]250000000
                if ($captureWindowStartEpochUnixNs -eq 0) {
                    $captureWindowStartEpochUnixNs =
                        [Int64]$captureClockAnchor.anchor_epoch_unix_ns
                }
                $captureClockEndAnchor = New-D01ClockAnchor
                Write-LabJson -Value $captureClockEndAnchor -Path (
                    Join-Path $captureEvidencePath 'clock-anchor-end.json'
                ) | Out-Null
                Stop-D01PacketCapture -State $capture `
                    -CleanupFailures $cleanupFailures
                Write-LabJson -Value $capture -Path (
                    Join-Path $captureEvidencePath 'capture-final.json'
                ) | Out-Null
                $captureEvidence = Get-D01PacketCaptureEvidence `
                    -State $capture -IPv4 $script:sourcePublicV4Text `
                    -IPv6 $script:sourceV6Address `
                    -CoordinatorIPv4 $script:coordinatorLocalV4Text `
                    -CoordinatorIPv6 $script:coordinatorV6Address `
                    -Port $SourceTcpPort `
                    -SocketSamplesPath $socketSamplesPath `
                    -CandidateProcessId $downloader.Id `
                    -ClockAnchor $captureClockAnchor `
                    -ClockEndAnchor $captureClockEndAnchor `
                    -WindowStartEpochUnixNs `
                        $captureWindowStartEpochUnixNs `
                    -WindowEndEpochUnixNs `
                        $captureWindowEndEpochUnixNs
                Write-LabJson -Value $captureEvidence -Path (
                    Join-Path $captureEvidencePath 'capture-verdict.json'
                ) | Out-Null
            } catch {
                $cleanupFailures.Add(
                    "Packet capture finalization failed: $($_.Exception.Message)"
                )
            }
        }
        if ($null -ne $downloader) {
            if ($null -eq $finalTelemetry) {
                try {
                    $after = if ($null -ne $baselineTelemetry -and
                        $baselineTelemetry.available -and
                        $baselineTelemetry.contract_valid) {
                        [Int64]$baselineTelemetry.data.sequence
                    } else { [Int64]0 }
                    $finalTelemetry = Get-D01TelemetrySnapshot `
                        -Port $DownloaderWebPort -AfterSequence $after
                    Add-D01JsonLine -Path $telemetrySamplesPath `
                        -Value $finalTelemetry
                } catch {}
            }
            if ($null -eq $dnsFinal) {
                try {
                    $dnsFinal = Get-D01DnsEvidence `
                        -Name $canonicalHostname `
                        -ExpectedA $script:sourcePublicV4Text `
                        -ExpectedAAAA $script:sourceV6Text `
                        -Stage 'final'
                    Write-LabJson -Value $dnsFinal -Path (
                        Join-Path $evidence 'dns-final.json'
                    ) | Out-Null
                } catch {}
            }
            $stopDownloader = Stop-D01OwnedProcess `
                -Process $downloader -ExpectedPath $downloaderExe
            if (-not $stopDownloader.stopped) {
                $cleanupFailures.Add('Downloader process remains running')
            }
        }
        $controlledServerStop =
            Stop-D01ControlledEd2kServer -Server $controlledServer
        if (-not $controlledServerStop.stopped -or
            $controlledServerStop.error) {
            $cleanupFailures.Add(
                'Controlled eD2K server did not stop cleanly'
            )
        }
        if (-not (Test-Path -LiteralPath $stopPath -PathType Leaf)) {
            try {
                Write-D01JsonAtomic -Value ([ordered]@{
                    schema = 'ese.v91.d01-stop-command/v2'
                    case_id = $caseId
                    run_nonce = $nonce
                    generated_at_utc = Get-LabUtcTimestamp
                    candidate_commit = if ($null -ne $identityBefore) {
                        $identityBefore.candidate.commit
                    } else { $Commit.ToLowerInvariant() }
                    candidate_emule_sha256 = $expectedEmuleHash
                    action = 'stop-owned-source'
                }) -Path $stopPath
                $stopPublished = $true
            } catch {
                $cleanupFailures.Add(
                    "Source stop command could not be published: $($_.Exception.Message)"
                )
            }
        } else {
            $stopPublished = $true
        }
        try {
            $sourceResultWait = Wait-D01JsonFile `
                -Path $sourceResultPath -TimeoutSeconds 120
            if ($null -ne $sourceResultWait) {
                $sourceResult = $sourceResultWait.value
            }
        } catch {}
        if ($null -eq $sourceObservation -and
            (Test-Path -LiteralPath $sourceObservationPath -PathType Leaf)) {
            try {
                $sourceObservation =
                    Get-Content -LiteralPath $sourceObservationPath -Raw |
                        ConvertFrom-Json -ErrorAction Stop
            } catch {}
        }
        try {
            $identityAfter = Get-D01CandidateIdentity
            Write-LabJson -Value $identityAfter.extracted_manifest -Path (
                Join-Path $evidence 'package-manifest-after.json'
            ) | Out-Null
            Write-LabJson -Value $identityAfter.zip_manifest -Path (
                Join-Path $evidence 'zip-manifest-after.json'
            ) | Out-Null
            $candidateUnchanged = $null -ne $identityBefore -and
                $identityAfter.exact -and
                $identityAfter.extracted_manifest.manifest_sha256 -eq
                    $identityBefore.extracted_manifest.manifest_sha256 -and
                $identityAfter.zip_manifest.zip_sha256 -eq
                    $identityBefore.zip_manifest.zip_sha256
            if (-not $candidateUnchanged) {
                $cleanupFailures.Add(
                    'Coordinator candidate package or ZIP changed'
                )
            }
        } catch {
            $cleanupFailures.Add(
                "Coordinator identity revalidation failed: $($_.Exception.Message)"
            )
        }
        if ($downloaderExe -and
            (Test-Path -LiteralPath $downloaderExe -PathType Leaf)) {
            $nodeExeUnchanged =
                (Get-LabSha256 -Path $downloaderExe) -eq
                    $expectedEmuleHash
        }
        if (-not $nodeExeUnchanged) {
            $cleanupFailures.Add('Prepared downloader executable changed')
        }
    }

    if ($null -eq $telemetryVerdict -and
        $null -ne $finalTelemetry -and $null -ne $sourceReady) {
        try {
            $baselineSequence = if ($null -ne $baselineTelemetry -and
                $baselineTelemetry.available -and
                $baselineTelemetry.contract_valid) {
                [Int64]$baselineTelemetry.data.sequence
            } else { [Int64]0 }
            $canonicalEndpoints =
                Get-D01CanonicalEndpointEvidence -Addresses @(
                    $script:sourcePublicV4Address,
                    $script:sourceV6Address
                ) -Port $SourceTcpPort
            $telemetryVerdict = Get-D01TelemetryVerdict `
                -Snapshot $finalTelemetry `
                -BaselineSequence $baselineSequence `
                -HostnameSha256 (
                    Get-LabStringSha256 -Value $canonicalHostname
                ) -FileEd2kHash (
                    [string]$sourceReady.fixture.ed2k_hash
                ) -Port $SourceTcpPort `
                -CanonicalEndpoints $canonicalEndpoints
        } catch {}
    }

    $baselineTelemetryObservable =
        $null -ne $baselineTelemetry -and
        $baselineTelemetry.available -and
        $baselineTelemetry.contract_valid
    $finalTelemetryObservable =
        $null -ne $finalTelemetry -and
        $finalTelemetry.available -and
        $finalTelemetry.contract_valid
    $captureSubstrateObservable =
        $null -ne $capture -and $null -ne $captureEvidence -and
        [bool]$capture.available -and
        [bool]$capture.capture_started_verified -and
        [bool]$capture.filters_applied_verified -and
        [bool]$captureEvidence.capture_observability_pass

    $sourceFirewallFixtureValid = $false
    if ($null -ne $sourceReady) {
        try {
            $firewallV4RemoteAddresses = @(
                @($sourceReady.firewall.ipv4_allow.remote_addresses) |
                    ForEach-Object { [string]$_ } |
                    Sort-Object -Unique
            )
            $topologyAllowedRemoteAddresses = @(
                @($sourceReady.topology.
                    allowed_inverse_remote_addresses) |
                    ForEach-Object { [string]$_ } |
                    Sort-Object -Unique
            )
            $firewallV4RemoteSetExact =
                $topologyAllowedRemoteAddresses.Count -gt 0 -and
                $firewallV4RemoteAddresses.Count -eq
                    $topologyAllowedRemoteAddresses.Count -and
                @(Compare-Object `
                    -ReferenceObject $topologyAllowedRemoteAddresses `
                    -DifferenceObject
                        $firewallV4RemoteAddresses).Count -eq 0
            $sourceFirewallFixtureValid =
                [bool]$sourceReady.firewall.rules_created -and
                [bool]$sourceReady.firewall.exact -and
                [bool]$sourceReady.firewall.ipv4_allow.exact -and
                $firewallV4RemoteSetExact -and
                [bool]$sourceReady.firewall.ipv6_drop.exact -and
                [string]$sourceReady.firewall.ipv6_drop.program -eq 'Any' -and
                [string]$sourceReady.firewall.ipv6_drop.remote_port -eq
                    'Any' -and
                [string]$sourceReady.firewall.ipv6_drop.profile -eq 'Any' -and
                [string]$sourceReady.firewall.AAAA_failure_mode -eq
                    'controlled silent inbound DROP'
        } catch {}
    }
    $sourceFirewallCleanupFailed = $false
    if ($null -ne $sourceResult) {
        try {
            $sourceFirewallCleanupFailed =
                -not [bool]$sourceResult.cleanup.
                    temporary_firewall_rules_removed
        } catch {}
    }

    $fixtureReasons = New-Object 'Collections.Generic.List[string]'
    $observabilityReasons = New-Object 'Collections.Generic.List[string]'
    $productReasons = New-Object 'Collections.Generic.List[string]'
    if ($null -eq $identityBefore -or -not $identityBefore.exact) {
        $fixtureReasons.Add('exact candidate package/ZIP fixture was not proven')
    }
    if ($null -eq $sourceReady) {
        $fixtureReasons.Add('controlled Maria source never reached ready barrier')
    }
    if (-not $sourceFirewallFixtureValid) {
        $fixtureReasons.Add(
            'exact IPv4 allow and controlled IPv6 DROP fixture was not proven'
        )
    }
    if ($null -eq $topologyEvidence -or -not $topologyEvidence.valid) {
        $fixtureReasons.Add('direct native T1/T2 topology was not proven')
    }
    if ($null -eq $isolation -or -not $isolation.strict_isolation_valid) {
        $fixtureReasons.Add('overlay/VPN/proxy isolation was not valid')
    }
    if ($null -eq $dnsInitial -or
        -not $dnsInitial.exact_controlled_answer_set -or
        $null -eq $dnsFinal -or
        -not $dnsFinal.exact_controlled_answer_set) {
        $fixtureReasons.Add('exact controlled A+AAAA DNS set was not stable')
    }
    if ($null -eq $aProbe -or -not $aProbe.connected) {
        $fixtureReasons.Add('baseline A reachability was not proven')
    }
    if ($null -eq $aaaaProbe -or $aaaaProbe.connected -or
        -not $aaaaProbe.timed_out) {
        $fixtureReasons.Add(
            'baseline AAAA controlled silent DROP timeout was not proven'
        )
    }
    if ($null -eq $controlledLogin -or -not $controlledLogin.connected) {
        $fixtureReasons.Add('controlled minimal eD2K scheduler was not proven')
    }
    if (-not $caseArmed) {
        $fixtureReasons.Add('controlled product case never reached armed boundary')
    }
    if ($sourceFirewallCleanupFailed) {
        $fixtureReasons.Add('temporary source firewall rules were not rolled back')
    }
    if ($runtimeError -and -not $caseArmed) {
        $fixtureReasons.Add(
            "pre-arming infrastructure error during $failureStage"
        )
    }
    $fixtureStatus = if ($fixtureReasons.Count -eq 0) {
        'PASS'
    } else { 'BLOCKED' }

    if (-not $captureSubstrateObservable) {
        $observabilityReasons.Add(
            'armed, lossless and fully restored PktMon+ETW capture was unavailable'
        )
    }
    $observabilityStatus = if ($observabilityReasons.Count -eq 0) {
        'PASS'
    } else { 'BLOCKED' }

    [Int64]$hairpinClockToleranceMs = 1000
    $sourceObservationInWindow = $false
    $coordinatorObservationInWindow = $false
    $hairpinObservationDeltaMs = $null
    if ($null -ne $sourceObservation -and
        $null -ne $v4EstablishedEvidence -and $null -ne $injection) {
        try {
            $sourceObservedAt = [DateTimeOffset]::Parse(
                [string]$sourceObservation.captured_at_utc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            ).UtcDateTime
            $coordinatorObservedAt = [DateTimeOffset]::Parse(
                [string]$v4EstablishedEvidence.captured_at_utc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            ).UtcDateTime
            $hairpinObservationDeltaMs = [Int64][Math]::Abs(
                ($sourceObservedAt - $coordinatorObservedAt).
                    TotalMilliseconds
            )
            $sourceObservationInWindow =
                $hairpinObservationDeltaMs -le $hairpinClockToleranceMs
            $coordinatorEpoch =
                [Int64]$v4EstablishedEvidence.sample_clock.epoch_unix_ns
            $coordinatorObservationInWindow =
                $coordinatorEpoch -ge
                    [Int64]$injection.clock.epoch_unix_ns -and
                $coordinatorEpoch -le $captureWindowEndEpochUnixNs
        } catch {}
    }
    $inverseStructureValid = $false
    if ($null -ne $sourceObservation -and $null -ne $sourceReady) {
        try {
            $inverseStructureValid =
                [string]$sourceObservation.schema -eq
                    'ese.v91.d01-source-observation/v4' -and
                [string]$sourceObservation.run_nonce -eq $nonce -and
                [bool]$sourceObservation.exact_inverse_pid_socket -and
                [bool]$sourceObservation.physical_adapter_proven -and
                [bool]$sourceObservation.baseline_zero -and
                [int]$sourceObservation.
                    baseline_established_connection_count -eq 0 -and
                [int]$sourceObservation.
                    baseline_nonlisten_connection_count -eq 0 -and
                [bool]$sourceObservation.
                    all_processes_and_nonlisten_states_checked -and
                [bool]$sourceObservation.
                    source_visible_remote_address_allowed -and
                [int]$sourceObservation.foreign_connection_count -eq 0 -and
                [int]$sourceObservation.
                    all_nonlisten_unique_socket_count -eq 1 -and
                [int]$sourceObservation.unique_new_socket_count -eq 1 -and
                [int]$sourceObservation.ambiguity_count -eq 0 -and
                [int]$sourceObservation.generation_count -eq 1 -and
                [bool]$sourceObservation.
                    hairpin_nat_remote_address_not_assumed -and
                [int]$sourceObservation.source_process_id -eq
                    [int]$sourceReady.process.process_id -and
                [int]$sourceObservation.connection.owning_process -eq
                    [int]$sourceReady.process.process_id -and
                [string]$sourceObservation.connection.state -eq
                    'Established' -and
                [string]$sourceObservation.connection.local_address -eq
                    $script:sourceLocalV4Text -and
                [int]$sourceObservation.connection.local_port -eq
                    $SourceTcpPort -and
                [bool]$sourceObservation.connection.physical_nonvirtual -and
                [string]$sourceObservation.connection.remote_address -in
                    @($sourceReady.topology.
                        allowed_inverse_remote_addresses) -and
                [int]$sourceObservation.connection.remote_port -gt 0
        } catch {}
    }
    $v4CoordinatorSocketValid = $false
    if ($null -ne $v4EstablishedEvidence -and $null -ne $downloader) {
        try {
            $v4CoordinatorSocketValid =
                [int]$v4EstablishedEvidence.owning_process -eq
                    [int]$downloader.Id -and
                [string]$v4EstablishedEvidence.state -eq 'Established' -and
                [string]$v4EstablishedEvidence.local_address -eq
                    $script:coordinatorLocalV4Text -and
                [int]$v4EstablishedEvidence.local_port -gt 0 -and
                [string]$v4EstablishedEvidence.remote_address -eq
                    $script:sourcePublicV4Text -and
                [int]$v4EstablishedEvidence.remote_port -eq $SourceTcpPort -and
                [bool]$v4EstablishedEvidence.physical_nonvirtual
        } catch {}
    }
    $exactInverseTupleLinked = $false
    if ($null -ne $sourceObservation -and
        $null -ne $v4EstablishedEvidence) {
        try {
            $exactInverseTupleLinked =
                [string]$sourceObservation.connection.local_address -eq
                    $script:sourceLocalV4Text -and
                [int]$sourceObservation.connection.local_port -eq
                    $SourceTcpPort -and
                [string]$sourceObservation.connection.remote_address -in
                    @(
                        [string]$v4EstablishedEvidence.local_address,
                        $script:coordinatorPublicV4Text
                    ) -and
                [int]$sourceObservation.connection.remote_port -eq
                    [int]$v4EstablishedEvidence.local_port
        } catch {}
    }
    $v4PcapSocketLinked = $false
    if ($null -ne $captureEvidence -and
        $null -ne $v4EstablishedEvidence) {
        try {
            $v4PcapSocketLinked = @(
                @($captureEvidence.per_syn_correlations) |
                    Where-Object {
                        [string]$_.family -eq 'ipv4' -and
                        [bool]$_.attributed -and
                        [int]$_.matched_sampler_row.owning_process -eq
                            [int]$downloader.Id -and
                        [int]$_.matched_sampler_row.local_port -eq
                            [int]$v4EstablishedEvidence.local_port
                    }
            ).Count -gt 0
        } catch {}
    }
    $inverseValid = $inverseStructureValid -and
        $v4CoordinatorSocketValid -and $exactInverseTupleLinked -and
        $v4PcapSocketLinked -and $coordinatorSocketBaselineZero
    if ($caseArmed -and -not $exactInverseTupleLinked) {
        $fixtureReasons.Add(
            'source-visible inverse tuple was rewritten or not proven exactly'
        )
        $fixtureStatus = 'BLOCKED'
    }
    $sourceReadyTopology = Get-D01OptionalProperty `
        -InputObject $sourceReady -Name 'topology'
    $sourceAllowedInverseAddresses = @(
        Get-D01OptionalProperty -InputObject $sourceReadyTopology `
            -Name 'allowed_inverse_remote_addresses' -DefaultValue @()
    )
    $hairpinCorrelation = [ordered]@{
        valid = $inverseValid
        source_pid_and_local_port_valid = $inverseStructureValid
        coordinator_pid_socket_valid = $v4CoordinatorSocketValid
        exact_cross_host_inverse_tuple_linked =
            $exactInverseTupleLinked
        source_observation_in_window = $sourceObservationInWindow
        coordinator_observation_in_window =
            $coordinatorObservationInWindow
        coordinator_socket_baseline_zero =
            $coordinatorSocketBaselineZero
        source_socket_baseline_zero = [bool](
            Get-D01OptionalProperty -InputObject $sourceObservation `
                -Name 'baseline_zero' -DefaultValue $false
        )
        source_all_nonlisten_states_baselined = [bool](
            Get-D01OptionalProperty -InputObject $sourceObservation `
                -Name 'all_processes_and_nonlisten_states_checked' `
                -DefaultValue $false
        )
        source_foreign_connection_count = [int](
            Get-D01OptionalProperty -InputObject $sourceObservation `
                -Name 'foreign_connection_count' -DefaultValue -1
        )
        source_visible_remote_address_allowlist =
            $sourceAllowedInverseAddresses
        pcap_syn_linked_by_pid_and_local_port = $v4PcapSocketLinked
        coordinator_local_port = if ($null -ne $v4EstablishedEvidence) {
            [int]$v4EstablishedEvidence.local_port
        } else { 0 }
        cross_host_observation_delta_ms = $hairpinObservationDeltaMs
        maximum_cross_host_delta_ms = $hairpinClockToleranceMs
        source_remote_address_equality_required = $true
        source_remote_port_equality_required = $true
        rationale =
            'Formal PASS requires Maria to see the coordinator local/public ' +
            'address with its exact ephemeral port; SNAT rewriting makes ' +
            'the fixture BLOCKED'
    }

    $v6SocketEvidenceValid = $false
    if ($null -ne $v6SynSentEvidence -and $null -ne $downloader) {
        try {
            $v6SocketEvidenceValid =
                [int]$v6SynSentEvidence.owning_process -eq
                    [int]$downloader.Id -and
                [string]$v6SynSentEvidence.state -eq 'SynSent' -and
                [string]$v6SynSentEvidence.local_address -eq
                    $script:coordinatorV6Text -and
                [int]$v6SynSentEvidence.local_port -gt 0 -and
                [string]$v6SynSentEvidence.remote_address -eq
                    $script:sourceV6Text -and
                [int]$v6SynSentEvidence.remote_port -eq $SourceTcpPort -and
                [bool]$v6SynSentEvidence.physical_nonvirtual
        } catch {}
    }
    if ($caseArmed) {
        if (-not $baselineTelemetryObservable -or
            -not $finalTelemetryObservable) {
            $productReasons.Add(
                'localhost product telemetry endpoint/contract was unavailable'
            )
        }
        if ($null -eq $telemetryVerdict -or
            -not $telemetryVerdict.exactly_one_new_event -or
            -not $telemetryVerdict.product_contract_pass) {
            $productReasons.Add(
                'one exact canonical A+AAAA materialization event was not proven'
            )
        }
        if ($captureSubstrateObservable) {
            if (-not $captureEvidence.correlation_pass -or
                -not $captureEvidence.ipv4_exact_tuple_correlated) {
                $productReasons.Add(
                    'PCAP/SYN sampler did not correlate every exact physical A tuple'
                )
            }
            if (-not $captureEvidence.correlation_pass -or
                -not $captureEvidence.ipv6_exact_tuple_correlated) {
                $productReasons.Add(
                    'PCAP/SYN sampler did not correlate every exact physical AAAA tuple'
                )
            }
        }
        if (-not $sawV4Socket -or -not $sawV4Established -or
            -not $sawV4Physical -or -not $v4CoordinatorSocketValid) {
            $productReasons.Add(
                'A connection was not attributed to downloader PID/physical route'
            )
        }
        if ($exactInverseTupleLinked -and
            $captureSubstrateObservable -and -not $v4PcapSocketLinked) {
            $productReasons.Add(
                'exact Maria inverse tuple lacked the coordinator PCAP/PID link'
            )
        }
        if (-not $sawV6Socket -or -not $sawV6Physical -or
            -not $sawV6SynSent -or -not $v6SocketEvidenceValid) {
            $productReasons.Add(
                'AAAA attempt lacked exact PID/physical SynSent attribution'
            )
        }
        if ($sawV6Established) {
            $productReasons.Add(
                'failing AAAA candidate unexpectedly established'
            )
        }
        if (-not $transferCompleted) {
            $productReasons.Add('one-file transfer did not complete hash-intact')
        }
        if ($injectionCount -ne 1 -or $null -eq $injection -or
            -not $injection.one_injection) {
            $productReasons.Add('ordinary hostname link was not injected exactly once')
        }
        if ($socketSampleCount -eq 0) {
            $productReasons.Add('coordinator PID socket sampler did not run')
        }
        if ($apiSamples -eq 0 -or $uiSamples -eq 0 -or
            $apiUnavailable -ne 0 -or $uiUnavailable -ne 0) {
            $productReasons.Add(
                'coordinator API/UI availability was not continuous'
            )
        }
        if ($apiIsolationFailures -ne 0) {
            $productReasons.Add(
                'API reported Kad/NetLab/third-party eD2K contamination'
            )
        }
        if ($uiUnresponsive -ne 0) {
            $productReasons.Add('UI message pump became unresponsive')
        }
        if ($null -eq $sourceResult) {
            $productReasons.Add(
                'Maria source result was unavailable after case arming'
            )
        } else {
            try {
                if ([string]$sourceResult.status -ne 'COMPLETE') {
                    $productReasons.Add(
                        'Maria source did not complete the armed product case'
                    )
                }
                if (-not [bool]$sourceResult.health.
                        observability_available -or
                    [int]$sourceResult.health.api_unavailable_count -ne 0 -or
                    [int]$sourceResult.health.ui_unavailable_count -ne 0) {
                    $productReasons.Add(
                        'Maria PID/API/UI availability was not continuous'
                    )
                }
                if ([int]$sourceResult.health.
                        api_isolation_failure_count -ne 0) {
                    $productReasons.Add(
                        'Maria API reported network isolation contamination'
                    )
                }
                if ([int]$sourceResult.health.ui_unresponsive_count -ne 0) {
                    $productReasons.Add(
                        'Maria UI message pump became unresponsive'
                    )
                }
                if (-not [bool]$sourceResult.cleanup.
                        source_process_stopped) {
                    $productReasons.Add(
                        'Maria source process did not stop after the case'
                    )
                }
                if (-not [bool]$sourceResult.candidate.unchanged -or
                    -not [bool]$sourceResult.candidate.
                        prepared_executable_unchanged) {
                    $productReasons.Add(
                        'Maria candidate identity changed during the armed case'
                    )
                }
                if (-not [bool]$sourceResult.
                        inverse_socket_baseline_zero -or
                    -not [bool]$sourceResult.
                        inverse_socket_baseline_all_nonlisten_states_checked -or
                    [int]$sourceResult.
                        inverse_socket_foreign_connection_count -ne 0 -or
                    [int]$sourceResult.
                        inverse_socket_all_nonlisten_unique_count -ne 1 -or
                    [int]$sourceResult.
                        inverse_socket_unique_new_count -ne 1 -or
                    [int]$sourceResult.
                        inverse_socket_ambiguity_count -ne 0 -or
                    [int]$sourceResult.
                        inverse_socket_generation_count -ne 1) {
                    $productReasons.Add(
                        'Maria inverse socket was pre-existing, foreign, ambiguous or reused'
                    )
                }
            } catch {
                $productReasons.Add(
                    'Maria source result contract was malformed'
                )
            }
        }
        if (-not $candidateUnchanged -or -not $nodeExeUnchanged) {
            $productReasons.Add(
                'coordinator candidate identity changed during the armed case'
            )
        }
        if ($unexpectedConnections.Count -ne 0) {
            $productReasons.Add(
                'downloader opened a third-party/unexpected socket'
            )
        }
        if ($sawForeignTargetSocket) {
            $productReasons.Add(
                'a foreign PID opened a target A/AAAA socket during the case'
            )
        }
        if ($sawWrongPortTargetSocket) {
            $productReasons.Add(
                'a target A/AAAA socket used a non-fixture destination port'
            )
        }
        $nonCaptureCleanupFailures = @(
            $cleanupFailures | Where-Object {
                [string]$_ -notmatch
                    '(?i)pktmon|packet capture|ETW|capture finalization'
            }
        )
        if ($nonCaptureCleanupFailures.Count -ne 0) {
            $productReasons.Add(
                'post-arming process, identity or cleanup checks failed'
            )
        }
        if ($null -eq $controlledServerStop -or
            -not $controlledServerStop.stopped -or
            $controlledServerStop.error -or
            -not [bool]$controlledServerStop.ownership.
                all_owned_resources_released) {
            $productReasons.Add(
                'controlled minimal eD2K scheduler did not stop cleanly'
            )
        }
        if (-not $stopPublished) {
            $productReasons.Add('Maria stop command was not published')
        }
        if ($productProcessExited) {
            $productReasons.Add('downloader exited during the product case')
        }
        if ($runtimeError -and $caseArmed) {
            $productReasons.Add("product-stage error: $runtimeError")
        }
    }
    $adjudication = Get-D01AdjudicationStatus `
        -CaseArmed $caseArmed -FixtureStatus $fixtureStatus `
        -ObservabilityStatus $observabilityStatus `
        -ProductFailureCount $productReasons.Count
    $productStatus = [string]$adjudication.product_status
    $formalStatus = [string]$adjudication.formal_status
    $sourceResultHealth = Get-D01OptionalProperty `
        -InputObject $sourceResult -Name 'health'
    $sourceResultCleanup = Get-D01OptionalProperty `
        -InputObject $sourceResult -Name 'cleanup'
    $sourceResultStatus = [string](
        Get-D01OptionalProperty -InputObject $sourceResult `
            -Name 'status' -DefaultValue 'UNAVAILABLE'
    )

    $summary = [ordered]@{
        schema = 'ese.v91.d01-dual-dns/v2'
        case_id = $caseId
        run_nonce = $nonce
        case_armed = $caseArmed
        formal_status = $formalStatus
        fixture_status = $fixtureStatus
        observability_status = $observabilityStatus
        product_status = $productStatus
        exit_code = if ($formalStatus -eq 'PASS') {
            0
        } elseif ($formalStatus -eq 'FAIL') { 1 } else { 2 }
        observed_topology = if ($null -ne $topologyEvidence) {
            $topologyEvidence.observed_topology
        } else { 'NOT_PROVEN' }
        accepted_topologies = @('T1', 'T2')
        candidate = [ordered]@{
            commit = if ($null -ne $identityBefore) {
                $identityBefore.candidate.commit
            } else { $Commit.ToLowerInvariant() }
            emule_sha256 = $expectedEmuleHash
            package_zip_sha256 = $expectedZipHash
            extracted_manifest_sha256 = if ($null -ne $identityBefore) {
                $identityBefore.extracted_manifest.manifest_sha256
            } else { '' }
            zip_manifest_sha256 = if ($null -ne $identityBefore) {
                $identityBefore.zip_manifest.manifest_sha256
            } else { '' }
            zip_matches_extracted_directory =
                $null -ne $identityBefore -and
                $identityBefore.zip_matches_extracted_directory
            candidate_unchanged = $candidateUnchanged
            prepared_executable_unchanged = $nodeExeUnchanged
        }
        timing = [ordered]@{
            started_at_utc = $startedAt.ToString('o')
            transfer_started_at_utc = if ($null -ne $transferStarted) {
                $transferStarted.ToString('o')
            } else { $null }
            transfer_finished_at_utc = if ($null -ne $transferFinished) {
                $transferFinished.ToString('o')
            } else { $null }
            finished_at_utc = Get-LabUtcTimestamp
        }
        topology = $topologyEvidence
        controlled_dns = [ordered]@{
            hostname = $canonicalHostname
            hostname_sha256 =
                Get-LabStringSha256 -Value $canonicalHostname
            expected_A = $script:sourcePublicV4Text
            expected_AAAA = $script:sourceV6Text
            initial = $dnsInitial
            final = $dnsFinal
            A_baseline_probe = $aProbe
            AAAA_baseline_probe = $aaaaProbe
        }
        scheduler_isolation = [ordered]@{
            controlled_profile = $controlledProfile
            controlled_login = $controlledLogin
            controlled_server_stop = $controlledServerStop
            kad_disabled = $true
            netlab_disabled = $true
            third_party_server_files_removed = $true
            unexpected_connection_count = $unexpectedConnections.Count
            unexpected_connections = $unexpectedConnections
            overlay_vpn_proxy_absent =
                $null -ne $isolation -and
                $isolation.strict_isolation_valid
        }
        telemetry = [ordered]@{
            endpoint =
                'http://127.0.0.1:<port>/api/debug/source-resolutions'
            query_after_used = $true
            baseline = $baselineTelemetry
            final = $finalTelemetry
            verdict = $telemetryVerdict
        }
        packet_capture = $captureEvidence
        sockets = [ordered]@{
            coordinator_sample_count = $socketSampleCount
            all_target_ports_sampled = $true
            wrong_port_target_socket_observed =
                $sawWrongPortTargetSocket
            foreign_pid_target_socket_observed =
                $sawForeignTargetSocket
            A_socket_observed = $sawV4Socket
            A_established = $sawV4Established
            A_established_on_physical_adapter = $sawV4Physical
            A_established_evidence = $v4EstablishedEvidence
            AAAA_socket_observed_by_os_sampler = $sawV6Socket
            AAAA_observed_on_physical_adapter = $sawV6Physical
            AAAA_SynSent_observed = $sawV6SynSent
            AAAA_established = $sawV6Established
            AAAA_observed_states = @($v6ObservedStates)
            AAAA_SynSent_evidence = $v6SynSentEvidence
            AAAA_SynSent_evidence_valid = $v6SocketEvidenceValid
            source_inverse_socket = $sourceObservation
            source_inverse_socket_valid = $inverseValid
            hairpin_correlation = $hairpinCorrelation
        }
        transfer = [ordered]@{
            one_file = $true
            one_hostname_source = $true
            injection_count = $injectionCount
            injection = $injection
            file_name = if ($null -ne $sourceReady) {
                $sourceReady.fixture.file_name
            } else { '' }
            file_bytes = $FileSizeBytes
            ed2k_hash = if ($null -ne $sourceReady) {
                ([string]$sourceReady.fixture.ed2k_hash).ToLowerInvariant()
            } else { '' }
            source_sha256 = if ($null -ne $sourceReady) {
                $sourceReady.fixture.file_sha256
            } else { '' }
            destination_bytes = $destinationBytes
            destination_sha256 = $destinationSha256
            hash_match = $transferCompleted
        }
        health = [ordered]@{
            coordinator = [ordered]@{
                api_sample_count = $apiSamples
                api_unavailable_count = $apiUnavailable
                api_isolation_failure_count = $apiIsolationFailures
                ui_sample_count = $uiSamples
                ui_unavailable_count = $uiUnavailable
                ui_unresponsive_count = $uiUnresponsive
            }
            source = $sourceResultHealth
        }
        adjudication = [ordered]@{
            fixture_blockers = @($fixtureReasons)
            observability_blockers = @($observabilityReasons)
            product_failures = @($productReasons)
            rule =
                'Any known post-arm product failure is FAIL; otherwise ' +
                'missing fixture or observability proof is BLOCKED'
        }
        execution = [ordered]@{
            failure_stage = $failureStage
            runtime_error = $runtimeError
            source_result_status = $sourceResultStatus
        }
        cleanup = [ordered]@{
            downloader_process_stopped = if ($null -eq $downloader) {
                $true
            } else {
                $null -eq (
                    Get-Process -Id $downloader.Id `
                        -ErrorAction SilentlyContinue
                )
            }
            controlled_server_stopped =
                $null -ne $controlledServerStop -and
                $controlledServerStop.stopped
            source_stop_published = $stopPublished
            source = $sourceResultCleanup
            candidate_unchanged = $candidateUnchanged
            pktmon_filter_inventory_restored =
                $null -ne $capture -and
                $capture.filter_inventory_restored_verified
            pktmon_etw_session_stopped =
                $null -ne $capture -and
                $capture.etw_session_stopped_verified
            dns_modified = $false
            hosts_modified = $false
            routes_modified = $false
            adapters_modified = $false
            overlay_vpn_modified = $false
            proxy_modified = $false
            failures = @($cleanupFailures)
        }
        evidence = [ordered]@{
            summary = 'evidence\summary.json'
            package_manifest_before =
                'evidence\package-manifest-before.json'
            package_manifest_after =
                'evidence\package-manifest-after.json'
            zip_manifest_before = 'evidence\zip-manifest-before.json'
            zip_manifest_after = 'evidence\zip-manifest-after.json'
            topology = 'evidence\topology.json'
            dns_initial = 'evidence\dns-initial.json'
            dns_final = 'evidence\dns-final.json'
            endpoint_probes = 'evidence\endpoint-probes.json'
            sole_injection = 'evidence\sole-link-injection.json'
            telemetry_samples =
                'evidence\api\source-resolutions.jsonl'
            telemetry_verdict =
                'evidence\api\telemetry-verdict.json'
            socket_samples = 'evidence\target-sockets.jsonl'
            health_samples = 'evidence\health-samples.jsonl'
            packet_capture = 'evidence\capture'
            source_result_coordination_file = $sourceResultPath
        }
    }
    Write-LabJson -Value $summary -Path $summaryPath | Out-Null
    Write-Host (
        "V91-D01 $formalStatus; topology=$($summary.observed_topology); " +
        "fixture=$fixtureStatus; observability=$observabilityStatus; " +
        "product=$productStatus"
    ) -ForegroundColor $(
        if ($formalStatus -eq 'PASS') {
            'Green'
        } elseif ($formalStatus -eq 'FAIL') { 'Red' } else { 'Yellow' }
    )
    if ($formalStatus -eq 'PASS') { return 0 }
    if ($formalStatus -eq 'FAIL') { return 1 }
    return 2
}

$exitCode = 2
try {
    if (-not $ControlledFixtureAcknowledged) {
        throw 'D01 requires an explicitly controlled/authorized two-host fixture'
    }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'V91-D01 is a Windows-only physical two-host harness'
    }
    if (-not (Test-D01Administrator)) {
        throw "$Role role requires elevated PowerShell for PID, firewall and ETW evidence"
    }
    if ([Uri]::CheckHostName($canonicalHostname) -ne
            [UriHostNameType]::Dns -or
        $canonicalHostname.IndexOfAny([char[]]'|,[]:') -ge 0) {
        throw "Hostname is not a safe controlled DNS name: '$Hostname'"
    }
    $hostnameLabels = @($canonicalHostname.Split('.'))
    if ($canonicalHostname.Length -gt 253 -or
        $canonicalHostname -notmatch
            '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' -or
        @($hostnameLabels | Where-Object {
            $_.Length -lt 1 -or $_.Length -gt 63 -or
            $_ -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
        }).Count -ne 0) {
        throw 'Hostname must be canonical ASCII/IDNA A-label syntax'
    }
    $script:sourcePublicV4Address = Convert-D01Address `
        -Value $SourcePublicIPv4 `
        -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'SourcePublicIPv4'
    $script:sourceLocalV4Address = Convert-D01Address `
        -Value $SourceLocalIPv4 `
        -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'SourceLocalIPv4'
    $script:sourceV6Address = Convert-D01Address `
        -Value $SourceIPv6 `
        -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
        -Name 'SourceIPv6'
    $script:coordinatorPublicV4Address = Convert-D01Address `
        -Value $CoordinatorPublicIPv4 `
        -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'CoordinatorPublicIPv4'
    $script:coordinatorLocalV4Address = Convert-D01Address `
        -Value $CoordinatorLocalIPv4 `
        -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'CoordinatorLocalIPv4'
    $script:coordinatorV6Address = Convert-D01Address `
        -Value $CoordinatorIPv6 `
        -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
        -Name 'CoordinatorIPv6'
    $script:sourcePublicV4Text = $sourcePublicV4Address.ToString()
    $script:sourceLocalV4Text = $sourceLocalV4Address.ToString()
    $script:sourceV6Text = $sourceV6Address.ToString()
    $script:coordinatorPublicV4Text =
        $coordinatorPublicV4Address.ToString()
    $script:coordinatorLocalV4Text =
        $coordinatorLocalV4Address.ToString()
    $script:coordinatorV6Text = $coordinatorV6Address.ToString()
    if ((Get-LabAddressClass -Address $sourcePublicV4Text) -ne
        'global-v4') {
        throw 'SourcePublicIPv4 must be a globally routable A record'
    }
    if ((Get-LabAddressClass -Address $coordinatorPublicV4Text) -ne
        'global-v4') {
        throw 'CoordinatorPublicIPv4 must be globally routable'
    }
    if ((Get-LabAddressClass -Address $sourceV6Text) -ne 'global-v6') {
        throw 'SourceIPv6 must be a native globally routable AAAA record'
    }
    if ((Get-LabAddressClass -Address $coordinatorV6Text) -ne
        'global-v6') {
        throw 'CoordinatorIPv6 must be native and globally routable'
    }
    if ((Get-LabAddressClass -Address $sourceLocalV4Text) -in @(
        'invalid', 'loopback-v4', 'linklocal-v4', 'special-v4'
    )) {
        throw 'SourceLocalIPv4 must be assigned unicast IPv4'
    }
    if ((Get-LabAddressClass -Address $coordinatorLocalV4Text) -in @(
        'invalid', 'loopback-v4', 'linklocal-v4', 'special-v4'
    )) {
        throw 'CoordinatorLocalIPv4 must be assigned unicast IPv4'
    }
    $ports = @(
        $SourceTcpPort, $SourceUdpPort, $SourceWebPort,
        $DownloaderTcpPort, $DownloaderUdpPort, $DownloaderWebPort
    )
    if (@($ports | Sort-Object -Unique).Count -ne $ports.Count) {
        throw 'All source/downloader TCP, UDP and Web ports must be unique'
    }
    $outputFull = [IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
    $coordinationFull =
        [IO.Path]::GetFullPath($CoordinationRoot).TrimEnd('\')
    if (($outputFull + '\').StartsWith(
            $coordinationFull + '\',
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        ($coordinationFull + '\').StartsWith(
            $outputFull + '\',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'OutputRoot and CoordinationRoot must not contain one another'
    }
    if ($Role -eq 'Source') {
        $exitCode = Invoke-D01SourceRole
    } else {
        $exitCode = Invoke-D01CoordinatorRole
    }
} catch {
    [Console]::Error.WriteLine(
        "V91-D01 BLOCKED before a formal adjudication: " +
        $_.Exception.Message
    )
    $exitCode = 2
}
$webPassword = $null
exit $exitCode
