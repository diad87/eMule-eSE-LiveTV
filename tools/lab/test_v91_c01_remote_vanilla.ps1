[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)][string]$RemoteVanillaAddress,
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)][int]$RemoteVanillaPort,
    [string]$ExpectedRemoteHostIdHash = '',
    [string]$ExpectedRemoteTailnetNodeIdHash = '',
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$ExpectedNonce,
    [string]$RemoteReadyJson = '',
    [ValidateRange(60, 3600)][int]$TimeoutSeconds = 1200,
    [string]$Commit = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$expectedCommit = '08aa6521f7d7907edb3584266abc3a9e31693161'
$expectedCandidateSha256 =
    '55c5aa0e968b25330720cfb7f622cbc28ea9875365145333cbcf9d9585c1c44a'
$expectedEseServerSha256 =
    'eeceef0f0dbe427f3667c033e2b653fc69e432abcc3e8afaF996840a7315e568'
$expectedBuildInfoSha256 =
    '7c87f77268030c2b4da40c6da8c960f968b4e1a033c9987b64e45c49cf4b5915'
$expectedVanillaSha256 =
    '1fd7eeb62e9a93914644dc4fbd11e0c7ac37ee0a416edf90f415eed7d9a7c105'
$expectedVanillaBytes = 7896576L
$fixtureName = 'net13-unique-ffmpeg.zip'
$fixtureBytes = 223394208L
$fixtureSha256 =
    'aac4b00281982e473aab7071b1a593eef3ad22301085d18d26933557b022890c'
$fixtureEd2k = 'A4140C71628D93D5FD0981FD962C2552'
$proxyPort = 48711
$candidatePorts = [ordered]@{ tcp = 8062; udp = 8072; web = 8111 }

$candidateInfo = Get-LabCandidateInfo -PackagePath $PackagePath
$package = $candidateInfo.package_path
$candidateCommit = $candidateInfo.commit
$candidateSha256 = $candidateInfo.emule_sha256
$output = Get-LabFullPath -Path $OutputRoot
$nodes = Join-Path $output 'nodes'
$evidence = Join-Path $output 'evidence'
$candidateRoot = $null
$candidate = $null
$proxy = $null
$candidateExe = ''
$nodeExe = ''
$firewallRule = 'eSE V91 C01 remote ' + [Guid]::NewGuid().ToString('N')
$firewallCreated = $false
$registryPath = 'HKCU:\Software\eMule'
$registryName = 'UsePublicUserDirectories'
$registryOriginalExists = $false
$registryOriginalValue = $null
$registryModified = $false
$candidateToVanilla = ''
$vanillaToCandidate = ''
$eventsPath = ''
$progressPath = ''
$destinationFile = ''
$started = $null
$finished = $null
$transferPass = $false
$destinationHash = ''
$socketCorrelationObserved = $false
$socketCorrelationEvidence = $null
$cleanupEvidence = [ordered]@{
    candidate_stopped = $false
    proxy_stopped = $false
    firewall_rule_removed = $false
    registry_restored = $false
    owned_sockets_absent = $false
}

function Get-RequiredProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )
    if ($null -eq $InputObject) {
        throw "$Context is absent"
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "$Context.$Name is absent"
    }
    return $property.Value
}

function Assert-Sha256 {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $text = [string]$Value
    if ($text -notmatch '^[0-9a-fA-F]{64}$') {
        throw "$Name is not a SHA-256 value"
    }
    return $text.ToLowerInvariant()
}

function Get-LocalHostIdHash {
    $machineGuid = [string](Get-ItemPropertyValue `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
        -Name 'MachineGuid')
    if ([string]::IsNullOrWhiteSpace($machineGuid)) {
        throw 'The local Windows MachineGuid is unavailable'
    }
    return Get-LabStringSha256 -Value $machineGuid.Trim().ToLowerInvariant()
}

function Test-IpAddressEqual {
    param(
        [AllowEmptyString()][string]$Left,
        [AllowEmptyString()][string]$Right
    )
    $leftAddress = $null
    $rightAddress = $null
    if (-not [Net.IPAddress]::TryParse(
            $Left.Trim('[', ']').Split('%')[0], [ref]$leftAddress) -or
        -not [Net.IPAddress]::TryParse(
            $Right.Trim('[', ']').Split('%')[0], [ref]$rightAddress)) {
        return $false
    }
    return $leftAddress.Equals($rightAddress)
}

function Get-ExpectedProcess {
    param(
        [int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )
    if ($ProcessId -le 0 -or [string]::IsNullOrWhiteSpace($ExpectedPath)) {
        return $null
    }
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $null }
    $actualPath = try { $process.Path } catch { '' }
    if ($actualPath -ne $ExpectedPath) { return $null }
    return $process
}

function Wait-Listener {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [AllowEmptyString()][string]$ExpectedAddress = '',
        [int]$Seconds = 90
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "Process $($Process.Id) exited before listener $Port became ready"
        }
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port `
            -ErrorAction SilentlyContinue | Where-Object {
                $_.OwningProcess -eq $Process.Id
            })
        if ($ExpectedAddress) {
            $listeners = @($listeners | Where-Object {
                Test-IpAddressEqual -Left $_.LocalAddress -Right $ExpectedAddress
            })
        }
        if ($listeners.Count -eq 1) { return $listeners[0] }
        if ($listeners.Count -gt 1) {
            throw "Listener $Port is not unique for PID $($Process.Id)"
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Listener $Port did not become ready for PID $($Process.Id)"
}

function Restore-UserDirectoryMode {
    if (-not $script:registryModified) { return }
    if ($script:registryOriginalExists) {
        New-ItemProperty -LiteralPath $script:registryPath `
            -Name $script:registryName -Value $script:registryOriginalValue `
            -PropertyType DWord -Force | Out-Null
    } else {
        Remove-ItemProperty -LiteralPath $script:registryPath `
            -Name $script:registryName -ErrorAction SilentlyContinue
    }
    $script:registryModified = $false
}

function Stop-TestProcess {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [AllowEmptyString()][string]$ExpectedPath = ''
    )
    if ($null -eq $Process) { return $true }
    $actual = Get-ExpectedProcess -ProcessId $Process.Id `
        -ExpectedPath $ExpectedPath
    if ($null -ne $actual) {
        Stop-Process -Id $actual.Id -Force -ErrorAction SilentlyContinue
        $null = $actual.WaitForExit(10000)
    }
    return $null -eq (Get-ExpectedProcess -ProcessId $Process.Id `
        -ExpectedPath $ExpectedPath)
}

function Read-Frames {
    param([Parameter(Mandatory = $true)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $offset = 0
    $frames = [System.Collections.Generic.List[object]]::new()
    $invalid = ''
    while ($offset + 5 -le $bytes.Length) {
        $protocol = $bytes[$offset]
        $declared = [BitConverter]::ToUInt32($bytes, $offset + 1)
        if ($declared -lt 1 -or $declared -gt 16777216) {
            $invalid = "invalid declared size $declared at offset $offset"
            break
        }
        $total = 5 + $declared
        if ($offset + $total -gt $bytes.Length) { break }
        $frames.Add([pscustomobject]@{
            offset = $offset
            protocol = $protocol
            opcode = $bytes[$offset + 5]
            total_bytes = $total
        })
        $offset += $total
    }
    return [pscustomobject]@{
        bytes = $bytes
        frames = $frames
        parsed_bytes = $offset
        trailing_bytes = $bytes.Length - $offset
        invalid = $invalid
    }
}

function Read-HelloTags {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset
    )
    $i = $Offset + 6
    $hashLength = $Bytes[$i]
    $i += 1 + $hashLength + 4 + 2
    $tagCount = [BitConverter]::ToUInt32($Bytes, $i)
    $i += 4
    $tags = @()
    for ($index = 0; $index -lt $tagCount; ++$index) {
        $type = $Bytes[$i]
        ++$i
        $nameLength = [BitConverter]::ToUInt16($Bytes, $i)
        $i += 2
        $nameBytes = [byte[]]$Bytes[$i..($i + $nameLength - 1)]
        $i += $nameLength
        $valueLength = 0
        switch ($type) {
            2 {
                $valueLength = [BitConverter]::ToUInt16($Bytes, $i)
                $i += 2 + $valueLength
            }
            3 { $valueLength = 4; $i += 4 }
            4 { $valueLength = 4; $i += 4 }
            5 { $valueLength = 1; $i += 1 }
            6 {
                $bits = [BitConverter]::ToUInt16($Bytes, $i)
                $i += 2
                $valueLength = [int][Math]::Ceiling($bits / 8.0)
                $i += $valueLength
            }
            7 {
                $valueLength = [BitConverter]::ToUInt32($Bytes, $i)
                $i += 4 + $valueLength
            }
            8 { $valueLength = 2; $i += 2 }
            9 { $valueLength = 1; $i += 1 }
            10 {
                $valueLength = $Bytes[$i]
                ++$i
                $i += $valueLength
            }
            11 { $valueLength = 8; $i += 8 }
            default {
                if ($type -ge 0x11 -and $type -le 0x20) {
                    $valueLength = $type - 0x10
                    $i += $valueLength
                } else {
                    throw "Unknown tag type 0x$('{0:X2}' -f $type)"
                }
            }
        }
        $name = if ($nameLength -eq 1) {
            '0x{0:X2}' -f $nameBytes[0]
        } else {
            [Text.Encoding]::ASCII.GetString($nameBytes)
        }
        $tags += [pscustomobject]@{
            type = '0x{0:X2}' -f $type
            name = $name
            value_length = $valueLength
        }
    }
    return $tags
}

function Convert-BytesToHex {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Count
    )
    return [BitConverter]::ToString($Bytes, $Offset, $Count).
        Replace('-', '').ToUpperInvariant()
}

function Get-CandidateRequestShapes {
    param(
        [Parameter(Mandatory = $true)][object]$FrameScan,
        [Parameter(Mandatory = $true)][string]$ExpectedEd2k,
        [Parameter(Mandatory = $true)][Int64]$ExpectedBytes
    )
    $startUploadFrames = @($FrameScan.frames | Where-Object {
        $_.protocol -eq 0xE3 -and $_.opcode -eq 0x54
    })
    $requestPartFrames = @($FrameScan.frames | Where-Object {
        $_.protocol -eq 0xE3 -and $_.opcode -eq 0x47
    })
    $invalidStartUploadFrames = 0
    $invalidRequestPartFrames = 0
    $activeRanges = 0
    $unusedRanges = 0
    $fileHash = $ExpectedEd2k.ToUpperInvariant()

    foreach ($frame in $startUploadFrames) {
        if ([Int64]$frame.total_bytes -ne 22 -or
            [Int64]$frame.offset + 22 -gt $FrameScan.bytes.Length) {
            ++$invalidStartUploadFrames
            continue
        }
        $observedHash = Convert-BytesToHex -Bytes $FrameScan.bytes `
            -Offset ([int]$frame.offset + 6) -Count 16
        if ($observedHash -ne $fileHash) {
            ++$invalidStartUploadFrames
        }
    }

    foreach ($frame in $requestPartFrames) {
        if ([Int64]$frame.total_bytes -ne 46 -or
            [Int64]$frame.offset + 46 -gt $FrameScan.bytes.Length) {
            ++$invalidRequestPartFrames
            continue
        }
        $observedHash = Convert-BytesToHex -Bytes $FrameScan.bytes `
            -Offset ([int]$frame.offset + 6) -Count 16
        $frameValid = $observedHash -eq $fileHash
        $frameActiveRanges = 0
        for ($rangeIndex = 0; $rangeIndex -lt 3; ++$rangeIndex) {
            $start = [UInt64][BitConverter]::ToUInt32(
                $FrameScan.bytes, [int]$frame.offset + 22 + (4 * $rangeIndex))
            $end = [UInt64][BitConverter]::ToUInt32(
                $FrameScan.bytes, [int]$frame.offset + 34 + (4 * $rangeIndex))
            if ($start -eq 0 -and $end -eq 0) {
                ++$unusedRanges
                continue
            }
            if ($start -ge $end -or $end -gt [UInt64]$ExpectedBytes) {
                $frameValid = $false
                continue
            }
            ++$frameActiveRanges
            ++$activeRanges
        }
        if ($frameActiveRanges -lt 1) { $frameValid = $false }
        if (-not $frameValid) { ++$invalidRequestPartFrames }
    }

    $pass = $startUploadFrames.Count -ge 1 -and
        $requestPartFrames.Count -ge 1 -and
        $invalidStartUploadFrames -eq 0 -and
        $invalidRequestPartFrames -eq 0
    return [pscustomobject][ordered]@{
        pass = $pass
        expected_file_ed2k = $fileHash
        start_upload_frame_count = $startUploadFrames.Count
        start_upload_expected_total_bytes = 22
        invalid_start_upload_frames = $invalidStartUploadFrames
        request_parts_frame_count = $requestPartFrames.Count
        request_parts_expected_total_bytes = 46
        active_ranges = $activeRanges
        unused_zero_ranges = $unusedRanges
        invalid_request_parts_frames = $invalidRequestPartFrames
    }
}

function Get-VanillaFixtureProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$CapturePath,
        [Parameter(Mandatory = $true)][object]$FrameScan,
        [Parameter(Mandatory = $true)][string]$ExpectedEd2k,
        [Parameter(Mandatory = $true)][Int64]$ExpectedBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $sendingFrames = @($FrameScan.frames | Where-Object {
        $_.protocol -eq 0xE3 -and $_.opcode -eq 0x46
    })
    $segments = [System.Collections.Generic.List[object]]::new()
    $invalidShapeFrames = 0
    $wrongEd2kFrames = 0
    $fileHash = $ExpectedEd2k.ToUpperInvariant()
    $expectedEd2kBytes = New-Object byte[] 16
    for ($hashByteIndex = 0; $hashByteIndex -lt 16; ++$hashByteIndex) {
        $expectedEd2kBytes[$hashByteIndex] = [Convert]::ToByte(
            $fileHash.Substring(2 * $hashByteIndex, 2), 16)
    }
    [UInt64]$payloadBytes = 0

    foreach ($frame in $sendingFrames) {
        if ([Int64]$frame.total_bytes -lt 30 -or
            [Int64]$frame.offset + [Int64]$frame.total_bytes -gt
                $FrameScan.bytes.Length) {
            ++$invalidShapeFrames
            continue
        }
        $ed2kMatches = $true
        $ed2kOffset = [int]$frame.offset + 6
        for ($hashByteIndex = 0; $hashByteIndex -lt 16; ++$hashByteIndex) {
            if ($FrameScan.bytes[$ed2kOffset + $hashByteIndex] -ne
                $expectedEd2kBytes[$hashByteIndex]) {
                $ed2kMatches = $false
                break
            }
        }
        if (-not $ed2kMatches) { ++$wrongEd2kFrames }
        [UInt64]$start = [BitConverter]::ToUInt32(
            $FrameScan.bytes, [int]$frame.offset + 22)
        [UInt64]$end = [BitConverter]::ToUInt32(
            $FrameScan.bytes, [int]$frame.offset + 26)
        $dataBytes = if ($end -ge $start) {
            [UInt64]($end - $start)
        } else {
            [UInt64]0
        }
        $expectedFrameBytes = [UInt64]30 + $dataBytes
        if ($start -ge $end -or $end -gt [UInt64]$ExpectedBytes -or
            [UInt64]$frame.total_bytes -ne $expectedFrameBytes) {
            ++$invalidShapeFrames
            continue
        }
        $segments.Add([pscustomobject][ordered]@{
            start = $start
            end = $end
            bytes = $dataBytes
            capture_data_offset = [Int64]$frame.offset + 30
        })
        $payloadBytes += $dataBytes
    }

    $sortedSegments = @($segments | Sort-Object start, end)
    [UInt64]$cursor = 0
    $coverageDiscontinuities = 0
    foreach ($segment in $sortedSegments) {
        if ([UInt64]$segment.start -ne $cursor) {
            ++$coverageDiscontinuities
        }
        $cursor = [UInt64]$segment.end
    }
    $coveragePass = $sendingFrames.Count -gt 0 -and
        $segments.Count -eq $sendingFrames.Count -and
        $invalidShapeFrames -eq 0 -and
        $wrongEd2kFrames -eq 0 -and
        $coverageDiscontinuities -eq 0 -and
        $payloadBytes -eq [UInt64]$ExpectedBytes -and
        $cursor -eq [UInt64]$ExpectedBytes

    $capturedSha256 = ''
    if ($coveragePass) {
        $captureFile = Get-Item -LiteralPath $CapturePath
        if ($captureFile.Length -ne $FrameScan.bytes.Length) {
            throw 'Capture changed after its frame scan'
        }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            foreach ($segment in $sortedSegments) {
                $dataOffset = [int]$segment.capture_data_offset
                $dataLength = [int]$segment.bytes
                $null = $sha256.TransformBlock(
                    $FrameScan.bytes, $dataOffset, $dataLength,
                    $FrameScan.bytes, $dataOffset)
            }
            $empty = New-Object byte[] 0
            $null = $sha256.TransformFinalBlock($empty, 0, 0)
            $capturedSha256 = ([BitConverter]::ToString($sha256.Hash)).
                Replace('-', '').ToLowerInvariant()
        } finally {
            $sha256.Dispose()
        }
    }
    $sha256Pass = $capturedSha256 -eq $ExpectedSha256.ToLowerInvariant()
    return [pscustomobject][ordered]@{
        pass = $coveragePass -and $sha256Pass
        sending_part_frame_count = $sendingFrames.Count
        parsed_segment_count = $segments.Count
        expected_file_ed2k = $fileHash
        frames_with_wrong_ed2k = $wrongEd2kFrames
        invalid_shape_frames = $invalidShapeFrames
        frame_shape = 'E3:46 hash[16] start_u32 end_u32 data[end-start]'
        coverage = [ordered]@{
            expected_start = 0
            observed_start = if ($sortedSegments.Count -gt 0) {
                [UInt64]$sortedSegments[0].start
            } else {
                $null
            }
            expected_end = $ExpectedBytes
            observed_end = if ($sortedSegments.Count -gt 0) {
                [UInt64]$sortedSegments[-1].end
            } else {
                $null
            }
            payload_bytes = $payloadBytes
            discontinuities = $coverageDiscontinuities
            contiguous_exact = $coveragePass
        }
        incremental_sha256 = $capturedSha256
        expected_sha256 = $ExpectedSha256.ToLowerInvariant()
        sha256_match = $sha256Pass
        reconstruction_copy_created = $false
    }
}

function Get-LocalProxyAddress {
    $candidates = @()
    foreach ($adapter in
        [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($adapter.OperationalStatus -ne
            [Net.NetworkInformation.OperationalStatus]::Up) {
            continue
        }
        $label = '{0}|{1}' -f $adapter.Name, $adapter.Description
        if ($label -match '(?i)Tailscale|Loopback') { continue }
        foreach ($unicast in $adapter.GetIPProperties().UnicastAddresses) {
            $address = $unicast.Address.ToString()
            if ((Get-LabAddressClass -Address $address) -ne 'global-v6') {
                continue
            }
            $candidates += [pscustomobject][ordered]@{
                address = $address
                interface_id = Get-LabInterfaceId -Id $adapter.Id `
                    -Name $adapter.Name -Description $adapter.Description
                route_kind = if ($label -match '(?i)Cloudflare|WARP') {
                    'warp-global-v6'
                } else {
                    'local-global-v6'
                }
                priority = if ($label -match '(?i)Cloudflare|WARP') { 0 } else { 1 }
            }
        }
    }
    $selected = @($candidates | Sort-Object priority, address |
        Select-Object -First 1)
    if ($selected.Count -ne 1) {
        throw 'No non-Tailscale WARP/local global IPv6 address is available'
    }
    return $selected[0]
}

function Get-TailnetPeer {
    param([Parameter(Mandatory = $true)][string]$Address)
    $tailscale = Get-Command tailscale.exe -ErrorAction SilentlyContinue
    if ($null -eq $tailscale) {
        throw 'tailscale.exe is required to authenticate the remote peer'
    }
    $rawStatus = @(& $tailscale.Source status --json 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'tailscale status --json failed'
    }
    $status = ($rawStatus -join [Environment]::NewLine) | ConvertFrom-Json
    $matches = @(
        $status.Peer.PSObject.Properties.Value | Where-Object {
            @($_.TailscaleIPs | Where-Object {
                Test-IpAddressEqual -Left ([string]$_) -Right $Address
            }).Count -gt 0
        }
    )
    if ($matches.Count -ne 1) {
        throw 'RemoteVanillaAddress does not identify exactly one Tailnet peer'
    }
    $peer = $matches[0]
    if (-not [bool]$peer.Online -or [string]$peer.OS -ne 'windows') {
        throw 'The selected Tailnet peer is not an online Windows node'
    }
    $peerId = [string]$peer.ID
    $selfId = [string](Get-RequiredProperty -InputObject $status.Self `
        -Name 'ID' -Context 'tailscale.self')
    if ([string]::IsNullOrWhiteSpace($peerId) -or
        [string]::IsNullOrWhiteSpace($selfId)) {
        throw 'Tailnet node identity is incomplete'
    }
    $peerHash = Get-LabStringSha256 -Value $peerId
    $selfHash = Get-LabStringSha256 -Value $selfId
    if ($peerHash -eq $selfHash) {
        throw 'The remote Tailnet peer resolves to the local node'
    }
    $selfIpv4 = @(
        $status.Self.TailscaleIPs | Where-Object {
            (Get-LabAddressClass -Address ([string]$_)) -eq 'cgnat-v4'
        } | Select-Object -First 1
    )
    if ($selfIpv4.Count -ne 1) {
        throw 'The local Tailnet node has no unique Tailscale IPv4 address'
    }
    return [pscustomobject][ordered]@{
        node_id_hash = $peerHash
        local_node_id_hash = $selfHash
        local_tailscale_ipv4 = [string]$selfIpv4[0]
        online = $true
        os = 'windows'
        address_class = Get-LabAddressClass -Address $Address
    }
}

function Get-SocketCorrelation {
    param(
        [Parameter(Mandatory = $true)][int]$CandidatePid,
        [Parameter(Mandatory = $true)][int]$ProxyPid,
        [Parameter(Mandatory = $true)][string]$ProxyAddress,
        [Parameter(Mandatory = $true)][int]$ProxyListenPort,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$RemotePort
    )
    $connections = @(Get-NetTCPConnection -State Established `
        -ErrorAction SilentlyContinue)
    $candidateSockets = @($connections | Where-Object {
        $_.OwningProcess -eq $CandidatePid -and
        $_.RemotePort -eq $ProxyListenPort -and
        (Test-IpAddressEqual -Left $_.RemoteAddress -Right $ProxyAddress)
    })
    $proxyInbound = @($connections | Where-Object {
        $_.OwningProcess -eq $ProxyPid -and
        $_.LocalPort -eq $ProxyListenPort -and
        (Test-IpAddressEqual -Left $_.LocalAddress -Right $ProxyAddress)
    })
    $proxyOutbound = @($connections | Where-Object {
        $_.OwningProcess -eq $ProxyPid -and
        $_.RemotePort -eq $RemotePort -and
        (Test-IpAddressEqual -Left $_.RemoteAddress -Right $RemoteAddress)
    })
    $candidatePair = $null
    $inboundPair = $null
    foreach ($candidateSocket in $candidateSockets) {
        foreach ($inboundSocket in $proxyInbound) {
            if ($candidateSocket.LocalPort -eq $inboundSocket.RemotePort -and
                $candidateSocket.RemotePort -eq $inboundSocket.LocalPort -and
                (Test-IpAddressEqual -Left $candidateSocket.LocalAddress `
                    -Right $inboundSocket.RemoteAddress) -and
                (Test-IpAddressEqual -Left $candidateSocket.RemoteAddress `
                    -Right $inboundSocket.LocalAddress)) {
                $candidatePair = $candidateSocket
                $inboundPair = $inboundSocket
                break
            }
        }
        if ($null -ne $candidatePair) { break }
    }
    $outbound = if ($proxyOutbound.Count -eq 1) {
        $proxyOutbound[0]
    } else {
        $null
    }
    $outboundInterface = if ($null -ne $outbound) {
        Get-LabInterfaceForAddress -Address $outbound.LocalAddress
    } else {
        $null
    }
    $outboundViaTailscale = $null -ne $outboundInterface -and
        ('{0}|{1}' -f $outboundInterface.name,
            $outboundInterface.description) -match '(?i)Tailscale'
    $pass = $candidateSockets.Count -eq 1 -and
        $proxyInbound.Count -eq 1 -and
        $proxyOutbound.Count -eq 1 -and
        $null -ne $candidatePair -and
        $outboundViaTailscale
    return [pscustomobject][ordered]@{
        pass = $pass
        candidate_socket_count = $candidateSockets.Count
        proxy_inbound_socket_count = $proxyInbound.Count
        proxy_outbound_socket_count = $proxyOutbound.Count
        candidate_pid = $CandidatePid
        proxy_pid = $ProxyPid
        candidate_to_proxy_correlated = $null -ne $candidatePair
        proxy_to_remote_correlated = $null -ne $outbound
        proxy_outbound_interface_id = if ($null -eq $outboundInterface) {
            $null
        } else {
            Get-LabInterfaceId -Id $outboundInterface.id `
                -Name $outboundInterface.name `
                -Description $outboundInterface.description
        }
        proxy_outbound_via_tailscale = $outboundViaTailscale
        proxy_address_sha256 = Get-LabStringSha256 -Value `
            $ProxyAddress.Trim('[', ']').Split('%')[0].ToLowerInvariant()
        remote_address_sha256 = Get-LabStringSha256 -Value `
            $RemoteAddress.Trim('[', ']').Split('%')[0].ToLowerInvariant()
        remote_port = $RemotePort
    }
}

if ($Commit -and $Commit.ToLowerInvariant() -ne $expectedCommit) {
    throw "V91-C01 is pinned to RC2 commit $expectedCommit"
}
if ($candidateCommit -ne $expectedCommit -or
    $candidateSha256 -ne $expectedCandidateSha256 -or
    $candidateInfo.ese_server_sha256 -ne $expectedEseServerSha256.ToLowerInvariant() -or
    $candidateInfo.build_info_sha256 -ne $expectedBuildInfoSha256) {
    throw 'The package is not the exact frozen V91 RC2 candidate'
}
if ($ExpectedRemoteHostIdHash) {
    $ExpectedRemoteHostIdHash = Assert-Sha256 `
        -Value $ExpectedRemoteHostIdHash -Name 'ExpectedRemoteHostIdHash'
}
if ($ExpectedRemoteTailnetNodeIdHash) {
    $ExpectedRemoteTailnetNodeIdHash = Assert-Sha256 `
        -Value $ExpectedRemoteTailnetNodeIdHash `
        -Name 'ExpectedRemoteTailnetNodeIdHash'
}
if ([string]::IsNullOrWhiteSpace($ExpectedNonce) -or
    $ExpectedNonce -notmatch '^[0-9a-fA-F]{32}$') {
    throw 'ExpectedNonce is mandatory and must be a 32-hex nonce'
}
$ExpectedNonce = $ExpectedNonce.ToLowerInvariant()

$remoteIp = $null
if (-not [Net.IPAddress]::TryParse(
        $RemoteVanillaAddress.Trim('[', ']'), [ref]$remoteIp) -or
    $remoteIp.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'RemoteVanillaAddress must be an IPv4 literal'
}
$remoteAddressNormalized = $remoteIp.ToString()
$remoteAddressClass = Get-LabAddressClass -Address $remoteAddressNormalized
$localHostIdHash = Get-LocalHostIdHash
$tailnetPeer = Get-TailnetPeer -Address $remoteAddressNormalized
if ($ExpectedRemoteTailnetNodeIdHash -and
    $tailnetPeer.node_id_hash -ne $ExpectedRemoteTailnetNodeIdHash) {
    throw 'The selected Tailnet peer does not match ExpectedRemoteTailnetNodeIdHash'
}

$readyPathCandidate = if ($RemoteReadyJson) {
    $RemoteReadyJson
} else {
    Join-Path $output 'remote-ready.json'
}
$readyPath = (Resolve-Path -LiteralPath $readyPathCandidate).Path
if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
    throw "Remote ready JSON is missing: $readyPathCandidate"
}
$ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
if ([string](Get-RequiredProperty -InputObject $ready -Name 'schema' `
        -Context 'ready') -ne 'ese.v91.c01.remote-vanilla-ready/v1' -or
    [string](Get-RequiredProperty -InputObject $ready -Name 'case_id' `
        -Context 'ready') -ne 'V91-C01') {
    throw 'Remote ready JSON has the wrong schema or case ID'
}
if ([string](Get-RequiredProperty -InputObject $ready -Name 'status' `
        -Context 'ready') -cne 'READY') {
    throw 'Remote ready JSON does not have the exact READY status'
}
$readyNonce = [string](Get-RequiredProperty -InputObject $ready -Name 'nonce' `
    -Context 'ready')
if ($readyNonce -notmatch '^[0-9a-fA-F]{32}$') {
    throw 'ready.nonce must be a 32-hex nonce'
}
$readyNonce = $readyNonce.ToLowerInvariant()
if ($readyNonce -ne $ExpectedNonce) {
    throw 'Remote ready nonce does not match ExpectedNonce'
}
$readyKitNonce = [string](Get-RequiredProperty -InputObject $ready `
    -Name 'kit_nonce' -Context 'ready')
if ($readyKitNonce -notmatch '^[0-9a-fA-F]{32}$' -or
    $readyKitNonce.ToLowerInvariant() -ne $readyNonce) {
    throw 'ready.kit_nonce does not match ready.nonce'
}
$readyCreatedText = [string](Get-RequiredProperty -InputObject $ready `
    -Name 'created_at_utc' -Context 'ready')
$readyCreated = [DateTimeOffset]::MinValue
if (-not [DateTimeOffset]::TryParse(
        $readyCreatedText, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$readyCreated)) {
    throw 'ready.created_at_utc is invalid'
}
$readyAtText = [string](Get-RequiredProperty -InputObject $ready `
    -Name 'ready_at_utc' -Context 'ready')
$readyAt = [DateTimeOffset]::MinValue
if (-not [DateTimeOffset]::TryParse(
        $readyAtText, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$readyAt) -or
    $readyAt.ToUniversalTime() -ne $readyCreated.ToUniversalTime()) {
    throw 'ready.ready_at_utc is invalid or differs from created_at_utc'
}
$readyAge = [DateTimeOffset]::UtcNow - $readyCreated.ToUniversalTime()
if ($readyAge.TotalMinutes -lt -5 -or $readyAge.TotalHours -gt 2) {
    throw 'Remote ready JSON is outside the allowed freshness window'
}
$readyExpiryText = [string](Get-RequiredProperty -InputObject $ready `
    -Name 'ready_expires_at_utc' -Context 'ready')
$readyExpiry = [DateTimeOffset]::MinValue
if (-not [DateTimeOffset]::TryParse(
        $readyExpiryText, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$readyExpiry)) {
    throw 'ready.ready_expires_at_utc is invalid'
}
$readyExpiry = $readyExpiry.ToUniversalTime()
if ($readyExpiry -le [DateTimeOffset]::UtcNow -or
    $readyExpiry -le $readyCreated.ToUniversalTime() -or
    ($readyExpiry - $readyCreated.ToUniversalTime()).TotalMinutes -gt 125) {
    throw 'Remote ready JSON is expired or has an invalid validity interval'
}
$readySourceAddress = [string](Get-RequiredProperty -InputObject $ready `
    -Name 'source_tailscale_ipv4' -Context 'ready')
$readyCoordinatorAddress = [string](Get-RequiredProperty -InputObject $ready `
    -Name 'coordinator_tailscale_ipv4' -Context 'ready')
if (-not (Test-IpAddressEqual -Left $readySourceAddress `
        -Right $remoteAddressNormalized) -or
    -not (Test-IpAddressEqual -Left $readyCoordinatorAddress `
        -Right $tailnetPeer.local_tailscale_ipv4)) {
    throw 'Remote ready transport endpoints do not match the live Tailnet peers'
}
$physicalConfirmation = Get-RequiredProperty -InputObject $ready `
    -Name 'independent_physical_windows_confirmation_required' `
    -Context 'ready'
if ($physicalConfirmation -isnot [bool] -or -not $physicalConfirmation) {
    throw 'Remote ready JSON lacks the physical Windows confirmation control'
}
$readyHostIdHash = Assert-Sha256 -Value (Get-RequiredProperty `
    -InputObject $ready -Name 'host_id_hash' -Context 'ready') `
    -Name 'ready.host_id_hash'
if ($readyHostIdHash -eq $localHostIdHash) {
    throw 'Remote ready JSON belongs to the local Windows host'
}
if ($ExpectedRemoteHostIdHash -and
    $readyHostIdHash -ne $ExpectedRemoteHostIdHash) {
    throw 'Remote ready host does not match ExpectedRemoteHostIdHash'
}
$readyTailnetHash = Assert-Sha256 -Value (Get-RequiredProperty `
    -InputObject $ready -Name 'tailnet_node_id_hash' -Context 'ready') `
    -Name 'ready.tailnet_node_id_hash'
if ($readyTailnetHash -ne $tailnetPeer.node_id_hash) {
    throw 'Remote ready Tailnet identity does not match the live selected peer'
}
$readyTopology = Get-RequiredProperty -InputObject $ready `
    -Name 'topology' -Context 'ready'
if ([string](Get-RequiredProperty -InputObject $readyTopology `
        -Name 'host_role' -Context 'ready.topology') -ne 'H2' -or
    [string](Get-RequiredProperty -InputObject $readyTopology `
        -Name 'isolation' -Context 'ready.topology') -ne
        'physical-independent-windows' -or
    [string](Get-RequiredProperty -InputObject $readyTopology `
        -Name 'topology_requirement' -Context 'ready.topology') -ne 'V1/H2' -or
    [string](Get-RequiredProperty -InputObject $readyTopology `
        -Name 'data_path' -Context 'ready.topology') -ne 'compat-overlay') {
    throw 'Remote ready topology is not V1/H2 physical compat-overlay'
}
$readyVanilla = Get-RequiredProperty -InputObject $ready `
    -Name 'vanilla' -Context 'ready'
$readyVanillaHash = Assert-Sha256 -Value (Get-RequiredProperty `
    -InputObject $readyVanilla -Name 'binary_sha256' `
    -Context 'ready.vanilla') -Name 'ready.vanilla.binary_sha256'
$readyVanillaVersion = [string](Get-RequiredProperty `
    -InputObject $readyVanilla -Name 'version' -Context 'ready.vanilla')
$readyVanillaProductVersion = [string](Get-RequiredProperty `
    -InputObject $readyVanilla -Name 'product_version' `
    -Context 'ready.vanilla')
$readyVanillaBytes = [Int64](Get-RequiredProperty `
    -InputObject $readyVanilla -Name 'emule_bytes' -Context 'ready.vanilla')
$readyVanillaHashAlias = Assert-Sha256 -Value (Get-RequiredProperty `
    -InputObject $readyVanilla -Name 'emule_sha256' `
    -Context 'ready.vanilla') -Name 'ready.vanilla.emule_sha256'
$readyVanillaPid = [int](Get-RequiredProperty -InputObject $readyVanilla `
    -Name 'process_id' -Context 'ready.vanilla')
if ($readyVanillaHash -ne $expectedVanillaSha256 -or
    $readyVanillaHashAlias -ne $expectedVanillaSha256 -or
    $readyVanillaHashAlias -ne $readyVanillaHash -or
    $readyVanillaVersion -ne '0.70b' -or
    $readyVanillaProductVersion -ne '0.70.1 Unicode' -or
    $readyVanillaBytes -ne $expectedVanillaBytes -or
    $readyVanillaPid -le 0) {
    throw 'Remote vanilla binary, version or PID does not match the pinned fixture'
}
$readyListener = Get-RequiredProperty -InputObject $ready `
    -Name 'listener' -Context 'ready'
$readyListenerPort = [int](Get-RequiredProperty -InputObject $readyListener `
    -Name 'port' -Context 'ready.listener')
$readyListenerPid = [int](Get-RequiredProperty -InputObject $readyListener `
    -Name 'owning_process_id' -Context 'ready.listener')
$readyListenerClass = [string](Get-RequiredProperty `
    -InputObject $readyListener -Name 'address_class' `
    -Context 'ready.listener')
$readyListening = Get-RequiredProperty -InputObject $readyListener `
    -Name 'listening' -Context 'ready.listener'
if ($readyListenerPort -ne $RemoteVanillaPort -or
    $readyListenerPid -ne $readyVanillaPid -or
    $readyListenerClass -ne $remoteAddressClass -or
    $readyListening -isnot [bool] -or -not $readyListening) {
    throw 'Remote ready listener is not the selected PID-owned endpoint'
}
$readyAddressHashProperty =
    $readyListener.PSObject.Properties['address_sha256']
if ($null -ne $readyAddressHashProperty) {
    $readyAddressHash = Assert-Sha256 -Value $readyAddressHashProperty.Value `
        -Name 'ready.listener.address_sha256'
    $expectedAddressHash = Get-LabStringSha256 -Value `
        $remoteAddressNormalized.ToLowerInvariant()
    if ($readyAddressHash -ne $expectedAddressHash) {
        throw 'Remote ready listener address does not match RemoteVanillaAddress'
    }
}
$readyFixture = Get-RequiredProperty -InputObject $ready `
    -Name 'fixture' -Context 'ready'
$readyFixtureAvailable = Get-RequiredProperty -InputObject $readyFixture `
    -Name 'available' -Context 'ready.fixture'
if ([string](Get-RequiredProperty -InputObject $readyFixture -Name 'name' `
        -Context 'ready.fixture') -ne $fixtureName -or
    [Int64](Get-RequiredProperty -InputObject $readyFixture -Name 'bytes' `
        -Context 'ready.fixture') -ne $fixtureBytes -or
    (Assert-Sha256 -Value (Get-RequiredProperty -InputObject $readyFixture `
        -Name 'sha256' -Context 'ready.fixture') `
        -Name 'ready.fixture.sha256') -ne $fixtureSha256 -or
    [string](Get-RequiredProperty -InputObject $readyFixture -Name 'ed2k' `
        -Context 'ready.fixture') -ne $fixtureEd2k -or
    $readyFixtureAvailable -isnot [bool] -or -not $readyFixtureAvailable) {
    throw 'Remote compatibility fixture does not match the pinned file'
}
$readyControls = Get-RequiredProperty -InputObject $ready `
    -Name 'controls' -Context 'ready'
$expectedControls = [ordered]@{
    clean_profile_generated = $true
    webserver_enabled = $false
    kad_enabled = $false
    ed2k_enabled = $false
    autoconnect_enabled = $false
    upnp_enabled = $false
    firewall_peer_scoped = $true
    firewall_nonce_scoped = $true
}
foreach ($controlName in $expectedControls.Keys) {
    $actualControl = Get-RequiredProperty -InputObject $readyControls `
        -Name $controlName -Context 'ready.controls'
    if ($actualControl -isnot [bool] -or
        $actualControl -ne $expectedControls[$controlName]) {
        throw "ready.controls.$controlName does not have the required value"
    }
}
$readyTransport = Get-RequiredProperty -InputObject $ready `
    -Name 'transport' -Context 'ready'
$nativeClaim = Get-RequiredProperty -InputObject $readyTransport `
    -Name 'native_reachability_claim' -Context 'ready.transport'
if ([string](Get-RequiredProperty -InputObject $readyTransport `
        -Name 'kind' -Context 'ready.transport') -ne
        'Tailscale IPv4 overlay' -or
    [string](Get-RequiredProperty -InputObject $readyTransport `
        -Name 'purpose' -Context 'ready.transport') -ne
        'V91-C01 classic-wire interoperability only' -or
    $nativeClaim -isnot [bool] -or $nativeClaim) {
    throw 'Remote ready transport controls do not match C01 compat-overlay'
}
$readyPrivateSessionSha256 = Assert-Sha256 -Value (Get-RequiredProperty `
    -InputObject $ready -Name 'private_session_sha256' -Context 'ready') `
    -Name 'ready.private_session_sha256'

$proxyAddress = Get-LocalProxyAddress
$candidateSourceHost =
    ($proxyAddress.address.Split('%')[0] -replace ':', '-') + '.sslip.io'

try {
    $output = New-LabDirectory -Path $output
    if (Test-Path -LiteralPath $nodes -PathType Container) {
        throw "Nodes directory already exists; refusing to overwrite it: $nodes"
    }
    if (Test-Path -LiteralPath $evidence -PathType Container) {
        throw "Evidence directory already exists; refusing to overwrite it: $evidence"
    }
    $nodes = New-LabDirectory -Path $nodes
    $evidence = New-LabDirectory -Path $evidence

    foreach ($port in @($proxyPort, $candidatePorts.tcp,
            $candidatePorts.web)) {
        if (Get-NetTCPConnection -State Listen -LocalPort $port `
            -ErrorAction SilentlyContinue) {
            throw "Required TCP port is already in use: $port"
        }
    }
    if (Get-NetUDPEndpoint -LocalPort $candidatePorts.udp `
        -ErrorAction SilentlyContinue) {
        throw "Required UDP port is already in use: $($candidatePorts.udp)"
    }

    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
        -SourcePackage $package -OutputRoot $nodes -RunId 'v91-c01-remote' `
        -PortOffset 3400
    $candidateRoot = Join-Path $nodes 'v91-c01-remote-b'
    $candidateExe = Join-Path $candidateRoot 'emule.exe'
    if ((Get-LabSha256 -Path $candidateExe) -ne $candidateSha256) {
        throw 'Prepared candidate node does not contain the frozen binary'
    }
    $candidateIncoming = New-LabDirectory `
        -Path (Join-Path $candidateRoot 'Incoming')
    $candidateTemp = New-LabDirectory `
        -Path (Join-Path $candidateRoot 'Temp')
    $candidatePreferences = Join-Path $candidateRoot 'config\preferences.ini'
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' `
        -Key 'Autoconnect' -Value '0'
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' `
        -Key 'NetworkKademlia' -Value '1'
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' `
        -Key 'FilterBadIPs' -Value '0'
    Set-LabIniValue -Path $candidatePreferences -Section 'Connection' `
        -Key 'KadNetworkMask' -Value '1'
    Set-LabIniValue -Path $candidatePreferences -Section 'UPnP' `
        -Key 'EnableUPnP' -Value '0'
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' `
        -Key 'IncomingDir' -Value ($candidateIncoming + '\')
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' `
        -Key 'TempDir' -Value ($candidateTemp + '\')

    $candidateToVanilla = Join-Path $evidence 'candidate-to-vanilla.bin'
    $vanillaToCandidate = Join-Path $evidence 'vanilla-to-candidate.bin'
    $eventsPath = Join-Path $evidence 'proxy-events.jsonl'
    $progressPath = Join-Path $evidence 'progress.jsonl'
    $destinationFile = Join-Path $candidateIncoming $fixtureName
    $link = "ed2k://|file|$fixtureName|$fixtureBytes|$fixtureEd2k|" +
        'h=WJ6IED5UAK6HTVKX2J5HJ2XAXHITGL6T|/|sources,' +
        "$candidateSourceHost`:$proxyPort|/"

    try {
        New-NetFirewallRule -DisplayName $firewallRule -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort $proxyPort `
            -Profile Any | Out-Null
        $firewallCreated = $true
    } catch {
        Write-Warning "Temporary firewall rule was not created: $($_.Exception.Message)"
    }

    $registry = Get-ItemProperty -LiteralPath $registryPath `
        -ErrorAction SilentlyContinue
    if ($null -ne $registry -and
        $null -ne $registry.PSObject.Properties[$registryName]) {
        $registryOriginalExists = $true
        $registryOriginalValue = [int]$registry.$registryName
    }
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name $registryName `
        -Value 2 -PropertyType DWord -Force | Out-Null
    $registryModified = $true

    $proxyScript = Join-Path $PSScriptRoot 'tcp_capture_proxy.js'
    $nodeExe = (Get-Command node.exe).Source
    $proxy = Start-Process -FilePath $nodeExe -WorkingDirectory $output `
        -ArgumentList @(
            $proxyScript, $proxyAddress.address, [string]$proxyPort,
            $remoteAddressNormalized, [string]$RemoteVanillaPort,
            $candidateToVanilla, $vanillaToCandidate, $eventsPath
        ) -WindowStyle Hidden -PassThru
    $proxyListener = Wait-Listener -Port $proxyPort -Process $proxy `
        -ExpectedAddress $proxyAddress.address -Seconds 30

    $candidate = Start-Process -FilePath $candidateExe `
        -WorkingDirectory $candidateRoot -ArgumentList @(
            '--portable', '--ignoreinstances', '--headless',
            "--metrics-port=$($candidatePorts.web)",
            "--tcp-port=$($candidatePorts.tcp)",
            "--udp-port=$($candidatePorts.udp)",
            $link
        ) -WindowStyle Hidden -PassThru
    try {
        Wait-Listener -Port $candidatePorts.tcp -Process $candidate | Out-Null
    } finally {
        Restore-UserDirectoryMode
    }
    Invoke-RestMethod -Uri (
        "http://127.0.0.1:$($candidatePorts.web)/api/network/connect?ed2k=0&kad=1"
    ) -TimeoutSec 10 | Out-Null
    $networkDeadline = [DateTime]::UtcNow.AddMinutes(3)
    do {
        $networkState = Invoke-RestMethod -Uri (
            "http://127.0.0.1:$($candidatePorts.web)/api/status"
        ) -TimeoutSec 5
        if ($networkState.kad_connected) { break }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $networkDeadline)
    if (-not $networkState.kad_connected) {
        throw 'Candidate did not reach the Kad state required by the legacy scheduler'
    }

    $started = [DateTime]::UtcNow
    $deadline = $started.AddSeconds($TimeoutSeconds)
    do {
        if ($null -eq (Get-ExpectedProcess -ProcessId $proxy.Id `
                -ExpectedPath $nodeExe)) {
            throw 'Capture proxy exited'
        }
        if ($null -eq (Get-ExpectedProcess -ProcessId $candidate.Id `
                -ExpectedPath $candidateExe)) {
            throw 'V91 candidate exited'
        }
        $socketState = Get-SocketCorrelation `
            -CandidatePid $candidate.Id -ProxyPid $proxy.Id `
            -ProxyAddress $proxyAddress.address `
            -ProxyListenPort $proxyPort `
            -RemoteAddress $remoteAddressNormalized `
            -RemotePort $RemoteVanillaPort
        if ($socketState.pass) {
            $socketCorrelationObserved = $true
            if ($null -eq $socketCorrelationEvidence) {
                $socketCorrelationEvidence = $socketState
            }
        }
        $destination = Get-Item -LiteralPath $destinationFile `
            -ErrorAction SilentlyContinue
        $c2v = Get-Item -LiteralPath $candidateToVanilla `
            -ErrorAction SilentlyContinue
        $v2c = Get-Item -LiteralPath $vanillaToCandidate `
            -ErrorAction SilentlyContinue
        [ordered]@{
            schema = 'ese.v91.c01-remote-sample/v1'
            captured_at_utc = Get-LabUtcTimestamp
            elapsed_seconds = [Math]::Round(
                ([DateTime]::UtcNow - $started).TotalSeconds, 3)
            destination_bytes = if ($destination) {
                $destination.Length
            } else {
                0
            }
            candidate_to_vanilla_bytes = if ($c2v) { $c2v.Length } else { 0 }
            vanilla_to_candidate_bytes = if ($v2c) { $v2c.Length } else { 0 }
            socket_correlation = [bool]$socketState.pass
        } | ConvertTo-Json -Compress | Add-Content `
            -LiteralPath $progressPath -Encoding utf8
        if ($destination -and $destination.Length -eq $fixtureBytes) { break }
        Start-Sleep -Seconds 5
    } while ([DateTime]::UtcNow -lt $deadline)
    $finished = [DateTime]::UtcNow
    if ((Test-Path -LiteralPath $destinationFile -PathType Leaf) -and
        (Get-Item -LiteralPath $destinationFile).Length -eq $fixtureBytes) {
        $destinationHash = Get-LabSha256 -Path $destinationFile
    }
    $transferPass = $destinationHash -eq $fixtureSha256
    if (-not $transferPass) {
        throw 'The pinned compatibility fixture did not transfer intact'
    }
    if (-not $socketCorrelationObserved) {
        throw 'No PID/socket-correlated candidate-proxy-remote sample was observed'
    }
} finally {
    Restore-UserDirectoryMode
    $cleanupEvidence.registry_restored = -not $registryModified
    $cleanupEvidence.candidate_stopped = Stop-TestProcess `
        -Process $candidate -ExpectedPath $candidateExe
    Start-Sleep -Seconds 2
    $cleanupEvidence.proxy_stopped = Stop-TestProcess `
        -Process $proxy -ExpectedPath $nodeExe
    Remove-NetFirewallRule -DisplayName $firewallRule `
        -ErrorAction SilentlyContinue
    $cleanupEvidence.firewall_rule_removed =
        -not [bool](Get-NetFirewallRule -DisplayName $firewallRule `
            -ErrorAction SilentlyContinue)
    $ownedPids = @()
    if ($null -ne $candidate) { $ownedPids += $candidate.Id }
    if ($null -ne $proxy) { $ownedPids += $proxy.Id }
    $cleanupEvidence.owned_sockets_absent =
        @(
            Get-NetTCPConnection -ErrorAction SilentlyContinue |
                Where-Object OwningProcess -In $ownedPids
        ).Count -eq 0
}

if (-not (Test-Path -LiteralPath $candidateToVanilla -PathType Leaf) -or
    -not (Test-Path -LiteralPath $vanillaToCandidate -PathType Leaf) -or
    -not (Test-Path -LiteralPath $eventsPath -PathType Leaf)) {
    throw 'Compatibility captures were not produced'
}
$candidateFrames = Read-Frames -Path $candidateToVanilla
$vanillaFrames = Read-Frames -Path $vanillaToCandidate
$hello = @($candidateFrames.frames | Where-Object {
    $_.protocol -eq 0xE3 -and $_.opcode -eq 0x01
} | Select-Object -First 1)
if ($hello.Count -ne 1) { throw 'Candidate HELLO was not captured' }
$helloTags = @(Read-HelloTags -Bytes $candidateFrames.bytes `
    -Offset $hello[0].offset)
$eseTagNames = @('0x68', '0x6C', '0x6D', '0x6E')
$observedEseTags = @($helloTags | Where-Object name -In $eseTagNames)
$candidateRequestShapes = Get-CandidateRequestShapes `
    -FrameScan $candidateFrames -ExpectedEd2k $fixtureEd2k `
    -ExpectedBytes $fixtureBytes
$sourceProvenance = Get-VanillaFixtureProvenance `
    -CapturePath $vanillaToCandidate -FrameScan $vanillaFrames `
    -ExpectedEd2k $fixtureEd2k -ExpectedBytes $fixtureBytes `
    -ExpectedSha256 $fixtureSha256
$allowedProtocols = @(0xE3, 0xC5)
$allowedCandidatePairs = @('E3:01', 'E3:47', 'E3:54', 'C5:A9', 'C5:B1')
$allowedVanillaPairs =
    @('E3:46', 'E3:4C', 'E3:55', 'C5:87', 'C5:B0', 'C5:B2')
$candidatePairs = @($candidateFrames.frames | ForEach-Object {
    '{0:X2}:{1:X2}' -f $_.protocol, $_.opcode
})
$vanillaPairs = @($vanillaFrames.frames | ForEach-Object {
    '{0:X2}:{1:X2}' -f $_.protocol, $_.opcode
})
$unexpectedProtocols = @(
    @($candidateFrames.frames) + @($vanillaFrames.frames) |
        Where-Object { $_.protocol -notin $allowedProtocols } |
        Select-Object -ExpandProperty protocol -Unique
)
$unexpectedCandidatePairs = @($candidatePairs |
    Where-Object { $_ -notin $allowedCandidatePairs } |
    Select-Object -Unique)
$unexpectedVanillaPairs = @($vanillaPairs |
    Where-Object { $_ -notin $allowedVanillaPairs } |
    Select-Object -Unique)
$framingPass = -not $candidateFrames.invalid -and
    $candidateFrames.trailing_bytes -eq 0 -and
    -not $vanillaFrames.invalid -and
    $vanillaFrames.trailing_bytes -eq 0
$strictWirePass = $framingPass -and
    $unexpectedProtocols.Count -eq 0 -and
    $unexpectedCandidatePairs.Count -eq 0 -and
    $unexpectedVanillaPairs.Count -eq 0 -and
    $candidateRequestShapes.pass

$proxyEvents = [System.Collections.Generic.List[object]]::new()
foreach ($line in Get-Content -LiteralPath $eventsPath) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $proxyEvents.Add(($line | ConvertFrom-Json))
}
$startEvents = @($proxyEvents | Where-Object type -eq 'start')
$connectEvents = @($proxyEvents | Where-Object type -eq 'connect')
$connectionIds = @($proxyEvents | Where-Object {
    $null -ne $_.PSObject.Properties['connection']
} | Select-Object -ExpandProperty connection -Unique)
$proxyErrorsBeforeFinish = @($proxyEvents | Where-Object {
    $_.type -eq 'server_error' -or
    ($_.type -eq 'error' -and
        [DateTimeOffset]::Parse([string]$_.utc).UtcDateTime -le $finished)
})
$proxyPass = $startEvents.Count -eq 1 -and
    $connectEvents.Count -eq 1 -and
    $connectionIds.Count -eq 1 -and
    [int]$connectionIds[0] -eq 1 -and
    $proxyErrorsBeforeFinish.Count -eq 0
$cleanupPass = -not ($cleanupEvidence.Values -contains $false)
$formalPass = $transferPass -and $strictWirePass -and $proxyPass -and
    $sourceProvenance.pass -and $socketCorrelationObserved -and $cleanupPass

$validatedReady = [ordered]@{
    schema = 'ese.v91.c01.remote-ready-validation/v1'
    ready_json_sha256 = Get-LabSha256 -Path $readyPath
    status = 'READY'
    nonce = $readyNonce
    kit_nonce = $readyKitNonce.ToLowerInvariant()
    created_at_utc = $readyCreated.ToUniversalTime().ToString('o')
    ready_at_utc = $readyAt.ToUniversalTime().ToString('o')
    ready_expires_at_utc = $readyExpiry.ToString('o')
    unexpired_when_validated = $true
    host_id_hash = $readyHostIdHash
    tailnet_node_id_hash = $readyTailnetHash
    live_tailnet_match = $true
    live_tailnet_peer_online = $tailnetPeer.online
    vanilla = [ordered]@{
        version = $readyVanillaVersion
        product_version = $readyVanillaProductVersion
        bytes = $readyVanillaBytes
        binary_sha256 = $readyVanillaHash
        process_id = $readyVanillaPid
    }
    listener = [ordered]@{
        owning_process_id = $readyListenerPid
        port = $readyListenerPort
        address_class = $readyListenerClass
        address_sha256 = Get-LabStringSha256 -Value `
            $remoteAddressNormalized.ToLowerInvariant()
        ready_attested = $true
        live_proxy_socket_observed = $socketCorrelationObserved
    }
    fixture = [ordered]@{
        name = $fixtureName
        bytes = $fixtureBytes
        sha256 = $fixtureSha256
        ed2k = $fixtureEd2k
        available = $true
    }
    controls = $expectedControls
    transport = [ordered]@{
        kind = 'Tailscale IPv4 overlay'
        purpose = 'V91-C01 classic-wire interoperability only'
        native_reachability_claim = $false
        source_endpoint_match = $true
        coordinator_endpoint_match = $true
    }
    private_session_sha256 = $readyPrivateSessionSha256
}
Write-LabJson -Value $validatedReady `
    -Path (Join-Path $evidence 'remote-ready-validated.json') | Out-Null

$summary = [ordered]@{
    schema = 'ese.v91.c01-pass/v1'
    case_id = 'V91-C01'
    formal_status = if ($formalPass) { 'PASS' } else { 'FAIL' }
    formal_v91_c01_eligible = $formalPass
    candidate = [ordered]@{
        commit = $candidateCommit
        binary_sha256 = $candidateSha256
        ese_server_sha256 = $candidateInfo.ese_server_sha256
        build_info_sha256 = $candidateInfo.build_info_sha256
        process_id = $socketCorrelationEvidence.candidate_pid
    }
    topology = [ordered]@{
        topology_requirement = 'V1/H2'
        candidate_host = 'H1'
        vanilla_host = 'H2'
        isolation = 'physical-independent-windows'
        data_path = 'compat-overlay'
        candidate_facing_path = $proxyAddress.route_kind
        candidate_facing_family = 'IPv6'
        proxy_to_vanilla_family = 'IPv4'
        proxy_to_vanilla_route = 'Tailscale'
        candidate_interface_id = $proxyAddress.interface_id
        remote_host_id_hash = $readyHostIdHash
        remote_tailnet_node_id_hash = $readyTailnetHash
    }
    started_at_utc = $started.ToString('o')
    finished_at_utc = $finished.ToString('o')
    elapsed_seconds = [Math]::Round(($finished - $started).TotalSeconds, 3)
    transfer = [ordered]@{
        bytes = $fixtureBytes
        ed2k = $fixtureEd2k
        source_sha256 = $fixtureSha256
        destination_sha256 = $destinationHash
        hash_match = $transferPass
        captured_source_provenance = $sourceProvenance
    }
    proxy = [ordered]@{
        implementation_sha256 = Get-LabSha256 `
            -Path (Join-Path $PSScriptRoot 'tcp_capture_proxy.js')
        byte_transparent = $transferPass
        process_id = $socketCorrelationEvidence.proxy_pid
        connections = $connectEvents.Count
        exactly_one_connection = $proxyPass
        errors_before_transfer_complete = $proxyErrorsBeforeFinish.Count
    }
    socket_attribution = $socketCorrelationEvidence
    framing = [ordered]@{
        candidate_to_vanilla_bytes = $candidateFrames.bytes.Length
        candidate_to_vanilla_frames = $candidateFrames.frames.Count
        vanilla_to_candidate_bytes = $vanillaFrames.bytes.Length
        vanilla_to_candidate_frames = $vanillaFrames.frames.Count
        complete = $framingPass
        unexpected_protocols = @($unexpectedProtocols |
            ForEach-Object { '0x{0:X2}' -f $_ })
        unexpected_candidate_frame_pairs = $unexpectedCandidatePairs
        unexpected_vanilla_frame_pairs = $unexpectedVanillaPairs
        candidate_request_shapes = $candidateRequestShapes
        normative_wire_verdict = if ($strictWirePass) { 'PASS' } else { 'FAIL' }
    }
    candidate_hello = [ordered]@{
        tag_count = $helloTags.Count
        tags = $helloTags
        ese_tags_observed = $observedEseTags
    }
    cleanup = $cleanupEvidence
    additive_hello_tags_policy =
        'Allowed only as extensible HELLO metadata; no eSE opcode or payload may be sent before capability negotiation.'
    claim = [ordered]@{
        proves = @(
            'Exact RC2 candidate interoperates with pinned vanilla eMule 0.70b on an independent physical Windows host.',
            'The complete pinned fixture transfers with an identical SHA-256.',
            'Every captured vanilla E3:46 segment carries the pinned ED2K hash and reconstructs exact gap-free fixture coverage with a matching incremental SHA-256.',
            'Captured eD2K framing uses only the allowlisted classic protocols and frame pairs.',
            'Candidate, proxy and remote endpoint are PID/socket/topology correlated.'
        )
        does_not_prove = @(
            'Native public IPv4 or IPv6 reachability between H1 and H2.',
            'Tailscale-free data transport.',
            'Any IPv6 feature implemented by vanilla eMule 0.70b.'
        )
    }
}
$summaryPath = Write-LabJson -Value $summary `
    -Path (Join-Path $evidence 'V91-C01-PASS.json')
if (-not $formalPass) {
    throw 'V91-C01 remote vanilla evidence failed a formal gate'
}
Write-Host "V91-C01 formal PASS: $summaryPath" -ForegroundColor Green
