[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$VanillaTemplatePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidateRange(60, 3600)][int]$TimeoutSeconds = 1200,
    [string]$Commit = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$candidateInfo = Get-LabCandidateInfo -PackagePath $PackagePath -ExpectedCommit $Commit
$candidateCommit = $candidateInfo.commit
$candidateSha256 = $candidateInfo.emule_sha256
$fixtureName = 'net13-unique-ffmpeg.zip'
$fixtureBytes = 223394208L
$fixtureSha256 = 'aac4b00281982e473aab7071b1a593eef3ad22301085d18d26933557b022890c'
$fixtureEd2k = 'A4140C71628D93D5FD0981FD962C2552'
$proxyPort = 48711
$vanillaPort = 48712
$candidatePorts = [ordered]@{ tcp = 8062; udp = 8072; web = 8111 }
$package = $candidateInfo.package_path
$template = (Resolve-Path -LiteralPath $VanillaTemplatePath).Path
$output = New-LabDirectory -Path $OutputRoot
$nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
$vanillaRoot = Join-Path $nodes 'vanilla-070b'
$candidateRoot = $null
$vanilla = $null
$candidate = $null
$proxy = $null
$firewallRule = 'eSE V91 partial C01 ' + [Guid]::NewGuid().ToString('N')
$registryPath = 'HKCU:\Software\eMule'
$registryName = 'UsePublicUserDirectories'
$registryOriginalExists = $false
$registryOriginalValue = $null
$registryModified = $false

function Get-ExpectedProcess {
    param(
        [int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )
    if ($ProcessId -le 0) { return $null }
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process -or $process.Path -ne $ExpectedPath) { return $null }
    return $process
}

function Wait-Listener {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [int]$Seconds = 90
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "Process $($Process.Id) exited before listener $Port became ready"
        }
        $listener = Get-NetTCPConnection -State Listen -LocalPort $Port `
            -ErrorAction SilentlyContinue |
            Where-Object OwningProcess -eq $Process.Id |
            Select-Object -First 1
        if ($null -ne $listener) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Listener $Port did not become ready for PID $($Process.Id)"
}

function Restore-UserDirectoryMode {
    if (-not $script:registryModified) { return }
    if ($script:registryOriginalExists) {
        New-ItemProperty -LiteralPath $script:registryPath -Name $script:registryName `
            -Value $script:registryOriginalValue -PropertyType DWord -Force | Out-Null
    } else {
        Remove-ItemProperty -LiteralPath $script:registryPath -Name $script:registryName `
            -ErrorAction SilentlyContinue
    }
    $script:registryModified = $false
}

function Stop-TestProcess {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [AllowEmptyString()][string]$ExpectedPath = ''
    )
    if ($null -eq $Process) { return }
    $actual = if ($ExpectedPath) {
        Get-ExpectedProcess -ProcessId $Process.Id -ExpectedPath $ExpectedPath
    } else {
        Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
    }
    if ($null -ne $actual) {
        Stop-Process -Id $actual.Id -Force -ErrorAction SilentlyContinue
        $null = $actual.WaitForExit(10000)
    }
}

function Read-Frames {
    param([Parameter(Mandatory = $true)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $offset = 0
    $frames = @()
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
        $frames += [pscustomobject]@{
            offset = $offset
            protocol = $protocol
            opcode = $bytes[$offset + 5]
            total_bytes = $total
        }
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

try {
    if ((Get-LabSha256 -Path (Join-Path $package 'emule.exe')) -ne $candidateSha256) {
        throw 'The package does not contain the frozen V91 candidate binary'
    }
    $templateFixture = Join-Path $template "Incoming\$fixtureName"
    if ((Get-Item -LiteralPath $templateFixture).Length -ne $fixtureBytes -or
        (Get-LabSha256 -Path $templateFixture) -ne $fixtureSha256) {
        throw 'The pinned vanilla compatibility fixture has changed'
    }
    foreach ($port in @($proxyPort, $vanillaPort, $candidatePorts.tcp,
        $candidatePorts.udp, $candidatePorts.web)) {
        if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) {
            throw "Required port is already in use: $port"
        }
    }

    Copy-Item -LiteralPath $template -Destination $vanillaRoot -Recurse -Force
    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
        -SourcePackage $package -OutputRoot $nodes -RunId 'v91-c01-partial' `
        -PortOffset 3400
    $candidateRoot = Join-Path $nodes 'v91-c01-partial-b'
    $candidateIncoming = New-LabDirectory -Path (Join-Path $candidateRoot 'Incoming')
    $candidateTemp = New-LabDirectory -Path (Join-Path $candidateRoot 'Temp')
    $candidatePreferences = Join-Path $candidateRoot 'config\preferences.ini'
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' -Key 'Autoconnect' -Value '0'
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' -Key 'NetworkKademlia' -Value '1'
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' -Key 'FilterBadIPs' -Value '0'
    Set-LabIniValue -Path $candidatePreferences -Section 'Connection' -Key 'KadNetworkMask' -Value '1'
    Set-LabIniValue -Path $candidatePreferences -Section 'UPnP' -Key 'EnableUPnP' -Value '0'
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' -Key 'IncomingDir' `
        -Value ($candidateIncoming + '\')
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' -Key 'TempDir' `
        -Value ($candidateTemp + '\')

    $vanillaIncoming = Join-Path $vanillaRoot 'Incoming'
    $vanillaTemp = New-LabDirectory -Path (Join-Path $vanillaRoot 'Temp')
    $vanillaPreferences = Join-Path $vanillaRoot 'config\preferences.ini'
    Set-LabIniValue -Path $vanillaPreferences -Section 'eMule' -Key 'Port' `
        -Value ([string]$vanillaPort)
    Set-LabIniValue -Path $vanillaPreferences -Section 'eMule' -Key 'UDPPort' `
        -Value ([string]($vanillaPort + 1))
    Set-LabIniValue -Path $vanillaPreferences -Section 'eMule' -Key 'Autoconnect' -Value '0'
    Set-LabIniValue -Path $vanillaPreferences -Section 'eMule' -Key 'IncomingDir' `
        -Value ($vanillaIncoming + '\')
    Set-LabIniValue -Path $vanillaPreferences -Section 'eMule' -Key 'TempDir' `
        -Value ($vanillaTemp + '\')

    $vanillaAddress = $null
    $candidateSourceAddress = $null
    foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($adapter.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up) { continue }
        $label = '{0}|{1}' -f $adapter.Name, $adapter.Description
        foreach ($unicast in $adapter.GetIPProperties().UnicastAddresses) {
            $address = $unicast.Address.ToString()
            $addressClass = Get-LabAddressClass -Address $address
            if (-not $vanillaAddress -and
                $label -notmatch '(?i)Tailscale|Cloudflare|WARP|Loopback' -and
                $addressClass -eq 'private-v4') {
                $vanillaAddress = $address
            }
            if (-not $candidateSourceAddress -and
                $label -notmatch '(?i)Tailscale|Loopback' -and
                $addressClass -eq 'global-v6') {
                $candidateSourceAddress = $address
            }
        }
    }
    if (-not $vanillaAddress) { throw 'No private LAN IPv4 address is available' }
    if (-not $candidateSourceAddress) {
        throw 'No non-Tailscale global IPv6 address is available for the candidate-facing proxy'
    }
    $candidateSourceHost = ($candidateSourceAddress -replace ':', '-') + '.sslip.io'

    $candidateToVanilla = Join-Path $evidence 'candidate-to-vanilla.bin'
    $vanillaToCandidate = Join-Path $evidence 'vanilla-to-candidate.bin'
    $events = Join-Path $evidence 'proxy-events.jsonl'
    $progress = Join-Path $evidence 'progress.jsonl'
    $destinationFile = Join-Path $candidateIncoming $fixtureName
    $link = "ed2k://|file|$fixtureName|$fixtureBytes|$fixtureEd2k|h=WJ6IED5UAK6HTVKX2J5HJ2XAXHITGL6T|/|sources,$candidateSourceHost`:$proxyPort|/"

    try {
        New-NetFirewallRule -DisplayName $firewallRule -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $proxyPort,$vanillaPort,$candidatePorts.tcp `
            -Profile Any | Out-Null
    } catch {
        Write-Warning "Temporary firewall rule was not created: $($_.Exception.Message)"
    }

    $registry = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
    if ($null -ne $registry -and $null -ne $registry.PSObject.Properties[$registryName]) {
        $registryOriginalExists = $true
        $registryOriginalValue = [int]$registry.$registryName
    }
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -LiteralPath $registryPath -Name $registryName -Value 2 `
        -PropertyType DWord -Force | Out-Null
    $registryModified = $true
    try {
        $vanillaExe = Join-Path $vanillaRoot 'emule.exe'
        $vanilla = Start-Process -FilePath $vanillaExe -WorkingDirectory $vanillaRoot `
            -ArgumentList @('-ignoreinstances') -WindowStyle Hidden -PassThru
        Wait-Listener -Port $vanillaPort -Process $vanilla
    } finally {
        Restore-UserDirectoryMode
    }

    $proxyScript = Join-Path $PSScriptRoot 'tcp_capture_proxy.js'
    $proxy = Start-Process -FilePath (Get-Command node.exe).Source `
        -WorkingDirectory $output -ArgumentList @(
            $proxyScript, '::', [string]$proxyPort, $vanillaAddress,
            [string]$vanillaPort, $candidateToVanilla, $vanillaToCandidate, $events
        ) -WindowStyle Hidden -PassThru
    Wait-Listener -Port $proxyPort -Process $proxy -Seconds 30

    $candidateExe = Join-Path $candidateRoot 'emule.exe'
    $started = [DateTime]::UtcNow
    $candidate = Start-Process -FilePath $candidateExe -WorkingDirectory $candidateRoot `
        -ArgumentList @(
            '--portable', '--ignoreinstances', '--headless',
            "--metrics-port=$($candidatePorts.web)",
            "--tcp-port=$($candidatePorts.tcp)",
            "--udp-port=$($candidatePorts.udp)",
            $link
        ) -WindowStyle Hidden -PassThru
    Wait-Listener -Port $candidatePorts.tcp -Process $candidate
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
        throw 'Candidate did not reach a connected Kad state required by the legacy download scheduler'
    }

    $deadline = $started.AddSeconds($TimeoutSeconds)
    do {
        if ($null -eq (Get-ExpectedProcess -ProcessId $vanilla.Id -ExpectedPath $vanillaExe)) {
            throw 'Vanilla 0.70b source exited'
        }
        if ($null -eq (Get-ExpectedProcess -ProcessId $proxy.Id `
            -ExpectedPath (Get-Command node.exe).Source)) {
            throw 'Capture proxy exited'
        }
        if ($null -eq (Get-ExpectedProcess -ProcessId $candidate.Id -ExpectedPath $candidateExe)) {
            throw 'V91 candidate exited'
        }
        $destination = Get-Item -LiteralPath $destinationFile -ErrorAction SilentlyContinue
        $c2v = Get-Item -LiteralPath $candidateToVanilla -ErrorAction SilentlyContinue
        $v2c = Get-Item -LiteralPath $vanillaToCandidate -ErrorAction SilentlyContinue
        [ordered]@{
            schema = 'ese.v91.c01-partial-sample/v1'
            captured_at_utc = Get-LabUtcTimestamp
            elapsed_seconds = [Math]::Round(([DateTime]::UtcNow - $started).TotalSeconds, 3)
            destination_bytes = if ($destination) { $destination.Length } else { 0 }
            candidate_to_vanilla_bytes = if ($c2v) { $c2v.Length } else { 0 }
            vanilla_to_candidate_bytes = if ($v2c) { $v2c.Length } else { 0 }
        } | ConvertTo-Json -Compress | Add-Content -LiteralPath $progress -Encoding utf8
        if ($destination -and $destination.Length -eq $fixtureBytes) { break }
        Start-Sleep -Seconds 5
    } while ([DateTime]::UtcNow -lt $deadline)
    $finished = [DateTime]::UtcNow
    $destinationHash = if ((Test-Path -LiteralPath $destinationFile) -and
        (Get-Item -LiteralPath $destinationFile).Length -eq $fixtureBytes) {
        Get-LabSha256 -Path $destinationFile
    } else {
        ''
    }
    $transferPass = $destinationHash -eq $fixtureSha256
} finally {
    Restore-UserDirectoryMode
    Start-Sleep -Seconds 2
    Stop-TestProcess -Process $candidate -ExpectedPath $(if ($candidateRoot) {
        Join-Path $candidateRoot 'emule.exe'
    } else { '' })
    Stop-TestProcess -Process $proxy
    Stop-TestProcess -Process $vanilla -ExpectedPath $(if (Test-Path $vanillaRoot) {
        Join-Path $vanillaRoot 'emule.exe'
    } else { '' })
    Remove-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue
}

if (-not (Test-Path -LiteralPath $candidateToVanilla -PathType Leaf) -or
    -not (Test-Path -LiteralPath $vanillaToCandidate -PathType Leaf)) {
    throw 'Compatibility captures were not produced'
}
$candidateFrames = Read-Frames -Path $candidateToVanilla
$vanillaFrames = Read-Frames -Path $vanillaToCandidate
$hello = @($candidateFrames.frames | Where-Object {
    $_.protocol -eq 0xE3 -and $_.opcode -eq 0x01
} | Select-Object -First 1)
if ($hello.Count -ne 1) { throw 'Candidate HELLO was not captured' }
$helloTags = @(Read-HelloTags -Bytes $candidateFrames.bytes -Offset $hello[0].offset)
$eseTagNames = @('0x68', '0x6C', '0x6D', '0x6E')
$observedEseTags = @($helloTags | Where-Object name -In $eseTagNames)
$allowedProtocols = @(0xE3, 0xC5)
$unexpectedProtocols = @($candidateFrames.frames | Where-Object {
    $_.protocol -notin $allowedProtocols
} | Select-Object -ExpandProperty protocol -Unique)
$allowedFramePairs = @('E3:01', 'E3:47', 'E3:54', 'C5:A9', 'C5:B1')
$unexpectedFramePairs = @($candidateFrames.frames | ForEach-Object {
    '{0:X2}:{1:X2}' -f $_.protocol, $_.opcode
} | Where-Object { $_ -notin $allowedFramePairs } | Select-Object -Unique)
$framingPass = -not $candidateFrames.invalid -and
    $candidateFrames.trailing_bytes -eq 0 -and
    -not $vanillaFrames.invalid -and
    $vanillaFrames.trailing_bytes -eq 0
$strictWirePass = $framingPass -and
    $unexpectedProtocols.Count -eq 0 -and
    $unexpectedFramePairs.Count -eq 0

$summary = [ordered]@{
    schema = 'ese.v91.c01-partial-vanilla/v1'
    case_id = 'V91-C01'
    formal_status = 'BLOCKED'
    formal_v91_c01_eligible = $false
    formal_limitation = 'V91-C01 requires vanilla 0.70b in Hyper-V V1; this capture uses two isolated processes on H1.'
    candidate_commit = $candidateCommit
    candidate_binary_sha256 = $candidateSha256
    vanilla_binary_sha256 = Get-LabSha256 -Path (Join-Path $vanillaRoot 'emule.exe')
    started_at_utc = $started.ToString('o')
    finished_at_utc = $finished.ToString('o')
    runtime_compatibility_verdict = if ($transferPass -and $framingPass) { 'PASS' } else { 'FAIL' }
    normative_wire_verdict = if ($strictWirePass) { 'PASS' } else { 'FAIL' }
    transfer = [ordered]@{
        bytes = $fixtureBytes
        source_sha256 = $fixtureSha256
        destination_sha256 = $destinationHash
        hash_match = $transferPass
    }
    framing = [ordered]@{
        candidate_to_vanilla_bytes = $candidateFrames.bytes.Length
        candidate_to_vanilla_frames = $candidateFrames.frames.Count
        vanilla_to_candidate_bytes = $vanillaFrames.bytes.Length
        vanilla_to_candidate_frames = $vanillaFrames.frames.Count
        complete = $framingPass
        unexpected_protocols = @($unexpectedProtocols | ForEach-Object { '0x{0:X2}' -f $_ })
        unexpected_frame_pairs = $unexpectedFramePairs
    }
    candidate_hello = [ordered]@{
        tag_count = $helloTags.Count
        tags = $helloTags
        ese_tags_observed = $observedEseTags
    }
    additive_hello_tags_policy = 'Allowed only as extensible HELLO metadata; no eSE opcode or payload may be sent before capability negotiation.'
}
Write-LabJson -Value $summary -Path (Join-Path $evidence 'summary.json') | Out-Null
if (-not $transferPass -or -not $framingPass) {
    throw 'Candidate-to-vanilla runtime compatibility transfer failed'
}
Write-Host "V91-C01 partial runtime compatibility PASS; normative wire verdict: $($summary.normative_wire_verdict)" -ForegroundColor Green
