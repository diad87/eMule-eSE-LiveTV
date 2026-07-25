[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidateRange(1, 7200)][int]$TimeoutSeconds = 3600,
    [ValidateRange(1048576, 17179869184)][Int64]$FileSizeBytes = 4294967296,
    [string]$FixtureSeedPath = '',
    [ValidateSet('IPv6', 'IPv4')][string]$TransportFamily = 'IPv6'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$candidateCommit = '72a5a41ebeec1bd08bff7ed17df27782930d96e3'
$candidateSha256 = '82360915292df613320af889e7680c69efcf422df9d8052b3613041a0a42da14'
$package = (Resolve-Path -LiteralPath $PackagePath).Path
$output = New-LabDirectory -Path $OutputRoot
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
$nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
$caseId = if ($TransportFamily -eq 'IPv6') { 'V91-I01' } else { 'V91-I05' }
$runId = if ($TransportFamily -eq 'IPv6') {
    'v91-i01-partial'
} else {
    'v91-i05-partial'
}
$fileName = "$runId-$FileSizeBytes.bin"
$password = 'v91-transfer-gate'
$source = $null
$downloader = $null
$firewallRule = 'eSE V91 partial I01 ' + [Guid]::NewGuid().ToString('N')

function Get-Md5Text {
    param([Parameter(Mandatory = $true)][string]$Value)
    $md5 = [Security.Cryptography.MD5]::Create()
    try {
        return ([BitConverter]::ToString(
            # eMule's MD5Sum(CString) hashes the native UTF-16LE TCHAR buffer,
            # not the UTF-8 representation used by most Web clients.
            $md5.ComputeHash([Text.Encoding]::Unicode.GetBytes($Value))
        )).Replace('-', '')
    } finally {
        $md5.Dispose()
    }
}

function Wait-Api {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before API startup (exit $($Process.ExitCode))"
        }
        try {
            return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/status" -TimeoutSec 2
        } catch {
            Start-Sleep -Milliseconds 500
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "API on port $Port did not become ready"
}

function Get-ClassicSession {
    param([Parameter(Mandatory = $true)][int]$Port)
    $encoded = [Uri]::EscapeDataString($password)
    # A 4 GiB fixture can keep the legacy WebServer worker unavailable while
    # eMule performs the initial ED2K hash.  Keep retrying long enough for that
    # legitimate startup phase; API readiness alone does not imply that the
    # classic pages are already responsive.
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        try {
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/?w=password&p=$encoded" `
                -UseBasicParsing -TimeoutSec 10
            $match = [regex]::Match($response.Content, 'ses=(\d+)')
            if ($match.Success) {
                return $match.Groups[1].Value
            }
        } catch {
            # The legacy WebServer may close its first connection while the
            # template and worker pool finish starting. Retry within the
            # bounded startup window.
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Classic WebServer login failed on port $Port after bounded retries"
}

function Get-SharedLink {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session
    )
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        $response = Invoke-WebRequest `
            -Uri "http://127.0.0.1:$Port/?ses=$Session&w=shared" `
            -UseBasicParsing -TimeoutSec 15
        $pattern = 'ed2k://\|file\|' + [regex]::Escape($fileName) +
            '\|' + $FileSizeBytes +
            '\|([A-Fa-f0-9]{32})(?:\|h=[A-Z2-7]{32})?\|/'
        $match = [regex]::Match($response.Content, $pattern)
        if ($match.Success) {
            return [pscustomobject]@{
                link = $match.Value
                ed2k_hash = $match.Groups[1].Value.ToUpperInvariant()
            }
        }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Timed out waiting for the 4 GiB file to enter the source shared list'
}

function Send-Ed2kLink {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Link
    )
    if (-not ('V91CopyData' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91CopyData {
    [StructLayout(LayoutKind.Sequential)]
    public struct COPYDATASTRUCT {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern IntPtr SendMessage(
        IntPtr hWnd, uint Msg, IntPtr wParam, ref COPYDATASTRUCT lParam);
}
'@
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $Process.Refresh()
        if ($Process.HasExited) { throw 'Downloader exited before WM_COPYDATA injection' }
        $handle = $Process.MainWindowHandle
        if ($handle -ne 0) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($handle -eq 0) { throw 'Downloader main window handle was not available' }

    $pointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Link)
    try {
        $payload = New-Object V91CopyData+COPYDATASTRUCT
        $payload.dwData = [IntPtr]12000
        $payload.cbData = ($Link.Length + 1) * 2
        $payload.lpData = $pointer
        [V91CopyData]::SendMessage(
            [IntPtr]$handle, 0x004A, [IntPtr]::Zero, [ref]$payload
        ) | Out-Null
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
    }
}

function Stop-TestProcess {
    param([AllowNull()][Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try { $Process.Refresh() } catch { return }
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $null = $Process.WaitForExit(10000)
    }
}

try {
    $packageHash = Get-LabSha256 -Path (Join-Path $package 'emule.exe')
    if ($packageHash -ne $candidateSha256) {
        throw "Unexpected candidate binary hash: $packageHash"
    }

    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
        -SourcePackage $package -OutputRoot $nodes -RunId $runId `
        -PortOffset 3000
    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
        -SourcePackage $package -OutputRoot $nodes -RunId $runId `
        -PortOffset 3100
    $sourceNode = Join-Path $nodes "$runId-a"
    $downloaderNode = Join-Path $nodes "$runId-b"
    $sourcePorts = [ordered]@{ tcp = 7662; udp = 7672; web = 7711 }
    $downloaderPorts = [ordered]@{ tcp = 7762; udp = 7772; web = 7811 }

    foreach ($node in @($sourceNode, $downloaderNode)) {
        $preferences = Join-Path $node 'config\preferences.ini'
        Set-LabIniValue -Path $preferences -Section 'eMule' -Key 'Autoconnect' -Value '0'
        Set-LabIniValue -Path $preferences -Section 'eMule' -Key 'NetworkKademlia' -Value '1'
        Set-LabIniValue -Path $preferences -Section 'eMule' -Key 'VerboseOptions' -Value '1'
        Set-LabIniValue -Path $preferences -Section 'eMule' -Key 'Verbose' -Value '1'
        Set-LabIniValue -Path $preferences -Section 'eMule' -Key 'SaveLogToDisk' -Value '1'
        Set-LabIniValue -Path $preferences -Section 'eMule' -Key 'SaveDebugToDisk' -Value '1'
        Set-LabIniValue -Path $preferences -Section 'Connection' -Key 'KadNetworkMask' -Value '1'
        Set-LabIniValue -Path $preferences -Section 'Connection' -Key 'IPv6Mode' `
            -Value $(if ($TransportFamily -eq 'IPv6') { '1' } else { '0' })
        Set-LabIniValue -Path $preferences -Section 'UPnP' -Key 'EnableUPnP' -Value '0'
        Set-LabIniValue -Path $preferences -Section 'WebServer' -Key 'Enabled' -Value '1'
        Set-LabIniValue -Path $preferences -Section 'WebServer' -Key 'Password' `
            -Value (Get-Md5Text -Value $password)
        Set-LabIniValue -Path $preferences -Section 'WebServer' -Key 'WebUseUPnP' -Value '0'
        $null = New-LabDirectory -Path (Join-Path $node 'Incoming')
        $null = New-LabDirectory -Path (Join-Path $node 'Temp')
        Set-LabIniValue -Path $preferences -Section 'eMule' -Key 'IncomingDir' `
            -Value ((Join-Path $node 'Incoming') + '\')
        Set-LabIniValue -Path $preferences -Section 'eMule' -Key 'TempDir' `
            -Value ((Join-Path $node 'Temp') + '\')
    }

    $sourceFile = Join-Path (Join-Path $sourceNode 'Incoming') $fileName
    $stream = [IO.File]::Open(
        $sourceFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        if ($FixtureSeedPath) {
            $seedPath = (Resolve-Path -LiteralPath $FixtureSeedPath).Path
            $seed = [IO.File]::OpenRead($seedPath)
            try {
                if ($seed.Length -eq 0) { throw 'Fixture seed must not be empty' }
                $buffer = New-Object byte[] (8MB)
                [Int64]$remaining = $FileSizeBytes
                while ($remaining -gt 0) {
                    $wanted = [int][Math]::Min([Int64]$buffer.Length, $remaining)
                    $read = $seed.Read($buffer, 0, $wanted)
                    if ($read -eq 0) {
                        $seed.Position = 0
                        continue
                    }
                    $stream.Write($buffer, 0, $read)
                    $remaining -= $read
                }
            } finally {
                $seed.Dispose()
            }
        } else {
            $stream.SetLength($FileSizeBytes)
        }
    } finally {
        $stream.Dispose()
    }
    $sourceSha256 = Get-LabSha256 -Path $sourceFile

    if ($TransportFamily -eq 'IPv6') {
        $globalV6 = @(
            Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.AddressState -eq 'Preferred' -and
                    (Get-LabAddressClass -Address $_.IPAddress) -eq 'global-v6' -and
                    $_.InterfaceAlias -match '(?i)Cloudflare|WARP'
                }
        ) | Select-Object -First 1
        if ($null -eq $globalV6) {
            throw 'No preferred global IPv6 address is available on Cloudflare WARP'
        }
        $address = $globalV6.IPAddress
        # sslip.io gives us an AAAA-only hostname for the current WARP address.
        # Using a hostname exercises the production A/AAAA resolver and avoids an
        # immediate literal-resolution callback racing initial AddDownload.
        $sourceHost = ($address -replace ':', '-') + '.sslip.io'
        $interfaceClass = 'Cloudflare WARP'
    } else {
        # Use the physical LAN address: eMule correctly rejects loopback as a
        # peer source, so 127.0.0.1 cannot exercise the inherited data plane.
        $lanV4 = @(
            Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.AddressState -eq 'Preferred' -and
                    (Get-LabAddressClass -Address $_.IPAddress) -eq 'private-v4' -and
                    $_.InterfaceAlias -notmatch '(?i)Cloudflare|WARP|Tailscale|vEthernet'
                }
        ) | Select-Object -First 1
        if ($null -eq $lanV4) {
            throw 'No preferred private IPv4 address is available on a physical LAN interface'
        }
        $address = $lanV4.IPAddress
        # Keep hostname resolution asynchronous so the source is not discarded
        # before AddDownload owns the file.
        $sourceHost = ($address -replace '\.', '-') + '.sslip.io'
        $interfaceClass = 'physical LAN IPv4'
    }

    try {
        New-NetFirewallRule -DisplayName $firewallRule -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort $sourcePorts.tcp,$downloaderPorts.tcp `
            -Profile Any | Out-Null
    } catch {
        Write-Warning "Temporary firewall rule was not created: $($_.Exception.Message)"
    }

    $source = Start-Process -FilePath (Join-Path $sourceNode 'emule.exe') `
        -ArgumentList @(
            '--portable', '--ignoreinstances', '--headless',
            "--metrics-port=$($sourcePorts.web)",
            "--tcp-port=$($sourcePorts.tcp)",
            "--udp-port=$($sourcePorts.udp)"
        ) -WorkingDirectory $sourceNode -PassThru -WindowStyle Hidden
    $downloader = Start-Process -FilePath (Join-Path $downloaderNode 'emule.exe') `
        -ArgumentList @(
            '--portable', '--ignoreinstances', '--headless',
            "--metrics-port=$($downloaderPorts.web)",
            "--tcp-port=$($downloaderPorts.tcp)",
            "--udp-port=$($downloaderPorts.udp)"
        ) -WorkingDirectory $downloaderNode -PassThru -WindowStyle Hidden

    Wait-Api -Port $sourcePorts.web -Process $source | Out-Null
    Wait-Api -Port $downloaderPorts.web -Process $downloader | Out-Null
    Invoke-RestMethod -Uri (
        "http://127.0.0.1:$($downloaderPorts.web)/api/network/connect?ed2k=0&kad=1"
    ) -TimeoutSec 10 | Out-Null
    $networkDeadline = [DateTime]::UtcNow.AddMinutes(3)
    do {
        $networkState = Invoke-RestMethod -Uri (
            "http://127.0.0.1:$($downloaderPorts.web)/api/status"
        ) -TimeoutSec 5
        if ($networkState.kad_connected) { break }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $networkDeadline)
    if (-not $networkState.kad_connected) {
        throw 'Downloader did not reach a connected Kad state required by the legacy download scheduler'
    }
    $session = Get-ClassicSession -Port $sourcePorts.web
    $shared = Get-SharedLink -Port $sourcePorts.web -Session $session
    $directLink = $shared.link + "|sources,$sourceHost`:$($sourcePorts.tcp)|/"

    $started = [DateTime]::UtcNow
    Send-Ed2kLink -Process $downloader -Link $directLink
    # The first link creates the part file.  Re-submit after the queue owns
    # that file so an asynchronously resolved IPv6 source cannot race the
    # AddDownload path and be discarded before GetFileByID can find it.
    Start-Sleep -Seconds 3
    Send-Ed2kLink -Process $downloader -Link $directLink
    $destinationFile = Join-Path (Join-Path $downloaderNode 'Incoming') $fileName
    $samplePath = Join-Path $evidence 'samples.jsonl'
    $sampleNumber = 0
    $sawIpv6 = $false
    $sawIpv4 = $false
    $maxSourceWorkingSet = 0L
    $maxDownloaderWorkingSet = 0L
    $deadline = $started.AddSeconds($TimeoutSeconds)

    do {
        $source.Refresh()
        $downloader.Refresh()
        if ($source.HasExited -or $downloader.HasExited) {
            throw "Transfer process exited early: source=$($source.HasExited), downloader=$($downloader.HasExited)"
        }
        $connections = @(
            Get-NetTCPConnection -OwningProcess $downloader.Id -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.RemotePort -eq $sourcePorts.tcp -and
                    [string]$_.State -eq 'Established'
                }
        )
        $ipv6Count = @($connections | Where-Object RemoteAddress -Match ':').Count
        $ipv4Count = @($connections | Where-Object RemoteAddress -NotMatch ':').Count
        if ($ipv6Count -gt 0) { $sawIpv6 = $true }
        if ($ipv4Count -gt 0) { $sawIpv4 = $true }
        $maxSourceWorkingSet = [Math]::Max($maxSourceWorkingSet, $source.WorkingSet64)
        $maxDownloaderWorkingSet = [Math]::Max($maxDownloaderWorkingSet, $downloader.WorkingSet64)
        $partFiles = @(
            Get-ChildItem -LiteralPath (Join-Path $downloaderNode 'Temp') `
                -File -Filter '*.part' -ErrorAction SilentlyContinue
        )
        $sample = [ordered]@{
            schema = 'ese.v91.i01-partial-sample/v1'
            sample_number = ++$sampleNumber
            captured_at_utc = Get-LabUtcTimestamp
            elapsed_seconds = [Math]::Round(([DateTime]::UtcNow - $started).TotalSeconds, 3)
            source_working_set_bytes = $source.WorkingSet64
            downloader_working_set_bytes = $downloader.WorkingSet64
            part_file_count = $partFiles.Count
            part_last_write_utc = if ($partFiles.Count) {
                ($partFiles | Sort-Object LastWriteTimeUtc -Descending |
                    Select-Object -First 1).LastWriteTimeUtc.ToString('o')
            } else {
                $null
            }
            destination_exists = Test-Path -LiteralPath $destinationFile -PathType Leaf
            ipv6_connection_count = $ipv6Count
            ipv4_connection_count = $ipv4Count
        }
        $sampleLine = $sample | ConvertTo-Json -Compress
        Add-Content -LiteralPath $samplePath -Value $sampleLine -Encoding utf8
        if ($sample.destination_exists) { break }
        Start-Sleep -Seconds 5
    } while ([DateTime]::UtcNow -lt $deadline)

    $finished = [DateTime]::UtcNow
    $destinationExists = Test-Path -LiteralPath $destinationFile -PathType Leaf
    $destinationSize = if ($destinationExists) {
        (Get-Item -LiteralPath $destinationFile).Length
    } else {
        0
    }
    $destinationSha256 = if ($destinationExists -and
        $destinationSize -eq $FileSizeBytes) {
        Get-LabSha256 -Path $destinationFile
    } else {
        ''
    }
    $expectedFamilyObserved = if ($TransportFamily -eq 'IPv6') {
        $sawIpv6
    } else {
        $sawIpv4
    }
    $unexpectedFamilyObserved = if ($TransportFamily -eq 'IPv6') {
        $sawIpv4
    } else {
        $sawIpv6
    }
    $partialPass = $destinationExists -and
        $destinationSize -eq $FileSizeBytes -and
        $destinationSha256 -eq $sourceSha256 -and
        $expectedFamilyObserved -and
        -not $unexpectedFamilyObserved

    $summary = [ordered]@{
        schema = if ($TransportFamily -eq 'IPv6') {
            'ese.v91.i01-partial-transfer/v1'
        } else {
            'ese.v91.i05-partial-transfer/v1'
        }
        case_id = $caseId
        formal_status = 'BLOCKED'
        partial_verdict = if ($partialPass) { 'PASS' } else { 'FAIL' }
        formal_eligible = $false
        formal_limitation = if ($TransportFamily -eq 'IPv6') {
            'V91-I01 requires two peers in T5 with IPv4 removed; this run uses two isolated profiles on H1 over WARP IPv6.'
        } else {
            "V91-I05 requires a controllable second physical T1 node; this run uses two isolated IPv6-disabled profiles on H1 over $interfaceClass."
        }
        candidate_commit = $candidateCommit
        candidate_binary_sha256 = $candidateSha256
        started_at_utc = $started.ToString('o')
        finished_at_utc = $finished.ToString('o')
        duration_seconds = [Math]::Round(($finished - $started).TotalSeconds, 3)
        file = [ordered]@{
            name = $fileName
            bytes = $FileSizeBytes
            ed2k_hash = $shared.ed2k_hash
            source_sha256 = $sourceSha256
            destination_sha256 = $destinationSha256
            destination_bytes = $destinationSize
        }
        route = [ordered]@{
            family = $TransportFamily
            interface_class = $interfaceClass
            address_sha256 = Get-LabStringSha256 -Value $address
            ipv6_connection_observed = $sawIpv6
            ipv4_connection_to_source_observed = $sawIpv4
        }
        process = [ordered]@{
            source_max_working_set_bytes = $maxSourceWorkingSet
            downloader_max_working_set_bytes = $maxDownloaderWorkingSet
        }
    }
    Write-LabJson -Value $summary -Path (Join-Path $evidence 'summary.json') | Out-Null
    if (-not $partialPass) {
        throw "Partial $FileSizeBytes-byte $TransportFamily transfer did not satisfy its same-host criteria"
    }
    Write-Host "$caseId partial transfer PASS: $output" -ForegroundColor Green
} finally {
    Stop-TestProcess -Process $downloader
    Stop-TestProcess -Process $source
    Remove-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue
    $password = $null
}
