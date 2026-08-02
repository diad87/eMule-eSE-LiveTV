[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CandidateZipPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$FixturePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedFixtureSha256,

    [string]$RunBase = 'D:\eSE-Lab',
    [string]$SourceIPv4 = '',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$H3IPv4,

    [ValidateRange(10, 86400)]
    [int]$ReadyTimeoutSeconds = 1800,

    [ValidateRange(60, 86400)]
    [int]$TransferTimeoutSeconds = 7200,

    [ValidateRange(1, 86400)]
    [int]$CompletionTimeoutSeconds = 300,

    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'v91_i05_t1_contract.ps1')

$constants = Get-I05T1Constants
$run = $null
$evidence = $null
$private = $null
$exchange = $null
$ownership = $null
$ownershipPath = $null
$sourceProcess = $null
$probeListener = $null
$probeClient = $null
$controlClient = $null
$controlStream = $null
$controlCommandAccepted = $false
$remoteStopSent = $false
$network = $null
$preferences = $null
$probeFirewallPresent = $false
$formalStatus = 'BLOCKED'
$stage = 'preflight'
$failureCodes = [Collections.Generic.List[string]]::new()
$cleanupStatus = 'NOT_RUN'
$routeObserved = $false
$unexpectedIpv6Observed = $false
$sourceCaptureStatus = 'NOT_REQUESTED'
$remoteReadyStatus = 'NOT_RECEIVED'
$remoteStartedStatus = 'NOT_RECEIVED'
$remoteCompleteStatus = 'NOT_RECEIVED'
$remoteCleanupStatus = 'NOT_RECEIVED'
$postBindingVerified = $false
$sourceIpv6ModeVerified = $false
$sourceKad6OffVerified = $false
$sourceFirstApiNetworksOffVerified = $false
$productBoundaryReached = $false
$remoteFailureClassification = ''
$remoteFailurePhase = ''
$formalClassification = ''
$formalCategory = ''
$remoteEvidenceBundleStatus = 'NOT_RECEIVED'
$remoteEvidenceBundlePath = ''
$startedAt = [DateTime]::UtcNow
$finishedAt = $null
$caughtException = $null

function Assert-I05SourceAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'V91-I05 T1 source coordination requires elevation.'
    }
}

function Assert-I05SourceNoReparsePoint {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Context cannot be a reparse point."
    }
    return $item
}

function Get-I05SourceCandidateObject {
    param([Parameter(Mandatory = $true)][object]$Candidate)

    return [ordered]@{
        version = [string]$Candidate.version
        commit = ([string]$Candidate.commit).ToLowerInvariant()
        dirty = $false
        emule_sha256 =
            ([string]$Candidate.emule_sha256).ToLowerInvariant()
        ese_server_sha256 =
            ([string]$Candidate.ese_server_sha256).ToLowerInvariant()
        build_info_sha256 =
            ([string]$Candidate.build_info_sha256).ToLowerInvariant()
    }
}

function Get-I05SourceMd5Text {
    param([Parameter(Mandatory = $true)][string]$Value)

    $md5 = [Security.Cryptography.MD5]::Create()
    try {
        $bytes = [Text.Encoding]::Unicode.GetBytes($Value)
        return ([BitConverter]::ToString(
            $md5.ComputeHash($bytes))).Replace('-', '')
    } finally {
        $md5.Dispose()
    }
}

function Assert-I05SourcePortAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('TCP', 'UDP')][string]$Protocol,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $owner = if ($Protocol -eq 'TCP') {
        Get-I05SourceTcpSnapshot |
            Where-Object {
                [string]$_.State -eq 'Listen' -and
                [int]$_.LocalPort -eq $Port
            } |
            Select-Object -First 1
    } else {
        Get-I05SourceUdpSnapshot |
            Where-Object { [int]$_.LocalPort -eq $Port } |
            Select-Object -First 1
    }
    if ($null -ne $owner) {
        throw "$Protocol/$Port is already in use."
    }
}

function Get-I05SourceNetwork {
    param([AllowEmptyString()][string]$RequestedIPv4)

    $addresses = @(
        Get-NetIPAddress -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue |
            Where-Object {
                [string]$_.AddressState -eq 'Preferred' -and
                (Get-LabAddressClass -Address ([string]$_.IPAddress)) `
                    -eq 'private-v4'
            }
    )
    if ($RequestedIPv4) {
        $canonicalRequested = ConvertTo-I05CanonicalIPv4 `
            -Value $RequestedIPv4 -Context 'Requested source IPv4'
        $addresses = @($addresses | Where-Object {
            [string]$_.IPAddress -eq $canonicalRequested
        })
    }

    $eligible = [Collections.Generic.List[object]]::new()
    foreach ($address in $addresses) {
        $adapter = Get-NetAdapter `
            -InterfaceIndex ([int]$address.InterfaceIndex) `
            -ErrorAction SilentlyContinue
        if ($null -eq $adapter) { continue }
        $virtual = $false
        if ($adapter.PSObject.Properties.Name -contains 'Virtual') {
            $virtual = [bool]$adapter.Virtual
        }
        $adapterText = '{0}|{1}' -f
            ([string]$adapter.Name),
            ([string]$adapter.InterfaceDescription)
        if ([string]$adapter.Status -ne 'Up' -or
            -not [bool]$adapter.HardwareInterface -or $virtual -or
            $adapterText -match $constants.forbidden_interface_pattern) {
            continue
        }

        $bindings = @(
            Get-NetAdapterBinding -Name ([string]$adapter.Name) `
            -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
        )
        if ($bindings.Count -ne 1 -or
            -not [bool]$bindings[0].Enabled) {
            continue
        }
        $binding = $bindings[0]
        $v6Candidates = @(
            Get-NetIPAddress `
                -InterfaceIndex ([int]$address.InterfaceIndex) `
                -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                Where-Object {
                    [string]$_.AddressState -eq 'Preferred' -and
                    (Get-LabAddressClass -Address ([string]$_.IPAddress)) `
                        -in @('linklocal-v6', 'ula-v6', 'global-v6')
                }
        )
        if ($v6Candidates.Count -eq 0) { continue }
        $v6 = $v6Candidates | Sort-Object @{
            Expression = {
                switch (Get-LabAddressClass `
                    -Address ([string]$_.IPAddress)) {
                    'linklocal-v6' { 0 }
                    'ula-v6' { 1 }
                    default { 2 }
                }
            }
        } | Select-Object -First 1

        $interfaceId = Get-LabInterfaceId `
            -Id ([string]$adapter.InterfaceGuid) `
            -Name ([string]$adapter.Name) `
            -Description ([string]$adapter.InterfaceDescription)
        $eligible.Add([pscustomobject][ordered]@{
            ipv4_address = ConvertTo-I05CanonicalIPv4 `
                -Value $address.IPAddress -Context 'Source IPv4'
            ipv4_prefix_length = [int]$address.PrefixLength
            ipv6_address = ConvertTo-I05CanonicalIPv6 `
                -Value $v6.IPAddress -Context 'Source IPv6'
            ipv6_class = Get-LabAddressClass `
                -Address ([string]$v6.IPAddress)
            interface_index = [int]$address.InterfaceIndex
            interface_alias = [string]$adapter.Name
            interface_description =
                [string]$adapter.InterfaceDescription
            interface_id = $interfaceId
            hardware_interface = [bool]$adapter.HardwareInterface
            virtual = $virtual
            ipv6_binding_enabled = [bool]$binding.Enabled
        })
    }

    if ($eligible.Count -eq 0) {
        throw (
            'No eligible Up physical private-LAN IPv4 interface with an ' +
            'enabled IPv6 binding and a Preferred IPv6 address exists.'
        )
    }
    if ($eligible.Count -gt 1) {
        if (-not $RequestedIPv4) {
            throw (
                'More than one physical private LAN is eligible. Supply ' +
                '-SourceIPv4 to select one explicitly.'
            )
        }
        throw 'Requested source IPv4 maps ambiguously to physical adapters.'
    }
    return $eligible[0]
}

function Get-I05SourceHostIdSha256 {
    return Get-I05HostIdSha256
}

function Write-I05SourceOwnership {
    if ($null -eq $ownership -or
        [string]::IsNullOrWhiteSpace($ownershipPath)) {
        return
    }
    $ownership.updated_at_utc = Get-LabUtcTimestamp
    $null = Write-LabJson -Value $ownership -Path $ownershipPath
}

function Wait-I05SourceApi {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$Port,
        [ValidateRange(1, 900)][int]$TimeoutSeconds = 120
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            Throw-I05SourceProductInvariant `
                -Category 'source-process-exited-before-api' `
                -Message 'Source candidate exited before API readiness.'
        }
        try {
            return Invoke-RestMethod `
                -Uri "http://127.0.0.1:$Port/api/status" `
                -TimeoutSec 2 -ErrorAction Stop
        } catch {
            Start-Sleep -Milliseconds 500
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    Throw-I05SourceProductInvariant `
        -Category 'source-api-readiness-timeout' `
        -Message 'Source API did not become ready on the fixed port.'
}

function New-I05SourceClassifiedException {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('LAB_BLOCKED', 'PRODUCT_INVARIANT')]
        [string]$Classification,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $exception = New-Object InvalidOperationException($Message)
    $exception.Data['I05Classification'] = $Classification
    $exception.Data['I05Category'] = $Category
    return $exception
}

function Throw-I05SourceProductInvariant {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Message
    )

    throw (New-I05SourceClassifiedException `
        -Classification PRODUCT_INVARIANT `
        -Category $Category -Message $Message)
}

function Throw-I05SourceLabBlocked {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Message
    )

    throw (New-I05SourceClassifiedException `
        -Classification LAB_BLOCKED `
        -Category $Category -Message $Message)
}

function Get-I05SourceTcpSnapshot {
    try {
        return @(Get-NetTCPConnection -ErrorAction Stop)
    } catch {
        Throw-I05SourceLabBlocked `
            -Category 'tcp-enumeration-failed' `
            -Message (
                'Windows TCP endpoint enumeration failed closed: ' +
                $_.Exception.Message
            )
    }
}

function Get-I05SourceUdpSnapshot {
    try {
        return @(Get-NetUDPEndpoint -ErrorAction Stop)
    } catch {
        Throw-I05SourceLabBlocked `
            -Category 'udp-enumeration-failed' `
            -Message (
                'Windows UDP endpoint enumeration failed closed: ' +
                $_.Exception.Message
            )
    }
}

function Get-I05SourceClassicSession {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $encoded = [Uri]::EscapeDataString($Password)
    $deadline = [DateTime]::UtcNow.AddMinutes(12)
    do {
        try {
            $response = Invoke-WebRequest -Uri (
                "http://127.0.0.1:$Port/?w=password&p=$encoded"
            ) -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            $match = [regex]::Match($response.Content, 'ses=(\d+)')
            if ($match.Success) {
                return $match.Groups[1].Value
            }
        } catch {
            # The classic WebServer can remain busy while hashing 4 GiB.
        }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Classic WebServer login did not become available after hashing.'
}

function Get-I05SourceSharedLink {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session
    )

    $deadline = [DateTime]::UtcNow.AddMinutes(12)
    do {
        $response = Invoke-WebRequest -Uri (
            "http://127.0.0.1:$Port/?ses=$Session&w=shared"
        ) -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
        $pattern = 'ed2k://\|file\|' +
            [regex]::Escape($constants.fixture_name) + '\|' +
            [string]$constants.fixture_bytes +
            '\|([A-Fa-f0-9]{32})(?:\|h=[A-Z2-7]{32})?\|/'
        $match = [regex]::Match($response.Content, $pattern)
        if ($match.Success) {
            $ed2k = $match.Groups[1].Value.ToUpperInvariant()
            Assert-I05ExactText -Actual $ed2k `
                -Expected $constants.fixture_ed2k `
                -Context 'Shared fixture ED2K' -IgnoreCase
            return [pscustomobject][ordered]@{
                link = $match.Value
                ed2k = $ed2k
                ed2k_source =
                    'fresh-candidate-shared-list-local-calculation'
                shared_page_sha256 =
                    Get-LabStringSha256 -Value $response.Content
            }
        }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Canonical fixture did not enter the source shared list.'
}

function Stop-I05SourceProbe {
    if ($null -ne $probeClient) {
        try { $probeClient.Close() } catch {}
        $script:probeClient = $null
    }
    if ($null -ne $probeListener) {
        try { $probeListener.Stop() } catch {}
        $script:probeListener = $null
    }
}

function Remove-I05SourceProbeFirewall {
    if (-not $probeFirewallPresent -or $null -eq $ownership) { return }
    # Removal is deliberately deferred to the formal cleanup, which validates
    # every filter of the exact ownership record before mutating the rule.
}

function Wait-I05SourceIpv6Probe {
    param(
        [Parameter(Mandatory = $true)][Threading.Tasks.Task]$AcceptTask,
        [Parameter(Mandatory = $true)][string]$ExpectedRequest,
        [Parameter(Mandatory = $true)][string]$Response,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($AcceptTask.IsCompleted) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $AcceptTask.IsCompleted) {
        throw 'H3 did not perform the required physical-LAN IPv6 probe.'
    }
    if ($AcceptTask.IsFaulted) {
        throw 'The physical-LAN IPv6 listener failed while accepting H3.'
    }

    $client = [Net.Sockets.TcpClient]$AcceptTask.Result
    $script:probeClient = $client
    $client.ReceiveTimeout = 15000
    $client.SendTimeout = 15000
    $remoteEndpoint =
        [Net.IPEndPoint]$client.Client.RemoteEndPoint
    $localEndpoint =
        [Net.IPEndPoint]$client.Client.LocalEndPoint
    $remoteAddress = ConvertTo-I05CanonicalIPv6 `
        -Value $remoteEndpoint.Address.ToString() `
        -Context 'Accepted H3 probe address'
    $remoteClass = Get-LabAddressClass -Address $remoteAddress
    if ($remoteClass -notin
        @('linklocal-v6', 'ula-v6', 'global-v6')) {
        throw 'The accepted probe did not originate from usable IPv6.'
    }

    $encoding = New-Object Text.UTF8Encoding($false)
    $reader = New-Object IO.StreamReader(
        $client.GetStream(), $encoding, $false, 1024, $true)
    $writer = New-Object IO.StreamWriter(
        $client.GetStream(), $encoding, 1024, $true)
    try {
        $writer.NewLine = "`r`n"
        $writer.AutoFlush = $true
        $line = $reader.ReadLine()
        Assert-I05ExactText -Actual ([string]$line) `
            -Expected $ExpectedRequest -Context 'IPv6 probe challenge'
        $writer.WriteLine($Response)
    } finally {
        $writer.Dispose()
        $reader.Dispose()
        $client.Close()
        $script:probeClient = $null
    }
    return [pscustomobject][ordered]@{
        completed_at_utc = Get-LabUtcTimestamp
        remote_address = $remoteAddress
        remote_address_class = $remoteClass
        remote_address_sha256 =
            Get-LabStringSha256 -Value $remoteAddress
        remote_port = [int]$remoteEndpoint.Port
        local_address = ConvertTo-I05CanonicalIPv6 `
            -Value $localEndpoint.Address.ToString() `
            -Context 'Accepted H1 probe address'
        challenge_sha256 =
            Get-LabStringSha256 -Value $ExpectedRequest
        response_sha256 = Get-LabStringSha256 -Value $Response
    }
}

function Assert-I05SourceReady {
    param(
        [Parameter(Mandatory = $true)][object]$Ready,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$Probe,
        [Parameter(Mandatory = $true)][string]$HostIdSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedH3IPv4,
        [Parameter(Mandatory = $true)][DateTimeOffset]$NotBefore,
        [Parameter(Mandatory = $true)][DateTimeOffset]$NotAfter
    )

    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Ready -Name 'schema' -Context 'READY')) `
        -Expected 'ese.v91.i05.t1-ready/v1' -Context 'READY schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Ready -Name 'case_id' -Context 'READY')) `
        -Expected $constants.case_id -Context 'READY case'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Ready -Name 'status' -Context 'READY')) `
        -Expected 'READY' -Context 'READY status'
    $readyNonce = Assert-I05Nonce -Value (Get-I05RequiredProperty `
        -Object $Ready -Name 'nonce' -Context 'READY') `
        -Context 'READY nonce'
    Assert-I05ExactText -Actual $readyNonce -Expected $Nonce `
        -Context 'READY nonce'
    $readyTime = ConvertTo-I05UtcTimestamp -Value (
        Get-I05RequiredProperty -Object $Ready `
            -Name 'created_at_utc' -Context 'READY'
    ) -Context 'READY timestamp'
    if ($readyTime -lt $NotBefore.AddSeconds(-5) -or
        $readyTime -gt $NotAfter) {
        throw 'READY is outside the nonce validity interval.'
    }
    Assert-I05CandidateContract -Candidate (Get-I05RequiredProperty `
        -Object $Ready -Name 'candidate' -Context 'READY') `
        -Context 'READY.candidate'

    $hostInfo = Get-I05RequiredProperty -Object $Ready `
        -Name 'host' -Context 'READY'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $hostInfo -Name 'role' -Context 'READY.host')) `
        -Expected 'H3' -Context 'READY host role'
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $hostInfo -Name 'physical_windows' `
        -Context 'READY.host') -Context 'READY physical Windows host'
    $remoteHostId = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $hostInfo -Name 'host_id_sha256' `
        -Context 'READY.host') -Context 'READY host identity'
    if ($remoteHostId -eq $HostIdSha256) {
        throw 'READY represents H1 itself instead of a distinct H3.'
    }
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $hostInfo -Name 'source_host_id_sha256' `
        -Context 'READY.host')) -Expected $HostIdSha256 `
        -Context 'READY H1 host binding' -IgnoreCase

    $storage = Get-I05RequiredProperty -Object $Ready `
        -Name 'storage' -Context 'READY'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $storage -Name 'filesystem' -Context 'READY.storage')) `
        -Expected 'NTFS' -Context 'READY storage filesystem' -IgnoreCase
    if ([Int64](Get-I05RequiredProperty -Object $storage `
            -Name 'free_bytes' -Context 'READY.storage') -lt
        $constants.downloader_min_free_bytes) {
        throw 'H3 does not report the minimum 10 GiB free.'
    }
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $storage -Name 'run_root_sha256' `
        -Context 'READY.storage') -Context 'READY run-root identity'

    $readyNetwork = Get-I05RequiredProperty -Object $Ready `
        -Name 'network' -Context 'READY'
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $readyNetwork -Name 'ipv6_binding_enabled' `
        -Context 'READY.network') -Context 'READY IPv6 binding'
    $ipv4 = Get-I05RequiredProperty -Object $readyNetwork `
        -Name 'ipv4' -Context 'READY.network'
    $remoteIPv4 = ConvertTo-I05CanonicalIPv4 -Value (
        Get-I05RequiredProperty -Object $ipv4 -Name 'address' `
            -Context 'READY.network.ipv4'
    ) -Context 'READY H3 IPv4'
    Assert-I05ExactText -Actual $remoteIPv4 `
        -Expected $ExpectedH3IPv4 -Context 'READY H3 control IPv4'
    if ((Get-LabAddressClass -Address $remoteIPv4) -ne 'private-v4') {
        throw 'READY H3 IPv4 is not RFC1918 private.'
    }
    $remoteIPv4Hash = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $ipv4 -Name 'address_sha256' `
            -Context 'READY.network.ipv4'
    ) -Context 'READY H3 IPv4 hash'
    Assert-I05ExactText -Actual $remoteIPv4Hash `
        -Expected (Get-LabStringSha256 -Value $remoteIPv4) `
        -Context 'READY H3 IPv4 hash' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $ipv4 -Name 'class' -Context 'READY.network.ipv4')) `
        -Expected 'private-v4' -Context 'READY IPv4 class'
    $remotePrefix = [int](Get-I05RequiredProperty -Object $ipv4 `
        -Name 'prefix_length' -Context 'READY.network.ipv4')
    if ($remotePrefix -lt 1 -or $remotePrefix -gt 32) {
        throw 'READY H3 IPv4 prefix is invalid.'
    }
    if (-not (Test-I05Ipv4SameSubnet `
            -Left $Network.ipv4_address -Right $remoteIPv4 `
            -PrefixLength $Network.ipv4_prefix_length) -or
        -not (Test-I05Ipv4SameSubnet `
            -Left $Network.ipv4_address -Right $remoteIPv4 `
            -PrefixLength $remotePrefix)) {
        throw 'H1 and H3 are not on the same asserted physical IPv4 LAN.'
    }
    Assert-I05True -Value (Get-I05RequiredProperty -Object $ipv4 `
        -Name 'physical' -Context 'READY.network.ipv4') `
        -Context 'READY physical IPv4'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $ipv4 -Name 'status' -Context 'READY.network.ipv4')) `
        -Expected 'Up' -Context 'READY IPv4 adapter status' -IgnoreCase
    Assert-I05True -Value (Get-I05RequiredProperty -Object $ipv4 `
        -Name 'source_on_link' -Context 'READY.network.ipv4') `
        -Context 'READY on-link route'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $ipv4 -Name 'next_hop' -Context 'READY.network.ipv4')) `
        -Expected '0.0.0.0' -Context 'READY IPv4 next hop'
    $remoteInterfaceId = [string](Get-I05RequiredProperty `
        -Object $ipv4 -Name 'interface_id' `
        -Context 'READY.network.ipv4')
    if ($remoteInterfaceId -notmatch '^[0-9a-f]{12}$') {
        throw 'READY H3 interface identity is invalid.'
    }
    $routeSourceHash = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $ipv4 `
            -Name 'source_address_sha256' `
            -Context 'READY.network.ipv4'
    ) -Context 'READY H3 route-source hash'
    Assert-I05ExactText -Actual $routeSourceHash `
        -Expected $remoteIPv4Hash `
        -Context 'READY H3 route-source hash' -IgnoreCase

    $v6 = Get-I05RequiredProperty -Object $readyNetwork `
        -Name 'ipv6_probe' -Context 'READY.network'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $v6 `
        -Name 'success' -Context 'READY.network.ipv6_probe') `
        -Context 'READY IPv6 probe success'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $v6 -Name 'family' `
        -Context 'READY.network.ipv6_probe')) `
        -Expected 'IPv6' -Context 'READY probe family'
    if ([int](Get-I05RequiredProperty -Object $v6 `
            -Name 'source_port' `
            -Context 'READY.network.ipv6_probe') -ne
        $constants.source_probe_port) {
        throw 'READY probe used the wrong target port.'
    }
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $v6 -Name 'interface_id' `
        -Context 'READY.network.ipv6_probe')) `
        -Expected $remoteInterfaceId `
        -Context 'READY probe interface identity'
    $probeSourceHash = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $v6 `
            -Name 'source_address_sha256' `
            -Context 'READY.network.ipv6_probe'
    ) -Context 'READY probe destination hash'
    Assert-I05ExactText -Actual $probeSourceHash `
        -Expected (Get-LabStringSha256 -Value $Network.ipv6_address) `
        -Context 'READY probe destination hash' -IgnoreCase
    $probeLocalHash = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $v6 `
            -Name 'local_address_sha256' `
            -Context 'READY.network.ipv6_probe'
    ) -Context 'READY probe local-address hash'
    Assert-I05ExactText -Actual $probeLocalHash `
        -Expected $Probe.remote_address_sha256 `
        -Context 'READY accepted H3 IPv6 identity' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $v6 -Name 'challenge_sha256' `
        -Context 'READY.network.ipv6_probe')) `
        -Expected $Probe.challenge_sha256 `
        -Context 'READY probe challenge hash' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $v6 -Name 'response_sha256' `
        -Context 'READY.network.ipv6_probe')) `
        -Expected $Probe.response_sha256 `
        -Context 'READY probe response hash' -IgnoreCase
    $probeTime = ConvertTo-I05UtcTimestamp -Value (
        Get-I05RequiredProperty -Object $v6 `
            -Name 'completed_at_utc' `
            -Context 'READY.network.ipv6_probe'
    ) -Context 'READY probe completion timestamp'
    $acceptedTime = ConvertTo-I05UtcTimestamp `
        -Value $Probe.completed_at_utc -Context 'Accepted probe time'
    if ([Math]::Abs(($probeTime - $acceptedTime).TotalMinutes) -gt 2) {
        throw 'READY probe time does not correlate with H1 acceptance.'
    }

    $node = Get-I05RequiredProperty -Object $Ready `
        -Name 'node' -Context 'READY'
    $remotePid = [int](Get-I05RequiredProperty -Object $node `
        -Name 'process_id' -Context 'READY.node')
    if ($remotePid -le 0) { throw 'READY H3 process ID is invalid.' }
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $node -Name 'emule_sha256' -Context 'READY.node')) `
        -Expected $constants.candidate_emule_sha256 `
        -Context 'READY H3 executable hash' -IgnoreCase
    foreach ($port in ([ordered]@{
        tcp_port = $constants.downloader_tcp_port
        udp_port = $constants.downloader_udp_port
        web_port = $constants.downloader_web_port
    }).GetEnumerator()) {
        if ([int](Get-I05RequiredProperty -Object $node `
                -Name $port.Key -Context 'READY.node') -ne
            [int]$port.Value) {
            throw "READY H3 $($port.Key) is not the fixed port."
        }
    }
    if ([int](Get-I05RequiredProperty -Object $node `
            -Name 'ipv6_mode' -Context 'READY.node') -ne 0) {
        Throw-I05SourceProductInvariant `
            -Category 'h3-network-state-ready' `
            -Message 'READY H3 candidate is not IPv6Mode=0.'
    }
    if ([int](Get-I05RequiredProperty -Object $node `
            -Name 'kad_network_mask' -Context 'READY.node') -ne 0) {
        Throw-I05SourceProductInvariant `
            -Category 'h3-network-state-ready' `
            -Message 'READY H3 KadNetworkMask is not zero.'
    }
    try {
        Assert-I05ApiNetworksOff -Status $node -Context 'READY.node'
    } catch {
        Throw-I05SourceProductInvariant `
            -Category 'h3-network-state-ready' `
            -Message $_.Exception.Message
    }
    Assert-I05True -Value (Get-I05RequiredProperty -Object $node `
        -Name 'tcp_listener_owned' -Context 'READY.node') `
        -Context 'READY H3 TCP listener ownership'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $node `
        -Name 'api_ipv4_only' -Context 'READY.node') `
        -Context 'READY H3 IPv4-only native API listener'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $node `
        -Name 'api_lan_access_denied' -Context 'READY.node') `
        -Context 'READY H3 LAN API denial'
    $apiLanDenialMode = [string](Get-I05RequiredProperty `
        -Object $node -Name 'api_lan_denial_mode' `
        -Context 'READY.node')
    if ($apiLanDenialMode -notin @('http-403', 'firewall-blocked')) {
        throw 'READY H3 LAN API denial mode is invalid.'
    }
    $apiLanHttpStatus = Get-I05RequiredProperty -Object $node `
        -Name 'api_lan_http_status' -Context 'READY.node'
    if (($apiLanHttpStatus -isnot [int] -and
         $apiLanHttpStatus -isnot [long]) -or
        [int]$apiLanHttpStatus -notin @(0, 403)) {
        throw 'READY H3 LAN API status is invalid.'
    }

    $capture = Get-I05RequiredProperty -Object $Ready `
        -Name 'capture' -Context 'READY'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $capture -Name 'backend' -Context 'READY.capture')) `
        -Expected 'pktmon' -Context 'READY capture backend' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $capture -Name 'arm_status' -Context 'READY.capture')) `
        -Expected 'ARMED' -Context 'READY capture arm'
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $capture -Name 'fail_closed' `
        -Context 'READY.capture') -Context 'READY fail-closed capture'
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $capture -Name 'intent_sha256' `
        -Context 'READY.capture') -Context 'READY capture intent'
    $componentMapping = Get-I05RequiredProperty -Object $capture `
        -Name 'component_mapping' -Context 'READY.capture'
    $componentGuidSha256 = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $componentMapping `
            -Name 'interface_guid_sha256' `
            -Context 'READY.capture.component_mapping'
    ) -Context 'READY capture interface GUID hash'
    $primaryComponentId = [Int64](Get-I05RequiredProperty `
        -Object $componentMapping -Name 'primary_id' `
        -Context 'READY.capture.component_mapping')
    if ($primaryComponentId -lt 1 -or
        $primaryComponentId -gt [uint32]::MaxValue) {
        throw 'READY primary PktMon component ID is invalid.'
    }
    $secondaryProperty =
        $componentMapping.PSObject.Properties['secondary_ids']
    if ($null -eq $secondaryProperty -or
        $secondaryProperty.Value -isnot [Array]) {
        throw 'READY secondary_ids must be one JSON array.'
    }
    $secondaryComponentIds =
        [Collections.Generic.List[Int64]]::new()
    foreach ($value in @($secondaryProperty.Value)) {
        $componentId = [Int64]$value
        if ($componentId -lt 1 -or
            $componentId -gt [uint32]::MaxValue -or
            $componentId -eq $primaryComponentId -or
            $secondaryComponentIds.Contains($componentId)) {
            throw 'READY secondary PktMon component IDs are invalid.'
        }
        $secondaryComponentIds.Add($componentId)
    }
    if ($secondaryComponentIds.Count -gt 1) {
        throw 'READY exposes more than one PktMon SecondaryId.'
    }
    $mappingKeySha256 = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $componentMapping `
            -Name 'mapping_sha256' `
            -Context 'READY.capture.component_mapping'
    ) -Context 'READY component-mapping semantic hash'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $componentMapping -Name 'mapping_key_sha256' `
        -Context 'READY.capture.component_mapping')) `
        -Expected $mappingKeySha256 `
        -Context 'READY component mapping-key alias' -IgnoreCase
    $inventories = Get-I05RequiredProperty -Object $componentMapping `
        -Name 'inventories' -Context 'READY.capture.component_mapping'
    $inventoryPreSha256 = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $inventories `
            -Name 'pre_sha256' `
            -Context 'READY.capture.component_mapping.inventories'
    ) -Context 'READY raw pre-inventory hash'
    $inventoryArmedSha256 = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $inventories `
            -Name 'armed_sha256' `
            -Context 'READY.capture.component_mapping.inventories'
    ) -Context 'READY raw armed-inventory hash'

    $coordination = Get-I05RequiredProperty -Object $Ready `
        -Name 'coordination' -Context 'READY'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $coordination -Name 'transport' `
        -Context 'READY.coordination')) -Expected 'lan-tcp-v1' `
        -Context 'READY coordination transport'
    $controlAddress = ConvertTo-I05CanonicalIPv4 -Value (
        Get-I05RequiredProperty -Object $coordination -Name 'address' `
            -Context 'READY.coordination'
    ) -Context 'READY control address'
    Assert-I05ExactText -Actual $controlAddress `
        -Expected $ExpectedH3IPv4 -Context 'READY control address'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $coordination -Name 'address_sha256' `
        -Context 'READY.coordination')) `
        -Expected (Get-LabStringSha256 -Value $ExpectedH3IPv4) `
        -Context 'READY control-address hash' -IgnoreCase
    if ([int](Get-I05RequiredProperty -Object $coordination `
            -Name 'port' -Context 'READY.coordination') -ne
        $constants.downloader_control_port) {
        throw 'READY control port is not TCP/8012.'
    }
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $coordination -Name 'remote_address_sha256' `
        -Context 'READY.coordination')) `
        -Expected (Get-LabStringSha256 -Value $Network.ipv4_address) `
        -Context 'READY control H1-address hash' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $coordination -Name 'challenge_sha256' `
        -Context 'READY.coordination')) `
        -Expected (Get-LabStringSha256 `
            -Value ("V91-I05-COMMAND $Nonce")) `
        -Context 'READY control challenge hash' -IgnoreCase
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $coordination -Name 'single_use' `
        -Context 'READY.coordination') `
        -Context 'READY single-use control'

    return [pscustomobject][ordered]@{
        host_id_sha256 = $remoteHostId
        ipv4_address = $remoteIPv4
        ipv4_address_sha256 = $remoteIPv4Hash
        ipv4_prefix_length = $remotePrefix
        interface_id = $remoteInterfaceId
        process_id = $remotePid
        capture_intent_sha256 =
            ([string]$capture.intent_sha256).ToLowerInvariant()
        component_guid_sha256 = $componentGuidSha256
        primary_component_id = $primaryComponentId
        secondary_component_ids = $secondaryComponentIds.ToArray()
        mapping_key_sha256 = $mappingKeySha256
        inventory_pre_sha256 = $inventoryPreSha256
        inventory_armed_sha256 = $inventoryArmedSha256
        ready_at_utc = $readyTime.ToString('o')
    }
}

function Get-I05SourceRoute {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteIPv4,
        [Parameter(Mandatory = $true)][object]$Network
    )

    $route = Get-I05EffectiveRouteEvidence `
        -RemoteIPv4 $RemoteIPv4
    if ($route.source_address -ne $Network.ipv4_address -or
        [int]$route.interface_index -ne $Network.interface_index -or
        [string]$route.next_hop -ne '0.0.0.0') {
        throw 'Route to H3 is not the selected on-link physical IPv4 LAN.'
    }
    return [pscustomobject][ordered]@{
        family = 'IPv4'
        interface_id = $Network.interface_id
        source_address_sha256 =
            Get-LabStringSha256 -Value $route.source_address
        remote_address_sha256 =
            Get-LabStringSha256 -Value $RemoteIPv4
        on_link = $true
        forbidden_interface = $false
        destination_prefix = $route.destination_prefix
        address_object_class = $route.address_object_class
        route_object_class = $route.route_object_class
    }
}

function Assert-I05SourceOwnedListeners {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$LanIPv4
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $tcpSnapshot = @(Get-I05SourceTcpSnapshot)
        $peerListeners = @($tcpSnapshot | Where-Object {
            [string]$_.State -eq 'Listen' -and
            [int]$_.LocalPort -eq $constants.source_tcp_port
        })
        $webListeners = @($tcpSnapshot | Where-Object {
            [string]$_.State -eq 'Listen' -and
            [int]$_.LocalPort -eq $constants.source_web_port
        })
        if (@($peerListeners | Where-Object {
                [int]$_.OwningProcess -ne $ProcessId
            }).Count -gt 0) {
            throw (
                'Source TCP listener is not exclusively owned by the ' +
                'candidate.'
            )
        }
        if (@($webListeners | Where-Object {
                [int]$_.OwningProcess -ne $ProcessId -or
                [string]$_.LocalAddress -notin @(
                    '0.0.0.0', '127.0.0.1'
                )
            }).Count -gt 0) {
            throw (
                'Source API is not exclusively candidate-owned and ' +
                'IPv4-only.'
            )
        }
        if ($peerListeners.Count -gt 0 -and
            $webListeners.Count -gt 0) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($peerListeners.Count -eq 0) {
        throw 'Source TCP listener did not become ready within 30 seconds.'
    }
    if ($webListeners.Count -eq 0) {
        throw 'Source API listener did not become ready within 30 seconds.'
    }

    $uri = "http://$LanIPv4`:$($constants.source_web_port)/api/status"
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
            $denialMode = 'firewall-blocked'
        } else {
            throw 'Source API LAN denial could not be verified.'
        }
    }
    if ($statusCode -eq 403) {
        $denialMode = 'http-403'
    } elseif ($denialMode -cne 'firewall-blocked') {
        throw "Source API through the LAN address returned HTTP $statusCode."
    }
    return [pscustomobject][ordered]@{
        denied = $true
        mode = $denialMode
        http_status = $statusCode
    }
}

function Assert-I05SourceDirectInjection {
    param(
        [Parameter(Mandatory = $true)][object]$Injection,
        [Parameter(Mandatory = $true)][string]$DirectLinkSha256
    )

    $expectedNames = @(
        'delivery_count',
        'direct_injected',
        'queue_owned_after_direct',
        'direct_link_sha256',
        'queue_observed_at_utc'
    )
    $actualNames = @($Injection.PSObject.Properties.Name)
    $unexpected = @($actualNames | Where-Object {
        $expectedNames -notcontains $_
    })
    $missing = @($expectedNames | Where-Object {
        $actualNames -notcontains $_
    })
    if ($actualNames.Count -ne $expectedNames.Count -or
        $unexpected.Count -gt 0 -or $missing.Count -gt 0) {
        throw (
            'STARTED.injection must contain exactly the five direct-only ' +
            'receipt fields and no legacy base-link field.'
        )
    }

    $deliveryCount = Get-I05RequiredProperty -Object $Injection `
        -Name 'delivery_count' -Context 'STARTED.injection'
    if (($deliveryCount -isnot [int] -and
         $deliveryCount -isnot [long]) -or
        [Int64]$deliveryCount -ne 1) {
        throw 'STARTED.injection.delivery_count must be the JSON integer 1.'
    }
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $Injection -Name 'direct_injected' `
        -Context 'STARTED.injection') `
        -Context 'STARTED direct injection'
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $Injection -Name 'queue_owned_after_direct' `
        -Context 'STARTED.injection') `
        -Context 'STARTED queue ownership after direct injection'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Injection -Name 'direct_link_sha256' `
        -Context 'STARTED.injection')) `
        -Expected $DirectLinkSha256 -Context 'STARTED direct-link hash' `
        -IgnoreCase
    $null = ConvertTo-I05UtcTimestamp -Value (
        Get-I05RequiredProperty -Object $Injection `
            -Name 'queue_observed_at_utc' -Context 'STARTED.injection'
    ) -Context 'STARTED direct queue observation'
}

function Assert-I05SourceStarted {
    param(
        [Parameter(Mandatory = $true)][object]$Started,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][object]$Remote,
        [Parameter(Mandatory = $true)][string]$DirectLinkSha256
    )

    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Started -Name 'schema' -Context 'STARTED')) `
        -Expected 'ese.v91.i05.t1-started/v1' -Context 'STARTED schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Started -Name 'status' -Context 'STARTED')) `
        -Expected 'STARTED' -Context 'STARTED status'
    Assert-I05ExactText -Actual (
        Assert-I05Nonce -Value (Get-I05RequiredProperty `
            -Object $Started -Name 'nonce' -Context 'STARTED') `
            -Context 'STARTED nonce'
    ) -Expected $Nonce -Context 'STARTED nonce'
    Assert-I05CandidateContract -Candidate (Get-I05RequiredProperty `
        -Object $Started -Name 'candidate' -Context 'STARTED') `
        -Context 'STARTED.candidate'
    $node = Get-I05RequiredProperty -Object $Started `
        -Name 'node' -Context 'STARTED'
    if ([int](Get-I05RequiredProperty -Object $node `
            -Name 'process_id' -Context 'STARTED.node') -ne
        $Remote.process_id -or
        [int](Get-I05RequiredProperty -Object $node `
            -Name 'ipv6_mode' -Context 'STARTED.node') -ne 0) {
        Throw-I05SourceProductInvariant `
            -Category 'h3-network-state-started' `
            -Message 'STARTED H3 node identity or IPv6Mode changed.'
    }
    if ([int](Get-I05RequiredProperty -Object $node `
            -Name 'kad_network_mask' -Context 'STARTED.node') -ne 0) {
        Throw-I05SourceProductInvariant `
            -Category 'h3-network-state-started' `
            -Message 'STARTED H3 KadNetworkMask is not zero.'
    }
    try {
        Assert-I05ApiNetworksOff -Status $node -Context 'STARTED.node'
    } catch {
        Throw-I05SourceProductInvariant `
            -Category 'h3-network-state-started' `
            -Message $_.Exception.Message
    }
    $injection = Get-I05RequiredProperty -Object $Started `
        -Name 'injection' -Context 'STARTED'
    try {
        Assert-I05SourceDirectInjection -Injection $injection `
            -DirectLinkSha256 $DirectLinkSha256
    } catch {
        if ($_.Exception.Data.Contains('I05Classification')) {
            throw
        }
        Throw-I05SourceProductInvariant `
            -Category 'direct-injection-invariant' `
            -Message $_.Exception.Message
    }
    $capture = Get-I05RequiredProperty -Object $Started `
        -Name 'capture' -Context 'STARTED'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $capture -Name 'backend' -Context 'STARTED.capture')) `
        -Expected 'pktmon' -Context 'STARTED capture backend' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $capture -Name 'status' -Context 'STARTED.capture')) `
        -Expected 'ARMED' -Context 'STARTED capture status'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $capture -Name 'intent_sha256' `
        -Context 'STARTED.capture')) `
        -Expected $Remote.capture_intent_sha256 `
        -Context 'STARTED capture intent' -IgnoreCase
}

function Get-I05SourceJsonDocumentFromBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $raw = $utf8.GetString($Bytes)
    $document = $raw | ConvertFrom-Json
    if ($null -eq $document -or $document -is [Array]) {
        throw "$Context is not one JSON object."
    }
    return $document
}

function Get-I05SourceCanonicalPortArray {
    param(
        [Parameter(Mandatory = $true)][object]$Owner,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $property = $Owner.PSObject.Properties[$Name]
    if ($null -eq $property -or $property.Value -isnot [Array]) {
        throw "$Context.$Name must be one JSON array."
    }
    $ports = [Collections.Generic.List[int]]::new()
    foreach ($value in @($property.Value)) {
        $port = [int]$value
        if ($port -lt 1024 -or $port -gt 65535 -or
            $port -in @(
                $constants.source_tcp_port,
                $constants.source_udp_port,
                $constants.source_web_port,
                $constants.source_probe_port,
                $constants.downloader_tcp_port,
                $constants.downloader_udp_port,
                $constants.downloader_web_port,
                $constants.downloader_control_port
            ) -or
            $ports.Contains($port)) {
            throw "$Context.$Name contains an invalid or duplicate port."
        }
        $ports.Add($port)
    }
    if ($ports.Count -lt 1 -or $ports.Count -gt 64) {
        throw "$Context.$Name count is outside the bounded range."
    }
    return @($ports.ToArray() | Sort-Object)
}

function Assert-I05SourceSamePorts {
    param(
        [Parameter(Mandatory = $true)][int[]]$Actual,
        [Parameter(Mandatory = $true)][int[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $left = (@($Actual | Sort-Object -Unique) -join ',')
    $right = (@($Expected | Sort-Object -Unique) -join ',')
    if (-not [string]::Equals(
            $left, $right, [StringComparison]::Ordinal)) {
        throw "$Context does not match the exact observed port set."
    }
}

function Assert-I05SourceExactProperties {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $actual = @($Object.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count -or
        @($actual | Where-Object {
            $Expected -cnotcontains $_
        }).Count -gt 0 -or
        @($Expected | Where-Object {
            $actual -cnotcontains $_
        }).Count -gt 0) {
        throw "$Context does not contain the exact required property set."
    }
}

function Get-I05SourceCanonicalRuleTokens {
    param(
        [Parameter(Mandatory = $true)][object]$Rule,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $property = $Rule.PSObject.Properties[$Name]
    if ($null -eq $property -or $property.Value -isnot [Array]) {
        throw "$Context.$Name must be one JSON array."
    }
    $seen = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::Ordinal)
    $tokens = [Collections.Generic.List[string]]::new()
    foreach ($value in @($property.Value)) {
        if ($value -isnot [string]) {
            throw "$Context.$Name contains a non-string token."
        }
        $token = [string]$value
        if ($token -notmatch '^(?:Any|[0-9]{1,5}(?:-[0-9]{1,5})?)$' -or
            -not $seen.Add($token)) {
            throw "$Context.$Name contains an invalid or duplicate token."
        }
        $tokens.Add($token)
    }
    if ($tokens.Count -lt 1) {
        throw "$Context.$Name cannot be empty."
    }
    [string[]]$ordered = $tokens.ToArray()
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    return $ordered
}

function ConvertTo-I05SourceIPv4UInt64 {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $canonical = ConvertTo-I05CanonicalIPv4 -Value $Address `
        -Context $Context
    $bytes = [Net.IPAddress]::Parse($canonical).GetAddressBytes()
    return (
        [UInt64]$bytes[0] * 16777216 +
        [UInt64]$bytes[1] * 65536 +
        [UInt64]$bytes[2] * 256 +
        [UInt64]$bytes[3]
    )
}

function ConvertFrom-I05SourceIPv4UInt64 {
    param([Parameter(Mandatory = $true)][UInt64]$Value)

    if ($Value -gt [UInt64]4294967295) {
        throw 'IPv4 integer is outside the UInt32 range.'
    }
    return '{0}.{1}.{2}.{3}' -f
        (($Value -shr 24) -band 255),
        (($Value -shr 16) -band 255),
        (($Value -shr 8) -band 255),
        ($Value -band 255)
}

function Get-I05SourceIPv4ComplementTokens {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$AllowedIntervals
    )

    $ordered = @($AllowedIntervals | Sort-Object `
        @{ Expression = { [UInt64]$_.start } },
        @{ Expression = { [UInt64]$_.end } })
    $merged = [Collections.Generic.List[object]]::new()
    foreach ($interval in $ordered) {
        $start = [UInt64]$interval.start
        $end = [UInt64]$interval.end
        if ($start -gt $end -or $end -gt [UInt64]4294967295) {
            throw 'Allowed IPv4 interval is invalid.'
        }
        if ($merged.Count -eq 0) {
            $merged.Add([pscustomobject]@{ start = $start; end = $end })
            continue
        }
        $last = $merged[$merged.Count - 1]
        if ($start -le ([UInt64]$last.end + 1)) {
            if ($end -gt [UInt64]$last.end) {
                $last.end = $end
            }
        } else {
            $merged.Add([pscustomobject]@{ start = $start; end = $end })
        }
    }

    $tokens = [Collections.Generic.List[string]]::new()
    [UInt64]$cursor = 0
    foreach ($interval in $merged.ToArray()) {
        $start = [UInt64]$interval.start
        if ($cursor -lt $start) {
            $gapEnd = $start - 1
            $left = ConvertFrom-I05SourceIPv4UInt64 -Value $cursor
            $right = ConvertFrom-I05SourceIPv4UInt64 -Value $gapEnd
            $tokens.Add($(if ($cursor -eq $gapEnd) {
                $left
            } else {
                "$left-$right"
            }))
        }
        if ([UInt64]$interval.end -eq [UInt64]4294967295) {
            $cursor = [UInt64]4294967295
            break
        }
        $cursor = [UInt64]$interval.end + 1
    }
    if ($merged.Count -eq 0 -or
        [UInt64]$merged[$merged.Count - 1].end -lt
            [UInt64]4294967295) {
        $left = ConvertFrom-I05SourceIPv4UInt64 -Value $cursor
        $right = '255.255.255.255'
        $tokens.Add($(if ($cursor -eq [UInt64]4294967295) {
            $left
        } else {
            "$left-$right"
        }))
    }
    [string[]]$result = $tokens.ToArray()
    [Array]::Sort($result, [StringComparer]::Ordinal)
    return $result
}

function Assert-I05SourceFirewallContainment {
    param(
        [Parameter(Mandatory = $true)][object]$Containment,
        [Parameter(Mandatory = $true)][string]$Context,
        [Parameter(Mandatory = $true)][string]$SourceIPv4,
        [Parameter(Mandatory = $true)][string]$Nonce
    )

    $topProperties = @(
        'schema',
        'rule_count',
        'rule_names_sha256',
        'spec_sha256',
        'spec_document_sha256',
        'inventory_before_sha256',
        'inventory_armed_sha256',
        'inventory_verified_sha256',
        'state_before_sha256',
        'state_armed_sha256',
        'state_verified_sha256',
        'direct_link_only',
        'third_party_sources_forbidden',
        'exact_rules_armed',
        'third_party_bytes_impossible',
        'watchdog_interval_ms',
        'watchdog_samples',
        'watchdog_violations',
        'verification_count',
        'inventory_scope',
        'profile_scope',
        'firewall_service_running',
        'firewall_profiles_enabled',
        'firewall_profile_count',
        'firewall_profiles_sha256',
        'engine_watchdog_samples',
        'engine_watchdog_exact_filter_checks',
        'canonical_rules'
    )
    Assert-I05SourceExactProperties -Object $Containment `
        -Expected $topProperties -Context $Context
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Containment -Name 'schema' -Context $Context)) `
        -Expected 'ese.v91.i05.t1-firewall-containment/v1' `
        -Context "$Context schema"

    $ruleCount = Get-I05RequiredProperty -Object $Containment `
        -Name 'rule_count' -Context $Context
    if (($ruleCount -isnot [int] -and $ruleCount -isnot [long]) -or
        [Int64]$ruleCount -ne 10) {
        throw "$Context.rule_count must be the JSON integer 10."
    }
    foreach ($hashName in @(
        'rule_names_sha256',
        'spec_sha256',
        'spec_document_sha256',
        'inventory_before_sha256',
        'inventory_armed_sha256',
        'inventory_verified_sha256',
        'state_before_sha256',
        'state_armed_sha256',
        'state_verified_sha256',
        'firewall_profiles_sha256'
    )) {
        $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
            -Object $Containment -Name $hashName -Context $Context) `
            -Context "$Context $hashName"
    }
    foreach ($flag in @(
        'direct_link_only',
        'third_party_sources_forbidden',
        'exact_rules_armed',
        'third_party_bytes_impossible'
    )) {
        Assert-I05True -Value (Get-I05RequiredProperty `
            -Object $Containment -Name $flag -Context $Context) `
            -Context "$Context $flag"
    }
    $watchdogInterval = Get-I05RequiredProperty -Object $Containment `
        -Name 'watchdog_interval_ms' -Context $Context
    $watchdogSamples = Get-I05RequiredProperty -Object $Containment `
        -Name 'watchdog_samples' -Context $Context
    $watchdogViolations = Get-I05RequiredProperty -Object $Containment `
        -Name 'watchdog_violations' -Context $Context
    $verificationCount = Get-I05RequiredProperty -Object $Containment `
        -Name 'verification_count' -Context $Context
    $engineWatchdogSamples = Get-I05RequiredProperty `
        -Object $Containment -Name 'engine_watchdog_samples' `
        -Context $Context
    $engineWatchdogExactFilterChecks = Get-I05RequiredProperty `
        -Object $Containment `
        -Name 'engine_watchdog_exact_filter_checks' `
        -Context $Context
    foreach ($number in @(
        [pscustomobject]@{ value = $watchdogInterval; name = 'interval' },
        [pscustomobject]@{ value = $watchdogSamples; name = 'samples' },
        [pscustomobject]@{ value = $watchdogViolations; name = 'violations' },
        [pscustomobject]@{
            value = $verificationCount
            name = 'firewall verification count'
        },
        [pscustomobject]@{
            value = $engineWatchdogSamples
            name = 'firewall engine watchdog samples'
        },
        [pscustomobject]@{
            value = $engineWatchdogExactFilterChecks
            name = 'firewall engine exact-filter checks'
        }
    )) {
        if ($number.value -isnot [int] -and
            $number.value -isnot [long]) {
            throw "$Context watchdog $($number.name) is not a JSON integer."
        }
    }
    if ([Int64]$watchdogInterval -ne 500 -or
        [Int64]$watchdogSamples -lt 1 -or
        [Int64]$watchdogViolations -ne 0 -or
        [Int64]$verificationCount -lt 1 -or
        [Int64]$engineWatchdogSamples -ne [Int64]$watchdogSamples -or
        [Int64]$engineWatchdogExactFilterChecks -ne
            [Int64]$watchdogSamples) {
        throw "$Context watchdog did not continuously prove exact rules."
    }
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Containment -Name 'inventory_scope' -Context $Context)) `
        -Expected 'exact-ten-nonce-program-rules-only' `
        -Context "$Context inventory scope"
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Containment -Name 'profile_scope' -Context $Context)) `
        -Expected 'Any' -Context "$Context profile scope"
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $Containment -Name 'firewall_service_running' `
        -Context $Context) -Context "$Context MpsSvc running"
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $Containment -Name 'firewall_profiles_enabled' `
        -Context $Context) -Context "$Context firewall profiles enabled"
    $profileCount = Get-I05RequiredProperty -Object $Containment `
        -Name 'firewall_profile_count' -Context $Context
    if (($profileCount -isnot [int] -and
         $profileCount -isnot [long]) -or
        [Int64]$profileCount -ne 3) {
        throw "$Context firewall_profile_count must be the JSON integer 3."
    }
    Assert-I05ExactText -Actual (
        [string]$Containment.firewall_profiles_sha256
    ) -Expected (Get-LabStringSha256 `
        -Value "Domain=true`nPrivate=true`nPublic=true") `
        -Context "$Context enabled firewall-profile set" -IgnoreCase

    $rulesProperty = $Containment.PSObject.Properties['canonical_rules']
    if ($null -eq $rulesProperty -or
        $rulesProperty.Value -isnot [Array] -or
        @($rulesProperty.Value).Count -ne 10) {
        throw "$Context.canonical_rules must contain exactly ten rules."
    }
    $expectedRoles = @(
        'in_tcp_v4_not_h1',
        'in_tcp_v6_all',
        'in_udp_v4_all',
        'in_udp_v6_all',
        'out_tcp_v4_not_h1_loopback',
        'out_tcp_v4_h1_wrong_ports',
        'out_tcp_v4_loopback_non_api_local_ports',
        'out_tcp_v6_all',
        'out_udp_v4_all',
        'out_udp_v6_all'
    )
    $sourceAddressValue = ConvertTo-I05SourceIPv4UInt64 `
        -Address $SourceIPv4 -Context "$Context source IPv4"
    $loopbackStart = ConvertTo-I05SourceIPv4UInt64 `
        -Address '127.0.0.0' -Context "$Context loopback start"
    $loopbackEnd = ConvertTo-I05SourceIPv4UInt64 `
        -Address '127.255.255.255' -Context "$Context loopback end"
    $complementSource = @(Get-I05SourceIPv4ComplementTokens `
        -AllowedIntervals @(
            [pscustomobject]@{
                start = $sourceAddressValue
                end = $sourceAddressValue
            }
        ))
    $complementSourceAndLoopback = @(
        Get-I05SourceIPv4ComplementTokens -AllowedIntervals @(
            [pscustomobject]@{
                start = $sourceAddressValue
                end = $sourceAddressValue
            },
            [pscustomobject]@{
                start = $loopbackStart
                end = $loopbackEnd
            }
        )
    )
    $expectedAddresses = [ordered]@{
        in_tcp_v4_not_h1 = $complementSource
        in_tcp_v6_all = @('::/1', '8000::/1')
        in_udp_v4_all = @('0.0.0.0-255.255.255.255')
        in_udp_v6_all = @('::/1', '8000::/1')
        out_tcp_v4_not_h1_loopback = $complementSourceAndLoopback
        out_tcp_v4_h1_wrong_ports = @(
            ConvertTo-I05CanonicalIPv4 -Value $SourceIPv4 `
                -Context "$Context source IPv4 token"
        )
        out_tcp_v4_loopback_non_api_local_ports = @(
            '127.0.0.0-127.255.255.255'
        )
        out_tcp_v6_all = @('::/1', '8000::/1')
        out_udp_v4_all = @('0.0.0.0-255.255.255.255')
        out_udp_v6_all = @('::/1', '8000::/1')
    }
    $ruleProperties = @(
        'role',
        'name_sha256',
        'direction',
        'action',
        'enabled',
        'profile',
        'protocol',
        'local_ports',
        'remote_ports',
        'remote_addresses_sha256',
        'remote_address_count',
        'program_sha256',
        'all_interfaces'
    )
    $seenRoles = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::Ordinal)
    $seenNames = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    $expectedRuleNames = [Collections.Generic.List[string]]::new()
    $canonicalLines = [Collections.Generic.List[string]]::new()
    foreach ($rule in @($rulesProperty.Value)) {
        Assert-I05SourceExactProperties -Object $rule `
            -Expected $ruleProperties -Context "$Context canonical rule"
        $role = [string](Get-I05RequiredProperty -Object $rule `
            -Name 'role' -Context "$Context canonical rule")
        if ($expectedRoles -cnotcontains $role -or
            -not $seenRoles.Add($role)) {
            throw "$Context has an unexpected or duplicate firewall role."
        }
        $nameSha256 = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
            -Object $rule -Name 'name_sha256' -Context "$Context $role") `
            -Context "$Context $role name hash"
        $roleToken = $role.Replace('_', '-')
        $expectedRuleName =
            "eSE-V91-I05-H3-Isolation-$Nonce-$roleToken"
        $expectedRuleNames.Add($expectedRuleName)
        Assert-I05ExactText -Actual $nameSha256 `
            -Expected (Get-LabStringSha256 -Value $expectedRuleName) `
            -Context "$Context $role deterministic rule-name hash" `
            -IgnoreCase
        if (-not $seenNames.Add($nameSha256)) {
            throw "$Context has duplicate firewall rule-name hashes."
        }
        $direction = [string](Get-I05RequiredProperty -Object $rule `
            -Name 'direction' -Context "$Context $role")
        $expectedDirection = if ($role.StartsWith(
                'in_', [StringComparison]::Ordinal)) {
            'Inbound'
        } else {
            'Outbound'
        }
        Assert-I05ExactText -Actual $direction `
            -Expected $expectedDirection -Context "$Context $role direction"
        Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
            -Object $rule -Name 'action' -Context "$Context $role")) `
            -Expected 'Block' -Context "$Context $role action"
        Assert-I05True -Value (Get-I05RequiredProperty -Object $rule `
            -Name 'enabled' -Context "$Context $role") `
            -Context "$Context $role enabled"
        $profile = [string](Get-I05RequiredProperty -Object $rule `
            -Name 'profile' -Context "$Context $role")
        Assert-I05ExactText -Actual $profile -Expected 'Any' `
            -Context "$Context $role all-profile block"
        $protocol = [string](Get-I05RequiredProperty -Object $rule `
            -Name 'protocol' -Context "$Context $role")
        $expectedProtocol = if ($role.Contains('_tcp_')) {
            'TCP'
        } else {
            'UDP'
        }
        Assert-I05ExactText -Actual $protocol `
            -Expected $expectedProtocol -Context "$Context $role protocol"
        $localPorts = @(Get-I05SourceCanonicalRuleTokens -Rule $rule `
            -Name 'local_ports' -Context "$Context $role")
        $remotePorts = @(Get-I05SourceCanonicalRuleTokens -Rule $rule `
            -Name 'remote_ports' -Context "$Context $role")
        $expectedLocalPorts = if ($role -ceq
            'out_tcp_v4_loopback_non_api_local_ports') {
            @(
                "1-$($constants.downloader_web_port - 1)",
                "$($constants.downloader_web_port + 1)-65535"
            )
        } elseif ($role -ceq 'in_tcp_v4_not_h1') {
            @([string]$constants.downloader_tcp_port)
        } else {
            @('Any')
        }
        $expectedRemotePorts = if ($role -ceq
            'out_tcp_v4_h1_wrong_ports') {
            @(
                "1-$($constants.source_tcp_port - 1)",
                "$($constants.source_tcp_port + 1)-65535"
            )
        } else {
            @('Any')
        }
        Assert-I05ExactText -Actual ($localPorts -join ',') `
            -Expected ($expectedLocalPorts -join ',') `
            -Context "$Context $role local ports"
        Assert-I05ExactText -Actual ($remotePorts -join ',') `
            -Expected ($expectedRemotePorts -join ',') `
            -Context "$Context $role remote ports"
        $remoteAddressesSha256 = Assert-I05Sha256 -Value (
            Get-I05RequiredProperty -Object $rule `
                -Name 'remote_addresses_sha256' -Context "$Context $role"
        ) -Context "$Context $role remote-address hash"
        $remoteAddressCount = Get-I05RequiredProperty -Object $rule `
            -Name 'remote_address_count' -Context "$Context $role"
        if (($remoteAddressCount -isnot [int] -and
             $remoteAddressCount -isnot [long]) -or
            [Int64]$remoteAddressCount -lt 1) {
            throw "$Context $role remote_address_count is invalid."
        }
        [string[]]$addressTokens = @(
            $expectedAddresses[$role] | Sort-Object -Unique
        )
        $expectedAddressSha256 =
            Get-LabStringSha256 -Value ($addressTokens -join "`n")
        Assert-I05ExactText -Actual $remoteAddressesSha256 `
            -Expected $expectedAddressSha256 `
            -Context "$Context $role address-set hash" -IgnoreCase
        if ([Int64]$remoteAddressCount -ne $addressTokens.Count) {
            throw "$Context $role address-set count does not match semantics."
        }
        $programSha256 = Assert-I05Sha256 -Value (
            Get-I05RequiredProperty -Object $rule `
                -Name 'program_sha256' -Context "$Context $role"
        ) -Context "$Context $role program hash"
        Assert-I05ExactText -Actual $programSha256 `
            -Expected $constants.candidate_emule_sha256 `
            -Context "$Context $role candidate program hash" -IgnoreCase
        Assert-I05True -Value (Get-I05RequiredProperty -Object $rule `
            -Name 'all_interfaces' -Context "$Context $role") `
            -Context "$Context $role all-interface block"

        $canonicalLine = (
            'role={0}|name_sha256={1}|direction={2}|' +
            'action=Block|enabled=true|profile={3}|protocol={4}|' +
            'local_ports={5}|remote_ports={6}|' +
            'remote_addresses_sha256={7}|remote_address_count={8}|' +
            'program_sha256={9}|all_interfaces=true'
        ) -f @(
            $role,
            $nameSha256,
            $direction,
            $profile,
            $protocol,
            ($localPorts -join ','),
            ($remotePorts -join ','),
            $remoteAddressesSha256,
            [string][Int64]$remoteAddressCount,
            $programSha256
        )
        $canonicalLines.Add($canonicalLine)
    }
    if ($seenRoles.Count -ne $expectedRoles.Count) {
        throw "$Context does not contain every required firewall role."
    }
    [string[]]$orderedExpectedNames = $expectedRuleNames.ToArray()
    [Array]::Sort($orderedExpectedNames, [StringComparer]::Ordinal)
    Assert-I05ExactText -Actual ([string]$Containment.rule_names_sha256) `
        -Expected (Get-LabStringSha256 `
            -Value ($orderedExpectedNames -join "`n")) `
        -Context "$Context deterministic rule-name set" -IgnoreCase
    [string[]]$orderedLines = $canonicalLines.ToArray()
    [Array]::Sort($orderedLines, [StringComparer]::Ordinal)
    $calculatedSpecSha256 =
        Get-LabStringSha256 -Value ($orderedLines -join "`n")
    Assert-I05ExactText -Actual $calculatedSpecSha256 `
        -Expected ([string]$Containment.spec_sha256) `
        -Context "$Context recomputed canonical spec" -IgnoreCase
    if ([string]::Equals(
            [string]$Containment.inventory_before_sha256,
            [string]$Containment.inventory_armed_sha256,
            [StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals(
            [string]$Containment.state_before_sha256,
            [string]$Containment.state_armed_sha256,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Context before/armed firewall states did not change."
    }
    Assert-I05ExactText -Actual (
        [string]$Containment.state_verified_sha256
    ) -Expected ([string]$Containment.state_armed_sha256) `
        -Context "$Context verified/armed firewall state" -IgnoreCase

    return [pscustomobject][ordered]@{
        rule_count = 10
        rule_names_sha256 =
            ([string]$Containment.rule_names_sha256).ToLowerInvariant()
        spec_sha256 =
            ([string]$Containment.spec_sha256).ToLowerInvariant()
        spec_document_sha256 =
            ([string]$Containment.spec_document_sha256).ToLowerInvariant()
        inventory_before_sha256 =
            ([string]$Containment.inventory_before_sha256).ToLowerInvariant()
        inventory_armed_sha256 =
            ([string]$Containment.inventory_armed_sha256).ToLowerInvariant()
        inventory_verified_sha256 =
            ([string]$Containment.inventory_verified_sha256).ToLowerInvariant()
        state_before_sha256 =
            ([string]$Containment.state_before_sha256).ToLowerInvariant()
        state_armed_sha256 =
            ([string]$Containment.state_armed_sha256).ToLowerInvariant()
        state_verified_sha256 =
            ([string]$Containment.state_verified_sha256).ToLowerInvariant()
        watchdog_samples = [Int64]$watchdogSamples
        verification_count = [Int64]$verificationCount
        firewall_profiles_sha256 =
            ([string]$Containment.firewall_profiles_sha256).ToLowerInvariant()
        engine_watchdog_samples = [Int64]$engineWatchdogSamples
        engine_watchdog_exact_filter_checks =
            [Int64]$engineWatchdogExactFilterChecks
    }
}

function Import-I05SourceEvidenceBundle {
    param(
        [Parameter(Mandatory = $true)][object]$Bundle,
        [Parameter(Mandatory = $true)][object]$Complete,
        [Parameter(Mandatory = $true)][object]$Remote,
        [Parameter(Mandatory = $true)][string]$SourceIPv4,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][int[]]$ObservedRemotePorts,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot
    )

    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Bundle -Name 'schema' -Context 'evidence_bundle')) `
        -Expected 'ese.v91.i05.t1-evidence-bundle/v1' `
        -Context 'evidence bundle schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Bundle -Name 'encoding' -Context 'evidence_bundle')) `
        -Expected 'base64' -Context 'evidence bundle encoding'
    $reportedBytes = [Int64](Get-I05RequiredProperty `
        -Object $Bundle -Name 'bytes' -Context 'evidence_bundle')
    if ($reportedBytes -lt 1 -or
        $reportedBytes -gt $constants.evidence_bundle_max_bytes) {
        throw 'Evidence bundle byte length exceeds the 512 KiB bound.'
    }
    $reportedSha256 = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $Bundle -Name 'sha256' `
            -Context 'evidence_bundle'
    ) -Context 'evidence bundle hash'
    $manifestSha256 = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $Bundle `
            -Name 'manifest_sha256' -Context 'evidence_bundle'
    ) -Context 'evidence manifest hash'
    $base64 = [string](Get-I05RequiredProperty -Object $Bundle `
        -Name 'content_base64' -Context 'evidence_bundle')
    if ($base64.Length -lt 4 -or $base64.Length -gt 699052 -or
        $base64 -notmatch '^[A-Za-z0-9+/]+={0,2}$') {
        throw 'Evidence bundle content is not bounded canonical base64.'
    }
    try {
        $bundleBytes = [Convert]::FromBase64String($base64)
    } catch {
        throw 'Evidence bundle base64 decoding failed.'
    }
    if ([Int64]$bundleBytes.Length -ne $reportedBytes -or
        [Convert]::ToBase64String($bundleBytes) -cne $base64) {
        throw 'Evidence bundle decoded length/base64 is not canonical.'
    }
    $actualBundleSha256 =
        Get-I05SourceBytesSha256 -Bytes $bundleBytes
    Assert-I05ExactText -Actual $actualBundleSha256 `
        -Expected $reportedSha256 -Context 'Evidence bundle hash' `
        -IgnoreCase

    if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) {
        throw 'H1 evidence root is missing before bundle import.'
    }
    $evidenceRootItem = Get-Item -LiteralPath $EvidenceRoot -Force
    if (($evidenceRootItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'H1 evidence root cannot be a reparse point.'
    }
    $bundlePath = Join-Path $EvidenceRoot 'h3-evidence-bundle.zip'
    $extractRoot = Join-Path $EvidenceRoot 'h3-evidence'
    if ((Test-Path -LiteralPath $bundlePath) -or
        (Test-Path -LiteralPath $extractRoot)) {
        throw 'H3 evidence destination is not fresh.'
    }
    [IO.File]::WriteAllBytes($bundlePath, $bundleBytes)

    $allowedNames = @(
        'manifest.json',
        'pcap-analysis.json',
        'component-mapping.json',
        'component-inventory-pre.json',
        'component-inventory-armed.json',
        'component-inventory-post.json',
        'pktmon-filter.json',
        'pktmon-loss.json',
        'pktmon-status.json',
        'socket-proof.json',
        'file-integrity.json'
    )
    $entryBytes =
        New-Object 'Collections.Generic.Dictionary[string,byte[]]' `
            ([StringComparer]::Ordinal)
    $seenNames =
        New-Object 'Collections.Generic.HashSet[string]' `
            ([StringComparer]::OrdinalIgnoreCase)
    [Int64]$expandedBytes = 0
    Add-Type -AssemblyName System.IO.Compression
    $memory = New-Object IO.MemoryStream(,$bundleBytes)
    $archive = New-Object IO.Compression.ZipArchive(
        $memory, [IO.Compression.ZipArchiveMode]::Read, $false)
    try {
        if ($archive.Entries.Count -ne
            $constants.evidence_bundle_max_entries) {
            throw 'Evidence ZIP does not contain exactly eleven entries.'
        }
        foreach ($entry in $archive.Entries) {
            $name = [string]$entry.FullName
            if ($allowedNames -cnotcontains $name -or
                -not $seenNames.Add($name) -or
                [IO.Path]::IsPathRooted($name) -or
                $name.Contains(':') -or $name.Contains('\') -or
                $name.Contains('/') -or
                $name -match '(^|[\\/])\.\.?([\\/]|$)') {
                throw 'Evidence ZIP contains an unsafe, duplicate or extra path.'
            }
            $external = [uint32]$entry.ExternalAttributes
            $unixType = ($external -shr 16) -band 0xf000
            if ($unixType -eq 0xa000 -or
                (($external -band 0xffff) -band
                    [uint32][IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Evidence ZIP contains a link/reparse entry.'
            }
            if ([Int64]$entry.Length -lt 2 -or
                [Int64]$entry.Length -gt 1048576) {
                throw 'Evidence ZIP entry length is outside its bound.'
            }
            $expandedBytes += [Int64]$entry.Length
            if ($expandedBytes -gt
                $constants.evidence_bundle_max_expanded_bytes) {
                throw 'Evidence ZIP expanded size exceeds 4 MiB.'
            }
            $stream = $entry.Open()
            $entryMemory = New-Object IO.MemoryStream
            try {
                $stream.CopyTo($entryMemory)
                $bytes = $entryMemory.ToArray()
            } finally {
                $entryMemory.Dispose()
                $stream.Dispose()
            }
            if ([Int64]$bytes.Length -ne [Int64]$entry.Length) {
                throw 'Evidence ZIP entry length changed while reading.'
            }
            $entryBytes.Add($name, $bytes)
        }
    } finally {
        $archive.Dispose()
        $memory.Dispose()
    }
    foreach ($name in $allowedNames) {
        if (-not $entryBytes.ContainsKey($name)) {
            throw "Evidence ZIP is missing '$name'."
        }
    }
    $null = New-Item -ItemType Directory -Path $extractRoot
    foreach ($name in $allowedNames) {
        [IO.File]::WriteAllBytes(
            (Join-Path $extractRoot $name), $entryBytes[$name])
    }
    $reparse = @(Get-ChildItem -LiteralPath $extractRoot -Force |
        Where-Object {
            ($_.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0
        })
    if ($reparse.Count -gt 0) {
        throw 'Extracted H3 evidence contains a reparse point.'
    }

    $actualManifestSha256 =
        Get-I05SourceBytesSha256 -Bytes $entryBytes['manifest.json']
    Assert-I05ExactText -Actual $actualManifestSha256 `
        -Expected $manifestSha256 -Context 'Evidence manifest hash' `
        -IgnoreCase
    $manifest = Get-I05SourceJsonDocumentFromBytes `
        -Bytes $entryBytes['manifest.json'] -Context 'Evidence manifest'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $manifest -Name 'schema' -Context 'Evidence manifest')) `
        -Expected 'ese.v91.i05.t1-evidence-manifest/v1' `
        -Context 'Evidence manifest schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $manifest -Name 'case_id' -Context 'Evidence manifest')) `
        -Expected $constants.case_id -Context 'Evidence manifest case'
    Assert-I05ExactText -Actual (
        Assert-I05Nonce -Value (Get-I05RequiredProperty `
            -Object $manifest -Name 'nonce' -Context 'Evidence manifest') `
            -Context 'Evidence manifest nonce'
    ) -Expected $Nonce -Context 'Evidence manifest nonce'
    $null = ConvertTo-I05UtcTimestamp -Value (
        Get-I05RequiredProperty -Object $manifest `
            -Name 'created_at_utc' -Context 'Evidence manifest'
    ) -Context 'Evidence manifest timestamp'

    $entriesProperty = $manifest.PSObject.Properties['entries']
    if ($null -eq $entriesProperty -or
        $entriesProperty.Value -isnot [Array] -or
        @($entriesProperty.Value).Count -ne 10) {
        throw 'Evidence manifest must enumerate exactly ten payload entries.'
    }
    $manifestNames =
        New-Object 'Collections.Generic.HashSet[string]' `
            ([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in @($entriesProperty.Value)) {
        $path = [string](Get-I05RequiredProperty -Object $record `
            -Name 'path' -Context 'Evidence manifest entry')
        if ($path -eq 'manifest.json' -or
            $allowedNames -cnotcontains $path -or
            -not $manifestNames.Add($path)) {
            throw 'Evidence manifest contains an invalid payload path.'
        }
        $bytes = [Int64](Get-I05RequiredProperty -Object $record `
            -Name 'bytes' -Context "Evidence manifest entry $path")
        if ($bytes -ne [Int64]$entryBytes[$path].Length) {
            throw "Evidence manifest length mismatch for '$path'."
        }
        $hash = Assert-I05Sha256 -Value (
            Get-I05RequiredProperty -Object $record -Name 'sha256' `
                -Context "Evidence manifest entry $path"
        ) -Context "Evidence manifest hash $path"
        Assert-I05ExactText -Actual (
            Get-I05SourceBytesSha256 -Bytes $entryBytes[$path]
        ) -Expected $hash -Context "Evidence payload hash $path" `
            -IgnoreCase
    }
    foreach ($name in @($allowedNames | Where-Object {
        $_ -ne 'manifest.json'
    })) {
        if (-not $manifestNames.Contains($name)) {
            throw "Evidence manifest omitted '$name'."
        }
    }

    $retainedProperty = $manifest.PSObject.Properties['retained_raw']
    $requiredRawKinds = @(
        'etl',
        'pcapng',
        'transfer_samples',
        'pktmon_log',
        'pktmon_filters_before_reset',
        'component_inventory_pre_raw',
        'component_inventory_armed_raw',
        'component_inventory_post_raw',
        'firewall_containment_spec',
        'firewall_containment_inventory_before',
        'firewall_containment_inventory_armed',
        'firewall_containment_inventory_verified'
    )
    if ($null -eq $retainedProperty -or
        $retainedProperty.Value -isnot [Array] -or
        @($retainedProperty.Value).Count -ne $requiredRawKinds.Count) {
        throw 'Evidence manifest retained_raw set is incomplete.'
    }
    $rawByKind = @{}
    $rawPaths = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in @($retainedProperty.Value)) {
        $kind = [string](Get-I05RequiredProperty -Object $record `
            -Name 'kind' -Context 'Evidence retained_raw')
        if ($requiredRawKinds -cnotcontains $kind -or
            $rawByKind.ContainsKey($kind)) {
            throw 'Evidence manifest retained_raw kind is invalid/duplicate.'
        }
        $path = [string](Get-I05RequiredProperty -Object $record `
            -Name 'path_relative' -Context "Evidence retained_raw $kind")
        $segments = @($path.Replace('/', '\') -split '\\')
        if ([string]::IsNullOrWhiteSpace($path) -or
            [IO.Path]::IsPathRooted($path) -or $path.Contains(':') -or
            @($segments | Where-Object {
                $_ -eq '' -or $_ -eq '.' -or $_ -eq '..'
            }).Count -gt 0 -or -not $rawPaths.Add($path)) {
            throw 'Evidence retained_raw path is unsafe or duplicate.'
        }
        $bytes = [Int64](Get-I05RequiredProperty -Object $record `
            -Name 'bytes' -Context "Evidence retained_raw $kind")
        if ($bytes -lt 1) {
            throw 'Evidence retained_raw byte length must be positive.'
        }
        $hash = Assert-I05Sha256 -Value (
            Get-I05RequiredProperty -Object $record -Name 'sha256' `
                -Context "Evidence retained_raw $kind"
        ) -Context "Evidence retained_raw hash $kind"
        $rawByKind[$kind] = [pscustomobject]@{
            path = $path
            bytes = $bytes
            sha256 = $hash
        }
    }

    $completeFile = Get-I05RequiredProperty -Object $Complete `
        -Name 'file' -Context 'COMPLETE'
    $fileIntegrity = Get-I05SourceJsonDocumentFromBytes `
        -Bytes $entryBytes['file-integrity.json'] `
        -Context 'File integrity evidence'
    Assert-I05ExactText -Actual (
        Get-I05SourceBytesSha256 -Bytes $entryBytes['file-integrity.json']
    ) -Expected ([string]$completeFile.integrity_sha256) `
        -Context 'File integrity artifact hash' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $fileIntegrity -Name 'schema' `
        -Context 'File integrity evidence')) `
        -Expected 'ese.v91.i05.t1-file-integrity/v1' `
        -Context 'File integrity schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $fileIntegrity -Name 'case_id' `
        -Context 'File integrity evidence')) `
        -Expected $constants.case_id -Context 'File integrity case'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $fileIntegrity -Name 'name' `
        -Context 'File integrity evidence')) `
        -Expected $constants.fixture_name -Context 'File integrity name'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $fileIntegrity -Name 'name_sha256' `
        -Context 'File integrity evidence')) `
        -Expected (Get-LabStringSha256 -Value $constants.fixture_name) `
        -Context 'File integrity name hash' -IgnoreCase
    $integrityPath = [string](Get-I05RequiredProperty `
        -Object $fileIntegrity -Name 'path_relative' `
        -Context 'File integrity evidence')
    $integritySegments = @(
        $integrityPath.Replace('/', '\') -split '\\'
    )
    if ([string]::IsNullOrWhiteSpace($integrityPath) -or
        [IO.Path]::IsPathRooted($integrityPath) -or
        $integrityPath.Contains(':') -or
        @($integritySegments | Where-Object {
            $_ -eq '' -or $_ -eq '.' -or $_ -eq '..'
        }).Count -gt 0) {
        throw 'File integrity relative path is unsafe.'
    }
    $integrityBytes = Get-I05RequiredProperty -Object $fileIntegrity `
        -Name 'bytes' -Context 'File integrity evidence'
    $integritySha256 = [string](Get-I05RequiredProperty `
        -Object $fileIntegrity -Name 'sha256' `
        -Context 'File integrity evidence')
    $integrityEd2k = [string](Get-I05RequiredProperty `
        -Object $fileIntegrity -Name 'ed2k' `
        -Context 'File integrity evidence')
    try {
        if ([Int64]$integrityBytes -ne $constants.fixture_bytes) {
            throw 'File integrity byte length is not exactly 4 GiB.'
        }
        Assert-I05ExactText -Actual $integritySha256 `
            -Expected $constants.fixture_sha256 `
            -Context 'File integrity SHA-256' -IgnoreCase
        Assert-I05ExactText -Actual $integrityEd2k `
            -Expected $constants.fixture_ed2k `
            -Context 'File integrity local ED2K' -IgnoreCase
    } catch {
        if ($_.Exception.Data.Contains('I05Classification')) {
            throw
        }
        Throw-I05SourceProductInvariant `
            -Category 'h3-file-integrity-evidence' `
            -Message $_.Exception.Message
    }
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $fileIntegrity -Name 'method' `
        -Context 'File integrity evidence')) `
        -Expected 'local-streaming-sha256-ed2k-md4' `
        -Context 'File integrity calculation method'
    $calculationReportSha256 = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty `
        -Object $fileIntegrity -Name 'calculation_report_sha256' `
        -Context 'File integrity evidence'
    ) -Context 'File integrity calculation-report hash'
    Assert-I05ExactText -Actual $calculationReportSha256 `
        -Expected ([string]$completeFile.calculation_report_sha256) `
        -Context 'Local calculation-report hash' -IgnoreCase
    $null = ConvertTo-I05UtcTimestamp -Value (
        Get-I05RequiredProperty -Object $fileIntegrity `
            -Name 'calculated_at_utc' -Context 'File integrity evidence'
    ) -Context 'File integrity calculation timestamp'

    $mapping = Get-I05SourceJsonDocumentFromBytes `
        -Bytes $entryBytes['component-mapping.json'] `
        -Context 'Component mapping evidence'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $mapping -Name 'schema' `
        -Context 'Component mapping evidence')) `
        -Expected 'ese.v91.i05.t1-component-mapping/v1' `
        -Context 'Component mapping schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $mapping -Name 'case_id' `
        -Context 'Component mapping evidence')) `
        -Expected $constants.case_id -Context 'Component mapping case'
    Assert-I05ExactText -Actual (
        Get-I05SourceBytesSha256 `
            -Bytes $entryBytes['component-mapping.json']
    ) -Expected ([string]$Complete.capture.component_mapping_sha256) `
        -Context 'Component mapping artifact hash' -IgnoreCase
    $mappingKeySha256 = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $mapping `
            -Name 'mapping_key_sha256' -Context 'Component mapping evidence'
    ) -Context 'Component mapping key hash'
    Assert-I05ExactText -Actual $mappingKeySha256 `
        -Expected $Remote.mapping_key_sha256 `
        -Context 'READY/final component mapping key' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $mapping -Name 'interface_guid_sha256' `
        -Context 'Component mapping evidence')) `
        -Expected $Remote.component_guid_sha256 `
        -Context 'Component mapping interface GUID' -IgnoreCase
    if ([Int64](Get-I05RequiredProperty -Object $mapping `
            -Name 'primary_id' -Context 'Component mapping evidence') -ne
        [Int64]$Remote.primary_component_id) {
        throw 'Component mapping primary ID differs from READY.'
    }
    $mappingSecondaryProperty =
        $mapping.PSObject.Properties['secondary_id']
    if ($null -eq $mappingSecondaryProperty) {
        throw 'Component mapping secondary_id is missing.'
    }
    if (@($Remote.secondary_component_ids).Count -eq 0) {
        if ([Int64]$mappingSecondaryProperty.Value -ne 0) {
            throw 'Component mapping has an unexpected SecondaryId.'
        }
    } elseif ([Int64]$mappingSecondaryProperty.Value -ne
            [Int64]$Remote.secondary_component_ids[0]) {
        throw 'Component mapping SecondaryId differs from READY.'
    }
    $conversionIdsProperty =
        $mapping.PSObject.Properties['conversion_component_ids']
    if ($null -eq $conversionIdsProperty -or
        $conversionIdsProperty.Value -isnot [Array]) {
        throw 'Component mapping conversion_component_ids is not an array.'
    }
    $expectedConversionIds = @(
        [Int64]$Remote.primary_component_id
    ) + @($Remote.secondary_component_ids | ForEach-Object {
        [Int64]$_
    })
    $actualConversionIds = @($conversionIdsProperty.Value |
        ForEach-Object { [Int64]$_ })
    if ((@($actualConversionIds | Sort-Object -Unique) -join ',') -cne
        (@($expectedConversionIds | Sort-Object -Unique) -join ',')) {
        throw 'Component mapping conversion ID set differs from READY.'
    }
    foreach ($flag in @(
        'unique_guid_component_match',
        'stable_pre_armed_post'
    )) {
        Assert-I05True -Value (Get-I05RequiredProperty `
            -Object $mapping -Name $flag `
            -Context 'Component mapping evidence') `
            -Context "Component mapping $flag"
    }
    foreach ($flag in @(
        'optional_if_index_correlated',
        'optional_mac_correlated'
    )) {
        $optionalCorrelation = Get-I05RequiredProperty `
            -Object $mapping -Name $flag `
            -Context 'Component mapping evidence'
        if ($optionalCorrelation -isnot [bool]) {
            throw "Component mapping $flag must be one JSON boolean."
        }
    }
    $mappingInventories = Get-I05RequiredProperty -Object $mapping `
        -Name 'inventories' -Context 'Component mapping evidence'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $mappingInventories -Name 'pre_raw_sha256' `
        -Context 'Component mapping inventories')) `
        -Expected $Remote.inventory_pre_sha256 `
        -Context 'Mapping pre raw inventory' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $mappingInventories -Name 'armed_raw_sha256' `
        -Context 'Component mapping inventories')) `
        -Expected $Remote.inventory_armed_sha256 `
        -Context 'Mapping armed raw inventory' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $mappingInventories -Name 'post_raw_sha256' `
        -Context 'Component mapping inventories')) `
        -Expected $rawByKind[
            'component_inventory_post_raw'].sha256 `
        -Context 'Mapping post raw inventory' -IgnoreCase

    $inventoryFiles = [ordered]@{
        pre = 'component-inventory-pre.json'
        armed = 'component-inventory-armed.json'
        post = 'component-inventory-post.json'
    }
    $inventories = @{}
    foreach ($inventoryStage in $inventoryFiles.Keys) {
        $fileName = $inventoryFiles[$inventoryStage]
        $inventory = Get-I05SourceJsonDocumentFromBytes `
            -Bytes $entryBytes[$fileName] `
            -Context "Component $inventoryStage inventory"
        Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
            -Object $inventory -Name 'schema' `
            -Context "Component $inventoryStage inventory")) `
            -Expected 'ese.v91.i05.t1-component-inventory/v1' `
            -Context "Component $inventoryStage inventory schema"
        Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
            -Object $inventory -Name 'stage' `
            -Context "Component $inventoryStage inventory")) `
            -Expected $inventoryStage `
            -Context "Component $inventoryStage inventory stage"
        if ([Int64](Get-I05RequiredProperty -Object $inventory `
                -Name 'raw_bytes' `
                -Context "Component $inventoryStage inventory") -lt 2) {
            throw "Component $inventoryStage raw inventory is empty."
        }
        $rawHash = Assert-I05Sha256 -Value (
            Get-I05RequiredProperty -Object $inventory `
                -Name 'raw_sha256' `
                -Context "Component $inventoryStage inventory"
        ) -Context "Component $inventoryStage raw inventory hash"
        Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
            -Object $inventory -Name 'mapping_key_sha256' `
            -Context "Component $inventoryStage inventory")) `
            -Expected $mappingKeySha256 `
            -Context "Component $inventoryStage mapping key" -IgnoreCase
        Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
            -Object $inventory -Name 'interface_guid_sha256' `
            -Context "Component $inventoryStage inventory")) `
            -Expected $Remote.component_guid_sha256 `
            -Context "Component $inventoryStage interface GUID" -IgnoreCase
        if ([Int64](Get-I05RequiredProperty -Object $inventory `
                -Name 'primary_id' `
                -Context "Component $inventoryStage inventory") -ne
            [Int64]$Remote.primary_component_id) {
            throw "Component $inventoryStage primary ID changed."
        }
        $inventorySecondaryProperty =
            $inventory.PSObject.Properties['secondary_id']
        if ($null -eq $inventorySecondaryProperty) {
            throw "Component $inventoryStage secondary_id is missing."
        }
        if (@($Remote.secondary_component_ids).Count -eq 0) {
            if ([Int64]$inventorySecondaryProperty.Value -ne 0) {
                throw "Component $inventoryStage has unexpected SecondaryId."
            }
        } elseif ([Int64]$inventorySecondaryProperty.Value -ne
                [Int64]$Remote.secondary_component_ids[0]) {
            throw "Component $inventoryStage SecondaryId changed."
        }
        $rawKind = "component_inventory_${inventoryStage}_raw"
        if ([Int64]$rawByKind[$rawKind].bytes -ne
            [Int64]$inventory.raw_bytes) {
            throw "Component $inventoryStage retained raw length differs."
        }
        Assert-I05ExactText -Actual $rawByKind[$rawKind].sha256 `
            -Expected $rawHash `
            -Context "Component $inventoryStage retained raw hash" `
            -IgnoreCase
        $inventories[$inventoryStage] = $inventory
    }
    Assert-I05ExactText -Actual $rawByKind[
        'component_inventory_pre_raw'].sha256 `
        -Expected $Remote.inventory_pre_sha256 `
        -Context 'READY pre-inventory retained hash' -IgnoreCase
    Assert-I05ExactText -Actual $rawByKind[
        'component_inventory_armed_raw'].sha256 `
        -Expected $Remote.inventory_armed_sha256 `
        -Context 'READY armed-inventory retained hash' -IgnoreCase

    $socketSummary = Get-I05RequiredProperty -Object $Complete `
        -Name 'socket_proof' -Context 'COMPLETE'
    $socketProof = Get-I05SourceJsonDocumentFromBytes `
        -Bytes $entryBytes['socket-proof.json'] `
        -Context 'Socket proof evidence'
    Assert-I05ExactText -Actual (
        Get-I05SourceBytesSha256 -Bytes $entryBytes['socket-proof.json']
    ) -Expected ([string]$socketSummary.sha256) `
        -Context 'Socket proof artifact hash' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $socketProof -Name 'schema' `
        -Context 'Socket proof evidence')) `
        -Expected 'ese.v91.i05.t1-socket-proof/v1' `
        -Context 'Socket proof schema'
    $proofPid = [int](Get-I05RequiredProperty -Object $socketProof `
        -Name 'candidate_pid' -Context 'Socket proof evidence')
    if ($proofPid -ne [int]$Remote.process_id -or
        $proofPid -ne [int]$socketSummary.candidate_pid) {
        throw 'Socket proof PID does not match READY/COMPLETE.'
    }
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $socketProof -Name 'source_ipv4_sha256' `
        -Context 'Socket proof evidence')) `
        -Expected (Get-LabStringSha256 -Value $SourceIPv4) `
        -Context 'Socket proof H1 address' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $socketProof -Name 'downloader_ipv4_sha256' `
        -Context 'Socket proof evidence')) `
        -Expected $Remote.ipv4_address_sha256 `
        -Context 'Socket proof H3 address' -IgnoreCase
    if ([int](Get-I05RequiredProperty -Object $socketProof `
            -Name 'remote_port' -Context 'Socket proof evidence') -ne
        $constants.source_tcp_port) {
        throw 'Socket proof does not target H1 TCP/7862.'
    }
    $proofForbidden = [Int64](Get-I05RequiredProperty `
        -Object $socketProof -Name 'forbidden_established_count' `
        -Context 'Socket proof evidence')
    if ($proofForbidden -ne 0 -or
        [Int64]$socketSummary.forbidden_tuple_count -ne 0) {
        Throw-I05SourceProductInvariant `
            -Category 'h3-socket-invariant-evidence' `
            -Message (
                'Socket proof contains a third-party established tuple.'
            )
    }
    $observedTuplesProperty =
        $socketProof.PSObject.Properties['observed_tuples']
    if ($null -eq $observedTuplesProperty -or
        $observedTuplesProperty.Value -isnot [Array]) {
        throw 'Socket proof observed_tuples must be one JSON array.'
    }
    $observedTuples = @($observedTuplesProperty.Value)
    $uniqueTupleCount = [int](Get-I05RequiredProperty `
        -Object $socketProof -Name 'unique_tuple_count' `
        -Context 'Socket proof evidence')
    if ($uniqueTupleCount -lt 1 -or
        $uniqueTupleCount -ne $observedTuples.Count -or
        $uniqueTupleCount -ne [int]$socketSummary.unique_tuple_count) {
        throw 'Socket proof unique tuple count is inconsistent.'
    }
    $tuplePorts = [Collections.Generic.List[int]]::new()
    foreach ($tuple in $observedTuples) {
        Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
            -Object $tuple -Name 'protocol' `
            -Context 'Socket proof tuple')) `
            -Expected 'TCP' -Context 'Socket proof tuple protocol'
        Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
            -Object $tuple -Name 'local_address_sha256' `
            -Context 'Socket proof tuple')) `
            -Expected $Remote.ipv4_address_sha256 `
            -Context 'Socket proof tuple H3 address' -IgnoreCase
        Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
            -Object $tuple -Name 'remote_address_sha256' `
            -Context 'Socket proof tuple')) `
            -Expected (Get-LabStringSha256 -Value $SourceIPv4) `
            -Context 'Socket proof tuple H1 address' -IgnoreCase
        $localPort = [int](Get-I05RequiredProperty -Object $tuple `
            -Name 'local_port' -Context 'Socket proof tuple')
        if ($localPort -lt 1024 -or $localPort -gt 65535 -or
            $tuplePorts.Contains($localPort) -or
            [int](Get-I05RequiredProperty -Object $tuple `
                -Name 'remote_port' -Context 'Socket proof tuple') -ne
                $constants.source_tcp_port -or
            [int](Get-I05RequiredProperty -Object $tuple `
                -Name 'pid' -Context 'Socket proof tuple') -ne
                $Remote.process_id -or
            [int](Get-I05RequiredProperty -Object $tuple `
                -Name 'observations' -Context 'Socket proof tuple') -lt 1) {
            throw 'Socket proof tuple is invalid or duplicated.'
        }
        $null = Get-I05RequiredProperty -Object $tuple `
            -Name 'first_sample' -Context 'Socket proof tuple'
        $null = Get-I05RequiredProperty -Object $tuple `
            -Name 'last_sample' -Context 'Socket proof tuple'
        $tuplePorts.Add($localPort)
    }
    $outerPorts = Get-I05SourceCanonicalPortArray `
        -Owner $socketSummary -Name 'observed_ephemeral_ports' `
        -Context 'COMPLETE.socket_proof'
    Assert-I05SourceSamePorts -Actual $tuplePorts.ToArray() `
        -Expected $outerPorts -Context 'Socket proof tuple ports'
    Assert-I05SourceSamePorts -Actual $outerPorts `
        -Expected $ObservedRemotePorts `
        -Context 'H1/H3 observed peer ports'
    if ([int](Get-I05RequiredProperty -Object $socketProof `
            -Name 'sample_count' -Context 'Socket proof evidence') -lt 1 -or
        [int]$socketSummary.sample_count -lt 1) {
        throw 'Socket proof contains no process-bound samples.'
    }
    $stableProperty = $socketProof.PSObject.Properties['stable_tuple']
    $outerStableProperty =
        $socketSummary.PSObject.Properties['stable_tuple']
    if ($null -eq $stableProperty -or $null -eq $outerStableProperty) {
        throw 'Socket proof stable_tuple field is missing.'
    }
    if ($uniqueTupleCount -eq 1) {
        if ($null -eq $stableProperty.Value -or
            $null -eq $outerStableProperty.Value) {
            throw 'Single socket proof tuple is not identified as stable.'
        }
        foreach ($field in @(
            'protocol',
            'local_address_sha256',
            'local_port',
            'remote_address_sha256',
            'remote_port',
            'pid'
        )) {
            $artifactValue = Get-I05RequiredProperty `
                -Object $stableProperty.Value -Name $field `
                -Context 'Socket proof stable tuple'
            $outerValue = Get-I05RequiredProperty `
                -Object $outerStableProperty.Value -Name $field `
                -Context 'COMPLETE stable tuple'
            Assert-I05ExactText -Actual ([string]$outerValue) `
                -Expected ([string]$artifactValue) `
                -Context "Stable tuple $field" -IgnoreCase
        }
    } elseif ($null -ne $stableProperty.Value -or
        $null -ne $outerStableProperty.Value) {
        throw 'Multi-tuple socket proof must report stable_tuple=null.'
    }

    $capture = Get-I05RequiredProperty -Object $Complete `
        -Name 'capture' -Context 'COMPLETE'
    $analysis = Get-I05SourceJsonDocumentFromBytes `
        -Bytes $entryBytes['pcap-analysis.json'] `
        -Context 'PCAP analysis evidence'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $analysis -Name 'schema' `
        -Context 'PCAP analysis evidence')) `
        -Expected 'ese.v91.i05.t1-pcap-analysis/v1' `
        -Context 'PCAP analysis schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $analysis -Name 'case_id' `
        -Context 'PCAP analysis evidence')) `
        -Expected $constants.case_id -Context 'PCAP analysis case'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $analysis `
        -Name 'parser_valid' -Context 'PCAP analysis evidence') `
        -Context 'PCAP parser validity'
    if ([int](Get-I05RequiredProperty -Object $analysis `
            -Name 'candidate_pid' -Context 'PCAP analysis evidence') -ne
        [int]$Remote.process_id) {
        throw (
            'PCAP analysis candidate PID context differs from socket proof.'
        )
    }
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $analysis -Name 'candidate_pid_role' `
        -Context 'PCAP analysis evidence')) `
        -Expected 'socket-watchdog-context-only' `
        -Context 'PCAP candidate PID role'
    Assert-I05False -Value (Get-I05RequiredProperty -Object $analysis `
        -Name 'pcap_pid_attributed' `
        -Context 'PCAP analysis evidence') `
        -Context 'PCAP PID attribution prohibition'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $analysis `
        -Name 'tuple_allowlist_pid_observed' `
        -Context 'PCAP analysis evidence') `
        -Context 'PCAP tuple allowlist socket observation'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $analysis -Name 'attribution_guard' `
        -Context 'PCAP analysis evidence')) `
        -Expected 'process-scoped-firewall-containment' `
        -Context 'PCAP attribution guard'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $analysis `
        -Name 'physical_component_guid_match' `
        -Context 'PCAP analysis evidence') `
        -Context 'PCAP physical component GUID'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $analysis -Name 'component_mapping_sha256' `
        -Context 'PCAP analysis evidence')) `
        -Expected ([string]$capture.component_mapping_sha256) `
        -Context 'PCAP component mapping hash' -IgnoreCase
    Assert-I05ExactText -Actual (
        Get-I05SourceBytesSha256 -Bytes $entryBytes['pcap-analysis.json']
    ) -Expected ([string]$capture.analysis_sha256) `
        -Context 'PCAP analysis artifact hash' -IgnoreCase
    $analysisPorts = Get-I05SourceCanonicalPortArray `
        -Owner $analysis -Name 'allowed_local_ports' `
        -Context 'PCAP analysis evidence'
    Assert-I05SourceSamePorts -Actual $analysisPorts `
        -Expected $outerPorts `
        -Context 'PCAP/socket exact local ports'
    if ([Int64](Get-I05RequiredProperty -Object $analysis `
            -Name 'conversion_component_id' `
            -Context 'PCAP analysis evidence') -ne
        [Int64]$capture.converted_component_id) {
        throw 'PCAP analysis used a different component ID.'
    }
    $countPairs = [ordered]@{
        exact_peer_packets = 'ipv4_peer_packets'
        rejected_peer_tuple_packets = 'rejected_peer_tuple_packets'
        third_party_peer_packets = 'third_party_peer_packets'
        ipv6_peer_packets = 'ipv6_peer_packets'
    }
    foreach ($pair in $countPairs.GetEnumerator()) {
        if ([Int64](Get-I05RequiredProperty -Object $analysis `
                -Name $pair.Key -Context 'PCAP analysis evidence') -ne
            [Int64](Get-I05RequiredProperty -Object $capture `
                -Name $pair.Value -Context 'COMPLETE.capture')) {
            throw "PCAP analysis count '$($pair.Key)' differs from COMPLETE."
        }
    }
    if ([Int64]$analysis.exact_peer_packets -lt 1 -or
        [Int64]$analysis.rejected_peer_tuple_packets -ne 0 -or
        [Int64]$analysis.third_party_peer_packets -ne 0 -or
        [Int64]$analysis.ipv6_peer_packets -ne 0) {
        Throw-I05SourceLabBlocked `
            -Category 'h3-pcap-fixture-not-adjudicable' `
            -Message (
                'PCAP analysis is not restricted to the exact clean H1/H3 ' +
                'tuple fixture; raw packets are not PID attribution.'
            )
    }
    $analysisRequestPartsI64 = Get-I05RequiredProperty `
        -Object $analysis -Name 'requestparts_i64' `
        -Context 'PCAP analysis evidence'
    $analysisCompressed32 = Get-I05RequiredProperty `
        -Object $analysis -Name 'compressedpart_32' `
        -Context 'PCAP analysis evidence'
    $analysisSendingI64 = Get-I05RequiredProperty `
        -Object $analysis -Name 'sendingpart_i64' `
        -Context 'PCAP analysis evidence'
    $analysisCompressedI64 = Get-I05RequiredProperty `
        -Object $analysis -Name 'compressedpart_i64' `
        -Context 'PCAP analysis evidence'
    $analysisInvalidI64 = Get-I05RequiredProperty `
        -Object $analysis -Name 'invalid_fixture_i64_frames' `
        -Context 'PCAP analysis evidence'
    if ([Int64]$analysisRequestPartsI64 -le 0 -or
        [Int64]$analysisCompressed32 -lt 0 -or
        [Int64]$analysisSendingI64 -lt 0 -or
        [Int64]$analysisCompressedI64 -lt 0 -or
        ([Int64]$analysisCompressed32 +
            [Int64]$analysisSendingI64 +
            [Int64]$analysisCompressedI64) -le 0 -or
        [Int64]$analysisInvalidI64 -ne 0) {
        Throw-I05SourceProductInvariant `
            -Category 'h3-wire-invariant-evidence' `
            -Message (
                'Valid exact capture contradicts the required large-file ' +
                'request/response framing or opcodes.'
            )
    }
    if ([Int64]$analysisRequestPartsI64 -ne
            [Int64]$capture.requestparts_i64 -or
        [Int64]$analysisCompressed32 -ne
            [Int64]$capture.compressedpart_32 -or
        [Int64]$analysisSendingI64 -ne
            [Int64]$capture.sending_i64 -or
        [Int64]$analysisCompressedI64 -ne
            [Int64]$capture.compressed_i64) {
        throw 'PCAP opcode analysis differs from COMPLETE.'
    }
    Assert-I05ExactText -Actual $rawByKind['pcapng'].sha256 `
        -Expected ([string]$capture.pcap_sha256) `
        -Context 'Retained PCAPNG hash' -IgnoreCase

    $filterEvidence = Get-I05SourceJsonDocumentFromBytes `
        -Bytes $entryBytes['pktmon-filter.json'] `
        -Context 'PktMon filter evidence'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $filterEvidence -Name 'schema' `
        -Context 'PktMon filter evidence')) `
        -Expected 'ese.v91.i05.t1-pktmon-filter/v1' `
        -Context 'PktMon filter schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $filterEvidence -Name 'case_id' `
        -Context 'PktMon filter evidence')) `
        -Expected $constants.case_id -Context 'PktMon filter case'
    $filtersProperty = $filterEvidence.PSObject.Properties['filters']
    if ($null -eq $filtersProperty -or
        $filtersProperty.Value -isnot [Array] -or
        @($filtersProperty.Value).Count -lt 1) {
        throw 'PktMon filter evidence has no exact filter descriptors.'
    }
    foreach ($snapshotName in @('before', 'armed', 'before_reset', 'after')) {
        if ([Int64](Get-I05RequiredProperty -Object $filterEvidence `
                -Name "${snapshotName}_bytes" `
                -Context 'PktMon filter evidence') -lt 1) {
            throw "PktMon filters $snapshotName snapshot is empty."
        }
        $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
            -Object $filterEvidence -Name "${snapshotName}_sha256" `
            -Context 'PktMon filter evidence') `
            -Context "PktMon filters $snapshotName hash"
    }
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $filterEvidence -Name 'restored_exactly' `
        -Context 'PktMon filter evidence') `
        -Context 'PktMon filter restoration'
    Assert-I05ExactText -Actual $rawByKind[
        'pktmon_filters_before_reset'].sha256 `
        -Expected ([string]$filterEvidence.before_reset_sha256) `
        -Context 'Retained pre-reset PktMon filter inventory hash' `
        -IgnoreCase
    $filterContainment = Assert-I05SourceFirewallContainment `
        -Containment (Get-I05RequiredProperty -Object $filterEvidence `
            -Name 'third_party_containment' `
            -Context 'PktMon filter evidence') `
        -Context 'PktMon third-party containment' `
        -SourceIPv4 $SourceIPv4 -Nonce $Nonce
    $completeContainment = Assert-I05SourceFirewallContainment `
        -Containment (Get-I05RequiredProperty -Object $Complete `
            -Name 'containment' -Context 'COMPLETE') `
        -Context 'COMPLETE third-party containment' `
        -SourceIPv4 $SourceIPv4 -Nonce $Nonce
    foreach ($field in @(
        'rule_count',
        'rule_names_sha256',
        'spec_sha256',
        'spec_document_sha256',
        'inventory_before_sha256',
        'inventory_armed_sha256',
        'inventory_verified_sha256',
        'state_before_sha256',
        'state_armed_sha256',
        'state_verified_sha256',
        'watchdog_samples',
        'verification_count',
        'firewall_profiles_sha256',
        'engine_watchdog_samples',
        'engine_watchdog_exact_filter_checks'
    )) {
        Assert-I05ExactText -Actual ([string]$completeContainment.$field) `
            -Expected ([string]$filterContainment.$field) `
            -Context "COMPLETE/filter containment $field" -IgnoreCase
    }
    Assert-I05ExactText -Actual (
        [string]$rawByKind['firewall_containment_spec'].sha256
    ) -Expected $filterContainment.spec_document_sha256 `
        -Context 'Retained containment spec-document hash' -IgnoreCase
    Assert-I05ExactText -Actual (
        [string]$rawByKind[
            'firewall_containment_inventory_before'
        ].sha256
    ) -Expected $filterContainment.inventory_before_sha256 `
        -Context 'Retained containment before-inventory hash' -IgnoreCase
    Assert-I05ExactText -Actual (
        [string]$rawByKind[
            'firewall_containment_inventory_armed'
        ].sha256
    ) -Expected $filterContainment.inventory_armed_sha256 `
        -Context 'Retained containment armed-inventory hash' -IgnoreCase
    Assert-I05ExactText -Actual (
        [string]$rawByKind[
            'firewall_containment_inventory_verified'
        ].sha256
    ) -Expected $filterContainment.inventory_verified_sha256 `
        -Context 'Retained containment verified-inventory hash' -IgnoreCase
    $expectedContainmentRawPaths = [ordered]@{
        firewall_containment_spec =
            'evidence/firewall-containment-spec.json'
        firewall_containment_inventory_before =
            'evidence/firewall-containment-inventory-before.json'
        firewall_containment_inventory_armed =
            'evidence/firewall-containment-inventory-armed.json'
        firewall_containment_inventory_verified =
            'evidence/firewall-containment-inventory-verified.json'
    }
    foreach ($entry in $expectedContainmentRawPaths.GetEnumerator()) {
        Assert-I05ExactText -Actual ([string]$rawByKind[$entry.Key].path) `
            -Expected ([string]$entry.Value) `
            -Context "Retained containment path $($entry.Key)"
    }

    $lossEvidence = Get-I05SourceJsonDocumentFromBytes `
        -Bytes $entryBytes['pktmon-loss.json'] `
        -Context 'PktMon loss evidence'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $lossEvidence -Name 'schema' `
        -Context 'PktMon loss evidence')) `
        -Expected 'ese.v91.i05.t1-pktmon-loss/v1' `
        -Context 'PktMon loss schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $lossEvidence -Name 'case_id' `
        -Context 'PktMon loss evidence')) `
        -Expected $constants.case_id -Context 'PktMon loss case'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $lossEvidence `
        -Name 'available' -Context 'PktMon loss evidence') `
        -Context 'PktMon loss counters available'
    foreach ($field in @(
        'error_code',
        'events_lost',
        'log_buffers_lost',
        'realtime_buffers_lost',
        'buffers_lost'
    )) {
        if ([Int64](Get-I05RequiredProperty -Object $lossEvidence `
                -Name $field -Context 'PktMon loss evidence') -ne 0) {
            throw "PktMon loss counter '$field' is nonzero."
        }
    }
    if ([Int64](Get-I05RequiredProperty -Object $lossEvidence `
            -Name 'buffers_written' -Context 'PktMon loss evidence') -lt 1) {
        throw 'PktMon ETW session wrote no buffers.'
    }
    Assert-I05True -Value (Get-I05RequiredProperty -Object $lossEvidence `
        -Name 'proved_zero' -Context 'PktMon loss evidence') `
        -Context 'PktMon zero-loss proof'

    $statusEvidence = Get-I05SourceJsonDocumentFromBytes `
        -Bytes $entryBytes['pktmon-status.json'] `
        -Context 'PktMon status evidence'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $statusEvidence -Name 'schema' `
        -Context 'PktMon status evidence')) `
        -Expected 'ese.v91.i05.t1-pktmon-status/v1' `
        -Context 'PktMon status schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $statusEvidence -Name 'case_id' `
        -Context 'PktMon status evidence')) `
        -Expected $constants.case_id -Context 'PktMon status case'
    if ([Int64](Get-I05RequiredProperty -Object $statusEvidence `
            -Name 'primary_component_id' `
            -Context 'PktMon status evidence') -ne
            [Int64]$Remote.primary_component_id -or
        [Int64](Get-I05RequiredProperty -Object $statusEvidence `
            -Name 'converted_component_id' `
            -Context 'PktMon status evidence') -ne
            [Int64]$capture.converted_component_id -or
        [int](Get-I05RequiredProperty -Object $statusEvidence `
            -Name 'conversion_hit_count' `
            -Context 'PktMon status evidence') -ne 1) {
        throw 'PktMon status component conversion identity is inconsistent.'
    }
    $expectedSecondaryId = if (
        @($Remote.secondary_component_ids).Count -eq 1
    ) {
        [Int64]$Remote.secondary_component_ids[0]
    } else {
        [Int64]0
    }
    if ([Int64](Get-I05RequiredProperty -Object $statusEvidence `
            -Name 'secondary_component_id' `
            -Context 'PktMon status evidence') -ne
        $expectedSecondaryId) {
        throw 'PktMon status SecondaryId differs from READY.'
    }
    $conversionResultsProperty =
        $statusEvidence.PSObject.Properties['conversion_results']
    if ($null -eq $conversionResultsProperty -or
        $conversionResultsProperty.Value -isnot [Array]) {
        throw 'PktMon conversion_results must be one JSON array.'
    }
    $conversionResults = @($conversionResultsProperty.Value)
    $expectedConversionIds = @(
        [Int64]$Remote.primary_component_id
    ) + @($Remote.secondary_component_ids | ForEach-Object {
        [Int64]$_
    })
    if ($conversionResults.Count -ne $expectedConversionIds.Count) {
        throw 'PktMon did not convert every primary/secondary component ID.'
    }
    $seenConversionIds =
        [Collections.Generic.HashSet[Int64]]::new()
    $flowHitCount = 0
    $retainedCount = 0
    foreach ($result in $conversionResults) {
        $resultId = [Int64](Get-I05RequiredProperty -Object $result `
            -Name 'component_id' -Context 'PktMon conversion result')
        if ($expectedConversionIds -notcontains $resultId -or
            -not $seenConversionIds.Add($resultId)) {
            throw 'PktMon conversion result ID is unexpected/duplicate.'
        }
        if ([Int64](Get-I05RequiredProperty -Object $result `
                -Name 'bytes' -Context 'PktMon conversion result') -lt 1) {
            throw 'PktMon component conversion produced no PCAPNG bytes.'
        }
        $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
            -Object $result -Name 'sha256' `
            -Context 'PktMon conversion result') `
            -Context 'PktMon conversion result hash'
        $parserValid = Get-I05RequiredProperty -Object $result `
            -Name 'parser_valid' -Context 'PktMon conversion result'
        $exactFlow = Get-I05RequiredProperty -Object $result `
            -Name 'exact_peer_flow' -Context 'PktMon conversion result'
        $retained = Get-I05RequiredProperty -Object $result `
            -Name 'retained' -Context 'PktMon conversion result'
        if ($parserValid -isnot [bool] -or $exactFlow -isnot [bool] -or
            $retained -isnot [bool]) {
            throw 'PktMon conversion result flags are not JSON booleans.'
        }
        if ([bool]$exactFlow) { ++$flowHitCount }
        if ([bool]$retained) {
            ++$retainedCount
            if ($resultId -ne [Int64]$capture.converted_component_id -or
                -not [bool]$exactFlow -or -not [bool]$parserValid) {
                throw 'PktMon retained conversion is not the unique hit.'
            }
        }
    }
    if ($flowHitCount -ne 1 -or $retainedCount -ne 1) {
        throw 'PktMon component conversion did not yield exactly one hit.'
    }
    foreach ($flag in @(
        'session_stopped',
        'filters_restored'
    )) {
        Assert-I05True -Value (Get-I05RequiredProperty `
            -Object $statusEvidence -Name $flag `
            -Context 'PktMon status evidence') `
            -Context "PktMon status $flag"
    }
    if ([Int64](Get-I05RequiredProperty -Object $statusEvidence `
            -Name 'command_log_bytes' `
            -Context 'PktMon status evidence') -ne
            [Int64]$rawByKind['pktmon_log'].bytes) {
        throw 'PktMon retained command-log length differs from status.'
    }
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $statusEvidence -Name 'command_log_sha256' `
        -Context 'PktMon status evidence')) `
        -Expected $rawByKind['pktmon_log'].sha256 `
        -Context 'PktMon retained command-log hash' -IgnoreCase
    if ([Int64](Get-I05RequiredProperty -Object $statusEvidence `
            -Name 'counters_bytes' `
            -Context 'PktMon status evidence') -lt 1) {
        throw 'PktMon raw counter report is empty.'
    }
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $statusEvidence -Name 'counters_sha256' `
        -Context 'PktMon status evidence') `
        -Context 'PktMon raw counter-report hash'
    foreach ($artifact in @(
        [pscustomobject]@{
            prefix = 'etl'; raw_kind = 'etl'
        },
        [pscustomobject]@{
            prefix = 'pcapng'; raw_kind = 'pcapng'
        },
        [pscustomobject]@{
            prefix = 'transfer_samples'; raw_kind = 'transfer_samples'
        }
    )) {
        if ([Int64](Get-I05RequiredProperty -Object $statusEvidence `
                -Name "$($artifact.prefix)_bytes" `
                -Context 'PktMon status evidence') -ne
            [Int64]$rawByKind[$artifact.raw_kind].bytes) {
            throw "Retained $($artifact.raw_kind) length differs from status."
        }
        Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
            -Object $statusEvidence `
            -Name "$($artifact.prefix)_sha256" `
            -Context 'PktMon status evidence')) `
            -Expected $rawByKind[$artifact.raw_kind].sha256 `
            -Context "Retained $($artifact.raw_kind) hash" -IgnoreCase
    }
    if ([Int64]$rawByKind['etl'].bytes -ne
            [Int64](Get-I05RequiredProperty -Object $capture `
                -Name 'etl_bytes' -Context 'COMPLETE.capture') -or
        [Int64]$rawByKind['pcapng'].bytes -ne
            [Int64](Get-I05RequiredProperty -Object $capture `
                -Name 'pcap_bytes' -Context 'COMPLETE.capture')) {
        throw 'Retained ETL/PCAP lengths differ from COMPLETE.'
    }
    Assert-I05ExactText -Actual $rawByKind['transfer_samples'].sha256 `
        -Expected ([string](Get-I05RequiredProperty `
            -Object (Get-I05RequiredProperty -Object $Complete `
                -Name 'evidence' -Context 'COMPLETE') `
            -Name 'samples_sha256' -Context 'COMPLETE.evidence')) `
        -Context 'Transfer samples COMPLETE hash' -IgnoreCase
    foreach ($field in @(
        'candidate_status_ready_sha256',
        'candidate_status_final_sha256'
    )) {
        $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
            -Object $statusEvidence -Name $field `
            -Context 'PktMon status evidence') `
            -Context "PktMon status $field"
    }
    $candidateNetworks = Get-I05RequiredProperty `
        -Object $statusEvidence -Name 'candidate_networks' `
        -Context 'PktMon status evidence'
    try {
        Assert-I05ApiNetworksOff -Status $candidateNetworks `
            -Context 'PktMon candidate networks'
    } catch {
        Throw-I05SourceProductInvariant `
            -Category 'h3-network-state-evidence' `
            -Message $_.Exception.Message
    }

    return [pscustomobject][ordered]@{
        status = 'PASS'
        bundle_path = $bundlePath
        extract_root = $extractRoot
        bytes = $reportedBytes
        sha256 = $reportedSha256
        manifest_sha256 = $manifestSha256
        entry_count = $allowedNames.Count
        retained_raw_count = $requiredRawKinds.Count
        observed_ephemeral_ports = $outerPorts
    }
}

function Assert-I05SourceCompleteFileProduct {
    param(
        [Parameter(Mandatory = $true)][object]$DestinationBytes,
        [Parameter(Mandatory = $true)][string]$DestinationSha256,
        [Parameter(Mandatory = $true)][string]$Ed2k,
        [Parameter(Mandatory = $true)][string]$Ed2kSource,
        [Parameter(Mandatory = $true)][object]$CompleteFlag
    )

    try {
        if ([Int64]$DestinationBytes -ne $constants.fixture_bytes) {
            throw 'COMPLETE destination length is not exactly 4 GiB.'
        }
        Assert-I05ExactText -Actual $DestinationSha256 `
            -Expected $constants.fixture_sha256 `
            -Context 'COMPLETE destination SHA-256' -IgnoreCase
        Assert-I05ExactText -Actual $Ed2k `
            -Expected $constants.fixture_ed2k `
            -Context 'COMPLETE ED2K' -IgnoreCase
        Assert-I05ExactText -Actual $Ed2kSource `
            -Expected 'local-streaming-calculation' `
            -Context 'COMPLETE ED2K source'
        Assert-I05True -Value $CompleteFlag `
            -Context 'COMPLETE file completion'
    } catch {
        if ($_.Exception.Data.Contains('I05Classification')) {
            throw
        }
        Throw-I05SourceProductInvariant `
            -Category 'h3-file-integrity-complete' `
            -Message $_.Exception.Message
    }
}

function Assert-I05SourceCompleteNodeProduct {
    param(
        [Parameter(Mandatory = $true)][object]$ProcessId,
        [Parameter(Mandatory = $true)][object]$ExpectedProcessId,
        [Parameter(Mandatory = $true)][object]$IPv6Mode,
        [Parameter(Mandatory = $true)][object]$KadNetworkMask,
        [Parameter(Mandatory = $true)][object]$Networks,
        [Parameter(Mandatory = $true)][object]$ApiResponsive,
        [Parameter(Mandatory = $true)][object]$TcpListenerOwned
    )

    try {
        if ([Int64]$ProcessId -ne [Int64]$ExpectedProcessId) {
            throw 'COMPLETE H3 PID differs from READY.'
        }
        if ([Int64]$IPv6Mode -ne 0) {
            throw 'COMPLETE H3 IPv6Mode is not zero.'
        }
        if ([Int64]$KadNetworkMask -ne 0) {
            throw 'COMPLETE H3 KadNetworkMask is not zero.'
        }
        Assert-I05ApiNetworksOff -Status $Networks `
            -Context 'COMPLETE.node'
        Assert-I05True -Value $ApiResponsive `
            -Context 'COMPLETE H3 API responsiveness'
        Assert-I05True -Value $TcpListenerOwned `
            -Context 'COMPLETE H3 listener ownership'
    } catch {
        if ($_.Exception.Data.Contains('I05Classification')) {
            throw
        }
        Throw-I05SourceProductInvariant `
            -Category 'h3-node-state-complete' `
            -Message $_.Exception.Message
    }
}

function Assert-I05SourceCompleteWireProduct {
    param(
        [Parameter(Mandatory = $true)][object]$SocketForbiddenTupleCount,
        [Parameter(Mandatory = $true)][object]$RequestPartsI64,
        [Parameter(Mandatory = $true)][object]$Compressed32,
        [Parameter(Mandatory = $true)][object]$SendingI64,
        [Parameter(Mandatory = $true)][object]$CompressedI64,
        [Parameter(Mandatory = $true)][object]$Ed2kFramingValid,
        [Parameter(Mandatory = $true)][object]$AllowedOpcodesOnly
    )

    try {
        if ([Int64]$SocketForbiddenTupleCount -ne 0) {
            throw 'COMPLETE socket proof contains a forbidden peer tuple.'
        }
        if ([Int64]$RequestPartsI64 -le 0) {
            throw 'COMPLETE capture has no OP_REQUESTPARTS_I64 frame.'
        }
        if ([Int64]$Compressed32 -lt 0 -or
            [Int64]$SendingI64 -lt 0 -or
            [Int64]$CompressedI64 -lt 0 -or
            ([Int64]$Compressed32 + [Int64]$SendingI64 +
                [Int64]$CompressedI64) -le 0) {
            throw 'COMPLETE capture has no valid data response frame.'
        }
        Assert-I05True -Value $Ed2kFramingValid `
            -Context 'COMPLETE capture ed2k_framing_valid'
        Assert-I05True -Value $AllowedOpcodesOnly `
            -Context 'COMPLETE capture allowed_opcodes_only'
    } catch {
        if ($_.Exception.Data.Contains('I05Classification')) {
            throw
        }
        Throw-I05SourceProductInvariant `
            -Category 'h3-wire-invariant-complete' `
            -Message $_.Exception.Message
    }
}

function Assert-I05SourceRemoteComplete {
    param(
        [Parameter(Mandatory = $true)][object]$Complete,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][object]$Remote,
        [Parameter(Mandatory = $true)][string]$SourceIPv4,
        [Parameter(Mandatory = $true)][int[]]$ObservedRemotePorts,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot
    )

    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Complete -Name 'schema' -Context 'COMPLETE')) `
        -Expected 'ese.v91.i05.t1-complete/v1' `
        -Context 'COMPLETE schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $Complete -Name 'status' -Context 'COMPLETE')) `
        -Expected 'PASS' -Context 'COMPLETE status'
    Assert-I05ExactText -Actual (
        Assert-I05Nonce -Value (Get-I05RequiredProperty `
            -Object $Complete -Name 'nonce' -Context 'COMPLETE') `
            -Context 'COMPLETE nonce'
    ) -Expected $Nonce -Context 'COMPLETE nonce'
    Assert-I05CandidateContract -Candidate (Get-I05RequiredProperty `
        -Object $Complete -Name 'candidate' -Context 'COMPLETE') `
        -Context 'COMPLETE.candidate'
    $file = Get-I05RequiredProperty -Object $Complete `
        -Name 'file' -Context 'COMPLETE'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $file -Name 'name' -Context 'COMPLETE.file')) `
        -Expected $constants.fixture_name -Context 'COMPLETE file name'
    $destinationBytes = Get-I05RequiredProperty -Object $file `
        -Name 'destination_bytes' -Context 'COMPLETE.file'
    $destinationSha256 = [string](Get-I05RequiredProperty `
        -Object $file -Name 'destination_sha256' `
        -Context 'COMPLETE.file')
    $destinationEd2k = [string](Get-I05RequiredProperty `
        -Object $file -Name 'ed2k' -Context 'COMPLETE.file')
    $destinationEd2kSource = [string](Get-I05RequiredProperty `
        -Object $file -Name 'ed2k_source' -Context 'COMPLETE.file')
    $destinationComplete = Get-I05RequiredProperty -Object $file `
        -Name 'complete' -Context 'COMPLETE.file'
    Assert-I05SourceCompleteFileProduct `
        -DestinationBytes $destinationBytes `
        -DestinationSha256 $destinationSha256 `
        -Ed2k $destinationEd2k `
        -Ed2kSource $destinationEd2kSource `
        -CompleteFlag $destinationComplete
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $file -Name 'integrity_sha256' `
        -Context 'COMPLETE.file') `
        -Context 'COMPLETE file-integrity artifact hash'
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $file -Name 'calculation_report_sha256' `
        -Context 'COMPLETE.file') `
        -Context 'COMPLETE local calculation-report hash'

    $node = Get-I05RequiredProperty -Object $Complete `
        -Name 'node' -Context 'COMPLETE'
    $completeProcessId = Get-I05RequiredProperty -Object $node `
        -Name 'process_id' -Context 'COMPLETE.node'
    $completeIPv6Mode = Get-I05RequiredProperty -Object $node `
        -Name 'ipv6_mode' -Context 'COMPLETE.node'
    $completeKadNetworkMask = Get-I05RequiredProperty -Object $node `
        -Name 'kad_network_mask' -Context 'COMPLETE.node'
    $completeApiResponsive = Get-I05RequiredProperty -Object $node `
        -Name 'api_responsive' -Context 'COMPLETE.node'
    $completeTcpListenerOwned = Get-I05RequiredProperty -Object $node `
        -Name 'tcp_listener_owned' -Context 'COMPLETE.node'
    Assert-I05SourceCompleteNodeProduct `
        -ProcessId $completeProcessId `
        -ExpectedProcessId $Remote.process_id `
        -IPv6Mode $completeIPv6Mode `
        -KadNetworkMask $completeKadNetworkMask `
        -Networks $node `
        -ApiResponsive $completeApiResponsive `
        -TcpListenerOwned $completeTcpListenerOwned

    $socketProof = Get-I05RequiredProperty -Object $Complete `
        -Name 'socket_proof' -Context 'COMPLETE'
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $socketProof -Name 'sha256' `
        -Context 'COMPLETE.socket_proof') `
        -Context 'COMPLETE socket-proof artifact hash'
    if ([int](Get-I05RequiredProperty -Object $socketProof `
            -Name 'candidate_pid' `
            -Context 'COMPLETE.socket_proof') -ne $Remote.process_id) {
        throw 'COMPLETE socket-proof PID differs from READY.'
    }
    $socketUniqueTupleCount = Get-I05RequiredProperty `
        -Object $socketProof -Name 'unique_tuple_count' `
        -Context 'COMPLETE.socket_proof'
    $socketSampleCount = Get-I05RequiredProperty `
        -Object $socketProof -Name 'sample_count' `
        -Context 'COMPLETE.socket_proof'
    $socketForbiddenTupleCount = Get-I05RequiredProperty `
        -Object $socketProof -Name 'forbidden_tuple_count' `
        -Context 'COMPLETE.socket_proof'
    if ([Int64]$socketUniqueTupleCount -lt 1 -or
        [Int64]$socketSampleCount -lt 1) {
        throw 'COMPLETE socket proof is empty.'
    }
    $null = Get-I05SourceCanonicalPortArray -Owner $socketProof `
        -Name 'observed_ephemeral_ports' `
        -Context 'COMPLETE.socket_proof'
    if ($null -eq $socketProof.PSObject.Properties['stable_tuple']) {
        throw 'COMPLETE socket proof is missing stable_tuple.'
    }
    $route = Get-I05RequiredProperty -Object $Complete `
        -Name 'route' -Context 'COMPLETE'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $route -Name 'family' -Context 'COMPLETE.route')) `
        -Expected 'IPv4' -Context 'COMPLETE route family'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $route `
        -Name 'physical' -Context 'COMPLETE.route') `
        -Context 'COMPLETE physical route'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $route `
        -Name 'on_link' -Context 'COMPLETE.route') `
        -Context 'COMPLETE on-link route'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $route -Name 'interface_id' -Context 'COMPLETE.route')) `
        -Expected $Remote.interface_id `
        -Context 'COMPLETE route interface'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $route -Name 'source_address_sha256' `
        -Context 'COMPLETE.route')) `
        -Expected $Remote.ipv4_address_sha256 `
        -Context 'COMPLETE route source-address hash' -IgnoreCase

    $capture = Get-I05RequiredProperty -Object $Complete `
        -Name 'capture' -Context 'COMPLETE'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $capture -Name 'backend' -Context 'COMPLETE.capture')) `
        -Expected 'pktmon' -Context 'COMPLETE capture backend' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $capture -Name 'status' -Context 'COMPLETE.capture')) `
        -Expected 'PASS' -Context 'COMPLETE capture status'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $capture -Name 'interface_id' `
        -Context 'COMPLETE.capture')) `
        -Expected $Remote.interface_id `
        -Context 'COMPLETE capture interface'
    if ([Int64](Get-I05RequiredProperty -Object $capture `
            -Name 'candidate_pid' -Context 'COMPLETE.capture') -ne
        [Int64]$Remote.process_id) {
        throw 'COMPLETE capture candidate PID context differs from READY.'
    }
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $capture -Name 'candidate_pid_role' `
        -Context 'COMPLETE.capture')) `
        -Expected 'socket-watchdog-context-only' `
        -Context 'COMPLETE capture candidate PID role'
    Assert-I05False -Value (Get-I05RequiredProperty -Object $capture `
        -Name 'pcap_pid_attributed' -Context 'COMPLETE.capture') `
        -Context 'COMPLETE PCAP PID attribution prohibition'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $capture `
        -Name 'tuple_allowlist_pid_observed' `
        -Context 'COMPLETE.capture') `
        -Context 'COMPLETE tuple allowlist socket observation'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $capture `
        -Name 'process_scoped_containment' `
        -Context 'COMPLETE.capture') `
        -Context 'COMPLETE process-scoped containment'
    if ([int](Get-I05RequiredProperty -Object $capture `
            -Name 'packet_size' -Context 'COMPLETE.capture') -ne
        $constants.capture_packet_size) {
        throw 'COMPLETE capture used the wrong bounded packet size.'
    }
    Assert-I05True -Value (Get-I05RequiredProperty -Object $capture `
        -Name 'physical_interface' -Context 'COMPLETE.capture') `
        -Context 'COMPLETE physical capture interface'
    if ([Int64](Get-I05RequiredProperty -Object $capture `
            -Name 'primary_component_id' `
            -Context 'COMPLETE.capture') -ne
        [Int64]$Remote.primary_component_id) {
        throw 'COMPLETE primary component ID differs from READY.'
    }
    $convertedComponentId = [Int64](Get-I05RequiredProperty `
        -Object $capture -Name 'converted_component_id' `
        -Context 'COMPLETE.capture')
    $allowedComponentIds = @(
        [Int64]$Remote.primary_component_id
    ) + @($Remote.secondary_component_ids | ForEach-Object {
        [Int64]$_
    })
    if ($allowedComponentIds -notcontains $convertedComponentId -or
        [int](Get-I05RequiredProperty -Object $capture `
            -Name 'conversion_hit_count' `
            -Context 'COMPLETE.capture') -ne 1) {
        throw 'COMPLETE component-filtered conversion is not unique.'
    }
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $capture -Name 'component_mapping_sha256' `
        -Context 'COMPLETE.capture') `
        -Context 'COMPLETE component-mapping artifact hash'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $capture -Name 'mapping_key_sha256' `
        -Context 'COMPLETE.capture')) `
        -Expected $Remote.mapping_key_sha256 `
        -Context 'COMPLETE component mapping key' -IgnoreCase
    Assert-I05True -Value (Get-I05RequiredProperty -Object $capture `
        -Name 'physical_component_guid_match' `
        -Context 'COMPLETE.capture') `
        -Context 'COMPLETE physical component GUID mapping'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $capture `
        -Name 'tuple_exact' -Context 'COMPLETE.capture') `
        -Context 'COMPLETE exact tuple correlation'
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $capture -Name 'analysis_sha256' `
        -Context 'COMPLETE.capture') `
        -Context 'COMPLETE capture analysis hash'
    $requestPartsI64 = Get-I05RequiredProperty -Object $capture `
        -Name 'requestparts_i64' -Context 'COMPLETE.capture'
    $compressed32 = Get-I05RequiredProperty -Object $capture `
        -Name 'compressedpart_32' -Context 'COMPLETE.capture'
    $sendingI64 = Get-I05RequiredProperty -Object $capture `
        -Name 'sending_i64' -Context 'COMPLETE.capture'
    $compressedI64 = Get-I05RequiredProperty -Object $capture `
        -Name 'compressed_i64' -Context 'COMPLETE.capture'
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $capture -Name 'pcap_sha256' `
        -Context 'COMPLETE.capture') -Context 'COMPLETE capture hash'
    $ipv4PeerPackets = Get-I05RequiredProperty -Object $capture `
        -Name 'ipv4_peer_packets' -Context 'COMPLETE.capture'
    $ipv6PeerPackets = Get-I05RequiredProperty -Object $capture `
        -Name 'ipv6_peer_packets' -Context 'COMPLETE.capture'
    $rejectedPeerTuplePackets = Get-I05RequiredProperty `
        -Object $capture -Name 'rejected_peer_tuple_packets' `
        -Context 'COMPLETE.capture'
    $thirdPartyPeerPackets = Get-I05RequiredProperty `
        -Object $capture -Name 'third_party_peer_packets' `
        -Context 'COMPLETE.capture'
    Assert-I05True -Value (Get-I05RequiredProperty -Object $capture `
        -Name 'capture_complete' -Context 'COMPLETE.capture') `
        -Context 'COMPLETE capture completeness'
    Assert-I05False -Value (Get-I05RequiredProperty -Object $capture `
        -Name 'packet_loss_detected' -Context 'COMPLETE.capture') `
        -Context 'COMPLETE capture packet-loss state'
    foreach ($proof in @(
        'filter_scope_exact',
        'etl_loss_proved_zero',
        'etl_below_file_limit',
        'pcap_parsed',
        'filters_absent_after',
        'etw_session_absent_after',
        'filter_inventory_restored'
    )) {
        Assert-I05True -Value (Get-I05RequiredProperty `
            -Object $capture -Name $proof `
            -Context 'COMPLETE.capture') `
            -Context "COMPLETE capture $proof"
    }
    if ([Int64]$ipv4PeerPackets -le 0 -or
        [Int64]$ipv6PeerPackets -ne 0 -or
        [Int64]$rejectedPeerTuplePackets -ne 0 -or
        [Int64]$thirdPartyPeerPackets -ne 0) {
        Throw-I05SourceLabBlocked `
            -Category 'h3-pcap-fixture-not-adjudicable' `
            -Message (
                'COMPLETE capture lacks an exact clean physical IPv4 peer ' +
                'fixture; raw PCAP counters are not PID attribution.'
            )
    }
    $ed2kFramingValid = Get-I05RequiredProperty -Object $capture `
        -Name 'ed2k_framing_valid' -Context 'COMPLETE.capture'
    $allowedOpcodesOnly = Get-I05RequiredProperty -Object $capture `
        -Name 'allowed_opcodes_only' -Context 'COMPLETE.capture'
    Assert-I05SourceCompleteWireProduct `
        -SocketForbiddenTupleCount $socketForbiddenTupleCount `
        -RequestPartsI64 $requestPartsI64 `
        -Compressed32 $compressed32 `
        -SendingI64 $sendingI64 `
        -CompressedI64 $compressedI64 `
        -Ed2kFramingValid $ed2kFramingValid `
        -AllowedOpcodesOnly $allowedOpcodesOnly

    $bundle = Get-I05RequiredProperty -Object $Complete `
        -Name 'evidence_bundle' -Context 'COMPLETE'
    return Import-I05SourceEvidenceBundle -Bundle $bundle `
        -Complete $Complete -Remote $Remote -SourceIPv4 $SourceIPv4 `
        -Nonce $Nonce -ObservedRemotePorts $ObservedRemotePorts `
        -EvidenceRoot $EvidenceRoot
}

function Write-I05SourceSample {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Value
    )

    $encoding = New-Object Text.UTF8Encoding($false)
    $writer = New-Object IO.StreamWriter($Path, $true, $encoding)
    try {
        $writer.WriteLine(($Value | ConvertTo-Json -Depth 12 -Compress))
    } finally {
        $writer.Dispose()
    }
}

function Get-I05SourceBytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash($Bytes))).Replace('-', '').
            ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Read-I05SourceControlLine {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [ValidateRange(32, 4096)][int]$MaximumBytes = 512
    )

    if ($Stream.CanTimeout) {
        $Stream.ReadTimeout = $TimeoutSeconds * 1000
    }
    $bytes = [Collections.Generic.List[byte]]::new()
    while ($bytes.Count -lt $MaximumBytes) {
        $value = $Stream.ReadByte()
        if ($value -lt 0) {
            throw 'H3 closed the physical control stream.'
        }
        if ($value -eq 10) {
            $lineBytes = $bytes.ToArray()
            $line = [Text.Encoding]::ASCII.GetString($lineBytes)
            return $line.TrimEnd([char]13)
        }
        if ($value -gt 127) {
            throw 'H3 control header is not strict ASCII.'
        }
        $bytes.Add([byte]$value)
    }
    throw 'H3 control header exceeds the bounded length.'
}

function Write-I05SourceControlLine {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][string]$Line
    )

    if ($Line.Contains("`r") -or $Line.Contains("`n") -or
        $Line -notmatch '^[\x20-\x7e]+$') {
        throw 'Control line must be one strict printable-ASCII line.'
    }
    $bytes = [Text.Encoding]::ASCII.GetBytes($Line + "`n")
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Read-I05SourceControlFrame {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)]
        [ValidateSet('READY', 'STARTED', 'COMPLETE', 'CLEANUP')]
        [string]$Type,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $line = Read-I05SourceControlLine -Stream $Stream `
        -TimeoutSeconds $TimeoutSeconds
    $pattern = '^V91-I05-(READY|STARTED|COMPLETE|CLEANUP|FAILURE)' +
        ' ([0-9a-f]{32}) ([1-9][0-9]{0,6}) ([0-9a-f]{64})$'
    $match = [regex]::Match(
        $line, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) {
        throw "H3 $Type frame header is invalid."
    }
    $actualType = $match.Groups[1].Value
    if ($actualType -ne $Type -and $actualType -ne 'FAILURE') {
        throw "H3 sent $actualType while H1 expected $Type."
    }
    Assert-I05ExactText -Actual $match.Groups[2].Value `
        -Expected $Nonce -Context "H3 $Type frame nonce"
    $length = [int]$match.Groups[3].Value
    if ($length -gt 1048576) {
        throw "H3 $actualType frame exceeds 1 MiB."
    }
    $expectedSha256 = $match.Groups[4].Value
    $body = New-Object byte[] $length
    $offset = 0
    if ($Stream.CanTimeout) {
        $Stream.ReadTimeout = $TimeoutSeconds * 1000
    }
    while ($offset -lt $length) {
        $read = $Stream.Read($body, $offset, $length - $offset)
        if ($read -le 0) {
            throw "H3 closed the stream inside the $actualType body."
        }
        $offset += $read
    }
    $actualSha256 = Get-I05SourceBytesSha256 -Bytes $body
    Assert-I05ExactText -Actual $actualSha256 `
        -Expected $expectedSha256 `
        -Context "H3 $actualType frame SHA-256" `
        -IgnoreCase
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $raw = $utf8.GetString($body)
    $document = $raw | ConvertFrom-Json
    if ($null -eq $document -or $document -is [Array]) {
        throw "H3 $actualType frame is not one JSON object."
    }
    return [pscustomobject][ordered]@{
        type = $actualType
        raw = $raw
        document = $document
        bytes = $length
        sha256 = $actualSha256
    }
}

function Assert-I05SourceExpectedFrame {
    param(
        [Parameter(Mandatory = $true)][object]$Frame,
        [Parameter(Mandatory = $true)]
        [ValidateSet('READY', 'STARTED', 'COMPLETE', 'CLEANUP')]
        [string]$ExpectedType,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [IO.Stream]$Stream = $null
    )

    if ([string]$Frame.type -eq $ExpectedType) {
        return
    }
    if ([string]$Frame.type -ne 'FAILURE') {
        throw "H3 sent an unsupported frame while expecting $ExpectedType."
    }
    $failure = $Frame.document
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $failure -Name 'schema' -Context 'FAILURE')) `
        -Expected 'ese.v91.i05.t1-failure/v1' `
        -Context 'FAILURE schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $failure -Name 'case_id' -Context 'FAILURE')) `
        -Expected $constants.case_id -Context 'FAILURE case'
    $classification = [string](Get-I05RequiredProperty `
        -Object $failure -Name 'status' -Context 'FAILURE')
    if ($classification -notin @('LAB_BLOCKED', 'PRODUCT_INVARIANT')) {
        throw 'FAILURE status is not a supported formal classification.'
    }
    Assert-I05ExactText -Actual (
        Assert-I05Nonce -Value (Get-I05RequiredProperty `
            -Object $failure -Name 'nonce' -Context 'FAILURE') `
            -Context 'FAILURE nonce'
    ) -Expected $Nonce -Context 'FAILURE nonce'
    $phase = [string](Get-I05RequiredProperty -Object $failure `
        -Name 'phase' -Context 'FAILURE')
    $category = [string](Get-I05RequiredProperty -Object $failure `
        -Name 'category' -Context 'FAILURE')
    if ($phase -notmatch '^[a-z0-9][a-z0-9._-]{0,63}$' -or
        $category -notmatch '^[a-z0-9][a-z0-9._-]{0,63}$') {
        throw 'FAILURE phase/category is not canonical.'
    }
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $failure -Name 'message_sha256' -Context 'FAILURE') `
        -Context 'FAILURE message hash'
    $cleanup = Get-I05RequiredProperty -Object $failure `
        -Name 'cleanup' -Context 'FAILURE'
    $attempted = Get-I05RequiredProperty -Object $cleanup `
        -Name 'attempted' -Context 'FAILURE.cleanup'
    $complete = Get-I05RequiredProperty -Object $cleanup `
        -Name 'complete' -Context 'FAILURE.cleanup'
    if ($attempted -isnot [bool] -or $complete -isnot [bool]) {
        throw 'FAILURE cleanup flags must be JSON booleans.'
    }
    $cleanupStatus = [string](Get-I05RequiredProperty `
        -Object $cleanup -Name 'status' -Context 'FAILURE.cleanup')
    if ($cleanupStatus -notin @(
        'CLEANUP_COMPLETE', 'FAILED', 'NOT_ATTEMPTED'
    )) {
        throw 'FAILURE cleanup status is invalid.'
    }
    $errorProperty = $cleanup.PSObject.Properties['error_sha256']
    if ($null -eq $errorProperty) {
        throw "FAILURE.cleanup is missing required property 'error_sha256'."
    }
    if ($cleanupStatus -eq 'CLEANUP_COMPLETE') {
        if (-not [bool]$attempted -or -not [bool]$complete -or
            $null -ne $errorProperty.Value) {
            throw 'FAILURE completed cleanup fields are inconsistent.'
        }
    } elseif ($cleanupStatus -eq 'FAILED') {
        if (-not [bool]$attempted -or [bool]$complete) {
            throw 'FAILURE failed-cleanup fields are inconsistent.'
        }
        $null = Assert-I05Sha256 -Value $errorProperty.Value `
            -Context 'FAILURE cleanup error hash'
    } else {
        if ([bool]$attempted -or [bool]$complete -or
            $null -ne $errorProperty.Value) {
            throw 'FAILURE not-attempted cleanup fields are inconsistent.'
        }
    }
    $script:remoteFailureClassification = $classification
    $script:remoteFailurePhase = $phase
    if ($null -ne $Stream) {
        Confirm-I05SourceControlFrame -Stream $Stream `
            -Frame $Frame -Nonce $Nonce
    }
    throw (New-I05SourceClassifiedException `
        -Classification $classification -Category $category `
        -Message (
            "H3 reported $classification during $phase ($category)."
        ))
}

function Confirm-I05SourceControlFrame {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][object]$Frame,
        [Parameter(Mandatory = $true)][string]$Nonce
    )

    Write-I05SourceControlLine -Stream $Stream -Line (
        "V91-I05-$($Frame.type)-ACCEPTED $Nonce $($Frame.sha256)"
    )
}

function Send-I05SourceControlFrame {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)]
        [ValidateSet('COMMAND', 'STOP')][string]$Type,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $raw = $Value | ConvertTo-Json -Depth 32
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $body = $utf8.GetBytes($raw)
    if ($body.Length -lt 1 -or $body.Length -gt 1048576) {
        throw "$Type JSON body is outside 1..1048576 bytes."
    }
    $sha256 = Get-I05SourceBytesSha256 -Bytes $body
    Write-I05SourceControlLine -Stream $Stream -Line (
        "V91-I05-$Type $Nonce $($body.Length) $sha256"
    )
    $Stream.Write($body, 0, $body.Length)
    $Stream.Flush()
    $ack = Read-I05SourceControlLine -Stream $Stream `
        -TimeoutSeconds $TimeoutSeconds
    Assert-I05ExactText -Actual $ack -Expected (
        "V91-I05-$Type-ACCEPTED $Nonce $sha256"
    ) -Context "H3 $Type acknowledgement"
    return [pscustomobject][ordered]@{
        raw = $raw
        bytes = $body.Length
        sha256 = $sha256
    }
}

function Connect-I05SourceControl {
    param(
        [Parameter(Mandatory = $true)][string]$LocalIPv4,
        [Parameter(Mandatory = $true)][string]$RemoteIPv4,
        [Parameter(Mandatory = $true)][int]$RemotePort,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastError = ''
    do {
        $client = New-Object Net.Sockets.TcpClient(
            [Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $client.NoDelay = $true
            $client.Client.SetSocketOption(
                [Net.Sockets.SocketOptionLevel]::Socket,
                [Net.Sockets.SocketOptionName]::KeepAlive, $true)
            $localEndpoint = New-Object Net.IPEndPoint(
                ([Net.IPAddress]::Parse($LocalIPv4)), 0)
            $client.Client.Bind($localEndpoint)
            $task = $client.ConnectAsync($RemoteIPv4, $RemotePort)
            if (-not $task.Wait(3000)) {
                throw 'bounded connect attempt timed out'
            }
            if (-not $client.Connected) {
                throw 'connect task completed without a connection'
            }
            $actualLocal =
                [Net.IPEndPoint]$client.Client.LocalEndPoint
            $actualRemote =
                [Net.IPEndPoint]$client.Client.RemoteEndPoint
            Assert-I05ExactText `
                -Actual $actualLocal.Address.ToString() `
                -Expected $LocalIPv4 `
                -Context 'H1 control local address'
            Assert-I05ExactText `
                -Actual $actualRemote.Address.ToString() `
                -Expected $RemoteIPv4 `
                -Context 'H3 control remote address'
            if ($actualRemote.Port -ne $RemotePort) {
                throw 'H3 control remote port changed.'
            }
            return $client
        } catch {
            $lastError = $_.Exception.Message
            try { $client.Close() } catch {}
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Could not reach H3 physical control listener: $lastError"
}

function Save-I05SourceControlFrame {
    param(
        [Parameter(Mandatory = $true)][object]$Frame,
        [Parameter(Mandatory = $true)][string]$FileName
    )

    $privatePath = Join-Path $private $FileName
    $coordinationPath = Join-Path $exchange $FileName
    $null = Write-LabText -Value $Frame.raw -Path $privatePath
    $null = Write-LabText -Value $Frame.raw -Path $coordinationPath
}

if ($env:ESE_V91_I05_SOURCE_LIBRARY_ONLY -ceq '1') {
    return
}

try {
    $expectedFixtureHash =
        $ExpectedFixtureSha256.ToLowerInvariant()
    Assert-I05ExactText -Actual $expectedFixtureHash `
        -Expected $constants.fixture_sha256 `
        -Context 'Expected canonical fixture SHA-256' -IgnoreCase

    if (-not (Test-Path -LiteralPath $CandidateZipPath -PathType Leaf)) {
        throw 'Exact RC3 candidate ZIP does not exist.'
    }
    $candidateZip = Assert-I05SourceNoReparsePoint `
        -Path (Resolve-Path -LiteralPath $CandidateZipPath).Path `
        -Context 'Exact RC3 candidate ZIP'
    if ([Int64]$candidateZip.Length -ne
        $constants.candidate_zip_bytes) {
        throw 'RC3 candidate ZIP has the wrong exact byte length.'
    }
    Assert-I05ExactText -Actual (
        Get-LabSha256 -Path $candidateZip.FullName
    ) -Expected $constants.candidate_zip_sha256 `
        -Context 'RC3 candidate ZIP SHA-256' -IgnoreCase

    $candidateObject = [ordered]@{
        version = $constants.candidate_version
        commit = $constants.candidate_commit
        dirty = $false
        emule_sha256 = $constants.candidate_emule_sha256
        ese_server_sha256 =
            $constants.candidate_ese_server_sha256
        build_info_sha256 =
            $constants.candidate_build_info_sha256
        zip_sha256 = $constants.candidate_zip_sha256
        zip_bytes = $constants.candidate_zip_bytes
    }

    if (-not (Test-Path -LiteralPath $FixturePath -PathType Leaf)) {
        throw 'Canonical external fixture does not exist.'
    }
    $fixtureItem = Assert-I05SourceNoReparsePoint `
        -Path (Resolve-Path -LiteralPath $FixturePath).Path `
        -Context 'Canonical external fixture'
    if ([Int64]$fixtureItem.Length -ne $constants.fixture_bytes) {
        throw 'Canonical fixture length is not exactly 4294967296 bytes.'
    }
    $actualFixtureHash = Get-LabSha256 -Path $fixtureItem.FullName
    Assert-I05ExactText -Actual $actualFixtureHash `
        -Expected $constants.fixture_sha256 `
        -Context 'Canonical fixture SHA-256' -IgnoreCase

    if (-not (Test-Path -LiteralPath $RunBase -PathType Container)) {
        throw 'RunBase must already exist as a local NTFS directory.'
    }
    $base = (Resolve-Path -LiteralPath $RunBase).Path
    $null = Assert-I05SourceNoReparsePoint `
        -Path $base -Context 'RunBase'
    $baseRoot = [IO.Path]::GetPathRoot($base)
    $fixtureRoot = [IO.Path]::GetPathRoot($fixtureItem.FullName)
    if ($baseRoot -notmatch '^[A-Za-z]:\\$' -or
        -not [string]::Equals(
            $baseRoot, $fixtureRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw (
            'RunBase and the external fixture must be on the same local ' +
            'volume so the isolated source can use a hardlink.'
        )
    }
    $volume = Get-Volume -DriveLetter $baseRoot.Substring(0, 1) `
        -ErrorAction Stop
    if (-not [string]::Equals(
            [string]$volume.FileSystem, 'NTFS',
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'RunBase volume is not NTFS.'
    }
    if ([Int64]$volume.SizeRemaining -lt 1073741824) {
        throw 'RunBase volume has less than 1 GiB free for node evidence.'
    }

    $network = Get-I05SourceNetwork -RequestedIPv4 $SourceIPv4
    $h3Address = ConvertTo-I05CanonicalIPv4 -Value $H3IPv4 `
        -Context 'H3 physical IPv4'
    if ((Get-LabAddressClass -Address $h3Address) -ne 'private-v4' -or
        $h3Address -eq $network.ipv4_address -or
        -not (Test-I05Ipv4SameSubnet -Left $network.ipv4_address `
            -Right $h3Address `
            -PrefixLength $network.ipv4_prefix_length)) {
        throw (
            'H3IPv4 must be a distinct RFC1918 address on the selected ' +
            'physical H1 subnet.'
        )
    }
    foreach ($port in @(
        $constants.source_tcp_port,
        $constants.source_web_port,
        $constants.source_probe_port
    )) {
        Assert-I05SourcePortAvailable -Protocol TCP -Port $port
    }
    Assert-I05SourcePortAvailable -Protocol UDP `
        -Port $constants.source_udp_port

    if ($PreflightOnly) {
        [pscustomobject][ordered]@{
            schema = 'ese.v91.i05.t1-source-preflight/v1'
            case_id = $constants.case_id
            status = 'PASS'
            mutation_performed = $false
            candidate_zip = [ordered]@{
                bytes = $constants.candidate_zip_bytes
                sha256 = $constants.candidate_zip_sha256
            }
            fixture = [ordered]@{
                bytes = $constants.fixture_bytes
                sha256 = $constants.fixture_sha256
            }
            source = [ordered]@{
                ipv4_class = 'private-v4'
                ipv6_class = $network.ipv6_class
                interface_id = $network.interface_id
                physical = $true
                ipv6_binding_enabled = $true
            }
            h3 = [ordered]@{
                ipv4_class = 'private-v4'
                same_subnet = $true
                control_port =
                    $constants.downloader_control_port
            }
        } | ConvertTo-Json -Depth 8
        return
    }
    Assert-I05SourceAdministrator

    $nonce = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
    $runStamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss')
    $runId = "v91-i05-t1-source-$runStamp-$($nonce.Substring(0, 8))"
    $run = Join-Path $base (Join-Path 'runs' $runId)
    if (Test-Path -LiteralPath $run) {
        throw 'Fresh nonce-scoped RunRoot already exists.'
    }
    $null = New-LabDirectory -Path (Join-Path $base 'runs')
    $null = New-Item -ItemType Directory -Path $run
    $nodes = New-LabDirectory -Path (Join-Path $run 'nodes')
    $evidence = New-LabDirectory -Path (Join-Path $run 'evidence')
    $private = New-LabDirectory -Path (Join-Path $run 'private')
    $exchange = New-LabDirectory `
        -Path (Join-Path $run 'coordination')
    foreach ($name in @(
        $constants.config_file,
        $constants.ready_file,
        $constants.command_file,
        $constants.started_file,
        $constants.complete_file,
        $constants.cleanup_file
    )) {
        if (Test-Path -LiteralPath (Join-Path $exchange $name)) {
            throw "ExchangePath contains stale V91-I05 file '$name'."
        }
    }

    $packageExtract = Join-Path $private 'package'
    if (Test-Path -LiteralPath $packageExtract) {
        throw 'Nonce-scoped candidate extraction path already exists.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead(
        $candidateZip.FullName)
    try {
        if ($archive.Entries.Count -lt 1 -or
            $archive.Entries.Count -gt 5000) {
            throw 'RC3 ZIP entry count is outside the bounded range.'
        }
        $entryNames = New-Object 'Collections.Generic.HashSet[string]' `
            ([StringComparer]::OrdinalIgnoreCase)
        [Int64]$totalExpandedBytes = 0
        foreach ($entry in $archive.Entries) {
            $name = ([string]$entry.FullName).Replace('/', '\')
            if ([string]::IsNullOrWhiteSpace($name) -or
                [IO.Path]::IsPathRooted($name) -or
                $name.Contains(':')) {
                throw 'RC3 ZIP contains an unsafe path.'
            }
            $segments = @($name -split '\\')
            if (@($segments | Where-Object {
                    $_ -eq '.' -or $_ -eq '..'
                }).Count -gt 0) {
                throw 'RC3 ZIP contains a traversal segment.'
            }
            if (-not $entryNames.Add($name)) {
                throw 'RC3 ZIP contains a case-insensitive duplicate path.'
            }
            $unixType = ([uint32]$entry.ExternalAttributes `
                -shr 16) -band 0xf000
            if ($unixType -eq 0xa000) {
                throw 'RC3 ZIP contains a symbolic link.'
            }
            $totalExpandedBytes += [Int64]$entry.Length
            if ($totalExpandedBytes -gt 2147483648) {
                throw 'RC3 ZIP expanded size exceeds the 2 GiB bound.'
            }
        }
    } finally {
        $archive.Dispose()
    }
    [IO.Compression.ZipFile]::ExtractToDirectory(
        $candidateZip.FullName, $packageExtract)
    $reparseEntries = @(
        Get-ChildItem -LiteralPath $packageExtract -Recurse -Force |
            Where-Object {
                ($_.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0
            }
    )
    if ($reparseEntries.Count -gt 0) {
        throw 'Extracted RC3 package contains a reparse point.'
    }
    $candidate = Get-LabCandidateInfo -PackagePath $packageExtract `
        -ExpectedCommit $constants.candidate_commit
    $validatedCandidateObject =
        Get-I05SourceCandidateObject -Candidate $candidate
    $validatedCandidateObject.zip_sha256 =
        $constants.candidate_zip_sha256
    $validatedCandidateObject.zip_bytes =
        $constants.candidate_zip_bytes
    Assert-I05CandidateContract -Candidate (
        [pscustomobject]$validatedCandidateObject
    ) -Context 'Extracted RC3 candidate'
    $candidateObject = $validatedCandidateObject

    $stage = 'source-prepare'
    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
        -SourcePackage $candidate.package_path -OutputRoot $nodes `
        -RunId 'v91-i05-t1-source' -PortOffset 3200
    $sourceNode = Join-Path $nodes 'v91-i05-t1-source-a'
    $sourceExe = Resolve-LabContainedFile -Root $run `
        -RelativePath 'nodes\v91-i05-t1-source-a\emule.exe'
    Assert-I05ExactText -Actual (Get-LabSha256 -Path $sourceExe) `
        -Expected $constants.candidate_emule_sha256 `
        -Context 'Isolated source executable' -IgnoreCase

    $probeFirewallName = "eSE-V91-I05-PROBE-$nonce"
    $probeFirewallDisplay =
        "eSE V91 I05 T1 probe $($nonce.Substring(0, 8))"
    $dataFirewallName = "eSE-V91-I05-DATA-$nonce"
    $dataFirewallDisplay =
        "eSE V91 I05 T1 data $($nonce.Substring(0, 8))"
    $probeProgram = [string](Get-Process -Id $PID).Path
    $ownership = [ordered]@{
        schema = 'ese.v91.i05.t1-source-ownership/v1'
        case_id = $constants.case_id
        topology = $constants.topology
        nonce = $nonce
        run_id = $runId
        created_at_utc = Get-LabUtcTimestamp
        updated_at_utc = Get-LabUtcTimestamp
        candidate = $candidateObject
        node_relative_path = 'nodes\v91-i05-t1-source-a'
        source = [ordered]@{
            ipv4_address = $network.ipv4_address
            ipv6_address = $network.ipv6_address
            interface_index = $network.interface_index
            interface_alias = $network.interface_alias
            interface_id = $network.interface_id
        }
        remote = [ordered]@{
            registered = $false
            ipv4_address = ''
            ipv4_address_sha256 = ''
            interface_id = ''
            process_id = 0
        }
        process = [ordered]@{
            launch_pending = $false
            launch_not_before_utc = ''
            started = $false
            process_id = 0
            start_time_utc = ''
        }
        firewall = [ordered]@{
            probe_name = $probeFirewallName
            probe_display_name = $probeFirewallDisplay
            probe_program = $probeProgram
            probe_pending = $false
            probe_pending_at_utc = ''
            probe_created = $false
            data_name = $dataFirewallName
            data_display_name = $dataFirewallDisplay
            data_pending = $false
            data_pending_at_utc = ''
            data_created = $false
        }
    }
    $ownershipPath = Join-Path $private 'ownership.json'
    Write-I05SourceOwnership

    $stage = 'ipv6-probe'
    $probeIp = [Net.IPAddress]::Parse($network.ipv6_address)
    if ($network.ipv6_class -eq 'linklocal-v6') {
        $probeIp.ScopeId = [Int64]$network.interface_index
    }
    $probeListener = New-Object Net.Sockets.TcpListener(
        $probeIp, $constants.source_probe_port)
    $probeListener.Server.DualMode = $false
    $probeListener.Start(1)
    $acceptTask = $probeListener.AcceptTcpClientAsync()

    $ownership.firewall.probe_pending = $true
    $ownership.firewall.probe_pending_at_utc = Get-LabUtcTimestamp
    Write-I05SourceOwnership
    New-NetFirewallRule -Name $probeFirewallName `
        -DisplayName $probeFirewallDisplay -Direction Inbound `
        -Action Allow -Enabled True -Profile Any -Protocol TCP `
        -LocalPort $constants.source_probe_port `
        -Program $probeProgram `
        -InterfaceAlias $network.interface_alias `
        -LocalAddress $network.ipv6_address `
        -RemoteAddress LocalSubnet -EdgeTraversalPolicy Block `
        -ErrorAction Stop | Out-Null
    $probeFirewallPresent = $true
    $ownership.firewall.probe_pending = $false
    $ownership.firewall.probe_created = $true
    Write-I05SourceOwnership

    $configCreated = [DateTimeOffset]::UtcNow
    $configExpires =
        $configCreated.AddSeconds($ReadyTimeoutSeconds + 300)
    $probeRequest = "V91-I05-PROBE $nonce"
    $probeResponse = "V91-I05-PROBE-OK $nonce"
    $hostIdSha256 = Get-I05SourceHostIdSha256
    $config = [ordered]@{
        schema = 'ese.v91.i05.t1-config/v1'
        case_id = $constants.case_id
        topology = $constants.topology
        status = 'ARMED'
        nonce = $nonce
        created_at_utc = $configCreated.ToString('o')
        expires_at_utc = $configExpires.ToString('o')
        candidate = $candidateObject
        source = [ordered]@{
            host_id_sha256 = $hostIdSha256
            ipv4_address = $network.ipv4_address
            ipv4_sha256 =
                Get-LabStringSha256 -Value $network.ipv4_address
            ipv4_prefix_length = $network.ipv4_prefix_length
            interface_id = $network.interface_id
            tcp_port = $constants.source_tcp_port
            udp_port = $constants.source_udp_port
            web_port = $constants.source_web_port
        }
        ipv6_probe = [ordered]@{
            required = $true
            protocol = 'TCP'
            source_interface_id = $network.interface_id
            address = $network.ipv6_address
            address_class = $network.ipv6_class
            address_sha256 =
                Get-LabStringSha256 -Value $network.ipv6_address
            port = $constants.source_probe_port
            challenge_sha256 =
                Get-LabStringSha256 -Value $probeRequest
            request_line = $probeRequest
            response_sha256 =
                Get-LabStringSha256 -Value $probeResponse
            response_line = $probeResponse
        }
        downloader = [ordered]@{
            expected_ipv4_address = $h3Address
            expected_ipv4_sha256 =
                Get-LabStringSha256 -Value $h3Address
            tcp_port = $constants.downloader_tcp_port
            udp_port = $constants.downloader_udp_port
            web_port = $constants.downloader_web_port
            min_free_bytes =
                $constants.downloader_min_free_bytes
            filesystem = 'NTFS'
        }
        fixture = [ordered]@{
            name = $constants.fixture_name
            bytes = $constants.fixture_bytes
            sha256 = $constants.fixture_sha256
            ed2k = $constants.fixture_ed2k
        }
        policy = [ordered]@{
            ipv6_mode = 0
            kad_network_mask = 0
            kad2_enabled = $false
            kad6_enabled = $false
            os_ipv6_binding_required = $true
            data_family = 'IPv4'
            forbidden_interface_pattern =
                $constants.forbidden_interface_pattern
            packet_capture_required = $true
            direct_link_only = $true
            third_party_sources_forbidden = $true
            discovery = 'direct-link-only'
            third_party_peers_allowed = $false
        }
        coordination = [ordered]@{
            transport = 'lan-tcp-v1'
            control_port = $constants.downloader_control_port
            h1_address_sha256 =
                Get-LabStringSha256 -Value $network.ipv4_address
            h3_address_sha256 =
                Get-LabStringSha256 -Value $h3Address
            single_stream = $true
            maximum_frame_bytes = 1048576
            ready_file = $constants.ready_file
            command_file = $constants.command_file
            started_file = $constants.started_file
            complete_file = $constants.complete_file
            cleanup_file = $constants.cleanup_file
        }
    }
    $configPath = Write-LabJson -Value $config `
        -Path (Join-Path $exchange $constants.config_file)
    $null = Write-LabJson -Value $config `
        -Path (Join-Path $private $constants.config_file)
    $null = Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i05.t1-source-config-receipt/v1'
        case_id = $constants.case_id
        status = 'WAITING_FOR_H3'
        created_at_utc = Get-LabUtcTimestamp
        nonce_sha256 = Get-LabStringSha256 -Value $nonce
        config_sha256 = Get-LabSha256 -Path $configPath
        source_interface_id = $network.interface_id
        source_ipv4_class = 'private-v4'
        source_ipv6_class = $network.ipv6_class
    }) -Path (Join-Path $evidence 'config-receipt.json')

    Write-Host 'V91-I05 T1: IPv6 preflight armed.' `
        -ForegroundColor Cyan
    Write-Host "Copy this CONFIG into the H3 kit root: $configPath"
    Write-Host (
        "H1 will then use the physical LAN control channel to H3 " +
        "$h3Address`:$($constants.downloader_control_port)."
    )

    $probe = Wait-I05SourceIpv6Probe -AcceptTask $acceptTask `
        -ExpectedRequest $probeRequest -Response $probeResponse `
        -TimeoutSeconds $ReadyTimeoutSeconds
    Stop-I05SourceProbe
    Remove-I05SourceProbeFirewall

    $route = Get-I05SourceRoute -RemoteIPv4 $h3Address `
        -Network $network
    $stage = 'control-ready'
    $controlClient = Connect-I05SourceControl `
        -LocalIPv4 $network.ipv4_address -RemoteIPv4 $h3Address `
        -RemotePort $constants.downloader_control_port `
        -TimeoutSeconds $ReadyTimeoutSeconds
    $controlStream = $controlClient.GetStream()
    $readyFrame = Read-I05SourceControlFrame -Stream $controlStream `
        -Type READY -Nonce $nonce -TimeoutSeconds $ReadyTimeoutSeconds
    if ($readyFrame.type -eq 'FAILURE') {
        Save-I05SourceControlFrame -Frame $readyFrame `
            -FileName 'FAILURE-READY-V91-I05-T1.json'
    }
    Assert-I05SourceExpectedFrame -Frame $readyFrame `
        -ExpectedType READY -Nonce $nonce -Stream $controlStream
    Save-I05SourceControlFrame -Frame $readyFrame `
        -FileName $constants.ready_file
    $remote = Assert-I05SourceReady -Ready $readyFrame.document `
        -Nonce $nonce -Network $network -Probe $probe `
        -HostIdSha256 $hostIdSha256 -ExpectedH3IPv4 $h3Address `
        -NotBefore $configCreated `
        -NotAfter $configExpires
    Confirm-I05SourceControlFrame -Stream $controlStream `
        -Frame $readyFrame -Nonce $nonce
    $remoteReadyStatus = 'PASS'
    $ownership.remote.registered = $true
    $ownership.remote.ipv4_address = $remote.ipv4_address
    $ownership.remote.ipv4_address_sha256 =
        $remote.ipv4_address_sha256
    $ownership.remote.interface_id = $remote.interface_id
    $ownership.remote.process_id = $remote.process_id
    Write-I05SourceOwnership
    $productBoundaryReached = $true

    $stage = 'source-profile'
    $preferences = Join-Path $sourceNode 'config\preferences.ini'
    $password = [Guid]::NewGuid().ToString('N')
    foreach ($entry in ([ordered]@{
        NetworkKademlia = '0'
        NetworkED2K = '0'
        Autoconnect = '0'
        FilterBadIPs = '0'
        ConfirmExit = '0'
        VerboseOptions = '1'
        Verbose = '1'
        SaveLogToDisk = '1'
        SaveDebugToDisk = '1'
        CryptLayerRequested = '0'
        CryptLayerRequired = '0'
        CryptLayerSupported = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
    }
    Set-LabIniValue -Path $preferences -Section 'Connection' `
        -Key 'KadNetworkMask' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'Connection' `
        -Key 'IPv6Mode' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'UPnP' `
        -Key 'EnableUPnP' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'WebServer' `
        -Key 'Enabled' -Value '1'
    Set-LabIniValue -Path $preferences -Section 'WebServer' `
        -Key 'Port' -Value ([string]$constants.source_web_port)
    Set-LabIniValue -Path $preferences -Section 'WebServer' `
        -Key 'Password' -Value (Get-I05SourceMd5Text -Value $password)
    Set-LabIniValue -Path $preferences -Section 'WebServer' `
        -Key 'WebUseUPnP' -Value '0'
    $incoming = New-LabDirectory -Path (Join-Path $sourceNode 'Incoming')
    $temp = New-LabDirectory -Path (Join-Path $sourceNode 'Temp')
    Set-LabIniValue -Path $preferences -Section 'eMule' `
        -Key 'IncomingDir' -Value ($incoming + '\')
    Set-LabIniValue -Path $preferences -Section 'eMule' `
        -Key 'TempDir' -Value ($temp + '\')

    $sourceFixture = Join-Path $incoming $constants.fixture_name
    if (Test-Path -LiteralPath $sourceFixture) {
        throw 'Isolated source fixture path unexpectedly exists.'
    }
    $hardlink = New-Item -ItemType HardLink -Path $sourceFixture `
        -Target $fixtureItem.FullName -ErrorAction Stop
    if ([Int64]$hardlink.Length -ne $constants.fixture_bytes) {
        throw 'Canonical fixture hardlink has the wrong length.'
    }

    $stage = 'source-start'
    $sourceArguments = @(
        '--portable', '--ignoreinstances', '--headless',
        "--metrics-port=$($constants.source_web_port)",
        "--tcp-port=$($constants.source_tcp_port)",
        "--udp-port=$($constants.source_udp_port)"
    )
    $ownership.process.launch_pending = $true
    $ownership.process.launch_not_before_utc = Get-LabUtcTimestamp
    Write-I05SourceOwnership
    $sourceProcess = Start-Process -FilePath $sourceExe `
        -ArgumentList $sourceArguments -WorkingDirectory $sourceNode `
        -WindowStyle Hidden -PassThru
    $sourceProcess.Refresh()
    $ownership.process.launch_pending = $false
    $ownership.process.started = $true
    $ownership.process.process_id = [int]$sourceProcess.Id
    $ownership.process.start_time_utc =
        $sourceProcess.StartTime.ToUniversalTime().ToString('o')
    Write-I05SourceOwnership
    $sourceStatus = Wait-I05SourceApi -Process $sourceProcess `
        -Port $constants.source_web_port
    try {
        Assert-I05ApiNetworksOff -Status $sourceStatus `
            -Context 'H1 source first API response'
    } catch {
        Throw-I05SourceProductInvariant `
            -Category 'source-first-api-network-state' `
            -Message $_.Exception.Message
    }
    $sourceFirstApiNetworksOffVerified = $true
    $sourceKad6OffVerified = $true
    try {
        $sourceApiProfile = Assert-I05SourceOwnedListeners `
            -ProcessId $sourceProcess.Id `
            -LanIPv4 $network.ipv4_address
    } catch {
        if ($_.Exception.Data.Contains('I05Classification')) {
            throw
        }
        Throw-I05SourceProductInvariant `
            -Category 'source-listener-invariant' `
            -Message $_.Exception.Message
    }
    $preferencesText = [IO.File]::ReadAllText($preferences)
    $sourceIpv6ModeVerified =
        $preferencesText -match '(?im)^\s*IPv6Mode\s*=\s*0\s*$' -and
        $preferencesText -match
            '(?im)^\s*KadNetworkMask\s*=\s*0\s*$' -and
        $preferencesText -match
            '(?im)^\s*NetworkKademlia\s*=\s*0\s*$' -and
        $preferencesText -match
            '(?im)^\s*FilterBadIPs\s*=\s*0\s*$' -and
        $preferencesText -match
            '(?im)^\s*ConfirmExit\s*=\s*0\s*$'
    if (-not $sourceIpv6ModeVerified) {
        Throw-I05SourceProductInvariant `
            -Category 'source-profile-network-state' `
            -Message (
                'Isolated source profile did not persist Kad/IPv6 off ' +
                'private-LAN source acceptance, and unattended exit.'
            )
    }
    $startupTcpSnapshot = @(Get-I05SourceTcpSnapshot)
    $startupUdpSnapshot = @(Get-I05SourceUdpSnapshot)
    $ipv6PeerListeners = @($startupTcpSnapshot | Where-Object {
        [int]$_.OwningProcess -eq $sourceProcess.Id -and
        [int]$_.LocalPort -eq $constants.source_tcp_port -and
        ([string]$_.LocalAddress).Contains(':')
    })
    $ipv6PeerUdp = @($startupUdpSnapshot | Where-Object {
        [int]$_.OwningProcess -eq $sourceProcess.Id -and
        [int]$_.LocalPort -eq $constants.source_udp_port -and
        ([string]$_.LocalAddress).Contains(':')
    })
    if ($ipv6PeerListeners.Count -gt 0 -or $ipv6PeerUdp.Count -gt 0) {
        Throw-I05SourceProductInvariant `
            -Category 'source-ipv6-endpoint-at-readiness' `
            -Message (
                'IPv6Mode=0 source exposes an IPv6 peer TCP/UDP endpoint.'
            )
    }
    $ownership.firewall.data_pending = $true
    $ownership.firewall.data_pending_at_utc = Get-LabUtcTimestamp
    Write-I05SourceOwnership
    New-NetFirewallRule -Name $dataFirewallName `
        -DisplayName $dataFirewallDisplay -Direction Inbound `
        -Action Allow -Enabled True -Profile Any -Protocol TCP `
        -LocalPort $constants.source_tcp_port -Program $sourceExe `
        -InterfaceAlias $network.interface_alias `
        -LocalAddress $network.ipv4_address `
        -RemoteAddress $remote.ipv4_address `
        -EdgeTraversalPolicy Block `
        -ErrorAction Stop | Out-Null
    $ownership.firewall.data_pending = $false
    $ownership.firewall.data_created = $true
    Write-I05SourceOwnership

    try {
        $classicSession = Get-I05SourceClassicSession `
            -Port $constants.source_web_port -Password $password
        $shared = Get-I05SourceSharedLink `
            -Port $constants.source_web_port -Session $classicSession
    } catch {
        Throw-I05SourceProductInvariant `
            -Category 'source-local-ed2k-proof' `
            -Message $_.Exception.Message
    }
    $password = $null
    $classicSession = $null
    $fileLinkPrefix = 'ed2k://|file|' + $constants.fixture_name + '|' +
        [string]$constants.fixture_bytes + '|' +
        $constants.fixture_ed2k + '|/'
    $directLink = $fileLinkPrefix +
        "|sources,$($network.ipv4_address)`:" +
        "$($constants.source_tcp_port)|/"
    $directLinkSha256 = Get-LabStringSha256 -Value $directLink

    $null = Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i05.t1-source-start/v1'
        case_id = $constants.case_id
        status = 'READY'
        captured_at_utc = Get-LabUtcTimestamp
        nonce_sha256 = Get-LabStringSha256 -Value $nonce
        candidate = $candidateObject
        process = [ordered]@{
            process_id = $sourceProcess.Id
            executable_sha256 =
                $constants.candidate_emule_sha256
            tcp_listener_owned = $true
            api_ipv4_only = $true
            api_lan_access_denied = [bool]$sourceApiProfile.denied
            api_lan_denial_mode = [string]$sourceApiProfile.mode
            api_lan_http_status = [int]$sourceApiProfile.http_status
            ipv6_mode = 0
            kad_network_mask = 0
            kad_connected = $false
            kad6_running = $false
            kad6_connected = $false
        }
        fixture = [ordered]@{
            bytes = $constants.fixture_bytes
            sha256 = $constants.fixture_sha256
            ed2k = $constants.fixture_ed2k
            source_local_ed2k = $shared.ed2k
            source_local_ed2k_source = $shared.ed2k_source
            source_shared_page_sha256 =
                $shared.shared_page_sha256
            source_local_ed2k_verified = $true
            hardlink_used = $true
            direct_link_sha256 = $directLinkSha256
        }
        route = $route
    }) -Path (Join-Path $evidence 'source-start.json')

    # The formal wire capture is owned and adjudicated on H3. H1 creates no
    # PktMon filter or ETW session; its independent gates are exact PID,
    # socket, route, API and end-to-end hash evidence.
    $sourceCaptureStatus = 'NOT_APPLICABLE_H3_CAPTURE_ONLY'

    $stage = 'command'
    $command = [ordered]@{
        schema = 'ese.v91.i05.t1-command/v1'
        case_id = $constants.case_id
        topology = $constants.topology
        status = 'START'
        nonce = $nonce
        created_at_utc = Get-LabUtcTimestamp
        candidate = $candidateObject
        source = [ordered]@{
            ipv4_address = $network.ipv4_address
            ipv4_sha256 =
                Get-LabStringSha256 -Value $network.ipv4_address
            interface_id = $network.interface_id
            tcp_port = $constants.source_tcp_port
            udp_port = $constants.source_udp_port
            web_port = $constants.source_web_port
        }
        fixture = [ordered]@{
            name = $constants.fixture_name
            bytes = $constants.fixture_bytes
            sha256 = $constants.fixture_sha256
            ed2k = $constants.fixture_ed2k
            direct_link = $directLink
            direct_link_sha256 = $directLinkSha256
        }
        injection = [ordered]@{
            delivery_count = 1
            direct_only = $true
        }
        policy = [ordered]@{
            data_family = 'IPv4'
            ipv6_mode = 0
            kad_network_mask = 0
            kad2_enabled = $false
            kad6_enabled = $false
            wire_capture_required = $true
            wire_capture_host = 'H3'
            classic_crypt_layers_disabled = $true
            direct_link_only = $true
            third_party_sources_forbidden = $true
            discovery = 'direct-link-only'
            third_party_peers_allowed = $false
        }
    }
    $commandFrame = Send-I05SourceControlFrame `
        -Stream $controlStream -Type COMMAND -Nonce $nonce `
        -Value $command -TimeoutSeconds $ReadyTimeoutSeconds
    $controlCommandAccepted = $true
    $null = Write-LabText -Value $commandFrame.raw `
        -Path (Join-Path $exchange $constants.command_file)
    $null = Write-LabText -Value $commandFrame.raw `
        -Path (Join-Path $private $constants.command_file)
    $null = Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i05.t1-command-receipt/v1'
        case_id = $constants.case_id
        status = 'SENT'
        captured_at_utc = Get-LabUtcTimestamp
        nonce_sha256 = Get-LabStringSha256 -Value $nonce
        command_sha256 = $commandFrame.sha256
        command_bytes = $commandFrame.bytes
        transport = 'lan-tcp-v1'
        direct_link_sha256 = $directLinkSha256
    }) -Path (Join-Path $evidence 'command-receipt.json')
    Write-Host 'COMMAND accepted by H3 over physical LAN TCP.' `
        -ForegroundColor Cyan

    $stage = 'transfer'
    $startedFrame = Read-I05SourceControlFrame -Stream $controlStream `
        -Type STARTED -Nonce $nonce `
        -TimeoutSeconds $ReadyTimeoutSeconds
    if ($startedFrame.type -eq 'FAILURE') {
        Save-I05SourceControlFrame -Frame $startedFrame `
            -FileName 'FAILURE-STARTED-V91-I05-T1.json'
    }
    Assert-I05SourceExpectedFrame -Frame $startedFrame `
        -ExpectedType STARTED -Nonce $nonce -Stream $controlStream
    Save-I05SourceControlFrame -Frame $startedFrame `
        -FileName $constants.started_file
    Assert-I05SourceStarted -Started $startedFrame.document `
        -Nonce $nonce -Remote $remote `
        -DirectLinkSha256 $directLinkSha256
    Confirm-I05SourceControlFrame -Stream $controlStream `
        -Frame $startedFrame -Nonce $nonce
    $remoteStartedStatus = 'PASS'

    $samplePath = Join-Path $evidence 'samples.jsonl'
    $sampleNumber = 0
    $transferStarted = [DateTime]::UtcNow
    $transferDeadline =
        $transferStarted.AddSeconds(
            $TransferTimeoutSeconds + $CompletionTimeoutSeconds)
    $completeFrame = $null
    $apiFailureStreak = 0
    $observedRemotePorts =
        [Collections.Generic.HashSet[int]]::new()
    do {
        $sourceProcess.Refresh()
        if ($sourceProcess.HasExited) {
            Throw-I05SourceProductInvariant `
                -Category 'source-process-exited' `
                -Message 'Source candidate exited during the physical transfer.'
        }
        $connections = @(Get-I05SourceTcpSnapshot | Where-Object {
            [int]$_.OwningProcess -eq $sourceProcess.Id
        })
        $matching = @($connections | Where-Object {
            [string]$_.State -eq 'Established' -and
            [int]$_.LocalPort -eq $constants.source_tcp_port -and
            [string]$_.LocalAddress -eq $network.ipv4_address -and
            [string]$_.RemoteAddress -eq $remote.ipv4_address
        })
        foreach ($connection in $matching) {
            $null = $observedRemotePorts.Add(
                [int]$connection.RemotePort)
        }
        $unexpectedEstablished = @($connections | Where-Object {
            [string]$_.State -eq 'Established' -and
            -not (
                [string]$_.LocalAddress -in @('127.0.0.1', '::1') -and
                [string]$_.RemoteAddress -in @('127.0.0.1', '::1')
            ) -and
            -not (
                [int]$_.LocalPort -eq $constants.source_tcp_port -and
                [string]$_.LocalAddress -eq $network.ipv4_address -and
                [string]$_.RemoteAddress -eq $remote.ipv4_address
            )
        })
        $ipv6Peer = @($connections | Where-Object {
            [string]$_.State -eq 'Established' -and
            ([string]$_.LocalAddress).Contains(':') -and
            [string]$_.LocalAddress -ne '::1' -and
            [string]$_.RemoteAddress -ne '::1'
        })
        if ($matching.Count -gt 0) { $routeObserved = $true }
        if ($unexpectedEstablished.Count -gt 0) {
            Throw-I05SourceProductInvariant `
                -Category 'unexpected-peer-socket' `
                -Message (
                    'Source candidate established a nonloopback TCP ' +
                    'connection outside the exact H1:7862/H3 tuple.'
                )
        }
        if ($ipv6Peer.Count -gt 0) {
            $unexpectedIpv6Observed = $true
            Throw-I05SourceProductInvariant `
                -Category 'ipv6-peer-socket' `
                -Message (
                    'Candidate established an IPv6 peer socket in ' +
                    'IPv4-only data mode.'
                )
        }
        $ipv6PeerUdp = @(Get-I05SourceUdpSnapshot | Where-Object {
            [int]$_.OwningProcess -eq $sourceProcess.Id -and
            ([string]$_.LocalAddress).Contains(':') -and
            [int]$_.LocalPort -eq $constants.source_udp_port
        })
        if ($ipv6PeerUdp.Count -gt 0) {
            $unexpectedIpv6Observed = $true
            Throw-I05SourceProductInvariant `
                -Category 'ipv6-peer-endpoint' `
                -Message (
                    'Candidate exposes an IPv6 UDP peer endpoint in ' +
                    'IPv4-only mode.'
                )
        }
        $apiAvailable = $false
        try {
            $sourceStatus = Invoke-RestMethod -Uri (
                "http://127.0.0.1:$($constants.source_web_port)/api/status"
            ) -TimeoutSec 2 -ErrorAction Stop
            $apiAvailable = $true
        } catch {}
        if ($apiAvailable) {
            $apiFailureStreak = 0
            try {
                Assert-I05ApiNetworksOff -Status $sourceStatus `
                    -Context 'H1 source transfer API'
            } catch {
                Throw-I05SourceProductInvariant `
                    -Category 'source-network-state' `
                    -Message $_.Exception.Message
            }
        } else {
            ++$apiFailureStreak
            if ($apiFailureStreak -ge 3) {
                Throw-I05SourceProductInvariant `
                    -Category 'source-api-unresponsive' `
                    -Message (
                        'Source API failed three consecutive transfer samples.'
                    )
            }
        }
        $sourceProcess.Refresh()
        Write-I05SourceSample -Path $samplePath -Value ([ordered]@{
            schema = 'ese.v91.i05.t1-source-sample/v1'
            sample_number = ++$sampleNumber
            captured_at_utc = Get-LabUtcTimestamp
            elapsed_seconds = [Math]::Round(
                ([DateTime]::UtcNow - $transferStarted).TotalSeconds, 3)
            process_alive = -not $sourceProcess.HasExited
            working_set_bytes = [Int64]$sourceProcess.WorkingSet64
            private_memory_bytes =
                [Int64]$sourceProcess.PrivateMemorySize64
            api_available = $apiAvailable
            candidate_connection_count = $connections.Count
            matching_physical_ipv4_connection_count = $matching.Count
            unexpected_established_connection_count =
                $unexpectedEstablished.Count
            observed_remote_ports = @(
                $observedRemotePorts | Sort-Object
            )
            nonloopback_ipv6_connection_count = $ipv6Peer.Count
            ipv6_peer_udp_endpoint_count = $ipv6PeerUdp.Count
            source_interface_id = $network.interface_id
            remote_address_sha256 =
                $remote.ipv4_address_sha256
        })

        if ($routeObserved -and
            -not (Test-Path -LiteralPath (
                Join-Path $evidence 'data-route.json'))) {
            & (Join-Path $PSScriptRoot 'assert_data_route.ps1') `
                -TargetProcessId $sourceProcess.Id `
                -ExpectedRemoteAddress $remote.ipv4_address `
                -ExpectedRemotePort 0 -RequiredFamily IPv4 `
                -ForbiddenInterfacePattern `
                    $constants.forbidden_interface_pattern `
                -MinimumConnections 1 `
                -OutFile (Join-Path $evidence 'data-route.json')
        }
        if ($controlClient.Client.Poll(
                0, [Net.Sockets.SelectMode]::SelectRead) -and
            $controlClient.Client.Available -eq 0) {
            throw 'H3 closed the physical control stream during transfer.'
        }
        if ($controlStream.DataAvailable) {
            $completeFrame = Read-I05SourceControlFrame `
                -Stream $controlStream -Type COMPLETE -Nonce $nonce `
                -TimeoutSeconds $CompletionTimeoutSeconds
            break
        }
        Start-Sleep -Seconds 5
    } while ([DateTime]::UtcNow -lt $transferDeadline)
    if ($null -eq $completeFrame) {
        throw 'H3 did not complete the transfer inside the bounded window.'
    }
    if ($completeFrame.type -eq 'FAILURE') {
        Save-I05SourceControlFrame -Frame $completeFrame `
            -FileName 'FAILURE-COMPLETE-V91-I05-T1.json'
    }
    Assert-I05SourceExpectedFrame -Frame $completeFrame `
        -ExpectedType COMPLETE -Nonce $nonce -Stream $controlStream
    Save-I05SourceControlFrame -Frame $completeFrame `
        -FileName $constants.complete_file
    if ($observedRemotePorts.Count -lt 1) {
        throw 'H1 never observed a process-bound H3 ephemeral peer port.'
    }
    $remoteBundle = Assert-I05SourceRemoteComplete `
        -Complete $completeFrame.document -Nonce $nonce -Remote $remote `
        -SourceIPv4 $network.ipv4_address `
        -ObservedRemotePorts @($observedRemotePorts) `
        -EvidenceRoot $evidence
    $remoteEvidenceBundleStatus = [string]$remoteBundle.status
    $remoteEvidenceBundlePath = [string]$remoteBundle.bundle_path
    Confirm-I05SourceControlFrame -Stream $controlStream `
        -Frame $completeFrame -Nonce $nonce
    $remoteCompleteStatus = 'PASS'
    if (-not $routeObserved) {
        throw 'H1 never observed the exact H3-to-source IPv4 socket.'
    }

    try {
        $bindingsAfter = @(
            Get-NetAdapterBinding -Name $network.interface_alias `
                -ComponentID 'ms_tcpip6' -ErrorAction Stop
        )
    } catch {
        Throw-I05SourceLabBlocked `
            -Category 'ipv6-binding-enumeration-failed' `
            -Message (
                'Physical NIC IPv6 binding could not be enumerated at ' +
                'COMPLETE: ' + $_.Exception.Message
            )
    }
    $postBindingVerified = $bindingsAfter.Count -eq 1 -and
        [bool]$bindingsAfter[0].Enabled
    if (-not $postBindingVerified) {
        Throw-I05SourceProductInvariant `
            -Category 'physical-ipv6-binding-changed' `
            -Message (
                'Physical NIC IPv6 binding was not preserved through COMPLETE.'
            )
    }
    try {
        $sourceStatus = Invoke-RestMethod -Uri (
            "http://127.0.0.1:$($constants.source_web_port)/api/status"
        ) -TimeoutSec 5 -ErrorAction Stop
    } catch {
        Throw-I05SourceProductInvariant `
            -Category 'source-api-unresponsive-at-complete' `
            -Message (
                'Source API was unresponsive at COMPLETE: ' +
                $_.Exception.Message
            )
    }
    try {
        Assert-I05ApiNetworksOff -Status $sourceStatus `
            -Context 'H1 source COMPLETE API'
    } catch {
        Throw-I05SourceProductInvariant `
            -Category 'source-network-state' -Message $_.Exception.Message
    }
    $sourceKad6OffVerified = $true

    $stage = 'remote-cleanup'
    $stop = [ordered]@{
        schema = 'ese.v91.i05.t1-stop/v1'
        case_id = $constants.case_id
        status = 'STOP'
        nonce = $nonce
        created_at_utc = Get-LabUtcTimestamp
        candidate = $candidateObject
        reason = 'completed'
    }
    $null = Send-I05SourceControlFrame -Stream $controlStream `
        -Type STOP -Nonce $nonce -Value $stop `
        -TimeoutSeconds $CompletionTimeoutSeconds
    $remoteStopSent = $true
    $cleanupFrame = Read-I05SourceControlFrame -Stream $controlStream `
        -Type CLEANUP -Nonce $nonce `
        -TimeoutSeconds $CompletionTimeoutSeconds
    if ($cleanupFrame.type -eq 'FAILURE') {
        Save-I05SourceControlFrame -Frame $cleanupFrame `
            -FileName 'FAILURE-CLEANUP-V91-I05-T1.json'
    }
    Assert-I05SourceExpectedFrame -Frame $cleanupFrame `
        -ExpectedType CLEANUP -Nonce $nonce -Stream $controlStream
    Save-I05SourceControlFrame -Frame $cleanupFrame `
        -FileName $constants.cleanup_file
    $cleanupDocument = $cleanupFrame.document
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $cleanupDocument -Name 'schema' `
        -Context 'H3 cleanup')) `
        -Expected 'ese.v91.i05.t1-cleanup/v1' `
        -Context 'H3 cleanup schema'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $cleanupDocument -Name 'status' `
        -Context 'H3 cleanup')) `
        -Expected 'CLEANUP_COMPLETE' -Context 'H3 cleanup status'
    Assert-I05ExactText -Actual (
        Assert-I05Nonce -Value (Get-I05RequiredProperty `
            -Object $cleanupDocument -Name 'nonce' `
            -Context 'H3 cleanup') -Context 'H3 cleanup nonce'
    ) -Expected $nonce -Context 'H3 cleanup nonce'
    Assert-I05CandidateContract -Candidate (Get-I05RequiredProperty `
        -Object $cleanupDocument -Name 'candidate' `
        -Context 'H3 cleanup') -Context 'H3 cleanup.candidate'
    $cleanupProcess = Get-I05RequiredProperty `
        -Object $cleanupDocument -Name 'process' `
        -Context 'H3 cleanup'
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $cleanupProcess -Name 'absent' `
        -Context 'H3 cleanup.process') `
        -Context 'H3 cleanup process absence'
    $cleanupFirewall = Get-I05RequiredProperty `
        -Object $cleanupDocument -Name 'firewall' `
        -Context 'H3 cleanup'
    foreach ($field in @(
        'peer_rule_absent',
        'control_rule_absent',
        'isolation_rules_absent',
        'inventory_restored'
    )) {
        Assert-I05True -Value (Get-I05RequiredProperty `
            -Object $cleanupFirewall -Name $field `
            -Context 'H3 cleanup.firewall') `
            -Context "H3 cleanup firewall $field"
    }
    $isolationRuleCount = Get-I05RequiredProperty `
        -Object $cleanupFirewall -Name 'isolation_rule_count' `
        -Context 'H3 cleanup.firewall'
    if (($isolationRuleCount -isnot [int] -and
         $isolationRuleCount -isnot [long]) -or
        [Int64]$isolationRuleCount -ne 10) {
        throw 'H3 cleanup isolation_rule_count is not the JSON integer 10.'
    }
    $completeContainment = Get-I05RequiredProperty `
        -Object $completeFrame.document -Name 'containment' `
        -Context 'COMPLETE'
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $cleanupFirewall -Name 'isolation_rule_names_sha256' `
        -Context 'H3 cleanup.firewall')) `
        -Expected ([string]$completeContainment.rule_names_sha256) `
        -Context 'H3 cleanup isolation rule-name hash' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $cleanupFirewall -Name 'isolation_spec_sha256' `
        -Context 'H3 cleanup.firewall')) `
        -Expected ([string]$completeContainment.spec_sha256) `
        -Context 'H3 cleanup isolation spec hash' -IgnoreCase
    Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
        -Object $cleanupFirewall `
        -Name 'isolation_spec_document_sha256' `
        -Context 'H3 cleanup.firewall')) `
        -Expected ([string]$completeContainment.spec_document_sha256) `
        -Context 'H3 cleanup isolation spec-document hash' -IgnoreCase
    $null = Assert-I05Sha256 -Value (Get-I05RequiredProperty `
        -Object $cleanupFirewall `
        -Name 'isolation_inventory_after_sha256' `
        -Context 'H3 cleanup.firewall') `
        -Context 'H3 cleanup isolation after-inventory hash'
    $cleanupIsolationStateBefore = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $cleanupFirewall `
            -Name 'isolation_state_before_sha256' `
            -Context 'H3 cleanup.firewall'
    ) -Context 'H3 cleanup isolation state before'
    $cleanupIsolationStateAfter = Assert-I05Sha256 -Value (
        Get-I05RequiredProperty -Object $cleanupFirewall `
            -Name 'isolation_state_after_sha256' `
            -Context 'H3 cleanup.firewall'
    ) -Context 'H3 cleanup isolation state after'
    Assert-I05ExactText -Actual $cleanupIsolationStateBefore `
        -Expected ([string]$completeContainment.state_before_sha256) `
        -Context 'COMPLETE/cleanup original firewall state' -IgnoreCase
    Assert-I05ExactText -Actual $cleanupIsolationStateAfter `
        -Expected $cleanupIsolationStateBefore `
        -Context 'H3 cleanup restored firewall state' -IgnoreCase
    $cleanupCapture = Get-I05RequiredProperty `
        -Object $cleanupDocument -Name 'capture' `
        -Context 'H3 cleanup'
    foreach ($field in @(
        'stopped',
        'owned_filters_absent',
        'etw_session_absent',
        'filter_inventory_restored'
    )) {
        Assert-I05True -Value (Get-I05RequiredProperty `
            -Object $cleanupCapture -Name $field `
            -Context 'H3 cleanup.capture') `
            -Context "H3 cleanup capture $field"
    }
    $restoration = Get-I05RequiredProperty `
        -Object $cleanupDocument -Name 'restoration' `
        -Context 'H3 cleanup'
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $restoration -Name 'ipv6_binding_enabled' `
        -Context 'H3 cleanup.restoration') `
        -Context 'H3 cleanup IPv6 binding'
    if ([int](Get-I05RequiredProperty -Object $restoration `
            -Name 'ipv6_mode' `
            -Context 'H3 cleanup.restoration') -ne 0 -or
        [int](Get-I05RequiredProperty -Object $restoration `
            -Name 'kad_network_mask' `
            -Context 'H3 cleanup.restoration') -ne 0 -or
        [int](Get-I05RequiredProperty -Object $restoration `
            -Name 'network_kademlia' `
            -Context 'H3 cleanup.restoration') -ne 0) {
        throw 'H3 cleanup restoration profile is not IPv4/Kad-off.'
    }
    Assert-I05True -Value (Get-I05RequiredProperty `
        -Object $cleanupDocument -Name 'cleanup_complete' `
        -Context 'H3 cleanup') -Context 'H3 cleanup completion'
    Confirm-I05SourceControlFrame -Stream $controlStream `
        -Frame $cleanupFrame -Nonce $nonce
    $remoteCleanupStatus = 'PASS'
    $formalStatus = 'PASS'
    $formalClassification = 'PASS'
    $formalCategory = 'all-gates-passed'
} catch {
    $caughtException = $_
    if ($null -eq $run) {
        throw
    }
    $failureCode = switch ($stage) {
        'ipv6-probe' { 'ipv6-preflight-incomplete' }
        'control-ready' { 'physical-control-ready-incomplete' }
        'source-prepare' { 'source-preparation-failed' }
        'source-profile' { 'source-profile-failed' }
        'source-start' { 'source-start-failed' }
        'command' { 'command-delivery-failed' }
        'transfer' { 'transfer-or-route-failed' }
        'remote-cleanup' { 'remote-cleanup-incomplete' }
        default { 'precondition-failed' }
    }
    if (-not $failureCodes.Contains($failureCode)) {
        $failureCodes.Add($failureCode)
    }
    $classification = ''
    if ($null -ne $_.Exception -and
        $null -ne $_.Exception.Data -and
        $_.Exception.Data.Contains('I05Classification')) {
        $classification =
            [string]$_.Exception.Data['I05Classification']
    }
    if ($classification -eq 'PRODUCT_INVARIANT') {
        $formalClassification = 'PRODUCT_INVARIANT'
        if ($_.Exception.Data.Contains('I05Category')) {
            $formalCategory = [string]$_.Exception.Data['I05Category']
        }
        if (-not $failureCodes.Contains('product-invariant')) {
            $failureCodes.Add('product-invariant')
        }
        $formalStatus = 'FAIL'
    } else {
        $formalClassification = if ($classification) {
            $classification
        } else {
            'LAB_BLOCKED'
        }
        if ($_.Exception.Data.Contains('I05Category')) {
            $formalCategory = [string]$_.Exception.Data['I05Category']
        } else {
            $formalCategory = 'unclassified-lab-precondition'
        }
        if ($classification -eq 'LAB_BLOCKED' -and
            -not $failureCodes.Contains('remote-lab-blocked')) {
            $failureCodes.Add('remote-lab-blocked')
        }
        $formalStatus = 'BLOCKED'
    }
} finally {
    Stop-I05SourceProbe
    Remove-I05SourceProbeFirewall
    if ($null -ne $controlStream) {
        try { $controlStream.Dispose() } catch {}
        $controlStream = $null
    }
    if ($null -ne $controlClient) {
        try { $controlClient.Close() } catch {}
        $controlClient = $null
    }
    if ($null -ne $network) {
        try {
            $bindingsFinal = @(
                Get-NetAdapterBinding -Name $network.interface_alias `
                    -ComponentID 'ms_tcpip6' `
                    -ErrorAction SilentlyContinue
            )
            $postBindingVerified =
                $bindingsFinal.Count -eq 1 -and
                [bool]$bindingsFinal[0].Enabled
        } catch {
            $postBindingVerified = $false
        }
    }
    if ($formalStatus -eq 'PASS' -and -not $postBindingVerified) {
        $formalStatus = 'BLOCKED'
        $formalClassification = 'LAB_BLOCKED'
        $formalCategory = 'final-ipv6-binding-not-proved'
        if (-not $failureCodes.Contains(
                'final-ipv6-binding-not-proved')) {
            $failureCodes.Add('final-ipv6-binding-not-proved')
        }
    }
    if ($formalStatus -eq 'PASS' -and
        (-not $sourceIpv6ModeVerified -or
         -not $sourceKad6OffVerified -or
         -not $sourceFirstApiNetworksOffVerified)) {
        $formalStatus = 'FAIL'
        $formalClassification = 'PRODUCT_INVARIANT'
        $formalCategory = 'final-ipv4-profile-not-proved'
        if (-not $failureCodes.Contains(
                'final-ipv4-profile-not-proved')) {
            $failureCodes.Add('final-ipv4-profile-not-proved')
        }
    }
    if ($null -ne $run -and
        -not [string]::IsNullOrWhiteSpace($ownershipPath) -and
        (Test-Path -LiteralPath $ownershipPath -PathType Leaf)) {
        try {
            & (Join-Path $PSScriptRoot `
                'cleanup_v91_i05_t1_source.ps1') `
                -RunRoot $run -NoOpen
            $cleanupStatus = 'PASS'
        } catch {
            $cleanupStatus = 'FAIL'
            if (-not $failureCodes.Contains('local-cleanup-incomplete')) {
                $failureCodes.Add('local-cleanup-incomplete')
            }
            if ($formalStatus -ne 'FAIL') {
                $formalStatus = 'BLOCKED'
                $formalClassification = 'LAB_BLOCKED'
                $formalCategory = 'local-cleanup-incomplete'
            }
        }
    }
    $finishedAt = [DateTime]::UtcNow
    if ($null -ne $run -and $null -ne $evidence) {
        $summary = [ordered]@{
            schema = 'ese.v91.i05.t1-source-summary/v1'
            case_id = $constants.case_id
            topology = $constants.topology
            formal_status = $formalStatus
            started_at_utc = $startedAt.ToString('o')
            finished_at_utc = $finishedAt.ToString('o')
            duration_seconds = [Math]::Round(
                ($finishedAt - $startedAt).TotalSeconds, 3)
            candidate = [ordered]@{
                version = $constants.candidate_version
                commit = $constants.candidate_commit
                dirty = $false
                emule_sha256 =
                    $constants.candidate_emule_sha256
                ese_server_sha256 =
                    $constants.candidate_ese_server_sha256
                build_info_sha256 =
                    $constants.candidate_build_info_sha256
                zip_sha256 = $constants.candidate_zip_sha256
                zip_bytes = $constants.candidate_zip_bytes
            }
            fixture = [ordered]@{
                name = $constants.fixture_name
                bytes = $constants.fixture_bytes
                sha256 = $constants.fixture_sha256
                ed2k = $constants.fixture_ed2k
                external_canonical = $true
                hardlink_only = $true
            }
            gates = [ordered]@{
                remote_ready = $remoteReadyStatus
                remote_started = $remoteStartedStatus
                remote_complete = $remoteCompleteStatus
                remote_evidence_bundle = $remoteEvidenceBundleStatus
                source_capture = $sourceCaptureStatus
                remote_cleanup = $remoteCleanupStatus
                local_cleanup = $cleanupStatus
                physical_ipv4_socket_observed = $routeObserved
                ipv6_peer_socket_observed =
                    $unexpectedIpv6Observed
            }
            policy = [ordered]@{
                os_ipv6_binding_preserved = $postBindingVerified
                candidate_ipv6_mode_zero_verified =
                    $sourceIpv6ModeVerified
                candidate_kad6_off_verified =
                    $sourceKad6OffVerified
                candidate_kad2_off_verified =
                    $sourceKad6OffVerified
                first_api_networks_off_verified =
                    $sourceFirstApiNetworksOffVerified
                direct_link_only = $true
                third_party_sources_forbidden = $true
                data_family = 'IPv4'
                forbidden_interface_pattern =
                    $constants.forbidden_interface_pattern
                packet_capture_required_for_pass = $true
                packet_capture_host = 'H3'
                h1_pktmon_or_etw_created = $false
            }
            failure_codes = $failureCodes.ToArray()
            classification = [ordered]@{
                value = $formalClassification
                category = $formalCategory
                fail_precedes_cleanup_blocked = $true
            }
            remote_failure = [ordered]@{
                classification = $remoteFailureClassification
                phase = $remoteFailurePhase
            }
            evidence = [ordered]@{
                config_receipt =
                    'evidence\config-receipt.json'
                source_start = 'evidence\source-start.json'
                command_receipt =
                    'evidence\command-receipt.json'
                samples = 'evidence\samples.jsonl'
                route = 'evidence\data-route.json'
                cleanup = 'evidence\cleanup.json'
                h3_bundle = if ($remoteEvidenceBundlePath) {
                    'evidence\h3-evidence-bundle.zip'
                } else { '' }
                h3_extracted = if ($remoteEvidenceBundlePath) {
                    'evidence\h3-evidence'
                } else { '' }
            }
            privacy = [ordered]@{
                nonce_included = $false
                ip_address_included = $false
                hostname_included = $false
                user_path_included = $false
                password_included = $false
                raw_coordination_excluded_from_summary = $true
            }
        }
        $summaryPath = Write-LabJson -Value $summary `
            -Path (Join-Path $evidence 'summary.json')
        $resultLines = @(
            "V91-I05 T1 SOURCE $formalStatus"
            "candidate_commit=$($constants.candidate_commit)"
            "fixture_sha256=$($constants.fixture_sha256)"
            "route_observed=$routeObserved"
            "source_capture=$sourceCaptureStatus"
            "local_cleanup=$cleanupStatus"
            'summary=evidence\summary.json'
        )
        $null = Write-LabText -Value (
            ($resultLines -join "`r`n") + "`r`n"
        ) -Path (Join-Path $run 'RESULT-V91-I05-T1.txt')
    }
}

if ($formalStatus -ne 'PASS') {
    $codes = if ($failureCodes.Count -gt 0) {
        $failureCodes.ToArray() -join ','
    } else {
        'unspecified'
    }
    throw (
        "V91-I05 T1 source result is $formalStatus ($codes). " +
        "Review the sanitized evidence summary under '$run'."
    )
}

Write-Host 'V91-I05 T1 SOURCE PASS' -ForegroundColor Green
Write-Host "Run: $run"
