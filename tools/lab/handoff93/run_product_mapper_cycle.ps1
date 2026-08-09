[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExePath,
    [Parameter(Mandatory = $true)][string]$PackageRoot,
    [Parameter(Mandatory = $true)][string]$ConfigRoot,
    [Parameter(Mandatory = $true)][string]$IniPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedExeSha256,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$TcpPort,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$UdpPort,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$WebPort,
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()][string]$ApiToken,
    [ValidateRange(1, 900)][int]$ObservationTimeoutSec = 180,
    [ValidateRange(1, 120)][int]$ShutdownTimeoutSec = 30
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot '..\common.ps1')
. (Join-Path $PSScriptRoot '..\v91_r01_upnp.ps1')

function Assert-R93NoReparseChain {
    param([string]$Root, [string]$Path, [string]$Label)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not [string]::Equals($pathFull, $rootFull,
            [StringComparison]::OrdinalIgnoreCase) -and
        -not $pathFull.StartsWith(
            $rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes its approved root."
    }
    $volumeRoot = [IO.Path]::GetPathRoot($pathFull).TrimEnd('\')
    $cursor = $volumeRoot
    foreach ($segment in @($pathFull.Substring(
                    [IO.Path]::GetPathRoot($pathFull).Length) `
                -split '\\' | Where-Object { $_ })) {
        $cursor = Join-Path $cursor $segment
        if (-not (Test-Path -LiteralPath $cursor)) {
            throw "$Label contains an absent path component."
        }
        if ((Get-Item -LiteralPath $cursor -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw "$Label contains a reparse path component."
        }
    }
    return $pathFull
}

function Test-R93PortBindable {
    param([ValidateSet('TCP', 'UDP')][string]$Protocol, [int]$Port)
    $socket = $null
    try {
        if ($Protocol -ceq 'TCP') {
            $socket = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, $Port)
            $socket.Server.ExclusiveAddressUse = $true
            $socket.Start(1)
        } else {
            $socket = [Net.Sockets.UdpClient]::new()
            $socket.ExclusiveAddressUse = $true
            $socket.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Any, $Port))
        }
        return $true
    } catch { return $false }
    finally {
        if ($null -ne $socket) {
            try { if ($Protocol -ceq 'TCP') { $socket.Stop() }
                else { $socket.Dispose() } } catch {}
        }
    }
}

function Set-R93ProductIni {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][int]$WebPort
    )
    Set-LabIniValue $Path UPnP EnableUPnP 1 | Out-Null
    Set-LabIniValue $Path eMule Port $TcpPort | Out-Null
    Set-LabIniValue $Path eMule UDPPort $UdpPort | Out-Null
    Set-LabIniValue $Path WebServer Enabled 1 | Out-Null
    Set-LabIniValue $Path WebServer Port $WebPort | Out-Null
}

function Restore-R93IniBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    [IO.File]::WriteAllBytes($Path, $Bytes)
    return (Get-FileHash $Path -Algorithm SHA256).Hash -ceq $ExpectedSha256
}

function Get-R93CandidateProjection {
    param(
        [Parameter(Mandatory = $true)]$Envelope,
        [Parameter(Mandatory = $true)][int]$ExpectedTcpPort,
        [Parameter(Mandatory = $true)][int]$ExpectedUdpPort
    )
    if (-not [bool]$Envelope.available -or $null -eq $Envelope.data -or
        [string]$Envelope.data.schema -cne 'ESE_REACH_STATUS_V1') {
        throw 'Projected reach status is unavailable or invalid.'
    }
    $tcp = $Envelope.data.planes.ed2k_tcp_v4
    $udp = $Envelope.data.planes.kad_udp_v4
    if ($null -eq $tcp -or $null -eq $udp) {
        throw 'Projected reach status lacks mapper planes.'
    }
    $topGeneration = [uint64]$Envelope.data.topology_generation
    $tcpGeneration = [uint64]$tcp.generation
    $udpGeneration = [uint64]$udp.generation
    $coherent = $topGeneration -gt 0 -and
        $tcpGeneration -eq $topGeneration -and
        $udpGeneration -eq $topGeneration -and
        [uint64]$tcp.lease.generation -eq $topGeneration -and
        [uint64]$udp.lease.generation -eq $topGeneration -and
        [string]$tcp.lease.transport -ceq 'Tcp' -and
        [string]$udp.lease.transport -ceq 'Udp' -and
        [int]$tcp.local.port -eq $ExpectedTcpPort -and
        [int]$udp.local.port -eq $ExpectedUdpPort -and
        [int]$tcp.lease.requested_external_port -eq $ExpectedTcpPort -and
        [int]$udp.lease.requested_external_port -eq $ExpectedUdpPort -and
        [int]$tcp.lease.granted_external_port -gt 0 -and
        [int]$udp.lease.granted_external_port -gt 0 -and
        [int]$tcp.mapped.port -eq [int]$tcp.lease.granted_external_port -and
        [int]$tcp.advertised.port -eq [int]$tcp.lease.granted_external_port -and
        [int]$udp.mapped.port -eq [int]$udp.lease.granted_external_port -and
        [int]$udp.advertised.port -eq [int]$udp.lease.granted_external_port -and
        [bool]$tcp.lease.owned_by_us -and
        [bool]$udp.lease.owned_by_us -and
        [bool]$tcp.lease.structurally_valid -and
        [bool]$udp.lease.structurally_valid -and
        [bool]$tcp.primary_evidence.current -and
        [bool]$udp.primary_evidence.current
    return [pscustomobject]@{
        same_generation = $coherent
        generation = $topGeneration
        tcp_candidate = [string]$tcp.gate_state -ceq 'CANDIDATE'
        udp_candidate = [string]$udp.gate_state -ceq 'CANDIDATE'
    }
}

function Invoke-R93PartialCycle {
    param(
        [Parameter(Mandatory = $true)]$Adapters,
        [ValidateRange(1, 10000)][int]$MaxSamples = 180
    )
    $started = $false
    $accredited = $false
    $token = $null
    $observed = $false
    $closed = $false
    $absent = $false
    $restored = $false
    $failureClass = ''
    try {
        & $Adapters.Configure
        $token = & $Adapters.Start
        $started = $true
        if (-not [bool](& $Adapters.Exists $token)) {
            throw 'Launched process no longer exists.'
        }
        $accredited = [bool](& $Adapters.IsAccredited $token)
        if (-not $accredited) {
            $failureClass = 'IDENTITY_NOT_ACCREDITED'
            throw 'Launched process identity is not accredited.'
        }
        for ($sampleIndex = 0; $sampleIndex -lt $MaxSamples; $sampleIndex++) {
            $sample = & $Adapters.Sample
            if ($null -ne $sample -and [bool]$sample.tcp_candidate -and
                [bool]$sample.udp_candidate -and [bool]$sample.same_generation -and
                [uint64]$sample.generation -gt 0) {
                $observed = $true
                break
            }
            & $Adapters.Pause
        }
        if (-not $observed) { $failureClass = 'CANDIDATE_PAIR_NOT_OBSERVED' }
    } catch {
        if ([string]::IsNullOrEmpty($failureClass)) {
            $failureClass = 'EXECUTION_FAILED'
        }
    }
    finally {
        if ($started) {
            try {
                $exists = [bool](& $Adapters.Exists $token)
                if ($exists -and $accredited -and
                    [bool](& $Adapters.IsAccredited $token)) {
                    & $Adapters.Close $token
                    $waited = [bool](& $Adapters.WaitForExit $token)
                    $closed = $waited -and -not [bool](& $Adapters.Exists $token)
                } elseif (-not $exists -and $accredited) { $closed = $true }
                elseif ($exists) { $failureClass = 'IDENTITY_NOT_ACCREDITED' }
            } catch { $closed = $false }
            if (-not $closed -and $failureClass -cne 'IDENTITY_NOT_ACCREDITED') {
                $failureClass = 'PROCESS_STILL_ALIVE'
            }
        }
        if ($started -and $closed) {
            try { $absent = [bool](& $Adapters.MappingsAbsent) }
            catch { $absent = $false }
            if (-not $absent) { $failureClass = 'MAPPING_REMAINS_UNTOUCHED' }
        }
        try { $restored = [bool](& $Adapters.RestoreIni) }
        catch { $restored = $false }
        if (-not $restored -and $failureClass -cne 'PROCESS_STILL_ALIVE') {
            $failureClass = 'INI_RESTORE_FAILED'
        }
    }
    $success = $observed -and $closed -and $absent -and $restored
    $blocked = -not $success -and
        $failureClass -in @('PROCESS_STILL_ALIVE', 'IDENTITY_NOT_ACCREDITED',
            'MAPPING_REMAINS_UNTOUCHED')
    return [pscustomobject][ordered]@{
        schema = 'ese.lab.product-mapper-cycle-partial/v1'
        status = if ($success) { 'MAPPING_OBSERVED_CLEAN_EXIT' } elseif ($blocked) {
            'BLOCKED'
        } else { 'FAIL' }
        satisfies_h93_15 = $false
        candidate_pair_same_generation = $observed
        graceful_exit = $closed
        mappings_absent = $absent
        ini_restored_byte_exact = $restored
        intervention_required = $failureClass -in @(
            'PROCESS_STILL_ALIVE', 'IDENTITY_NOT_ACCREDITED')
        failure_class = if ($success) { $null } else { $failureClass }
    }
}

function Send-R93WmClose {
    param([int]$ProcessId)
    if ($null -eq ('R93WmClose' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class R93WmClose {
 delegate bool EnumProc(IntPtr h, IntPtr p);
 [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc c, IntPtr p);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
 [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
 public static int Send(int expected) { var ws=new List<IntPtr>(); EnumWindows(delegate(IntPtr h,IntPtr x){uint p;GetWindowThreadProcessId(h,out p);if(p==(uint)expected)ws.Add(h);return true;},IntPtr.Zero);int n=0;foreach(var h in ws)if(PostMessage(h,0x0010,IntPtr.Zero,IntPtr.Zero))n++;return n; }
}
'@
    }
    return [R93WmClose]::Send($ProcessId)
}

function Get-R93PhysicalSoapBackend {
    foreach ($route in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' `
                -AddressFamily IPv4 -ErrorAction Stop |
                Sort-Object RouteMetric)) {
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex `
            -ErrorAction SilentlyContinue
        if ($null -eq $adapter -or -not $adapter.HardwareInterface -or
            $adapter.Virtual -or $adapter.Status -cne 'Up') { continue }
        $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex `
            -AddressFamily IPv4 -AddressState Preferred -ErrorAction Stop |
            Where-Object { -not $_.SkipAsSource })
        if ($addresses.Count -ne 1) { throw 'Physical route address is ambiguous.' }
        return New-R01UpnpBackend ([string]$addresses[0].IPAddress) `
            ([string]$route.NextHop)
    }
    throw 'No physical IPv4 default route is available.'
}

$package = Assert-R93NoReparseChain -Root $PackageRoot -Path $PackageRoot `
    -Label PackageRoot
$config = Assert-R93NoReparseChain -Root $package -Path $ConfigRoot `
    -Label ConfigRoot
$exe = Assert-R93NoReparseChain -Root $package -Path $ExePath -Label ExePath
$ini = Assert-R93NoReparseChain -Root $config -Path $IniPath -Label IniPath
if ($TcpPort -eq $UdpPort -or $TcpPort -eq $WebPort -or $UdpPort -eq $WebPort) {
    throw 'Explicit ports must be distinct.'
}
$exeHash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($exeHash -cne $ExpectedExeSha256.ToLowerInvariant()) { throw 'Executable hash mismatch.' }
if (@(Get-CimInstance Win32_Process | Where-Object {
            [string]::Equals([string]$_.ExecutablePath, $exe,
                [StringComparison]::OrdinalIgnoreCase) }).Count -ne 0) {
    throw 'Explicit executable already has a live instance.'
}
if (-not (Test-R93PortBindable TCP $TcpPort) -or
    -not (Test-R93PortBindable UDP $UdpPort) -or
    -not (Test-R93PortBindable TCP $WebPort)) { throw 'Explicit port is unavailable.' }

$iniBytes = [IO.File]::ReadAllBytes($ini)
$iniHash = (Get-FileHash $ini -Algorithm SHA256).Hash
$process = $null
$backend = $null
$baseUrl = "http://127.0.0.1:$WebPort"
$adapters = [pscustomobject]@{
    Configure = { Set-R93ProductIni $ini $TcpPort $UdpPort $WebPort }
    Start = { $script:process = Start-Process -FilePath $exe `
            -WorkingDirectory $package `
            -ArgumentList @('--portable','--ignoreinstances','--headless') `
            -WindowStyle Hidden -PassThru; return $script:process.Id }
    Exists = { param($token) @(Get-CimInstance Win32_Process `
            -Filter "ProcessId=$token").Count -eq 1 }
    IsAccredited = { param($token)
        $matches = @(Get-CimInstance Win32_Process -Filter "ProcessId=$token" |
            Where-Object { [string]::Equals([string]$_.ExecutablePath, $exe,
                    [StringComparison]::OrdinalIgnoreCase) })
        $matches.Count -eq 1 -and
            (Get-FileHash -LiteralPath ([string]$matches[0].ExecutablePath) `
                -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $exeHash }
    Sample = { $envelope = Invoke-LabApi -BaseUrl $baseUrl `
            -Path '/api/reach/status' -Token $ApiToken -AllowUnavailable
        if (-not $envelope.available) { return $null }
        Get-R93CandidateProjection $envelope $TcpPort $UdpPort }
    Pause = { Start-Sleep -Seconds 1 }
    Close = { param($token) if ((Send-R93WmClose $token) -lt 1) {
            throw 'No accredited window accepted WM_CLOSE.' } }
    WaitForExit = { param($token) $script:process.WaitForExit(
            $ShutdownTimeoutSec * 1000) }
    MappingsAbsent = { if ($null -eq $script:backend) {
            $script:backend = Get-R93PhysicalSoapBackend }
        $null -eq (Get-R01UpnpMapping $script:backend $TcpPort TCP) -and
        $null -eq (Get-R01UpnpMapping $script:backend $UdpPort UDP) }
    RestoreIni = { Restore-R93IniBytes $ini $iniBytes $iniHash }
}
$result = Invoke-R93PartialCycle -Adapters $adapters `
    -MaxSamples $ObservationTimeoutSec
$result | ConvertTo-Json -Compress
if ([string]$result.status -cne 'MAPPING_OBSERVED_CLEAN_EXIT') { exit 1 }
