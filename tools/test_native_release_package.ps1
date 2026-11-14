[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][ValidateSet('x64', 'Win32')][string]$Architecture
)

$ErrorActionPreference = 'Stop'
$Architecture = if ($Architecture -eq 'Win32') { 'Win32' } else { 'x64' }
. (Join-Path $PSScriptRoot 'release_fingerprint.ps1')
. (Join-Path $PSScriptRoot 'start_v93_detached_process.ps1')
Add-Type -AssemblyName System.Net.Http

if (-not ('EseV93.NativeSmokeProfile' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace EseV93 {
    public static class NativeSmokeProfile {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern bool WritePrivateProfileString(string section, string key, string value, string path);
    }
}
'@
}

function Get-LoopbackPort {
    $server = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try { $server.Start(); return $server.LocalEndpoint.Port }
    finally { $server.Stop() }
}

function Get-WebChallenge {
    param(
        [Net.Http.HttpClient]$Client,
        [string]$BaseAddress,
        $StartingProcess,
        [DateTime]$ReadyUntil = [DateTime]::MinValue
    )
    # The native listener opens before the classic web dispatcher is ready.
    do {
        try {
            $response = $Client.GetAsync("$BaseAddress/").GetAwaiter().GetResult()
            break
        } catch [Net.Http.HttpRequestException] {
            if (-not $StartingProcess -or $StartingProcess.HasExited -or [DateTime]::UtcNow -ge $ReadyUntil) { throw }
            Start-Sleep -Milliseconds 200
        }
    } while ($true)
    try {
        $null = $response.EnsureSuccessStatusCode()
        $page = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    } finally { $response.Dispose() }
    $matches = [regex]::Matches($page, 'name=["'']n["''][^>]*value=["'']([0-9a-fA-F]{64})["'']')
    if ($matches.Count -ne 1) { throw 'Native web login did not issue a challenge' }
    return $matches[0].Groups[1].Value.ToLowerInvariant()
}

function New-LoopbackWebClient {
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(3)
    return $client
}

$archivePath = (Resolve-Path -LiteralPath $Archive).Path
$digest = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
$checksum = (Get-Content -LiteralPath "$archivePath.sha256" -Raw).Trim()
if ($checksum -ne "$digest  $([IO.Path]::GetFileName($archivePath))") {
    throw "$Architecture ZIP checksum does not match the selected archive"
}
$work = Join-Path ([IO.Path]::GetTempPath()) "ese-v93-$($Architecture.ToLowerInvariant())-package-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $work | Out-Null
Expand-Archive -LiteralPath $archivePath -DestinationPath $work
$manifestPath = Join-Path $work "third_party\quic\manifest-$Architecture.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 'ese.quic.release-dependencies/v1' -or $manifest.architecture -cne $Architecture) {
    throw "$Architecture archive does not carry the matching release dependency manifest"
}
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
$exe = Join-Path $work 'emule.exe'
Assert-ReleaseQuicBinary -BinaryPath $exe -QuicManifestSha256 $manifestHash -Architecture $Architecture
foreach ($image in Get-ChildItem -LiteralPath $work -Recurse -File) {
    if ($image.Extension -in @('.exe', '.dll')) {
        Assert-ReleasePEArchitecture -BinaryPath $image.FullName -Architecture $Architecture
    }
}

$webPort = Get-LoopbackPort
do { $tcpPort = Get-LoopbackPort } while ($tcpPort -eq $webPort)
$storedHash = [Guid]::NewGuid().ToString('N')
$ini = Join-Path $work 'config\preferences.ini'
$settings = [ordered]@{
    eMule = @{
        AutoConnect='0'; AutoStart='0'; AutoTakeED2KLinks='0'; NetworkED2K='0'; NetworkKademlia='0';
        UsePublicUserDirectories='2'; OpenPortsOnStartUp='0'; BindAddr='127.0.0.1'; Port=[string]$tcpPort;
        UDPPort='0'; SaveLogToDisk='1'; RunAsUnprivilegedUser='0'
    }
    Connection = @{ IPv6Mode='0'; KadNetworkMask='0' }
    UPnP = @{ EnableUPnP='0' }
    WebServer = @{ Enabled='1'; Port=[string]$webPort; Password=$storedHash; WebUseUPnP='0'; AllowAdminHiLevelFunc='1' }
}
foreach ($section in $settings.Keys) {
    foreach ($key in $settings[$section].Keys) {
        if (-not [EseV93.NativeSmokeProfile]::WritePrivateProfileString($section,$key,$settings[$section][$key],$ini)) {
            throw "Cannot set $Architecture smoke preference [$section] $key"
        }
    }
}

$process = $null
$untrusted = $null
$admin = $null
$previousCpuOverride = $env:GNUTLS_CPUID_OVERRIDE
$stage = 'private desktop startup'
try {
    $env:GNUTLS_CPUID_OVERRIDE = $null
    # The dedicated native listener mode also suppresses dashboard autostart.
    $process = Start-V93DetachedProcess -FilePath $exe -WorkingDirectory $work `
        -ArgumentList @('--portable','--headless','--ignoreinstances',"--metrics-port=$webPort")
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    do {
        if ($process.HasExited) { throw "$Architecture package exited before opening the native WebServer" }
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $webPort `
            -OwningProcess $process.Id -ErrorAction SilentlyContinue)
        if ($listeners.Count) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $listeners.Count -or @($listeners | Where-Object { $_.LocalAddress -notin @('127.0.0.1','::1') }).Count) {
        throw 'Expected an owned native loopback WebServer listener'
    }

    $baseAddress = "http://127.0.0.1:$webPort"
    $untrusted = New-LoopbackWebClient
    $stage = 'initial login challenge'
    $nonce = Get-WebChallenge $untrusted $baseAddress -StartingProcess $process -ReadyUntil $deadline
    $stage = 'invalid challenge rejection'
    $bad = $untrusted.GetAsync("$baseAddress/?w=password&n=$nonce&r=$('0' * 64)").GetAwaiter().GetResult()
    try {
        if ($bad.Headers.Contains('X-CSRF-Token') -or $bad.Headers.Contains('Set-Cookie')) {
            throw 'Native WebServer accepted an invalid challenge response'
        }
    } finally { $bad.Dispose() }
    $stage = 'post-rejection login challenge'
    $null = Get-WebChallenge $untrusted $baseAddress

    $admin = New-LoopbackWebClient
    $stage = 'fresh admin login challenge'
    $nonce = Get-WebChallenge $admin $baseAddress
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $proof = ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::ASCII.GetBytes($nonce + $storedHash)))).Replace('-','').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
    $stage = 'valid challenge authentication'
    $login = $admin.GetAsync("$baseAddress/?w=password&n=$nonce&r=$proof").GetAwaiter().GetResult()
    try {
        $csrf = if ($login.Headers.Contains('X-CSRF-Token')) { @($login.Headers.GetValues('X-CSRF-Token'))[0] } else { '' }
        $cookie = if ($login.Headers.Contains('Set-Cookie')) { @($login.Headers.GetValues('Set-Cookie'))[0] } else { '' }
        if (-not $login.IsSuccessStatusCode -or $csrf -cnotmatch '^[0-9a-f]{64}$' -or
            $cookie -cnotmatch '^eSEWebSession=[0-9a-f]{64}; Path=/; HttpOnly; SameSite=Strict$') {
            throw "Native WebServer did not establish an authenticated admin session (HTTP $([int]$login.StatusCode))"
        }
    } finally { $login.Dispose() }
    $stage = 'authenticated shutdown'
    $close = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, "$baseAddress/?w=close")
    try {
        $close.Headers.Add('X-CSRF-Token', $csrf)
        $close.Headers.Add('Sec-Fetch-Site', 'same-origin')
        $closing = $null
        # A successful shutdown can stop the socket before the reply arrives.
        try { $closing = $admin.SendAsync($close).GetAwaiter().GetResult() }
        catch [Net.Http.HttpRequestException] { if ($process.HasExited -and $process.ExitCode -ne 0) { throw } }
        if ($closing) {
            try {
                if (-not $closing.IsSuccessStatusCode -or -not $closing.Headers.Contains('Set-Cookie') -or
                    @($closing.Headers.GetValues('Set-Cookie'))[0] -cnotmatch '^eSEWebSession=; Path=/; Max-Age=0;') {
                    throw 'Native WebServer did not accept authenticated shutdown'
                }
            } finally { $closing.Dispose() }
        }
    } finally { $close.Dispose() }
    if (-not $process.WaitForExit(15000) -or $process.ExitCode -ne 0) {
        throw "Authenticated $Architecture shutdown did not finish cleanly"
    }
    Write-Host "$Architecture ZIP native web challenge and shutdown PASS ($($process.Desktop)); extracted evidence: $work"
} catch {
    $cause = $_.Exception.GetBaseException().Message
    throw "$Architecture ZIP smoke failed during $stage ($work): $cause"
} finally {
    $env:GNUTLS_CPUID_OVERRIDE = $previousCpuOverride
    if ($admin) { $admin.Dispose() }
    if ($untrusted) { $untrusted.Dispose() }
    if ($process) {
        if (-not $process.HasExited) { $process.StopIncompleteLaunch() }
        $process.Dispose()
    }
}
