[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Archive)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'release_fingerprint.ps1')
. (Join-Path $PSScriptRoot 'start_v93_detached_process.ps1')
Add-Type -AssemblyName System.Net.Http

if (-not ('EseV93.Win32SmokeProfile' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace EseV93 {
    public static class Win32SmokeProfile {
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

function Get-WebChallenge([Net.Http.HttpClient]$Client, [string]$BaseAddress) {
    $page = $Client.GetStringAsync("$BaseAddress/").GetAwaiter().GetResult()
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
    throw 'Win32 ZIP checksum does not match the selected archive'
}
$work = Join-Path ([IO.Path]::GetTempPath()) ('ese-v93-win32-package-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
Expand-Archive -LiteralPath $archivePath -DestinationPath $work
$manifestPath = Join-Path $work 'third_party\quic\manifest-Win32.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 'ese.quic.release-dependencies/v1' -or $manifest.architecture -ne 'Win32') {
    throw 'Win32 archive does not carry a release dependency manifest'
}
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
$exe = Join-Path $work 'emule.exe'
Assert-ReleaseQuicBinary -BinaryPath $exe -QuicManifestSha256 $manifestHash -Architecture Win32
foreach ($image in Get-ChildItem -LiteralPath $work -Recurse -File) {
    if ($image.Extension -in @('.exe', '.dll')) {
        Assert-ReleasePEArchitecture -BinaryPath $image.FullName -Architecture Win32
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
    WebServer = @{ Enabled='1'; Port=[string]$webPort; Password=$storedHash; WebUseUPnP='0' }
}
foreach ($section in $settings.Keys) {
    foreach ($key in $settings[$section].Keys) {
        if (-not [EseV93.Win32SmokeProfile]::WritePrivateProfileString($section,$key,$settings[$section][$key],$ini)) {
            throw "Cannot set Win32 smoke preference [$section] $key"
        }
    }
}

$process = $null
$untrusted = $null
$admin = $null
$previousCpuOverride = $env:GNUTLS_CPUID_OVERRIDE
try {
    $env:GNUTLS_CPUID_OVERRIDE = $null
    $process = Start-V93DetachedProcess -FilePath $exe -WorkingDirectory $work `
        -ArgumentList @('--portable','--headless','--ignoreinstances')
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    do {
        if ($process.HasExited) { throw 'Win32 package exited before opening the native WebServer' }
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
    $nonce = Get-WebChallenge $untrusted $baseAddress
    $bad = $untrusted.GetAsync("$baseAddress/?w=password&n=$nonce&r=$('0' * 64)").GetAwaiter().GetResult()
    try {
        if ($bad.Headers.Contains('X-CSRF-Token')) { throw 'Native WebServer accepted an invalid challenge response' }
    } finally { $bad.Dispose() }
    $null = Get-WebChallenge $untrusted $baseAddress

    $admin = New-LoopbackWebClient
    $nonce = Get-WebChallenge $admin $baseAddress
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $proof = ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::ASCII.GetBytes($nonce + $storedHash)))).Replace('-','').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
    $login = $admin.GetAsync("$baseAddress/?w=password&n=$nonce&r=$proof").GetAwaiter().GetResult()
    try {
        $csrf = if ($login.Headers.Contains('X-CSRF-Token')) { @($login.Headers.GetValues('X-CSRF-Token'))[0] } else { '' }
        if (-not $login.IsSuccessStatusCode -or $csrf -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Native WebServer did not establish an authenticated admin session'
        }
    } finally { $login.Dispose() }
    $close = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, "$baseAddress/?w=close")
    try {
        $close.Headers.Add('X-CSRF-Token', $csrf)
        $close.Headers.Add('Sec-Fetch-Site', 'same-origin')
        try { $closing = $admin.SendAsync($close).GetAwaiter().GetResult(); $closing.Dispose() }
        catch { if ($process.HasExited -and $process.ExitCode -ne 0) { throw } }
    } finally { $close.Dispose() }
    if (-not $process.WaitForExit(15000) -or $process.ExitCode -ne 0) {
        throw 'Authenticated Win32 shutdown did not finish cleanly'
    }
    Write-Host "Win32 ZIP native web challenge and shutdown PASS ($($process.Desktop)); extracted evidence: $work"
} catch {
    throw "Win32 ZIP smoke failed ($work): $($_.Exception.Message)"
} finally {
    $env:GNUTLS_CPUID_OVERRIDE = $previousCpuOverride
    if ($admin) { $admin.Dispose() }
    if ($untrusted) { $untrusted.Dispose() }
    if ($process) {
        if (-not $process.HasExited) { $process.StopIncompleteLaunch() }
        $process.Dispose()
    }
}
