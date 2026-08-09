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

function Get-R93ProductProcessInventory {
    param([Parameter(Mandatory = $true)][string]$ExecutableName)
    $rows = @(Get-CimInstance Win32_Process -ErrorAction Stop |
        Where-Object { [string]::Equals([string]$_.Name, $ExecutableName,
                [StringComparison]::OrdinalIgnoreCase) })
    $inventory = @()
    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace([string]$row.ExecutablePath)) {
            throw 'A product process has no inspectable executable path.'
        }
        $canonicalPath = [IO.Path]::GetFullPath([string]$row.ExecutablePath)
        $creation = ([DateTime]$row.CreationDate).ToUniversalTime().ToString(
            'o', [Globalization.CultureInfo]::InvariantCulture)
        $inventory += [pscustomobject][ordered]@{
            pid = [int]$row.ProcessId
            canonical_path = $canonicalPath
            sha256 = (Get-FileHash -LiteralPath $canonicalPath -Algorithm SHA256).Hash.ToLowerInvariant()
            creation_time_utc = $creation
            session_id = [int]$row.SessionId
        }
    }
    return @($inventory | Sort-Object pid)
}

function Get-R93LockedExecutableSha256 {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw 'Executable lock stream is not readable and seekable.'
    }
    $Stream.Position = 0
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace(
            '-', '').ToLowerInvariant()
    } finally { $sha.Dispose(); $Stream.Position = 0 }
}

function Assert-R93LaunchedProcessHandleIdentity {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)]$ExpectedIdentity,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    try {
        if ($Process.HasExited -or [int]$Process.Id -ne [int]$ExpectedIdentity.pid) {
            throw 'Launched process handle no longer identifies a live process.'
        }
        $null = $Process.Handle
        $handleCreation = $Process.StartTime.ToUniversalTime().ToString(
            'o', [Globalization.CultureInfo]::InvariantCulture)
        $handleSession = [int]$Process.SessionId
    } catch { throw 'Launched process handle identity is unavailable.' }
    $expectedCreation = [DateTime]::ParseExact(
        [string]$ExpectedIdentity.creation_time_utc, 'o',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $handleCreationValue = [DateTime]::ParseExact($handleCreation, 'o',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    # Process.StartTime and CIM are backed by the same Windows creation time,
    # but CIM exposes microsecond precision, so conversion may differ by less
    # than one microsecond (ten 100-ns ticks).
    if ([Math]::Abs($handleCreationValue.Ticks - $expectedCreation.Ticks) -ge 10 -or
        $handleSession -ne [int]$ExpectedIdentity.session_id -or
        -not [string]::Equals([string]$ExpectedIdentity.canonical_path,
            $ExpectedPath, [StringComparison]::OrdinalIgnoreCase) -or
        [string]$ExpectedIdentity.sha256 -cne $ExpectedSha256) {
        throw 'Launched process handle and system identity disagree.'
    }
    $current = @(Get-R93ProductProcessInventory ([IO.Path]::GetFileName(
                    $ExpectedPath)) | Where-Object {
                [int]$_.pid -eq [int]$Process.Id })
    if ($current.Count -ne 1) {
        throw 'Launched process is absent or its PID was reused.'
    }
    $null = Assert-R93ExactProcessIdentitySet @($ExpectedIdentity) $current
    return $true
}

function Read-R93PreexistingProcessAllowlist {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)
    try {
        if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
            throw 'Allowlist stream is not readable and seekable.'
        }
        $Stream.Position = 0
        $reader = [IO.StreamReader]::new($Stream,
            [Text.UTF8Encoding]::new($true), $true, 1024, $true)
        try { $json = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $Stream.Position = 0
        $document = $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch { throw 'Preexisting process allowlist is not valid JSON.' }
    $documentFields = @($document.PSObject.Properties.Name | Sort-Object)
    if (($documentFields -join ',') -cne 'processes,schema' -or
        [string]$document.schema -cne 'ese.lab.preexisting-process-allowlist/v1') {
        throw 'Preexisting process allowlist has an unexpected schema.'
    }
    $result = @()
    $seen = @{}
    foreach ($entry in @($document.processes)) {
        $fields = @($entry.PSObject.Properties.Name | Sort-Object)
        if (($fields -join ',') -cne
            'canonical_path,creation_time_utc,pid,session_id,sha256') {
            throw 'Preexisting process identity has unexpected fields.'
        }
        if ([int64]$entry.pid -le 0 -or [int64]$entry.pid -gt [int]::MaxValue -or
            [int64]$entry.session_id -lt 0 -or
            [string]$entry.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Preexisting process identity has an invalid scalar.'
        }
        $parsedCreation = [DateTime]::MinValue
        if (-not [DateTime]::TryParseExact([string]$entry.creation_time_utc, 'o',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$parsedCreation) -or $parsedCreation.Kind -ne [DateTimeKind]::Utc) {
            throw 'Preexisting process creation time is not canonical UTC.'
        }
        $canonical = [IO.Path]::GetFullPath([string]$entry.canonical_path)
        $key = [string][int]$entry.pid
        if ($seen.ContainsKey($key)) { throw 'Preexisting process PID is duplicated.' }
        $seen[$key] = $true
        $result += [pscustomobject][ordered]@{
            pid = [int]$entry.pid; canonical_path = $canonical
            sha256 = ([string]$entry.sha256).ToLowerInvariant()
            creation_time_utc = $parsedCreation.ToString('o',
                [Globalization.CultureInfo]::InvariantCulture)
            session_id = [int]$entry.session_id
        }
    }
    return @($result | Sort-Object pid)
}

function Assert-R93ExactProcessIdentitySet {
    param([object[]]$Expected, [object[]]$Actual)
    $expectedArray = @($Expected | Sort-Object pid)
    $actualArray = @($Actual | Sort-Object pid)
    if ($expectedArray.Count -ne $actualArray.Count) {
        throw 'Product process set differs from the explicit allowlist.'
    }
    for ($index = 0; $index -lt $expectedArray.Count; $index++) {
        $left = $expectedArray[$index]; $right = $actualArray[$index]
        if ([int]$left.pid -ne [int]$right.pid -or
            -not [string]::Equals([string]$left.canonical_path,
                [string]$right.canonical_path,
                [StringComparison]::OrdinalIgnoreCase) -or
            [string]$left.sha256 -cne [string]$right.sha256 -or
            [string]$left.creation_time_utc -cne [string]$right.creation_time_utc -or
            [int]$left.session_id -ne [int]$right.session_id) {
            throw 'A preexisting product process changed identity.'
        }
    }
    return $true
}

function Assert-R93OneNewCandidateProcess {
    param(
        [object[]]$Before, [object[]]$After, [int]$LaunchedPid,
        [string]$ExpectedPath, [string]$ExpectedSha256
    )
    $beforePids = @{}; foreach ($item in @($Before)) { $beforePids[[int]$item.pid] = $true }
    $newItems = @($After | Where-Object { -not $beforePids.ContainsKey([int]$_.pid) })
    if ($newItems.Count -ne 1 -or [int]$newItems[0].pid -ne $LaunchedPid -or
        -not [string]::Equals([string]$newItems[0].canonical_path, $ExpectedPath,
            [StringComparison]::OrdinalIgnoreCase) -or
        [string]$newItems[0].sha256 -cne $ExpectedSha256) {
        throw 'Start did not create exactly one accredited candidate process.'
    }
    $survivors = @($After | Where-Object { $beforePids.ContainsKey([int]$_.pid) })
    $null = Assert-R93ExactProcessIdentitySet $Before $survivors
    return $newItems[0]
}

function Assert-R93NonFirstStartIni {
    param([Parameter(Mandatory = $true)][string]$Path)
    $required = @(
        [pscustomobject]@{ key = 'AppVersion'; value = 'R93_ISOLATED_PROFILE' },
        [pscustomobject]@{ key = 'StartupMinimized'; value = '1' },
        [pscustomobject]@{ key = 'MinToTray_Aero'; value = '1' },
        [pscustomobject]@{ key = 'MinToTray'; value = '1' })
    $section = ''
    $observed = @{}
    foreach ($item in $required) { $observed[$item.key] = @() }
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\[([^\]]+)\]$') {
            $section = [string]$Matches[1]
            continue
        }
        if ($line -notmatch '^([^=]+)=(.*)$') { continue }
        $key = [string]$Matches[1]
        $value = [string]$Matches[2]
        foreach ($item in $required) {
            if ([string]::Equals($key, [string]$item.key,
                    [StringComparison]::OrdinalIgnoreCase)) {
                $observed[$item.key] += [pscustomobject]@{
                    section = $section; value = $value }
                break
            }
        }
    }
    foreach ($item in $required) {
        $matches = @($observed[$item.key])
        if ($matches.Count -ne 1 -or
            -not [string]::Equals([string]$matches[0].section, 'eMule',
                [StringComparison]::OrdinalIgnoreCase) -or
            [string]$matches[0].value -cne [string]$item.value) {
            throw 'Isolated profile contract is incomplete or ambiguous.'
        }
    }
    return $true
}

function Set-R93ProductIni {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$StoredPasswordHash
    )
    # Preferences.cpp derives IsFirstStart() solely from an empty
    # [eMule] AppVersion.  A fresh lab profile must never enter the modal
    # first-run wizard because that would invalidate unattended shutdown.
    Set-LabIniValue $Path eMule AppVersion R93_ISOLATED_PROFILE | Out-Null
    # --headless suppresses interactive work but deliberately does not hide the
    # MFC dialog.  Preferences.cpp reads these exact keys; both tray variants
    # are fixed so Aero/non-Aero hosts converge on a hidden main window.
    Set-LabIniValue $Path eMule StartupMinimized 1 | Out-Null
    Set-LabIniValue $Path eMule MinToTray_Aero 1 | Out-Null
    Set-LabIniValue $Path eMule MinToTray 1 | Out-Null
    Set-LabIniValue $Path UPnP EnableUPnP 1 | Out-Null
    Set-LabIniValue $Path eMule Port $TcpPort | Out-Null
    Set-LabIniValue $Path eMule UDPPort $UdpPort | Out-Null
    # CIni::GetString with an explicit section makes that section current.
    # Preferences reads Password explicitly first, so all following web keys
    # (including high-level admin permission) come from [WebServer].
    Set-LabIniValue $Path WebServer Enabled 1 | Out-Null
    Set-LabIniValue $Path WebServer Port $WebPort | Out-Null
    Set-LabIniValue $Path WebServer Password `
        $StoredPasswordHash.ToLowerInvariant() | Out-Null
    Set-LabIniValue $Path WebServer AllowAdminHiLevelFunc 1 | Out-Null
    $null = Assert-R93NonFirstStartIni $Path
}

function Assert-R93ExpectedHeadlessWindowSet {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [ValidateRange(0, 30000)][int]$TimeoutMs = 10000,
        [ValidateRange(2, 20)][int]$StableSamples = 5,
        [ValidateRange(1, 1000)][int]$SampleIntervalMs = 100,
        [scriptblock]$InventoryProvider,
        [scriptblock]$IdentityGuard,
        [string]$ExpectedMfcWindowClass = ''
    )
    if ($null -eq $InventoryProvider) {
        if ($null -eq ('R93WindowInventoryNative' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class R93WindowInventoryNative {
    public sealed class Inventory {
        public bool enumeration_complete;
        public Row[] rows;
    }
    public sealed class Row {
        public long hwnd;
        public long owner;
        public bool visible;
        public string window_class;
        public string title;
    }
    private delegate bool EnumProc(IntPtr hwnd, IntPtr context);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc callback, IntPtr context);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetWindow(IntPtr hwnd, uint command);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr hwnd, StringBuilder value, int size);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetWindowText(IntPtr hwnd, StringBuilder value, int size);
    public static Inventory Get(uint expectedProcessId) {
        var result = new List<Row>();
        bool complete = EnumWindows(delegate(IntPtr hwnd, IntPtr ignored) {
            uint processId;
            GetWindowThreadProcessId(hwnd, out processId);
            if (processId == expectedProcessId) {
                var windowClass = new StringBuilder(256);
                var title = new StringBuilder(256);
                GetClassName(hwnd, windowClass, windowClass.Capacity);
                GetWindowText(hwnd, title, title.Capacity);
                result.Add(new Row { hwnd = hwnd.ToInt64(),
                    owner = GetWindow(hwnd, 4).ToInt64(),
                    visible = IsWindowVisible(hwnd),
                    window_class = windowClass.ToString(),
                    title = title.ToString() });
            }
            return true;
        }, IntPtr.Zero);
        return new Inventory { enumeration_complete = complete,
            rows = result.ToArray() };
    }
}
'@
        }
        $InventoryProvider = {
            param($expectedProcessId)
            return [R93WindowInventoryNative]::Get(
                [uint32]$expectedProcessId)
        }
    }
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    $stable = 0
    do {
        if ($null -ne $IdentityGuard -and
            -not [bool](& $IdentityGuard $ProcessId)) {
            throw 'Launched process identity changed during window preflight.'
        }
        $inventory = & $InventoryProvider $ProcessId
        if ($null -ne $inventory -and
            $null -ne $inventory.PSObject.Properties['enumeration_complete']) {
            if (-not [bool]$inventory.enumeration_complete) {
                throw 'Top-level window enumeration was incomplete.'
            }
            $rows = @($inventory.rows)
        } else {
            # Injectable providers used by the offline campaign predate the
            # native completion envelope and are complete by construction.
            $rows = @($inventory)
        }
        if ($null -ne $IdentityGuard -and
            -not [bool](& $IdentityGuard $ProcessId)) {
            throw 'Launched process identity changed during window preflight.'
        }
        $visibleExpectedMain = @($rows | Where-Object {
                [bool]$_.visible -and [int64]$_.owner -eq 0 -and
                [string]$_.window_class -ceq '#32770' -and
                ([string]$_.title).StartsWith('eMule ',
                    [StringComparison]::Ordinal) })
        $otherVisible = @($rows | Where-Object {
                [bool]$_.visible -and -not (
                    [int64]$_.owner -eq 0 -and
                    [string]$_.window_class -ceq '#32770' -and
                    ([string]$_.title).StartsWith('eMule ',
                        [StringComparison]::Ordinal)) })
        if ($otherVisible.Count -gt 0 -or $visibleExpectedMain.Count -gt 1) {
            throw 'Launched headless process exposed an unexpected modal window.'
        }
        $main = @($rows | Where-Object {
                [string]$_.window_class -ceq '#32770' -and
                -not [bool]$_.visible -and [int64]$_.owner -eq 0 -and
                ([string]$_.title).StartsWith('eMule ',
                    [StringComparison]::Ordinal) })
        $unexpected = @($rows | Where-Object {
                $windowClass = [string]$_.window_class
                $title = [string]$_.title
                $isMain = $windowClass -ceq '#32770' -and
                    [int64]$_.owner -eq 0 -and
                    $title.StartsWith('eMule ',
                        [StringComparison]::Ordinal)
                $isKnownInfrastructure =
                    (($windowClass -in @('Auto-Suggest Dropdown',
                            'eMule_TaskbarNotifierWndClass', 'ComboLBox',
                            'tooltips_class32')) -and
                        [string]::IsNullOrEmpty($title)) -or
                    ($windowClass -ceq 'MSCTFIME UI' -and
                        $title -ceq 'MSCTFIME UI') -or
                    ($windowClass -ceq 'IME' -and $title -ceq 'Default IME') -or
                    (-not [string]::IsNullOrEmpty($ExpectedMfcWindowClass) -and
                        $windowClass -ceq $ExpectedMfcWindowClass -and
                        $title -in @('eMule Async DNS Resolve Socket Wnd #2',
                            'Socket Notification Sink'))
                -not ($isMain -or $isKnownInfrastructure)
            })
        if ($unexpected.Count -gt 0) {
            throw 'Launched headless process exposed an unallowlisted window.'
        }
        if ($main.Count -eq 1 -and $visibleExpectedMain.Count -eq 0) {
            $stable++
            if ($stable -ge $StableSamples) { return $true }
        } else { $stable = 0 }
        if ($TimeoutMs -eq 0 -or [DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds $SampleIntervalMs
    } while ($true)
    throw 'Expected hidden headless main window was not uniquely observable.'
}

function Invoke-R93AuthenticatedWebClose {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$StoredPasswordHash,
        [scriptblock]$RequestInvoker
    )
    $null = Assert-LabApiUrl -BaseUrl $BaseUrl
    if ($null -eq $RequestInvoker) {
        $RequestInvoker = {
            param($Uri, $Session, $Headers)
            Invoke-WebRequest -Uri $Uri -Method Get -WebSession $Session `
                -Headers $Headers -TimeoutSec 5 -UseBasicParsing
        }
    }
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $challengePage = & $RequestInvoker "$BaseUrl/" $session @{}
    $matches = [regex]::Matches([string]$challengePage.Content,
        'name=["'']n["''][^>]*value=["'']([0-9a-fA-F]{64})["'']',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if ($matches.Count -ne 1) {
        throw 'Local login page did not issue one exact challenge nonce.'
    }
    $nonce = $matches[0].Groups[1].Value.ToLowerInvariant()
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $response = (($sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes(
                    $nonce + $StoredPasswordHash.ToLowerInvariant())) |
                ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally { $sha256.Dispose() }
    $login = & $RequestInvoker "$BaseUrl/?w=password&n=$nonce&r=$response" `
        $session @{}
    $csrf = [string]$login.Headers['X-CSRF-Token']
    if ($csrf -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Local admin login did not issue an exact CSRF token.'
    }
    try {
        $closeResponse = & $RequestInvoker "$BaseUrl/?w=close" $session @{
            'X-CSRF-Token' = $csrf
            'Sec-Fetch-Site' = 'same-origin'
        }
        $clearCookie = [string]$closeResponse.Headers['Set-Cookie']
        if ($clearCookie -cnotmatch '(?:^|[,;]\s*)eSEWebSession=;' -or
            $clearCookie -cnotmatch '(?:^|;\s*)Max-Age=0(?:;|$)') {
            throw 'Local admin close was not observably accepted.'
        }
        return $true
    }
    catch {
        # Shutdown may close the loopback connection before a response arrives.
        # Only the independently observed process exit can resolve that ambiguity.
        return $false
    }
}

function Invoke-R93AccreditedWebShutdown {
    param(
        [Parameter(Mandatory = $true)]$Token,
        [ValidateRange(1, 300)][int]$TimeoutSec,
        [Parameter(Mandatory = $true)][scriptblock]$Exists,
        [Parameter(Mandatory = $true)][scriptblock]$IsAccredited,
        [Parameter(Mandatory = $true)][scriptblock]$CloseAttempt,
        [Parameter(Mandatory = $true)][scriptblock]$WaitForExit
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    do {
        if (-not [bool](& $Exists $Token)) { return $true }
        if (-not [bool](& $IsAccredited $Token)) {
            throw 'Process identity changed during authenticated shutdown.'
        }
        try { $null = & $CloseAttempt $Token } catch { }
        $remainingMs = [Math]::Max(1, [Math]::Min(1000,
                [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)))
        if ([bool](& $WaitForExit $Token $remainingMs)) { return $true }
    } while ([DateTime]::UtcNow -lt $deadline)
    return -not [bool](& $Exists $Token)
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
        if ($null -ne $Adapters.PSObject.Properties['VerifyPreexisting']) {
            $null = & $Adapters.VerifyPreexisting
        }
        & $Adapters.Configure
        $token = & $Adapters.Start
        $started = $true
        if ($null -ne $Adapters.PSObject.Properties['AccreditNewProcess']) {
            $null = & $Adapters.AccreditNewProcess $token
        }
        if (-not [bool](& $Adapters.Exists $token)) {
            throw 'Launched process no longer exists.'
        }
        $accredited = [bool](& $Adapters.IsAccredited $token)
        if (-not $accredited) {
            $failureClass = 'IDENTITY_NOT_ACCREDITED'
            throw 'Launched process identity is not accredited.'
        }
        for ($sampleIndex = 0; $sampleIndex -lt $MaxSamples; $sampleIndex++) {
            if ($null -ne $Adapters.PSObject.Properties['VerifyPreexisting']) {
                $null = & $Adapters.VerifyPreexisting
            }
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
        if (-not $started -and
            $null -ne $Adapters.PSObject.Properties['GetSpawnedToken']) {
            try {
                $registeredToken = & $Adapters.GetSpawnedToken
                if ($null -ne $registeredToken) {
                    $token = $registeredToken
                    $started = $true
                    $failureClass = 'IDENTITY_NOT_ACCREDITED'
                }
            } catch { }
        }
        if ([string]::IsNullOrEmpty($failureClass)) {
            $failureClass = 'EXECUTION_FAILED'
        }
    }
    finally {
        try {
            if ($null -ne $Adapters.PSObject.Properties['VerifyPreexisting']) {
                $null = & $Adapters.VerifyPreexisting
            }
        } catch { $failureClass = 'PREEXISTING_PROCESS_CHANGED' }
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
        $mayStillWriteIni = $started
        if ($started) {
            try { $mayStillWriteIni = [bool](& $Adapters.Exists $token) }
            catch { $mayStillWriteIni = $true }
        }
        if (-not $mayStillWriteIni) {
            try { $restored = [bool](& $Adapters.RestoreIni) }
            catch { $restored = $false }
            if (-not $restored -and $failureClass -cne 'PROCESS_STILL_ALIVE') {
                $failureClass = 'INI_RESTORE_FAILED'
            }
        } elseif ([string]::IsNullOrEmpty($failureClass)) {
            $failureClass = 'PROCESS_STILL_ALIVE'
        }
        try {
            if ($null -ne $Adapters.PSObject.Properties['VerifyPreexisting']) {
                $null = & $Adapters.VerifyPreexisting
            }
        } catch { $failureClass = 'PREEXISTING_PROCESS_CHANGED' }
    }
    $success = $observed -and $closed -and $absent -and $restored
    $blocked = -not $success -and
        $failureClass -in @('PROCESS_STILL_ALIVE', 'IDENTITY_NOT_ACCREDITED',
            'MAPPING_REMAINS_UNTOUCHED', 'PREEXISTING_PROCESS_CHANGED')
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
            'PROCESS_STILL_ALIVE', 'IDENTITY_NOT_ACCREDITED',
            'PREEXISTING_PROCESS_CHANGED')
        failure_class = if ($success) { $null } else { $failureClass }
    }
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
$allowlistLock = $null
$exeLock = [IO.File]::Open($exe, [IO.FileMode]::Open, [IO.FileAccess]::Read,
    [IO.FileShare]::Read)
trap {
    if ($null -ne $exeLock) { $exeLock.Dispose(); $exeLock = $null }
    if ($null -ne $allowlistLock) {
        $allowlistLock.Dispose(); $allowlistLock = $null
    }
    throw
}
$exeHash = Get-R93LockedExecutableSha256 $exeLock
if ($exeHash -cne $ExpectedExeSha256.ToLowerInvariant()) { throw 'Executable hash mismatch.' }
$productName = [IO.Path]::GetFileName($exe)
$allowlistFixedPath = Join-Path $config 'preexisting-process-allowlist.json'
$preexistingExpected = @()
if (Test-Path -LiteralPath $allowlistFixedPath) {
    $allowlistFixedPath = Assert-R93NoReparseChain -Root $config `
        -Path $allowlistFixedPath -Label PreexistingProcessAllowlist
    $allowlistLock = [IO.File]::Open($allowlistFixedPath,
        [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $allowlistHash = Get-R93LockedExecutableSha256 $allowlistLock
    $preexistingExpected = @(Read-R93PreexistingProcessAllowlist `
        $allowlistLock)
}
$preexistingBaseline = @(Get-R93ProductProcessInventory $productName)
$null = Assert-R93ExactProcessIdentitySet $preexistingExpected $preexistingBaseline
if (-not (Test-R93PortBindable TCP $TcpPort) -or
    -not (Test-R93PortBindable UDP $UdpPort) -or
    -not (Test-R93PortBindable TCP $WebPort)) { throw 'Explicit port is unavailable.' }

$iniBytes = [IO.File]::ReadAllBytes($ini)
$iniHash = (Get-FileHash $ini -Algorithm SHA256).Hash
$credentialBytes = New-Object byte[] 16
$credentialRng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $credentialRng.GetBytes($credentialBytes) }
finally { $credentialRng.Dispose() }
$adminHash = (($credentialBytes | ForEach-Object { $_.ToString('x2') }) -join '')
[Array]::Clear($credentialBytes, 0, $credentialBytes.Length)
$process = $null
$spawnedToken = $null
$launchedIdentity = $null
$expectedMfcWindowClass = ''
$backend = $null
$baseUrl = "http://127.0.0.1:$WebPort"
$adapters = [pscustomobject]@{
    Configure = { Set-R93ProductIni $ini $TcpPort $UdpPort $WebPort $adminHash }
    Start = { $script:process = Start-Process -FilePath $exe `
            -WorkingDirectory $package `
            -ArgumentList @('--portable','--ignoreinstances','--headless') `
            -WindowStyle Hidden -PassThru
        # Register ownership before every fallible identity/property access.
        $script:spawnedToken = [int]$script:process.Id
        return $script:spawnedToken }
    GetSpawnedToken = { return $script:spawnedToken }
    VerifyPreexisting = {
        if ($null -ne $allowlistLock -and
            (Get-R93LockedExecutableSha256 $allowlistLock) -cne $allowlistHash) {
            throw 'Locked preexisting-process allowlist changed content.'
        }
        $current = @(Get-R93ProductProcessInventory $productName)
        if ($null -ne $script:process) {
            $current = @($current | Where-Object {
                    [int]$_.pid -ne [int]$script:process.Id })
        }
        Assert-R93ExactProcessIdentitySet $preexistingBaseline $current }
    AccreditNewProcess = { param($token)
        # These captures are intentionally after the token has been published.
        $null = $script:process.Handle
        $null = $script:process.StartTime
        $null = $script:process.SessionId
        $after = @(Get-R93ProductProcessInventory $productName)
        $script:launchedIdentity = Assert-R93OneNewCandidateProcess `
            $preexistingBaseline $after ([int]$token) $exe $exeHash
        $null = Assert-R93LaunchedProcessHandleIdentity $script:process `
            $script:launchedIdentity $exe $exeHash
        $script:expectedMfcWindowClass = 'Afx:{0:X16}:0' -f `
            $script:process.MainModule.BaseAddress.ToInt64()
        $identityGuard = { param($guardToken)
            try {
                $null = Assert-R93LaunchedProcessHandleIdentity `
                    $script:process $script:launchedIdentity $exe $exeHash
                return [int]$script:process.Id -eq [int]$guardToken
            } catch { return $false }
        }.GetNewClosure()
        $null = Assert-R93ExpectedHeadlessWindowSet `
            -ProcessId ([int]$token) -IdentityGuard $identityGuard `
            -ExpectedMfcWindowClass $script:expectedMfcWindowClass
        return $true }
    Exists = { param($token)
        if ($null -eq $script:process -or
            [int]$script:process.Id -ne [int]$token) { return $false }
        try { return -not $script:process.HasExited } catch { return $false } }
    IsAccredited = { param($token)
        if ($null -eq $script:launchedIdentity -or
            [int]$script:launchedIdentity.pid -ne [int]$token) { return $false }
        try { $null = Assert-R93LaunchedProcessHandleIdentity `
                $script:process $script:launchedIdentity $exe $exeHash }
        catch { return $false }
        return $true }
    Sample = { $envelope = Invoke-LabApi -BaseUrl $baseUrl `
            -Path '/api/reach/status' -Token $ApiToken -AllowUnavailable
        if (-not $envelope.available) { return $null }
        Get-R93CandidateProjection $envelope $TcpPort $UdpPort }
    Pause = { Start-Sleep -Seconds 1 }
    Close = { param($token) $null = Invoke-R93AccreditedWebShutdown `
            -Token $token -TimeoutSec $ShutdownTimeoutSec `
            -Exists $adapters.Exists -IsAccredited $adapters.IsAccredited `
            -CloseAttempt { param($ignored)
                $preCloseIdentity = { param($guardToken)
                    try {
                        $null = Assert-R93LaunchedProcessHandleIdentity `
                            $script:process $script:launchedIdentity $exe $exeHash
                        return [int]$script:process.Id -eq [int]$guardToken
                    } catch { return $false }
                }.GetNewClosure()
                $null = Assert-R93ExpectedHeadlessWindowSet `
                    -ProcessId ([int]$ignored) `
                    -IdentityGuard $preCloseIdentity `
                    -ExpectedMfcWindowClass $script:expectedMfcWindowClass
                Invoke-R93AuthenticatedWebClose -BaseUrl $baseUrl `
                    -StoredPasswordHash $adminHash } `
            -WaitForExit { param($ignored, $milliseconds)
                $script:process.WaitForExit($milliseconds) } }
    WaitForExit = { param($token) $script:process.WaitForExit(0) }
    MappingsAbsent = { if ($null -eq $script:backend) {
            $script:backend = Get-R93PhysicalSoapBackend }
        $null -eq (Get-R01UpnpMapping $script:backend $TcpPort TCP) -and
        $null -eq (Get-R01UpnpMapping $script:backend $UdpPort UDP) }
    RestoreIni = { Restore-R93IniBytes $ini $iniBytes $iniHash }
}
try {
    $result = Invoke-R93PartialCycle -Adapters $adapters `
        -MaxSamples $ObservationTimeoutSec
}
finally {
    $adminHash = $null
    if ($null -ne $exeLock) { $exeLock.Dispose(); $exeLock = $null }
    if ($null -ne $allowlistLock) {
        $allowlistLock.Dispose(); $allowlistLock = $null
    }
}
$result | ConvertTo-Json -Compress
if ([string]$result.status -cne 'MAPPING_OBSERVED_CLEAN_EXIT') { exit 1 }
