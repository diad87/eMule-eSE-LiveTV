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
    [ValidateRange(1, 120)][int]$ShutdownTimeoutSec = 30,
    [switch]$FormalSoakChild
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

function Get-R93ProductLaunchArguments {
    param([Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$WebPort)
    # Emule.cpp accepts the metrics override only as --metrics-port=<N>.
    # It also prevents LaunchEseServer from forcing 4711 and replacing the
    # isolated credential. TCP/UDP remain attributed exclusively by the INI.
    return @('--portable', '--ignoreinstances', '--headless',
        ('--metrics-port={0}' -f $WebPort))
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
        [string]$ExpectedMfcWindowClass = '',
        [scriptblock]$DiagnosticReporter
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
    $lastVisibleMainCount = 0
    $lastHiddenMainCount = 0
    do {
        if ($null -ne $DiagnosticReporter) { & $DiagnosticReporter 'GUARD_PRE' }
        if ($null -ne $IdentityGuard -and
            -not [bool](& $IdentityGuard $ProcessId)) {
            throw 'Launched process identity changed during window preflight.'
        }
        if ($null -ne $DiagnosticReporter) { & $DiagnosticReporter 'INVENTORY_CALL' }
        $inventory = & $InventoryProvider $ProcessId
        if ($null -ne $DiagnosticReporter) { & $DiagnosticReporter 'INVENTORY_SHAPE' }
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
        if ($null -ne $DiagnosticReporter) { & $DiagnosticReporter 'GUARD_POST' }
        if ($null -ne $IdentityGuard -and
            -not [bool](& $IdentityGuard $ProcessId)) {
            throw 'Launched process identity changed during window preflight.'
        }
        if ($null -ne $DiagnosticReporter) { & $DiagnosticReporter 'CLASSIFY_VISIBLE' }
        $visibleExpectedMain = @($rows | Where-Object {
                [bool]$_.visible -and [int64]$_.owner -eq 0 -and
                [string]$_.window_class -ceq '#32770' -and
                 ([string]$_.title).StartsWith('eMule ',
                     [StringComparison]::Ordinal) })
        $lastVisibleMainCount = $visibleExpectedMain.Count
        $otherVisible = @($rows | Where-Object {
                [bool]$_.visible -and -not (
                    [int64]$_.owner -eq 0 -and
                    [string]$_.window_class -ceq '#32770' -and
                    ([string]$_.title).StartsWith('eMule ',
                        [StringComparison]::Ordinal)) })
        if ($otherVisible.Count -gt 0 -or $visibleExpectedMain.Count -gt 1) {
            if ($null -ne $DiagnosticReporter) {
                if ($otherVisible.Count -gt 0) { & $DiagnosticReporter 'OTHER_VISIBLE' }
                else { & $DiagnosticReporter 'MULTIPLE_VISIBLE_MAIN' }
            }
            throw 'Launched headless process exposed an unexpected modal window.'
        }
        if ($null -ne $DiagnosticReporter) { & $DiagnosticReporter 'CLASSIFY_HIDDEN' }
        $main = @($rows | Where-Object {
                [string]$_.window_class -ceq '#32770' -and
                -not [bool]$_.visible -and [int64]$_.owner -eq 0 -and
                 ([string]$_.title).StartsWith('eMule ',
                     [StringComparison]::Ordinal) })
        $lastHiddenMainCount = $main.Count
        if ($null -ne $DiagnosticReporter) { & $DiagnosticReporter 'CLASSIFY_UNEXPECTED' }
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
            if ($null -ne $DiagnosticReporter) { & $DiagnosticReporter 'UNEXPECTED_WINDOW' }
            throw 'Launched headless process exposed an unallowlisted window.'
        }
        if ($null -ne $DiagnosticReporter) { & $DiagnosticReporter 'STABILITY' }
        if ($main.Count -eq 1 -and $visibleExpectedMain.Count -eq 0) {
            $stable++
            if ($stable -ge $StableSamples) { return $true }
        } else { $stable = 0 }
        if ($TimeoutMs -eq 0 -or [DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds $SampleIntervalMs
    } while ($true)
    if ($null -ne $DiagnosticReporter) {
        if ($lastVisibleMainCount -eq 1 -and $lastHiddenMainCount -eq 0) {
            & $DiagnosticReporter 'VISIBLE_MAIN'
        } elseif ($lastVisibleMainCount -eq 0 -and $lastHiddenMainCount -eq 0) {
            & $DiagnosticReporter 'NO_HIDDEN_MAIN_TIMEOUT'
        } else { & $DiagnosticReporter 'UNSTABLE_MAIN_TIMEOUT' }
    }
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
        tcp_granted_external_port = [int]$tcp.lease.granted_external_port
        udp_granted_external_port = [int]$udp.lease.granted_external_port
        tcp_candidate = [string]$tcp.gate_state -ceq 'CANDIDATE'
        udp_candidate = [string]$udp.gate_state -ceq 'CANDIDATE'
        tcp_gate_state = if ([string]$tcp.gate_state -in @('CANDIDATE','REACHABLE','BLOCKED','UNKNOWN')) { [string]$tcp.gate_state } else { 'OTHER' }
        udp_gate_state = if ([string]$udp.gate_state -in @('CANDIDATE','REACHABLE','BLOCKED','UNKNOWN')) { [string]$udp.gate_state } else { 'OTHER' }
        tcp_reason_code = if ([uint64]$tcp.reason_code -le 65535) { [uint16]$tcp.reason_code } else { [uint16]65535 }
        udp_reason_code = if ([uint64]$udp.reason_code -le 65535) { [uint16]$udp.reason_code } else { [uint16]65535 }
    }
}

function Set-R93ObservedGrantedMappingPair {
    param(
        [Parameter(Mandatory = $true)]$Projection,
        [Parameter(Mandatory = $true)]$State
    )
    if (-not [bool]$Projection.same_generation -or
        -not [bool]$Projection.tcp_candidate -or
        -not [bool]$Projection.udp_candidate -or
        [uint64]$Projection.generation -eq 0 -or
        [int]$Projection.tcp_granted_external_port -lt 1 -or
        [int]$Projection.tcp_granted_external_port -gt 65535 -or
        [int]$Projection.udp_granted_external_port -lt 1 -or
        [int]$Projection.udp_granted_external_port -gt 65535) {
        return $false
    }
    $State.tcp_granted_external_port = [int]$Projection.tcp_granted_external_port
    $State.udp_granted_external_port = [int]$Projection.udp_granted_external_port
    $State.generation = [uint64]$Projection.generation
    return $true
}

function Invoke-R93PartialCycle {
    param(
        [Parameter(Mandatory = $true)]$Adapters,
        [ValidateRange(1, 10000)][int]$MaxSamples = 180,
        [scriptblock]$AfterObserved
    )
    $started = $false
    $accredited = $false
    $token = $null
    $observed = $false
    $closed = $false
    $absent = $false
    $restored = $false
    $failureClass = ''
    $cleanupFailureClass = $null
    $samplesTotal = 0
    $samplesAvailable = 0
    $tcpCandidateSamples = 0
    $udpCandidateSamples = 0
    $sameGenerationSamples = 0
    $lastTcpGateState = 'UNAVAILABLE'
    $lastUdpGateState = 'UNAVAILABLE'
    $lastTcpReasonCode = 65535
    $lastUdpReasonCode = 65535
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
            $samplesTotal++
            if ($null -ne $sample) {
                $samplesAvailable++
                if ([bool]$sample.tcp_candidate) { $tcpCandidateSamples++ }
                if ([bool]$sample.udp_candidate) { $udpCandidateSamples++ }
                if ([bool]$sample.same_generation) { $sameGenerationSamples++ }
                if ($null -ne $sample.PSObject.Properties['tcp_gate_state']) { $lastTcpGateState = [string]$sample.tcp_gate_state }
                if ($null -ne $sample.PSObject.Properties['udp_gate_state']) { $lastUdpGateState = [string]$sample.udp_gate_state }
                if ($null -ne $sample.PSObject.Properties['tcp_reason_code']) { $lastTcpReasonCode = [uint16]$sample.tcp_reason_code }
                if ($null -ne $sample.PSObject.Properties['udp_reason_code']) { $lastUdpReasonCode = [uint16]$sample.udp_reason_code }
            }
            if ($null -ne $sample -and [bool]$sample.tcp_candidate -and
                [bool]$sample.udp_candidate -and [bool]$sample.same_generation -and
                [uint64]$sample.generation -gt 0) {
                $observed = $true
                break
            }
            & $Adapters.Pause
        }
        if (-not $observed) { $failureClass = 'CANDIDATE_PAIR_NOT_OBSERVED' }
        elseif ($null -ne $AfterObserved) { $null = & $AfterObserved $token }
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
            if (-not $absent) {
                $cleanupFailureClass = 'MAPPING_REMAINS_UNTOUCHED'
                if ([string]::IsNullOrEmpty($failureClass)) { $failureClass = $cleanupFailureClass }
            }
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
        cleanup_failure_class = $cleanupFailureClass
        sample_observation = [pscustomobject][ordered]@{
            samples_total = $samplesTotal
            samples_available = $samplesAvailable
            tcp_candidate_samples = $tcpCandidateSamples
            udp_candidate_samples = $udpCandidateSamples
            same_generation_samples = $sameGenerationSamples
            last_tcp_gate_state = $lastTcpGateState
            last_udp_gate_state = $lastUdpGateState
            last_tcp_reason_code = [int]$lastTcpReasonCode
            last_udp_reason_code = [int]$lastUdpReasonCode
        }
    }
}

function Invoke-R93FormalSoakHold {
    param(
        [Parameter(Mandatory = $true)]$Adapters,
        [Parameter(Mandatory = $true)][int]$Token,
        [Parameter(Mandatory = $true)]$Process,
        [Parameter(Mandatory = $true)]$State,
        [scriptblock]$ClockMilliseconds,
        [scriptblock]$EmitRecord,
        [Parameter(Mandatory = $true)][scriptblock]$AwaitControllerRelease,
        [ValidateSet('FORMAL_RELEASE', 'NON_RELEASE_ACCELERATED')]
        [string]$Mode = 'FORMAL_RELEASE'
    )
    if ($null -ne $ClockMilliseconds -and $Mode -ceq 'FORMAL_RELEASE') {
        throw 'Formal soak does not permit an injected clock.'
    }
    if ($null -eq $EmitRecord) {
        $EmitRecord = { param($record)
            [Console]::Out.WriteLine(($record | ConvertTo-Json -Compress))
            [Console]::Out.Flush()
        }
    }
    $durationMs = if ($Mode -ceq 'FORMAL_RELEASE') { [int64]28800000 } else { [int64]180000 }
    $sampleMs = if ($Mode -ceq 'FORMAL_RELEASE') { [int64]60000 } else { [int64]60000 }
    $sampleCount = [int]($durationMs / $sampleMs)
    $maximumObservedGapMs = [int64]70000
    $lastObservedMs = [int64]0
    if (-not [bool](& $Adapters.Exists $Token) -or
        -not [bool](& $Adapters.IsAccredited $Token)) {
        throw 'Formal soak product identity changed before STARTED.'
    }
    if ($null -ne $Adapters.PSObject.Properties['VerifyPreexisting']) {
        $null = & $Adapters.VerifyPreexisting
    }
    $State.sequence++
    $null = & $EmitRecord ([pscustomobject][ordered]@{
        schema = 'ese.v92.o01-product-started/v1'
        sequence = $State.sequence
        elapsed_ms = [int64]0
        identity_accredited = $true
        preexisting_processes_unchanged = $true
    })
    # STARTED is the observable epoch zero.  The release clock must not exist
    # before the record has been synchronously written and flushed.
    if ($null -eq $ClockMilliseconds) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $ClockMilliseconds = { return [int64]$clock.ElapsedMilliseconds }.GetNewClosure()
    }
    for ($ordinal = 1; $ordinal -le $sampleCount; $ordinal++) {
        $targetMs = [int64]$ordinal * $sampleMs
        while ([int64](& $ClockMilliseconds) -lt $targetMs) {
            if (-not [bool](& $Adapters.Exists $Token) -or
                -not [bool](& $Adapters.IsAccredited $Token)) {
                throw 'Formal soak product identity changed.'
            }
            if ($null -ne $Adapters.PSObject.Properties['VerifyPreexisting']) {
                $null = & $Adapters.VerifyPreexisting
            }
            & $Adapters.Pause
        }
        if (-not [bool](& $Adapters.Exists $Token) -or
            -not [bool](& $Adapters.IsAccredited $Token)) {
            throw 'Formal soak product identity changed before sample.'
        }
        if ($null -ne $Adapters.PSObject.Properties['VerifyPreexisting']) {
            $null = & $Adapters.VerifyPreexisting
        }
        try {
            $Process.Refresh()
        }
        catch {
            throw 'Formal soak product resource refresh failed.'
        }
        if (-not [bool](& $Adapters.Exists $Token) -or
            -not [bool](& $Adapters.IsAccredited $Token)) {
            throw 'Formal soak product identity changed after resource refresh.'
        }
        $elapsedMs = [int64](& $ClockMilliseconds)
        if ($elapsedMs -le $lastObservedMs -or
            $elapsedMs - $lastObservedMs -gt $maximumObservedGapMs) {
            throw 'Formal soak product sample cadence was interrupted.'
        }
        $lastObservedMs = $elapsedMs
        $projection = & $Adapters.Sample
        $State.sequence++
        $available = $null -ne $projection
        $sampleRecord = [pscustomobject][ordered]@{
            schema = 'ese.v92.o01-product-sample/v1'
            sequence = $State.sequence
            elapsed_ms = $elapsedMs
            available = $available
            tcp_state = if ($available) { [string]$projection.tcp_gate_state } else { 'UNAVAILABLE' }
            udp_state = if ($available) { [string]$projection.udp_gate_state } else { 'UNAVAILABLE' }
            same_generation = if ($available) { [bool]$projection.same_generation } else { $false }
            generation = if ($available) { [uint64]$projection.generation } else { [uint64]0 }
            tcp_reason_code = if ($available) { [uint16]$projection.tcp_reason_code } else { [uint16]65535 }
            udp_reason_code = if ($available) { [uint16]$projection.udp_reason_code } else { [uint16]65535 }
            working_set_bytes = [uint64]$Process.WorkingSet64
            handle_count = [uint64]$Process.HandleCount
        }
        $null = & $EmitRecord $sampleRecord
    }
    $State.elapsed_ms = [int64](& $ClockMilliseconds)
    if ([int64]$State.elapsed_ms -lt $durationMs) {
        throw 'Formal soak duration was incomplete.'
    }
    $null = & $AwaitControllerRelease $Token
    $State.elapsed_ms = [int64](& $ClockMilliseconds)
    return $true
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
$mappingObservation = [pscustomobject]@{
    tcp_granted_external_port = 0
    udp_granted_external_port = 0
    generation = [uint64]0
}
$identityDiagnosticStream = $null
$identityDiagnosticEnabled = [Environment]::GetEnvironmentVariable(
    'R93_LOCAL_IDENTITY_DIAGNOSTIC', 'Process') -ceq '1'
$identityDiagnosticState = [pscustomobject]@{ stage = '' }
if ($identityDiagnosticEnabled) {
    try {
        $identityDiagnosticPath = Join-Path $config 'r93-local-identity-stage.txt'
        if (-not (Test-Path -LiteralPath $identityDiagnosticPath)) {
            $identityDiagnosticStream = [IO.File]::Open($identityDiagnosticPath,
                [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
                [IO.FileShare]::Read)
        }
    } catch { $identityDiagnosticStream = $null }
}
$setIdentityStage = { param([string]$Stage)
    $null = ($identityDiagnosticState.stage = $Stage)
    if ($null -ne $identityDiagnosticStream) {
        try {
            $bytes = [Text.Encoding]::ASCII.GetBytes($Stage)
            $null = ($identityDiagnosticStream.Position = 0)
            $null = $identityDiagnosticStream.SetLength(0)
            $null = $identityDiagnosticStream.Write($bytes, 0, $bytes.Length)
            $null = $identityDiagnosticStream.Flush($true)
        } catch { }
    }
}.GetNewClosure()
$baseUrl = "http://127.0.0.1:$WebPort"
$adapters = [pscustomobject]@{
    Configure = { Set-R93ProductIni $ini $TcpPort $UdpPort $WebPort $adminHash }
    Start = { $script:process = Start-Process -FilePath $exe `
            -WorkingDirectory $package `
            -ArgumentList @(Get-R93ProductLaunchArguments $WebPort) `
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
        & $setIdentityStage 'HANDLE'
        # These captures are intentionally after the token has been published.
        $null = $script:process.Handle
        $null = $script:process.StartTime
        $null = $script:process.SessionId
        & $setIdentityStage 'INVENTORY'
        $after = @(Get-R93ProductProcessInventory $productName)
        & $setIdentityStage 'CANDIDATE'
        $script:launchedIdentity = Assert-R93OneNewCandidateProcess `
            $preexistingBaseline $after ([int]$token) $exe $exeHash
        & $setIdentityStage 'HANDLE_IDENTITY'
        $null = Assert-R93LaunchedProcessHandleIdentity $script:process `
            $script:launchedIdentity $exe $exeHash
        & $setIdentityStage 'MODULE'
        $script:expectedMfcWindowClass = 'Afx:{0:X16}:0' -f `
            $script:process.MainModule.BaseAddress.ToInt64()
        $identityGuard = { param($guardToken)
            try {
                $null = & $setIdentityStage 'GUARD_ASSERT_BEGIN'
                $null = Assert-R93LaunchedProcessHandleIdentity `
                    $script:process $script:launchedIdentity $exe $exeHash
                $null = & $setIdentityStage 'GUARD_ASSERT_DONE'
                $null = & $setIdentityStage 'GUARD_TOKEN_COMPARE'
                $sameToken = [int]$script:process.Id -eq [int]$guardToken
                if (-not $sameToken) { $null = & $setIdentityStage 'GUARD_FALSE' }
                return $sameToken
            } catch { $null = & $setIdentityStage 'GUARD_FALSE'; return $false }
        }
        & $setIdentityStage 'WINDOW_SET'
        try {
            $null = Assert-R93ExpectedHeadlessWindowSet `
                -ProcessId ([int]$token) -IdentityGuard $identityGuard `
                -DiagnosticReporter $setIdentityStage `
                -ExpectedMfcWindowClass $script:expectedMfcWindowClass `
                -TimeoutMs 30000
        } catch {
            $message = [string]$_.Exception.Message
            $stage = if ($message -ceq 'Top-level window enumeration was incomplete.') {
                'WINDOW_ENUM_INCOMPLETE'
            } elseif ($message -ceq 'Launched headless process exposed an unexpected modal window.') {
                'WINDOW_MODAL'
            } elseif ($message -ceq 'Launched headless process exposed an unallowlisted window.') {
                'WINDOW_UNALLOWLISTED'
            } elseif ($message -ceq 'Expected hidden headless main window was not uniquely observable.') {
                'WINDOW_TIMEOUT'
            } elseif ($message -ceq 'Launched process identity changed during window preflight.') {
                'WINDOW_IDENTITY_GUARD'
            } else {
                $type = $_.Exception.GetType().FullName
                if ($type -ceq 'System.Management.Automation.PropertyNotFoundException') {
                    'WINDOW_INTERNAL_PROPERTY'
                } elseif ($type -ceq 'System.Management.Automation.MethodInvocationException') {
                    'WINDOW_INTERNAL_METHOD'
                } elseif ($type -ceq 'System.Management.Automation.ParameterBindingException') {
                    'WINDOW_INTERNAL_PARAMETER'
                } elseif ($type -ceq 'System.Management.Automation.RuntimeException') {
                    'WINDOW_INTERNAL_RUNTIME'
                } else { 'WINDOW_INTERNAL_OTHER' }
            }
            $currentStage = [string]$identityDiagnosticState.stage
            $replaceGenericIdentityStage =
                $message -ceq 'Launched process identity changed during window preflight.' -and
                $currentStage -in @('WINDOW_SET', 'GUARD_PRE', 'GUARD_POST')
            if ($currentStage -ceq 'WINDOW_SET' -or $replaceGenericIdentityStage) {
                & $setIdentityStage $stage
            }
            throw
        }
        & $setIdentityStage 'ACCREDITED'
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
        $projection = Get-R93CandidateProjection $envelope $TcpPort $UdpPort
        $null = Set-R93ObservedGrantedMappingPair $projection $script:mappingObservation
        return $projection }
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
                }
                $null = Assert-R93ExpectedHeadlessWindowSet `
                    -ProcessId ([int]$ignored) `
                    -IdentityGuard $preCloseIdentity `
                    -ExpectedMfcWindowClass $script:expectedMfcWindowClass
                Invoke-R93AuthenticatedWebClose -BaseUrl $baseUrl `
                    -StoredPasswordHash $adminHash } `
            -WaitForExit { param($ignored, $milliseconds)
                $script:process.WaitForExit($milliseconds) } }
    WaitForExit = { param($token) $script:process.WaitForExit(0) }
    MappingsAbsent = { if ([int]$script:mappingObservation.tcp_granted_external_port -lt 1 -or
            [int]$script:mappingObservation.udp_granted_external_port -lt 1 -or
            [uint64]$script:mappingObservation.generation -eq 0) { return $false }
        if ($null -eq $script:backend) {
            $script:backend = Get-R93PhysicalSoapBackend }
        $null -eq (Get-R01UpnpMapping $script:backend `
            ([int]$script:mappingObservation.tcp_granted_external_port) TCP) -and
        $null -eq (Get-R01UpnpMapping $script:backend `
            ([int]$script:mappingObservation.udp_granted_external_port) UDP) }
    RestoreIni = { Restore-R93IniBytes $ini $iniBytes $iniHash }
}
function Get-R93FormalCandidateProjection { param([Parameter(Mandatory=$true)]$Envelope,[Parameter(Mandatory=$true)][int]$ExpectedTcpPort,[Parameter(Mandatory=$true)][int]$ExpectedUdpPort);if(-not[bool]$Envelope.available-or$null-eq$Envelope.data-or[string]$Envelope.data.schema-cne'ESE_REACH_STATUS_V1'){throw 'Projected reach status is unavailable or invalid.'};$tcp=$Envelope.data.planes.ed2k_tcp_v4;$udp=$Envelope.data.planes.kad_udp_v4;if($null-eq$tcp-or$null-eq$udp){throw 'Projected reach status lacks mapper planes.'};$top=[uint64]$Envelope.data.topology_generation;$tcpGeneration=[uint64]$tcp.generation;$udpGeneration=[uint64]$udp.generation;$coherent=$top-gt0-and$tcpGeneration-eq$top-and$udpGeneration-eq$top-and[uint64]$tcp.lease.generation-eq$top-and[uint64]$udp.lease.generation-eq$top-and[string]$tcp.lease.transport-ceq'Tcp'-and[string]$udp.lease.transport-ceq'Udp'-and[int]$tcp.local.port-eq$ExpectedTcpPort-and[int]$udp.local.port-eq$ExpectedUdpPort-and[int]$tcp.lease.requested_external_port-eq$ExpectedTcpPort-and[int]$udp.lease.requested_external_port-eq$ExpectedUdpPort-and[int]$tcp.lease.granted_external_port-gt0-and[int]$udp.lease.granted_external_port-gt0-and[int]$tcp.mapped.port-eq[int]$tcp.lease.granted_external_port-and[int]$tcp.advertised.port-eq[int]$tcp.lease.granted_external_port-and[int]$udp.mapped.port-eq[int]$udp.lease.granted_external_port-and[int]$udp.advertised.port-eq[int]$udp.lease.granted_external_port-and[bool]$tcp.lease.owned_by_us-and[bool]$udp.lease.owned_by_us-and[bool]$tcp.lease.structurally_valid-and[bool]$udp.lease.structurally_valid-and[string]$tcp.gate_state-ceq'CANDIDATE'-and[string]$udp.gate_state-ceq'CANDIDATE';[pscustomobject]@{same_generation=$coherent;generation=$top;tcp_candidate=[string]$tcp.gate_state-ceq'CANDIDATE';udp_candidate=[string]$udp.gate_state-ceq'CANDIDATE';tcp_gate_state=if([string]$tcp.gate_state-cin@('DISABLED','DISCOVERING','CANDIDATE','VERIFIED','WITHDRAWN','BLOCKED')){[string]$tcp.gate_state}else{'OTHER'};udp_gate_state=if([string]$udp.gate_state-cin@('DISABLED','DISCOVERING','CANDIDATE','VERIFIED','WITHDRAWN','BLOCKED')){[string]$udp.gate_state}else{'OTHER'};tcp_reason_code=if([uint64]$tcp.reason_code-le65535){[uint16]$tcp.reason_code}else{[uint16]65535};udp_reason_code=if([uint64]$udp.reason_code-le65535){[uint16]$udp.reason_code}else{[uint16]65535}}};function Write-R93FormalFailureRecord { param([Parameter(Mandatory=$true)]$Result,[Parameter(Mandatory=$true)]$State,[IO.TextWriter]$Writer=[Console]::Out);$failure=[string]$Result.failure_class;$cleanup=if($null-eq$Result.cleanup_failure_class){$null}else{[string]$Result.cleanup_failure_class};if($failure-ceq'MAPPING_REMAINS_UNTOUCHED'-and$cleanup-ceq'MAPPING_REMAINS_UNTOUCHED'){$failure='EXECUTION_FAILED'};$allowed=@('CANDIDATE_PAIR_NOT_OBSERVED','EXECUTION_FAILED','IDENTITY_NOT_ACCREDITED','INI_RESTORE_FAILED','PREEXISTING_PROCESS_CHANGED','PROCESS_STILL_ALIVE');$sample=$Result.sample_observation;$sampleKeys=if($null-eq$sample){@()}else{@($sample.PSObject.Properties.Name|Sort-Object)};$counts=@('samples_total','samples_available','tcp_candidate_samples','udp_candidate_samples','same_generation_samples');$states=@('UNAVAILABLE','DISABLED','DISCOVERING','CANDIDATE','VERIFIED','WITHDRAWN','BLOCKED','OTHER');if($null-eq$Writer-or$failure-cnotin$allowed-or($null-ne$cleanup-and$cleanup-cne'MAPPING_REMAINS_UNTOUCHED')-or$State.sequence-isnot[int]-or[int]$State.sequence-lt0-or[int]$State.sequence-ge482-or$null-eq$sample-or($sampleKeys-join',')-cne'last_tcp_gate_state,last_tcp_reason_code,last_udp_gate_state,last_udp_reason_code,same_generation_samples,samples_available,samples_total,tcp_candidate_samples,udp_candidate_samples'){throw 'Formal product failure record is invalid.'};foreach($name in $counts){if($sample.$name-isnot[int]-or[int]$sample.$name-lt0-or[int]$sample.$name-gt180){throw 'Formal product failure record is invalid.'}};if([int]$sample.samples_available-gt[int]$sample.samples_total-or[int]$sample.tcp_candidate_samples-gt[int]$sample.samples_available-or[int]$sample.udp_candidate_samples-gt[int]$sample.samples_available-or[int]$sample.same_generation_samples-gt[int]$sample.samples_available-or$sample.last_tcp_gate_state-isnot[string]-or[string]$sample.last_tcp_gate_state-cnotin$states-or$sample.last_udp_gate_state-isnot[string]-or[string]$sample.last_udp_gate_state-cnotin$states-or$sample.last_tcp_reason_code-isnot[int]-or[int]$sample.last_tcp_reason_code-lt0-or[int]$sample.last_tcp_reason_code-gt65535-or$sample.last_udp_reason_code-isnot[int]-or[int]$sample.last_udp_reason_code-lt0-or[int]$sample.last_udp_reason_code-gt65535-or([int]$sample.samples_available-eq0-and([string]$sample.last_tcp_gate_state-cne'UNAVAILABLE'-or[string]$sample.last_udp_gate_state-cne'UNAVAILABLE'-or[int]$sample.last_tcp_reason_code-ne65535-or[int]$sample.last_udp_reason_code-ne65535))-or([int]$sample.samples_available-gt0-and([string]$sample.last_tcp_gate_state-ceq'UNAVAILABLE'-or[string]$sample.last_udp_gate_state-ceq'UNAVAILABLE'-or[int]$sample.last_tcp_reason_code-gt21-or[int]$sample.last_udp_reason_code-gt21))){throw 'Formal product failure record is invalid.'};$observation=[pscustomobject][ordered]@{samples_total=[int]$sample.samples_total;samples_available=[int]$sample.samples_available;tcp_candidate_samples=[int]$sample.tcp_candidate_samples;udp_candidate_samples=[int]$sample.udp_candidate_samples;same_generation_samples=[int]$sample.same_generation_samples;last_tcp_gate_state=[string]$sample.last_tcp_gate_state;last_udp_gate_state=[string]$sample.last_udp_gate_state;last_tcp_reason_code=[int]$sample.last_tcp_reason_code;last_udp_reason_code=[int]$sample.last_udp_reason_code};$State.sequence++;$record=[pscustomobject][ordered]@{schema='ese.v92.o01-product-failure/v2';sequence=[int]$State.sequence;failure_class=$failure;cleanup_failure_class=$cleanup;sample_observation=$observation};$Writer.WriteLine(($record|ConvertTo-Json -Compress -Depth 3));$Writer.Flush();return $record};$formalState = [pscustomobject]@{ elapsed_ms = [int64]0; sequence = 0 }
$formalSoak = $null
if ($FormalSoakChild) {
    if ($ObservationTimeoutSec -ne 180 -or $ShutdownTimeoutSec -ne 45) {
        throw 'Formal soak child requires canonical observation and shutdown timeouts.'
    }
    $scenarioPath = Join-Path $PSScriptRoot '..\nat_gateway\v92_o01_scenario.json'
    $controllerReleasePath = 'C:\o01\controller-tick-2880.release'
    if (Test-Path -LiteralPath $controllerReleasePath) { throw 'Formal controller release signal already exists.' }
    $scenario = Get-Content -Raw -LiteralPath $scenarioPath | ConvertFrom-Json -ErrorAction Stop
    if ([string]$scenario.schema -cne 'ese.v92.o01-scenario/v1' -or
        [int64]$scenario.formal_duration_ms -ne 28800000 -or
        [int64]$scenario.sample_ms -ne 60000 -or
        [int64]$scenario.tick_ms -ne 10000 -or
        [int64]$scenario.limits.checkpoint_max_gap_ms -ne 370000) {
        throw 'Formal soak scenario is not canonical.'
    }
    $baseConfigure=$adapters.Configure;$adapters.Configure={&$baseConfigure;Set-LabIniValue $ini Connection LastWorkingImplementation 3|Out-Null;Set-LabIniValue $ini Connection DisableMiniUPNPLibImpl 1|Out-Null;Set-LabIniValue $ini Connection DisableWinServImpl 1|Out-Null};$adapters.Sample={$envelope=Invoke-LabApi -BaseUrl $baseUrl -Path '/api/reach/status' -Token $ApiToken -AllowUnavailable;if(-not$envelope.available){return $null};$projection=Get-R93FormalCandidateProjection $envelope $TcpPort $UdpPort;$projection|Add-Member -MemberType NoteProperty -Name tcp_granted_external_port -Value ([int]$envelope.data.planes.ed2k_tcp_v4.lease.granted_external_port);$projection|Add-Member -MemberType NoteProperty -Name udp_granted_external_port -Value ([int]$envelope.data.planes.kad_udp_v4.lease.granted_external_port);$null=Set-R93ObservedGrantedMappingPair $projection $script:mappingObservation;return $projection};$formalSoak = { param($token)
        $awaitControllerRelease = { param($releaseToken)
            foreach ($attempt in 1..60) {
                if (Test-Path -LiteralPath $controllerReleasePath) {
                    $approvedRelease = Assert-R93NoReparseChain -Root 'C:\o01' -Path $controllerReleasePath -Label FormalControllerRelease
                    if ((Test-Path -LiteralPath $approvedRelease -PathType Leaf) -and
                        [IO.File]::ReadAllText($approvedRelease, [Text.Encoding]::ASCII) -ceq "O01_CONTROLLER_TICK_2880_RELEASE`n") { return $true }
                    throw 'Formal controller release signal is invalid.'
                }
                if (-not [bool](& $adapters.Exists $releaseToken) -or
                    -not [bool](& $adapters.IsAccredited $releaseToken)) { throw 'Formal soak product identity changed before controller release.' }
                if ($null -ne $adapters.PSObject.Properties['VerifyPreexisting']) { $null = & $adapters.VerifyPreexisting }
                if ($attempt -lt 60) { & $adapters.Pause }
            }
            throw 'Formal controller release signal was not observed.'
        }.GetNewClosure()
        $null = Invoke-R93FormalSoakHold -Adapters $adapters -Token $token `
            -Process $script:process -State $formalState `
            -AwaitControllerRelease $awaitControllerRelease
    }
}
try {
    $result = Invoke-R93PartialCycle -Adapters $adapters `
        -MaxSamples $ObservationTimeoutSec -AfterObserved $formalSoak
}
finally {
    $adminHash = $null
    if ($null -ne $identityDiagnosticStream) {
        $identityDiagnosticStream.Dispose(); $identityDiagnosticStream = $null
    }
    if ($null -ne $exeLock) { $exeLock.Dispose(); $exeLock = $null }
    if ($null -ne $allowlistLock) {
        $allowlistLock.Dispose(); $allowlistLock = $null
    }
}
if ($FormalSoakChild) {
    if ([string]$result.status -cne 'MAPPING_OBSERVED_CLEAN_EXIT') { $null=Write-R93FormalFailureRecord -Result $result -State $formalState;exit 1 }
    $formalState.sequence++
    [pscustomobject][ordered]@{
        schema = 'ese.v92.o01-product-terminal/v1'
        sequence = $formalState.sequence
        elapsed_ms = $formalState.elapsed_ms
        graceful_exit = [bool]$result.graceful_exit
        mappings_absent = [bool]$result.mappings_absent
        ini_restored_byte_exact = [bool]$result.ini_restored_byte_exact
        preexisting_processes_unchanged = -not [bool]$result.intervention_required
    } | ConvertTo-Json -Compress
    exit 0
}
$result | ConvertTo-Json -Compress
if ([string]$result.status -cne 'MAPPING_OBSERVED_CLEAN_EXIT') { exit 1 }
