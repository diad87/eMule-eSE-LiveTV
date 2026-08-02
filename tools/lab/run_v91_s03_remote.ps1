[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$jobEnvelope = Get-Content -LiteralPath $JobRequestPath -Raw |
    ConvertFrom-Json
$request = $jobEnvelope.request
$jobId = [string]$jobEnvelope.job_id
$jobRoot = Split-Path -Parent $JobRequestPath
$kitRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
. (Join-Path $kitRoot 'common.ps1')

$baseNode = [IO.Path]::GetFullPath(
    (Join-Path $kitRoot ([string]$request.base_node_relative)))
$nodePath = Join-Path $jobRoot 'node'
$evidencePath = Join-Path $jobRoot 'evidence'
$archiveRelative = [string]$request.candidate_archive_relative
if ([string]::IsNullOrWhiteSpace($archiveRelative)) {
    $archiveSource = Join-Path $PSScriptRoot 'candidate-archive.txt'
} else {
    if ($archiveRelative -cnotmatch
            '^injected/[0-9a-f]{32}/candidate-archive\.txt$') {
        throw 'candidate_archive_relative no cumple la allowlist.'
    }
    $archiveSource = [IO.Path]::GetFullPath(
        (Join-Path $kitRoot $archiveRelative.Replace('/', '\')))
}
$archivePath = Join-Path $jobRoot 'candidate.zip'
$caseId = if ($null -ne $request.case_id) {
    [string]$request.case_id
} else {
    'V91-S03'
}
if ($caseId -notin @('V91-K02', 'V91-S01', 'V91-S02', 'V91-S03')) {
    throw 'case_id no cumple la allowlist del runner Kad6.'
}
$localIPv6 = [string]$request.local_ipv6
$peerIPv6 = [string]$request.peer_ipv6
$peerIPv6Addresses = @(
    if ($null -ne $request.peer_ipv6s) {
        $request.peer_ipv6s | ForEach-Object { [string]$_ }
    } else {
        $peerIPv6
    }
)
$peerLinkLayerAddress = if ($null -ne $request.peer_link_layer_address) {
    [string]$request.peer_link_layer_address
} else {
    ''
}
$peerIPv4 = if ($null -ne $request.peer_ipv4) {
    [string]$request.peer_ipv4
} else {
    ''
}
if (-not [string]::IsNullOrWhiteSpace($peerLinkLayerAddress) -and
    $peerLinkLayerAddress -notmatch
        '^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$') {
    throw 'peer_link_layer_address no es una MAC valida.'
}
if ($peerIPv6Addresses.Count -lt 1 -or $peerIPv6Addresses.Count -gt 8) {
    throw 'peer_ipv6s debe contener entre una y ocho ULA.'
}
$interfaceIndex = [int]$request.interface_index
$interfaceAlias = [string]$request.interface_alias
$captureComponentId = [int]$request.capture_component_id
$tcpPort = [int]$request.tcp_port
$udpPort = [int]$request.udp_port
$webPort = [int]$request.web_port
$expectedExeSha256 = ([string]$request.exe_sha256).ToLowerInvariant()
$holdSeconds = [Math]::Max(30, [Math]::Min(180, [int]$request.hold_seconds))
$k02PhaseSeconds = if ($caseId -eq 'V91-K02') {
    [Math]::Max(12, [Math]::Min(45, [int]$request.phase_seconds))
} else {
    0
}
if ($captureComponentId -le 0) {
    throw 'capture_component_id debe identificar la NIC fisica.'
}

$readyPath = Join-Path $jobRoot 'ready.json'
$resultPath = Join-Path $jobRoot 'result.json'
$etlPath = Join-Path $evidencePath 'v91-s03-packets.etl'
$pcapPath = Join-Path $evidencePath 'v91-s03-packets.pcapng'
$textPath = Join-Path $evidencePath 'v91-s03-packets.txt'
$filterBeforePath = Join-Path $evidencePath 'pktmon-filters-before.txt'
$filterAfterPath = Join-Path $evidencePath 'pktmon-filters-after.txt'
$routePath = Join-Path $evidencePath 'ipv6-route.json'
$endpointPath = Join-Path $evidencePath 'udp-endpoint.json'
$firewallName = "eSE-V91-S03-$jobId"
$firewallNames = [Collections.Generic.List[string]]::new()
$peerRoutesCreated = [Collections.Generic.List[string]]::new()
$peerNeighborsCreated = [Collections.Generic.List[string]]::new()

$process = $null
$addressCreated = $false
$firewallCreated = $false
$captureStarted = $false
$filterInventoryBefore = @()
$samples = [Collections.Generic.List[object]]::new()
$phaseResults = [Collections.Generic.List[object]]::new()
$finalStatus = 'ERROR'
$failure = $null

function Write-S03Json {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $temp = $Path + '.tmp-' + [Guid]::NewGuid().ToString('N')
    $Value | ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $Path -Force
}

function Assert-S03Ula {
    param([Parameter(Mandatory = $true)][string]$Address)
    $parsed = [Net.IPAddress]::Parse($Address)
    if ($parsed.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetworkV6 -or
        ($parsed.GetAddressBytes()[0] -band 0xfe) -ne 0xfc) {
        throw "No es una ULA IPv6 valida: $Address"
    }
}

function Set-K02KadMask {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 3)][int]$Mask
    )
    if ($null -eq ('EseK02Ui' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class EseK02Ui {
    private delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool EnumWindows(
        EnumProc callback, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(
        IntPtr parent, EnumProc callback, IntPtr lParam);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(
        IntPtr hwnd, out uint processId);
    [DllImport("user32.dll")] private static extern int GetDlgCtrlID(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetParent(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool PostMessage(
        IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern IntPtr SendMessage(
        IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(
        IntPtr hwnd, StringBuilder text, int maxCount);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(
        IntPtr hwnd, StringBuilder text, int maxCount);

    private const uint WM_COMMAND = 0x0111;
    private const uint WM_USER = 0x0400;
    private const uint PSM_APPLY = WM_USER + 110;
    private const uint PSM_SETCURSEL = WM_USER + 101;
    private const uint TV_FIRST = 0x1100;
    private const uint TVM_GETNEXTITEM = TV_FIRST + 10;
    private const uint TVM_SELECTITEM = TV_FIRST + 11;
    private const int TVGN_ROOT = 0;
    private const int TVGN_NEXT = 1;
    private const int TVGN_CARET = 9;
    private const uint BM_SETCHECK = 0x00F1;
    private const int BST_UNCHECKED = 0;
    private const int BST_CHECKED = 1;
    private const int MP_HM_PREFS = 10217;
    private const int CONNECTION_PAGE_INDEX = 2;
    private const int IDC_PAGE_TREE = 0x7EEE;
    private const int IDC_NETWORK_KAD2 = 2114;
    private const int IDC_NETWORK_KAD6 = 3062;
    private const int IDOK = 1;

    private static List<IntPtr> TopWindows(int processId) {
        List<IntPtr> result = new List<IntPtr>();
        EnumWindows(delegate(IntPtr hwnd, IntPtr ignored) {
            uint owner;
            GetWindowThreadProcessId(hwnd, out owner);
            if (owner == (uint)processId) result.Add(hwnd);
            return true;
        }, IntPtr.Zero);
        return result;
    }

    private static IntPtr FindControl(IntPtr root, int id) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(root, delegate(IntPtr hwnd, IntPtr ignored) {
            if (GetDlgCtrlID(hwnd) == id) {
                found = hwnd;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    private static string WindowInventory(int processId) {
        StringBuilder result = new StringBuilder();
        foreach (IntPtr hwnd in TopWindows(processId)) {
            StringBuilder title = new StringBuilder(128);
            StringBuilder klass = new StringBuilder(128);
            GetWindowText(hwnd, title, title.Capacity);
            GetClassName(hwnd, klass, klass.Capacity);
            if (result.Length > 0) result.Append("|");
            result.Append("0x").Append(hwnd.ToInt64().ToString("x"))
                .Append(":").Append(klass)
                .Append(":").Append(title)
                .Append(":tree=")
                .Append(FindControl(hwnd, IDC_PAGE_TREE) != IntPtr.Zero);
        }
        return result.ToString();
    }

    public static IntPtr FindMain(int processId) {
        foreach (IntPtr hwnd in TopWindows(processId)) {
            StringBuilder title = new StringBuilder(128);
            StringBuilder klass = new StringBuilder(128);
            GetWindowText(hwnd, title, title.Capacity);
            GetClassName(hwnd, klass, klass.Capacity);
            if (klass.ToString() == "#32770" &&
                title.ToString().StartsWith(
                    "eMule ", StringComparison.OrdinalIgnoreCase))
                return hwnd;
        }
        return IntPtr.Zero;
    }

    public static string SetMask(int processId, int mask) {
        Process process = Process.GetProcessById(processId);
        process.Refresh();
        IntPtr main = FindMain(processId);
        if (main == IntPtr.Zero || !IsWindow(main))
            return "main_window_missing";
        Thread commandThread = new Thread(delegate() {
            SendMessage(main, WM_COMMAND,
                new IntPtr(MP_HM_PREFS), IntPtr.Zero);
        });
        commandThread.IsBackground = true;
        commandThread.Start();

        IntPtr sheet = IntPtr.Zero;
        IntPtr kad2 = IntPtr.Zero;
        IntPtr kad6 = IntPtr.Zero;
        for (int attempt = 0; attempt < 100; ++attempt) {
            foreach (IntPtr candidate in TopWindows(processId)) {
                SendMessage(candidate, PSM_SETCURSEL,
                            new IntPtr(CONNECTION_PAGE_INDEX), IntPtr.Zero);
                IntPtr tree = FindControl(candidate, IDC_PAGE_TREE);
                if (tree != IntPtr.Zero) {
                    IntPtr item = SendMessage(tree, TVM_GETNEXTITEM,
                        new IntPtr(TVGN_ROOT), IntPtr.Zero);
                    for (int index = 0;
                         index < CONNECTION_PAGE_INDEX &&
                         item != IntPtr.Zero; ++index) {
                        item = SendMessage(tree, TVM_GETNEXTITEM,
                            new IntPtr(TVGN_NEXT), item);
                    }
                    if (item != IntPtr.Zero) {
                        SendMessage(tree, TVM_SELECTITEM,
                            new IntPtr(TVGN_CARET), item);
                    }
                }
                IntPtr c2 = FindControl(candidate, IDC_NETWORK_KAD2);
                IntPtr c6 = FindControl(candidate, IDC_NETWORK_KAD6);
                if (c2 != IntPtr.Zero && c6 != IntPtr.Zero) {
                    sheet = candidate;
                    kad2 = c2;
                    kad6 = c6;
                    break;
                }
            }
            if (sheet != IntPtr.Zero) break;
            Thread.Sleep(100);
        }
        if (sheet == IntPtr.Zero) {
            commandThread.Join(1000);
            return "connection_page_missing;" + WindowInventory(processId);
        }

        SendMessage(kad2, BM_SETCHECK,
                    new IntPtr((mask & 1) != 0 ? BST_CHECKED : BST_UNCHECKED),
                    IntPtr.Zero);
        SendMessage(kad6, BM_SETCHECK,
                    new IntPtr((mask & 2) != 0 ? BST_CHECKED : BST_UNCHECKED),
                    IntPtr.Zero);
        IntPtr page2 = GetParent(kad2);
        IntPtr page6 = GetParent(kad6);
        SendMessage(page2, WM_COMMAND, new IntPtr(IDC_NETWORK_KAD2), kad2);
        SendMessage(page6, WM_COMMAND, new IntPtr(IDC_NETWORK_KAD6), kad6);
        SendMessage(sheet, PSM_APPLY, IntPtr.Zero, IntPtr.Zero);
        PostMessage(sheet, WM_COMMAND, new IntPtr(IDOK), IntPtr.Zero);
        commandThread.Join(5000);
        return "ok";
    }
}
'@
    }
    $uiResult = [EseK02Ui]::SetMask($ProcessId, $Mask)
    if ($uiResult -cne 'ok') {
        throw "No se pudo aplicar KadNetworkMask=$Mask via UI: $uiResult"
    }
}

try {
    if ($caseId -eq 'V91-K02') {
        foreach ($address in @($localIPv6) + $peerIPv6Addresses) {
            $parsed = [Net.IPAddress]::Parse($address)
            if ($parsed.AddressFamily -ne
                    [Net.Sockets.AddressFamily]::InterNetworkV6) {
                throw "K02 requiere una direccion IPv6 nativa: $address"
            }
            $bytes = $parsed.GetAddressBytes()
            if ($bytes[0] -ne 0x20 -or $bytes[1] -ne 0x01 -or
                $bytes[2] -ne 0x00 -or $bytes[3] -ne 0x02 -or
                $bytes[4] -ne 0x00 -or $bytes[5] -ne 0x00) {
                throw "K02 solo admite el prefijo RFC 5180 2001:2::/48."
            }
        }
    } else {
        Assert-S03Ula -Address $localIPv6
        foreach ($peerAddress in $peerIPv6Addresses) {
            Assert-S03Ula -Address $peerAddress
        }
    }
    if (-not (Test-Path -LiteralPath $baseNode -PathType Container) -or
        -not (Test-Path -LiteralPath (
            Join-Path $baseNode 'emule.exe') -PathType Leaf)) {
        throw 'No existe el nodo base fijado.'
    }
    if (-not (Test-Path -LiteralPath $archiveSource -PathType Leaf)) {
        throw 'No existe el archivo candidato desplegado.'
    }

    New-Item -ItemType Directory -Path $nodePath -Force | Out-Null
    New-Item -ItemType Directory -Path $evidencePath -Force | Out-Null
    Get-ChildItem -LiteralPath $baseNode -Force |
        Where-Object Name -NotIn @('Incoming', 'Temp') |
        Copy-Item -Destination $nodePath -Recurse -Force
    New-Item -ItemType Directory -Path (Join-Path $nodePath 'Incoming') `
        -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $nodePath 'Temp') `
        -Force | Out-Null
    Copy-Item -LiteralPath $archiveSource -Destination $archivePath -Force
    Expand-Archive -LiteralPath $archivePath -DestinationPath $nodePath -Force

    $emulePath = Join-Path $nodePath 'emule.exe'
    $actualExeSha256 = (Get-FileHash -LiteralPath $emulePath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualExeSha256 -cne $expectedExeSha256) {
        throw 'El SHA-256 del emule.exe desplegado no coincide.'
    }

    $preferences = Join-Path $nodePath 'config\preferences.ini'
    $legacyKadEnabled = if ($caseId -eq 'V91-K02') { '1' } else { '0' }
    $initialKadMask = if ($caseId -eq 'V91-K02') { '3' } else { '2' }
    Set-LabIniValue -Path $preferences -Section 'eMule' `
        -Key 'Port' -Value ([string]$tcpPort)
    Set-LabIniValue -Path $preferences -Section 'eMule' `
        -Key 'UDPPort' -Value ([string]$udpPort)
    Set-LabIniValue -Path $preferences -Section 'eMule' `
        -Key 'NetworkKademlia' -Value $legacyKadEnabled
    Set-LabIniValue -Path $preferences -Section 'eMule' `
        -Key 'NetworkED2K' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'eMule' `
        -Key 'AutoConnect' -Value '0'
    if ($caseId -eq 'V91-K02') {
        # K02 authorizes one RFC1918 lab peer explicitly. The production
        # IP filter would otherwise discard that physical Kad2 fixture
        # before the protocol-plane isolation can be observed.
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key 'FilterBadIPs' -Value '0'
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key 'FilterLevel' -Value '0'
    }
    Set-LabIniValue -Path $preferences -Section 'Connection' `
        -Key 'KadNetworkMask' -Value $initialKadMask
    Set-LabIniValue -Path $preferences -Section 'Connection' `
        -Key 'IPv6Mode' -Value '2'
    $ipv6BindAddress = if ($caseId -eq 'V91-K02') { '::' } else {
        $localIPv6
    }
    Set-LabIniValue -Path $preferences -Section 'Connection' `
        -Key 'IPv6BindAddr' -Value $ipv6BindAddress
    Set-LabIniValue -Path $preferences -Section 'WebServer' `
        -Key 'Enabled' -Value '1'
    Set-LabIniValue -Path $preferences -Section 'WebServer' `
        -Key 'Port' -Value ([string]$webPort)
    Set-LabIniValue -Path $preferences -Section 'WebServer' `
        -Key 'WebUseUPnP' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'eSE' `
        -Key 'Kad6PublicExitOptIn' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'eSE' `
        -Key 'Kad6BetaExitOptIn' -Value '0'

    $existingAddress = Get-NetIPAddress -InterfaceIndex $interfaceIndex `
        -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object IPAddress -EQ $localIPv6
    if ($null -eq $existingAddress) {
        New-NetIPAddress -InterfaceIndex $interfaceIndex `
            -IPAddress $localIPv6 -PrefixLength 64 `
            -AddressFamily IPv6 -Type Unicast | Out-Null
        $addressCreated = $true
    }
    $addressDeadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    do {
        $addressState = Get-NetIPAddress -InterfaceIndex $interfaceIndex `
            -AddressFamily IPv6 -IPAddress $localIPv6 `
            -ErrorAction SilentlyContinue
        if ($null -ne $addressState -and
            [string]$addressState.AddressState -in @(
                'Preferred', 'Deprecated')) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $addressDeadline)
    if ($null -eq $addressState) {
        throw 'La ULA del candidato no quedo configurada.'
    }

    foreach ($peerAddress in $peerIPv6Addresses) {
        $peerPrefix = "$peerAddress/128"
        $existingPeerRoute = @(Get-NetRoute -AddressFamily IPv6 `
            -DestinationPrefix $peerPrefix -ErrorAction SilentlyContinue |
            Where-Object InterfaceIndex -EQ $interfaceIndex)
        if ($existingPeerRoute.Count -eq 0) {
            New-NetRoute -AddressFamily IPv6 `
                -DestinationPrefix $peerPrefix `
                -InterfaceIndex $interfaceIndex -NextHop '::' `
                -RouteMetric 1 | Out-Null
            $peerRoutesCreated.Add($peerPrefix)
        }
        if (-not [string]::IsNullOrWhiteSpace($peerLinkLayerAddress)) {
            $neighborCreated = $false
            for ($neighborAttempt = 0; $neighborAttempt -lt 5;
                    ++$neighborAttempt) {
                Get-NetNeighbor -AddressFamily IPv6 `
                    -InterfaceIndex $interfaceIndex -IPAddress $peerAddress `
                    -ErrorAction SilentlyContinue |
                    Remove-NetNeighbor -Confirm:$false `
                        -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 200
                try {
                    New-NetNeighbor -AddressFamily IPv6 `
                        -InterfaceIndex $interfaceIndex `
                        -IPAddress $peerAddress `
                        -LinkLayerAddress $peerLinkLayerAddress `
                        -State Permanent -ErrorAction Stop | Out-Null
                    $neighborCreated = $true
                    break
                } catch {
                    if ($neighborAttempt -eq 4) {
                        throw
                    }
                    Start-Sleep -Milliseconds 300
                }
            }
            if (-not $neighborCreated) {
                throw "No se pudo fijar el vecino IPv6 $peerAddress."
            }
            $peerNeighborsCreated.Add($peerAddress)
        }
    }

    for ($peerIndex = 0; $peerIndex -lt $peerIPv6Addresses.Count;
            ++$peerIndex) {
        $peerRuleName = "$firewallName-$peerIndex"
        New-NetFirewallRule -Name $peerRuleName `
            -DisplayName $peerRuleName `
            -Direction Inbound -Action Allow -Protocol UDP `
            -LocalPort $udpPort -LocalAddress "$localIPv6/128" `
            -RemoteAddress "$($peerIPv6Addresses[$peerIndex])/128" `
            -InterfaceAlias $interfaceAlias -Program $emulePath | Out-Null
        $firewallNames.Add($peerRuleName)
    }
    if ($caseId -eq 'V91-K02') {
        $parsedPeerIPv4 = [Net.IPAddress]::Parse($peerIPv4)
        if ($parsedPeerIPv4.AddressFamily -ne
                [Net.Sockets.AddressFamily]::InterNetwork) {
            throw 'peer_ipv4 no es una IPv4 valida para V91-K02.'
        }
        $peerV4RuleName = "$firewallName-v4"
        New-NetFirewallRule -Name $peerV4RuleName `
            -DisplayName $peerV4RuleName `
            -Direction Inbound -Action Allow -Protocol UDP `
            -LocalPort $udpPort -RemoteAddress "$peerIPv4/32" `
            -InterfaceAlias $interfaceAlias -Program $emulePath | Out-Null
        $firewallNames.Add($peerV4RuleName)
    }
    $firewallCreated = $true

    $routes = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction Stop |
        Where-Object {
            $_.InterfaceIndex -eq $interfaceIndex -or
            $_.DestinationPrefix -like 'fd91:91:503:2026::*'
        } | ForEach-Object {
            [ordered]@{
                destination = $_.DestinationPrefix
                next_hop = $_.NextHop
                if_index = [int]$_.InterfaceIndex
                metric = [int]$_.RouteMetric
                state = [string]$_.State
            }
        })
    Write-S03Json -Value $routes -Path $routePath

    $sessionBefore = @(& logman.exe query -ets PktMon 2>&1)
    if ($LASTEXITCODE -eq 0) {
        throw 'Ya existe una sesion PktMon activa.'
    }
    @(& pktmon.exe filter list 2>&1) |
        Set-Content -LiteralPath $filterBeforePath -Encoding UTF8
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo inventariar los filtros PktMon.'
    }
    $filterInventoryBefore = @(
        Get-Content -LiteralPath $filterBeforePath
    )
    if (($filterInventoryBefore -join "`n") -notmatch
            '(?im)^\s*(?:none|ninguno)\s*$') {
        throw 'El inventario PktMon no esta vacio; se rechaza una captura contaminada.'
    }
    # Capture the complete PktMon path. Mirrored WSL traffic can enter through
    # a forwarding component before it reaches the physical Wi-Fi component;
    # the adjudicator correlates every matching frame back to the pinned NIC.
    & pktmon.exe start --capture --pkt-size 0 --file-name $etlPath `
        --file-size 16 --log-mode circular | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo iniciar PktMon.'
    }
    $captureStarted = $true

    $process = Start-Process -FilePath $emulePath -ArgumentList @(
        '--portable', '--ignoreinstances', '--headless',
        "--metrics-port=$webPort", "--tcp-port=$tcpPort",
        "--udp-port=$udpPort"
    ) -WorkingDirectory $nodePath -WindowStyle Hidden -PassThru

    $status = $null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 400
        $process.Refresh()
        if ($process.HasExited) {
            throw "El candidato termino con codigo $($process.ExitCode)."
        }
        try {
            $status = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$webPort/api/status" `
                -TimeoutSec 2
        } catch {
            $status = $null
        }
    } while ($null -eq $status -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($null -eq $status) {
        throw 'La API local del candidato no quedo disponible.'
    }
    if (-not [bool]$status.kad6_running) {
        $networkControl = Invoke-RestMethod -Uri (
            "http://127.0.0.1:$webPort" +
            '/api/network/connect?ed2k=0&kad=1'
        ) -TimeoutSec 10
        Write-S03Json -Value $networkControl -Path (
            Join-Path $evidencePath 'network-control.json')
        $networkDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 400
            $process.Refresh()
            if ($process.HasExited) {
                throw "El candidato termino con codigo $($process.ExitCode)."
            }
            $status = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$webPort/api/status" `
                -TimeoutSec 2
            if ([bool]$status.kad6_running) {
                break
            }
        } while ([DateTimeOffset]::UtcNow -lt $networkDeadline)
    }
    Write-S03Json -Value $status -Path (
        Join-Path $evidencePath 'startup-status.json')
    $expectedStartupMask = if ($caseId -eq 'V91-K02') { 3 } else { 2 }
    if ([int]$status.kad_running_mask -ne $expectedStartupMask -or
        [int]$status.kad_configured_mask -ne $expectedStartupMask) {
        throw "El candidato no quedo en Kad mask $expectedStartupMask."
    }

    $udpEndpointDeadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    $allProcessUdpEndpoints = @()
    do {
        $allProcessUdpEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop |
            Where-Object OwningProcess -EQ $process.Id |
            ForEach-Object {
                [ordered]@{
                    local_address = $_.LocalAddress
                    local_port = [int]$_.LocalPort
                    owning_process = [int]$_.OwningProcess
                }
            })
        $udpEndpoints = @($allProcessUdpEndpoints |
            Where-Object local_port -EQ $udpPort)
        if ($udpEndpoints.Count -gt 0) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $udpEndpointDeadline)
    Write-S03Json -Value $allProcessUdpEndpoints -Path (
        Join-Path $evidencePath 'all-process-udp-endpoints.json')
    if ($udpEndpoints.Count -lt 1) {
        throw 'No existe endpoint UDP del candidato en el puerto fijado.'
    }
    Write-S03Json -Value $udpEndpoints -Path $endpointPath

    $ready = [ordered]@{
        schema = 'ese.v91.kad6-ready/v1'
        case_id = $caseId
        status = 'READY'
        created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        expires_at_utc = [DateTimeOffset]::UtcNow.
            AddSeconds($holdSeconds).ToString('o')
        process_id = $process.Id
        exe_sha256 = $actualExeSha256
        candidate_ipv6 = $localIPv6
        probe_ipv6 = $peerIPv6
        probe_ipv6s = $peerIPv6Addresses
        probe_ipv4 = $peerIPv4
        interface_index = $interfaceIndex
        interface_alias = $interfaceAlias
        capture_component_id = $captureComponentId
        capture_scope = 'all_components'
        udp_port = $udpPort
        tcp_port = $tcpPort
        web_port = $webPort
        kad_configured_mask = $status.kad_configured_mask
        kad_running_mask = $status.kad_running_mask
        kad2_running = [bool]$status.kad2_running
        kad6_running = [bool]$status.kad6_running
        capture = 'ARMED'
    }
    Write-S03Json -Value $ready -Path $readyPath

    if ($caseId -eq 'V91-K02') {
        $phasePlan = @(
            [ordered]@{ name = 'both'; mask = 3 },
            [ordered]@{ name = 'kad6-only'; mask = 2 },
            [ordered]@{ name = 'kad2-only'; mask = 1 }
        )
        foreach ($phase in $phasePlan) {
            if ([int]$phase.mask -ne 3) {
                Set-K02KadMask -ProcessId $process.Id -Mask ([int]$phase.mask)
            }
            $phaseStatus = $null
            $phaseDeadline = [DateTimeOffset]::UtcNow.AddSeconds(12)
            do {
                Start-Sleep -Milliseconds 250
                $phaseStatus = Invoke-RestMethod `
                    -Uri "http://127.0.0.1:$webPort/api/status" `
                    -TimeoutSec 2
                if ([int]$phaseStatus.kad_running_mask -eq [int]$phase.mask -and
                    [int]$phaseStatus.kad_configured_mask -eq [int]$phase.mask) {
                    break
                }
            } while ([DateTimeOffset]::UtcNow -lt $phaseDeadline)
            if ([int]$phaseStatus.kad_running_mask -ne [int]$phase.mask -or
                [int]$phaseStatus.kad_configured_mask -ne [int]$phase.mask) {
                throw "La fase $($phase.name) no aplico mask=$($phase.mask)."
            }
            $phaseReady = [ordered]@{
                schema = 'ese.v91.k02-phase/v1'
                case_id = $caseId
                status = 'READY'
                phase = [string]$phase.name
                mask = [int]$phase.mask
                created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                expires_at_utc = [DateTimeOffset]::UtcNow.
                    AddSeconds($k02PhaseSeconds).ToString('o')
                process_id = $process.Id
                exe_sha256 = $actualExeSha256
            }
            Write-S03Json -Value $phaseReady -Path (
                Join-Path $jobRoot "phase-$($phase.name).json")
            $phaseSampleStart = $samples.Count
            $phaseEnd = [DateTimeOffset]::UtcNow.AddSeconds($k02PhaseSeconds)
            do {
                Start-Sleep -Seconds 1
                $process.Refresh()
                if ($process.HasExited) {
                    throw "El candidato termino con codigo $($process.ExitCode)."
                }
                try {
                    $sample = Invoke-RestMethod `
                        -Uri "http://127.0.0.1:$webPort/api/status" `
                        -TimeoutSec 2
                    $samples.Add([ordered]@{
                        at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                        phase = [string]$phase.name
                        expected_mask = [int]$phase.mask
                        api_ok = $true
                        kad_configured_mask = [int]$sample.kad_configured_mask
                        kad_running_mask = [int]$sample.kad_running_mask
                        kad2_running = [bool]$sample.kad2_running
                        kad6_running = [bool]$sample.kad6_running
                        kad6_verified_contacts =
                            $sample.kad6_verified_contacts
                    })
                } catch {
                    $samples.Add([ordered]@{
                        at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                        phase = [string]$phase.name
                        expected_mask = [int]$phase.mask
                        api_ok = $false
                        error = $_.Exception.Message
                    })
                }
            } while ([DateTimeOffset]::UtcNow -lt $phaseEnd)
            $badPhaseSamples = @($samples |
                Select-Object -Skip $phaseSampleStart |
                Where-Object {
                    -not $_.api_ok -or
                    [int]$_.kad_running_mask -ne [int]$phase.mask -or
                    [int]$_.kad_configured_mask -ne [int]$phase.mask -or
                    [bool]$_.kad2_running -ne (
                        ([int]$phase.mask -band 1) -ne 0) -or
                    [bool]$_.kad6_running -ne (
                        ([int]$phase.mask -band 2) -ne 0)
                })
            $phaseResults.Add([ordered]@{
                phase = [string]$phase.name
                expected_mask = [int]$phase.mask
                sample_count = $samples.Count - $phaseSampleStart
                bad_sample_count = $badPhaseSamples.Count
                status = if ($badPhaseSamples.Count -eq 0) {
                    'PASS'
                } else {
                    'FAIL'
                }
            })
            if ($badPhaseSamples.Count -ne 0) {
                throw "La fase $($phase.name) cruzo estados Kad2/Kad6."
            }
        }
    } else {
        $holdDeadline = [DateTimeOffset]::UtcNow.AddSeconds($holdSeconds)
        do {
            Start-Sleep -Seconds 2
            $process.Refresh()
            if ($process.HasExited) {
                throw "El candidato termino con codigo $($process.ExitCode)."
            }
            try {
                $sample = Invoke-RestMethod `
                    -Uri "http://127.0.0.1:$webPort/api/status" `
                    -TimeoutSec 2
                $samples.Add([ordered]@{
                    at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                    api_ok = $true
                    kad2_running = [bool]$sample.kad2_running
                    kad6_running = [bool]$sample.kad6_running
                    kad6_verified_contacts = $sample.kad6_verified_contacts
                })
            } catch {
                $samples.Add([ordered]@{
                    at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                    api_ok = $false
                    error = $_.Exception.Message
                })
            }
        } while ([DateTimeOffset]::UtcNow -lt $holdDeadline)

        if (@($samples | Where-Object {
                -not $_.api_ok -or -not $_.kad6_running -or $_.kad2_running
            }).Count -ne 0) {
            throw 'El candidato no mantuvo Kad6-only y API responsiva.'
        }
    }
    $finalStatus = 'PASS'
} catch {
    $failure = $_.Exception.Message
    $finalStatus = 'FAIL'
} finally {
    if ($null -ne $process) {
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force `
                    -ErrorAction SilentlyContinue
                $process.WaitForExit(10000) | Out-Null
            }
        } catch {}
    }
    if ($captureStarted) {
        & pktmon.exe stop | Out-Null
        $captureStarted = $false
        if (Test-Path -LiteralPath $etlPath -PathType Leaf) {
            & pktmon.exe etl2pcap $etlPath --out $pcapPath | Out-Null
            $pcapExitCode = $LASTEXITCODE
            & pktmon.exe etl2txt $etlPath --out $textPath `
                --timestamp --verbose --hex | Out-Null
            $textExitCode = $LASTEXITCODE
        }
    }
    @(& pktmon.exe filter list 2>&1) |
        Set-Content -LiteralPath $filterAfterPath -Encoding UTF8
    $filterInventoryAfter = @(
        Get-Content -LiteralPath $filterAfterPath
    )
    $filtersUnchanged = (
        $filterInventoryBefore -join "`n"
    ) -ceq (
        $filterInventoryAfter -join "`n"
    )
    if ($firewallCreated) {
        foreach ($peerRuleName in $firewallNames) {
            Remove-NetFirewallRule -Name $peerRuleName `
                -ErrorAction SilentlyContinue
        }
    }
    if ($addressCreated) {
        Remove-NetIPAddress -InterfaceIndex $interfaceIndex `
            -IPAddress $localIPv6 -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    foreach ($peerPrefix in $peerRoutesCreated) {
        Remove-NetRoute -AddressFamily IPv6 `
            -DestinationPrefix $peerPrefix `
            -InterfaceIndex $interfaceIndex -NextHop '::' `
            -Confirm:$false -ErrorAction SilentlyContinue
    }
    foreach ($peerAddress in $peerNeighborsCreated) {
        Remove-NetNeighbor -AddressFamily IPv6 `
            -InterfaceIndex $interfaceIndex -IPAddress $peerAddress `
            -State Permanent -PolicyStore ActiveStore `
            -Confirm:$false -ErrorAction SilentlyContinue
    }
    $etlBytes = if (Test-Path -LiteralPath $etlPath -PathType Leaf) {
        [Int64](Get-Item -LiteralPath $etlPath).Length
    } else { 0L }
    $pcapBytes = if (Test-Path -LiteralPath $pcapPath -PathType Leaf) {
        [Int64](Get-Item -LiteralPath $pcapPath).Length
    } else { 0L }
    $textBytes = if (Test-Path -LiteralPath $textPath -PathType Leaf) {
        [Int64](Get-Item -LiteralPath $textPath).Length
    } else { 0L }
    $captureHasTraffic = $etlBytes -gt 12000 -and $pcapBytes -gt 180 `
        -and $textBytes -gt 1842 -and $pcapExitCode -eq 0 `
        -and $textExitCode -eq 0
    $firewallAbsent = @($firewallNames | Where-Object {
            @(Get-NetFirewallRule -Name $_ `
                -ErrorAction SilentlyContinue).Count -ne 0
        }).Count -eq 0
    $addressAbsent = @(
        Get-NetIPAddress -InterfaceIndex $interfaceIndex `
            -AddressFamily IPv6 -IPAddress $localIPv6 `
            -ErrorAction SilentlyContinue
    ).Count -eq 0
    $peerRoutesAbsent = @($peerRoutesCreated | Where-Object {
            @(Get-NetRoute -AddressFamily IPv6 `
                -DestinationPrefix $_ -InterfaceIndex $interfaceIndex `
                -ErrorAction SilentlyContinue).Count -ne 0
        }).Count -eq 0
    $peerNeighborsAbsent = @($peerNeighborsCreated | Where-Object {
            @(Get-NetNeighbor -AddressFamily IPv6 `
                -InterfaceIndex $interfaceIndex -IPAddress $_ `
                -State Permanent -PolicyStore ActiveStore `
                -ErrorAction SilentlyContinue).Count -ne 0
        }).Count -eq 0

    $result = [ordered]@{
        schema = 'ese.v91.kad6-remote/v1'
        case_id = $caseId
        status = $finalStatus
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        failure = $failure
        process_id = if ($null -eq $process) { $null } else { $process.Id }
        exe_sha256 = if (Get-Variable actualExeSha256 `
                -ErrorAction SilentlyContinue) {
            $actualExeSha256
        } else {
            $null
        }
        candidate_ipv6 = $localIPv6
        probe_ipv6 = $peerIPv6
        probe_ipv6s = $peerIPv6Addresses
        probe_ipv4 = $peerIPv4
        interface_index = $interfaceIndex
        interface_alias = $interfaceAlias
        capture_component_id = $captureComponentId
        capture_scope = 'all_components'
        udp_port = $udpPort
        samples = $samples.ToArray()
        phases = $phaseResults.ToArray()
        capture = [ordered]@{
            etl = Test-Path -LiteralPath $etlPath -PathType Leaf
            pcapng = Test-Path -LiteralPath $pcapPath -PathType Leaf
            text = Test-Path -LiteralPath $textPath -PathType Leaf
            etl_bytes = $etlBytes
            pcapng_bytes = $pcapBytes
            text_bytes = $textBytes
            traffic_observed = $captureHasTraffic
        }
        cleanup = [ordered]@{
            process_stopped = $true
            capture_stopped = -not $captureStarted
            filters_unchanged = $filtersUnchanged
            firewall_removed = $firewallAbsent
            address_removed = $addressAbsent
            peer_routes_removed = $peerRoutesAbsent
            peer_neighbors_removed = $peerNeighborsAbsent
        }
    }
    Write-S03Json -Value $result -Path $resultPath
    $result | ConvertTo-Json -Depth 12
}

if ($finalStatus -ne 'PASS') {
    exit 1
}
