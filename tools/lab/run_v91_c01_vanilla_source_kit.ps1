[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$expectedEmuleBytes = 7896576L
$expectedEmuleSha256 =
    '1FD7EEB62E9A93914644DC4FBD11E0C7AC37EE0A416EDF90F415EED7D9A7C105'
$expectedTemplateBytes = 115017L
$expectedTemplateSha256 =
    '09E4C42F069F06EE77C0A2185A84265DCF08A00A5805CDD197741C2DE742C08E'
$fixtureName = 'net13-unique-ffmpeg.zip'
$fixtureBytes = 223394208L
$fixtureSha256 =
    'AAC4B00281982E473AAB7071B1A593EEF3AD22301085D18D26933557B022890C'
$fixtureEd2k = 'A4140C71628D93D5FD0981FD962C2552'
$tcpPort = 48712
$formalKitNonce = '49b2b8a7ecaf401b8be9e8a950c6a06e'
$formalCoordinatorTailscaleIPv4 = '100.69.24.30'
$payloadName = 'V91-C01-VANILLA-PAYLOAD.zip'
$payloadSha256 =
    '7807DA0912BA2A1BE16D8E26E3929C77C91F699BA396087DDFBAE3C8616DD0A8'
$layoutRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$directPayloadPath = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot $payloadName))
$payloadPath = if (
    Test-Path -LiteralPath $directPayloadPath -PathType Leaf
) {
    $directPayloadPath
} else {
    $fallbackPayloadCandidates = @(
        @(
            (Split-Path -Parent $PSScriptRoot),
            $layoutRoot,
            (Split-Path -Parent $layoutRoot)
        ) | ForEach-Object {
            if ($_ -and
                (Test-Path -LiteralPath (Join-Path $_ $payloadName) `
                    -PathType Leaf)) {
                [IO.Path]::GetFullPath((Join-Path $_ $payloadName))
            }
        } | Sort-Object -Unique
    )
    if ($fallbackPayloadCandidates.Count -eq 1) {
        [string]$fallbackPayloadCandidates[0]
    } else {
        ''
    }
}
$kitRoot = if ($payloadPath) {
    [IO.Path]::GetFullPath((Split-Path -Parent $payloadPath))
} elseif (
    (Test-Path -LiteralPath (Join-Path $layoutRoot 'C01-REMOTE-CONFIG.json') `
        -PathType Leaf) -or
    (Test-Path -LiteralPath (Join-Path $layoutRoot 'node') `
        -PathType Container)
) {
    $layoutRoot
} else {
    throw (
        "No se encontro exactamente un $payloadName en el directorio del " +
        'starter, sus layouts padre o el padre de kitRoot.'
    )
}
$nodeRoot = Join-Path $kitRoot 'node'
$configPath = Join-Path $kitRoot 'C01-REMOTE-CONFIG.json'
$activePath = Join-Path $kitRoot 'ACTIVE-C01.json'
$latestReadyPath = Join-Path $kitRoot 'READY-C01.json'
$emulePath = Join-Path $nodeRoot 'emule.exe'
$templatePath = Join-Path $nodeRoot 'eMule.tmpl'
$fixturePath = Join-Path $nodeRoot "Incoming\$fixtureName"
$generatedConfig = Join-Path $nodeRoot 'config'
$process = $null
$firewallCreated = $false
$firewallName = ''
$runRoot = ''

function Write-JsonUtf8 {
    param([Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path)
    [IO.File]::WriteAllText(
        $Path, ($Value | ConvertTo-Json -Depth 12),
        (New-Object Text.UTF8Encoding($false)))
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Este kit V91-C01 debe ejecutarse como administrador.'
    }
}

function Assert-File {
    param([string]$Path, [long]$Bytes, [string]$Sha256, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Falta ${Label}: $Path"
    }
    if ((Get-Item -LiteralPath $Path).Length -ne $Bytes) {
        throw "Longitud incorrecta para $Label."
    }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne
        $Sha256) {
        throw "SHA-256 incorrecto para $Label."
    }
}

function Convert-ToTailscaleIPv4 {
    param([string]$Value, [string]$Label)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$parsed) -or
        $parsed.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Label no es IPv4."
    }
    $bytes = $parsed.GetAddressBytes()
    if ($bytes[0] -ne 100 -or $bytes[1] -lt 64 -or $bytes[1] -gt 127) {
        throw "$Label no pertenece al rango Tailscale 100.64.0.0/10."
    }
    return $parsed.ToString()
}

function Get-MachineIdentityHash {
    $seed = [string](Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
        -Name MachineGuid -ErrorAction Stop).MachineGuid
    return Get-StringSha256 -Value $seed
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) |
            ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function Restore-DirectoryMode {
    if (-not $script:registryChanged) { return }
    if ($script:registryOriginalExists) {
        New-ItemProperty -LiteralPath $script:registryPath `
            -Name $script:registryName -Value $script:registryOriginalValue `
            -PropertyType DWord -Force | Out-Null
    } else {
        Remove-ItemProperty -LiteralPath $script:registryPath `
            -Name $script:registryName -ErrorAction SilentlyContinue
    }
    $script:registryChanged = $false
}

Assert-Admin
if (Test-Path -LiteralPath $activePath) {
    throw 'Ya existe ACTIVE-C01.json. Ejecute primero STOP-V91-C01-VANILLA.cmd.'
}

if (-not (Test-Path -LiteralPath $nodeRoot -PathType Container)) {
    if (-not $payloadPath) {
        throw (
            "No se encontro exactamente un $payloadName junto al kit. " +
            "Encontrados=$($payloadCandidates.Count)."
        )
    }
    if ((Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash -ne
        $payloadSha256) {
        throw 'El ZIP payload V91-C01 no coincide con el SHA-256 formal.'
    }
    $null = New-Item -ItemType Directory -Path $nodeRoot
    try {
        Expand-Archive -LiteralPath $payloadPath -DestinationPath $nodeRoot `
            -Force
    } catch {
        throw (
            "No se pudo extraer el payload; se conserva '$nodeRoot' para " +
            "diagnostico: $($_.Exception.Message)"
        )
    }
}
if (Test-Path -LiteralPath $generatedConfig) {
    throw 'El nodo remoto ya contiene config. Use un kit nuevo o ejecute cleanup.'
}

if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    $kit = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    if ($kit.schema -ne 'ese.v91.c01-remote-kit-config/v1' -or
        $kit.case_id -ne 'V91-C01' -or
        [string]$kit.kit_nonce -notmatch '^[0-9a-f]{32}$') {
        throw 'C01-REMOTE-CONFIG.json no es un manifiesto V91-C01 valido.'
    }
    $now = [DateTimeOffset]::UtcNow
    $created = [DateTimeOffset]::Parse([string]$kit.created_at_utc)
    $expires = [DateTimeOffset]::Parse([string]$kit.expires_at_utc)
    if ($created -gt $now.AddMinutes(5) -or $expires -le $now -or
        $expires -le $created) {
        throw 'La configuracion remota V91-C01 ha caducado o tiene fechas invalidas.'
    }
} else {
    $kit = [pscustomobject]@{
        schema = 'ese.v91.c01-remote-kit-config/v1'
        case_id = 'V91-C01'
        kit_nonce = $formalKitNonce
        coordinator_tailscale_ipv4 =
            $formalCoordinatorTailscaleIPv4
    }
}
$coordinatorIPv4 = Convert-ToTailscaleIPv4 `
    -Value ([string]$kit.coordinator_tailscale_ipv4) `
    -Label 'IPv4 Tailscale del coordinador'

foreach ($path in $emulePath, $templatePath, $fixturePath) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Payload incompleto: $path"
    }
}
Assert-File -Path $emulePath -Bytes $expectedEmuleBytes `
    -Sha256 $expectedEmuleSha256 -Label 'emule.exe vanilla'
Assert-File -Path $templatePath -Bytes $expectedTemplateBytes `
    -Sha256 $expectedTemplateSha256 -Label 'eMule.tmpl vanilla'
Assert-File -Path $fixturePath -Bytes $fixtureBytes `
    -Sha256 $fixtureSha256 -Label 'fixture de compatibilidad'
if ([string](Get-Item -LiteralPath $emulePath).VersionInfo.ProductVersion -ne
    '0.70.1 Unicode') {
    throw 'emule.exe no declara ProductVersion 0.70.1 Unicode.'
}

$tailscaleAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object {
    $_.Status -eq 'Up' -and
    ('{0}|{1}' -f $_.Name, $_.InterfaceDescription) -match '(?i)Tailscale'
})
if ($tailscaleAdapters.Count -ne 1) {
    throw 'Se esperaba exactamente un adaptador Tailscale activo.'
}
$tailscaleAdapter = $tailscaleAdapters[0]
$sourceAddresses = @(
    Get-NetIPAddress -InterfaceIndex $tailscaleAdapter.ifIndex `
        -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object AddressState -eq 'Preferred'
)
if ($sourceAddresses.Count -ne 1) {
    throw 'Se esperaba exactamente una IPv4 Tailscale preferida.'
}
$sourceIPv4 = Convert-ToTailscaleIPv4 `
    -Value ([string]$sourceAddresses[0].IPAddress `
    ) -Label 'IPv4 Tailscale del Source'
if ($sourceIPv4 -eq $coordinatorIPv4) {
    throw 'Source y Coordinator anuncian la misma IPv4 Tailscale.'
}
$tailscaleCommand = Get-Command tailscale.exe -ErrorAction Stop
$tailscaleStatusText = ((& $tailscaleCommand.Source status --json) -join "`n")
if ($LASTEXITCODE -ne 0) {
    throw 'tailscale status --json fallo en el Source.'
}
$tailscaleStatus = $tailscaleStatusText | ConvertFrom-Json
$tailnetNodeId = [string]$tailscaleStatus.Self.ID
if ([string]::IsNullOrWhiteSpace($tailnetNodeId)) {
    throw 'tailscale status no contiene Self.ID.'
}
$tailnetNodeIdHash = Get-StringSha256 -Value $tailnetNodeId
if (Get-NetTCPConnection -State Listen -LocalPort $tcpPort `
        -ErrorAction SilentlyContinue) {
    throw "TCP/$tcpPort ya esta en uso."
}

$stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$runRoot = Join-Path $kitRoot (
    "runs\v91-c01-source-$($kit.kit_nonce.Substring(0,8))-$stamp")
$evidenceRoot = Join-Path $runRoot 'evidence'
$null = New-Item -ItemType Directory -Path $evidenceRoot -Force
$null = New-Item -ItemType Directory -Path $generatedConfig -Force
$null = New-Item -ItemType Directory -Path (Join-Path $nodeRoot 'Temp') -Force
$null = New-Item -ItemType Directory -Path (Join-Path $nodeRoot 'logs') -Force

$preferencesPath = Join-Path $generatedConfig 'preferences.ini'
$preferences = @(
    '[eMule]',
    'AppVersion=0.70b',
    'Nick=eMule-0.70b-V91-C01',
    "Port=$tcpPort",
    'UDPPort=0',
    'Autoconnect=0',
    'AutoStart=0',
    'NetworkKademlia=0',
    'NetworkED2K=0',
    'Networks=',
    'EnableUPnP=0',
    'WebServerUseUPnP=0',
    'OpenPortsOnStartUp=0',
    'AddServersFromServer=0',
    'AddServersFromClient=0',
    'Serverlist=0',
    'FilterBadIPs=0',
    'AllowLocalHostIP=1',
    'MaxUpload=-1',
    'MaxDownload=-1',
    'UploadCapacityNew=100000',
    'DownloadCapacity=100000',
    'CryptLayerRequested=0',
    'CryptLayerRequired=0',
    'CryptLayerSupported=0',
    'SaveLogToDisk=1',
    'Verbose=1',
    "IncomingDir=$(Join-Path $nodeRoot 'Incoming')\",
    "TempDir=$(Join-Path $nodeRoot 'Temp')\",
    "WebTemplateFile=$templatePath",
    '',
    '[WebServer]',
    'Enabled=0',
    'WebUseUPnP=0',
    '',
    '[UPnP]',
    'EnableUPnP=0'
)
[IO.File]::WriteAllLines(
    $preferencesPath, $preferences,
    (New-Object Text.UTF8Encoding($false)))

$firewallName = "eSE-V91-C01-$($kit.kit_nonce)"
$firewallDisplay = "eSE V91 C01 vanilla $($kit.kit_nonce)"
if (@(Get-NetFirewallRule -Name $firewallName `
        -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'Ya existe la regla firewall nonce-scoped de este kit.'
}

$script:registryPath = 'HKCU:\Software\eMule'
$script:registryName = 'UsePublicUserDirectories'
$script:registryOriginalExists = $false
$script:registryOriginalValue = $null
$script:registryChanged = $false
try {
    New-NetFirewallRule -Name $firewallName -DisplayName $firewallDisplay `
        -Direction Inbound -Action Allow -Profile Any -Protocol TCP `
        -LocalPort $tcpPort -LocalAddress $sourceIPv4 -Program $emulePath `
        -InterfaceAlias $tailscaleAdapter.Name `
        -RemoteAddress $coordinatorIPv4 | Out-Null
    $firewallCreated = $true

    $registry = Get-ItemProperty -LiteralPath $script:registryPath `
        -ErrorAction SilentlyContinue
    if ($null -ne $registry -and
        $null -ne $registry.PSObject.Properties[$script:registryName]) {
        $script:registryOriginalExists = $true
        $script:registryOriginalValue =
            [int]$registry.$($script:registryName)
    }
    $null = New-Item -Path $script:registryPath -Force
    New-ItemProperty -LiteralPath $script:registryPath `
        -Name $script:registryName -Value 2 -PropertyType DWord -Force |
        Out-Null
    $script:registryChanged = $true
    try {
        $process = Start-Process -FilePath $emulePath `
            -WorkingDirectory $nodeRoot -ArgumentList @('-ignoreinstances') `
            -WindowStyle Minimized -PassThru
        # Vanilla 0.70b has no --portable switch. Keep the directory-mode
        # registry override in place until its PID owns the expected listener;
        # restoring it immediately after Start-Process races profile loading.
        $deadline = [DateTime]::UtcNow.AddSeconds(90)
        $listener = $null
        do {
            $process.Refresh()
            if ($process.HasExited) {
                throw 'eMule vanilla termino antes de abrir el listener.'
            }
            $listener = Get-NetTCPConnection -State Listen `
                -LocalPort $tcpPort -ErrorAction SilentlyContinue |
                Where-Object OwningProcess -eq $process.Id |
                Select-Object -First 1
            if ($null -ne $listener) { break }
            Start-Sleep -Milliseconds 500
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($null -eq $listener) {
            throw "eMule vanilla no abrio TCP/$tcpPort."
        }
    } finally {
        Restore-DirectoryMode
    }

    # A fresh profile must hash the pinned 223 MiB fixture before answering.
    Start-Sleep -Seconds 30
    $process.Refresh()
    if ($process.HasExited) {
        throw 'eMule vanilla termino durante el indexado inicial.'
    }

    $startedAt = [DateTimeOffset]$process.StartTime.ToUniversalTime()
    $readyAt = [DateTimeOffset]::UtcNow
    $machineHash = Get-MachineIdentityHash
    $session = [ordered]@{
        schema = 'ese.v91.c01-vanilla-source-session/v1'
        case_id = 'V91-C01'
        kit_nonce = [string]$kit.kit_nonce
        started_at_utc = $startedAt.ToString('o')
        ready_at_utc = $readyAt.ToString('o')
        source_process_id = $process.Id
        source_executable = $emulePath
        source_machine_identity_sha256 = $machineHash
        source_tailscale_ipv4 = $sourceIPv4
        coordinator_tailscale_ipv4 = $coordinatorIPv4
        tcp_port = $tcpPort
        firewall_rule_name = $firewallName
        firewall_display_name = $firewallDisplay
        firewall_interface_alias = [string]$tailscaleAdapter.Name
        vanilla_emule_sha256 = $expectedEmuleSha256.ToLowerInvariant()
        fixture_sha256 = $fixtureSha256.ToLowerInvariant()
        fixture_bytes = $fixtureBytes
        fixture_ed2k = $fixtureEd2k
        preferences_sha256 = (
            Get-FileHash -LiteralPath $preferencesPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        clean_profile_generated = $true
        webserver_enabled = $false
        kad_enabled = $false
        ed2k_enabled = $false
        autoconnect_enabled = $false
        upnp_enabled = $false
        transport = 'Tailscale IPv4 overlay'
    }
    $sessionPath = Join-Path $evidenceRoot 'source-session-private.json'
    Write-JsonUtf8 -Value $session -Path $sessionPath

    $ready = [ordered]@{
        schema = 'ese.v91.c01.remote-vanilla-ready/v1'
        case_id = 'V91-C01'
        status = 'READY'
        nonce = [string]$kit.kit_nonce
        kit_nonce = [string]$kit.kit_nonce
        created_at_utc = $readyAt.ToString('o')
        ready_at_utc = $readyAt.ToString('o')
        ready_expires_at_utc = $readyAt.AddHours(2).ToString('o')
        host_id_hash = $machineHash
        tailnet_node_id_hash = $tailnetNodeIdHash
        independent_physical_windows_confirmation_required = $true
        source_tailscale_ipv4 = $sourceIPv4
        coordinator_tailscale_ipv4 = $coordinatorIPv4
        topology = [ordered]@{
            host_role = 'H2'
            isolation = 'physical-independent-windows'
            topology_requirement = 'V1/H2'
            data_path = 'compat-overlay'
        }
        listener = [ordered]@{
            address_class = 'cgnat-v4'
            port = $tcpPort
            owning_process_id = $process.Id
            listening = $true
        }
        vanilla = [ordered]@{
            version = '0.70b'
            product_version = '0.70.1 Unicode'
            process_id = $process.Id
            emule_bytes = $expectedEmuleBytes
            binary_sha256 = $expectedEmuleSha256.ToLowerInvariant()
            emule_sha256 = $expectedEmuleSha256.ToLowerInvariant()
        }
        fixture = [ordered]@{
            name = $fixtureName
            bytes = $fixtureBytes
            sha256 = $fixtureSha256.ToLowerInvariant()
            ed2k = $fixtureEd2k
            available = $true
        }
        controls = [ordered]@{
            clean_profile_generated = $true
            webserver_enabled = $false
            kad_enabled = $false
            ed2k_enabled = $false
            autoconnect_enabled = $false
            upnp_enabled = $false
            firewall_peer_scoped = $true
            firewall_nonce_scoped = $true
        }
        transport = [ordered]@{
            kind = 'Tailscale IPv4 overlay'
            purpose = 'V91-C01 classic-wire interoperability only'
            native_reachability_claim = $false
        }
        private_session_sha256 = (
            Get-FileHash -LiteralPath $sessionPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
    $readyPath = Join-Path $runRoot 'READY-C01.json'
    Write-JsonUtf8 -Value $ready -Path $readyPath
    Copy-Item -LiteralPath $readyPath -Destination $latestReadyPath -Force

    $active = [ordered]@{
        schema = 'ese.v91.c01-active-source/v1'
        case_id = 'V91-C01'
        kit_nonce = [string]$kit.kit_nonce
        run_root = $runRoot
        session_path = $sessionPath
        ready_path = $readyPath
        process_id = $process.Id
        firewall_rule_name = $firewallName
    }
    Write-JsonUtf8 -Value $active -Path $activePath
    $result = [ordered]@{
        schema = 'ese.v91.c01-source-start-result/v1'
        case_id = 'V91-C01'
        verdict = 'READY'
        formal_case_verdict = 'NOT_YET_EXECUTED'
        ready_sha256 = (
            Get-FileHash -LiteralPath $readyPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        process_alive = $true
        listener_owned = $true
        firewall_peer_scoped = $true
        clean_profile = $true
    }
    Write-JsonUtf8 -Value $result `
        -Path (Join-Path $evidenceRoot 'source-start-result.json')

    try {
        & $tailscaleCommand.Source file cp $latestReadyPath `
            'iaki-casa-1:' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'Taildrop de READY-C01.json devolvio error.'
        }
    } catch {
        Write-Warning (
            'READY-C01.json esta listo localmente, pero Taildrop fallo: ' +
            $_.Exception.Message
        )
    }

    $readyTextPath = Join-Path $runRoot 'READY-C01.txt'
    [IO.File]::WriteAllLines($readyTextPath, @(
        'V91-C01 VANILLA SOURCE READY',
        "run_root=$runRoot",
        "ready_json=$latestReadyPath",
        "kit_nonce=$($kit.kit_nonce)",
        "source_tailscale_ipv4=$sourceIPv4",
        "source_tcp_port=$tcpPort",
        "vanilla_emule_sha256=$expectedEmuleSha256",
        "fixture_sha256=$fixtureSha256",
        '',
        'No cierre eMule hasta terminar la transferencia C01.',
        'El resultado formal se decide en el coordinador local.'
    ), (New-Object Text.UTF8Encoding($false)))
    Write-Host "V91-C01 SOURCE READY: $readyTextPath" -ForegroundColor Green
    Start-Process -FilePath notepad.exe -ArgumentList @($readyTextPath) |
        Out-Null
} catch {
    Restore-DirectoryMode
    if ($null -ne $process) {
        $owned = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
        if ($null -ne $owned -and $owned.Path -eq $emulePath) {
            Stop-Process -Id $owned.Id -Force -ErrorAction SilentlyContinue
        }
    }
    if ($firewallCreated) {
        Remove-NetFirewallRule -Name $firewallName `
            -ErrorAction SilentlyContinue
    }
    if ($runRoot) {
        $errorPath = Join-Path $runRoot 'ERROR-C01.txt'
        [IO.File]::WriteAllText(
            $errorPath, "V91-C01 SOURCE ERROR`r`n$($_.Exception.Message)`r`n",
            (New-Object Text.UTF8Encoding($false)))
    }
    foreach ($generated in 'config', 'Temp', 'logs') {
        $generatedPath = [IO.Path]::GetFullPath(
            (Join-Path $nodeRoot $generated))
        $nodePrefix = [IO.Path]::GetFullPath($nodeRoot).TrimEnd('\') + '\'
        if ($generatedPath.StartsWith(
                $nodePrefix, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $generatedPath)) {
            Remove-Item -LiteralPath $generatedPath -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
    }
    throw
}
