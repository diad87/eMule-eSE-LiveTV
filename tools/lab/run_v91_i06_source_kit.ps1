[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$candidateCommit =
    '08aa6521f7d7907edb3584266abc3a9e31693161'
$expectedEmuleSha256 =
    '55C5AA0E968B25330720CFB7F622CBC28EA9875365145333CBCF9D9585C1C44A'
$expectedEseServerSha256 =
    'EECEEF0F0DBE427F3667C033E2B653FC69E432ABCC3E8AFAF996840A7315E568'
$expectedBuildInfoSha256 =
    '7C87F77268030C2B4DA40C6DA8C960F968B4E1A033C9987B64E45C49CF4B5915'
$viewerTailscaleIPv6 = 'fd7a:115c:a1e0::8134:181e'
$tcpPort = 6962
$udpPort = 6972
$webPort = 7011
$bitrateKbps = 4000

$kitRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$packagePath = Join-Path $kitRoot 'package'
$starterPath = Join-Path $PSScriptRoot 'start_v91_i06_isolated_source.ps1'
$commonPath = Join-Path $PSScriptRoot 'common.ps1'
$preparePath = Join-Path $PSScriptRoot 'prepare_node.ps1'
$runStamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss')
$outputRoot = Join-Path $kitRoot "runs\v91-i06-source-$runStamp"
$firewallRuleName = "eSE-V91-I06-$runStamp"
$sessionPath = Join-Path $outputRoot 'evidence\session.json'
$readyPath = Join-Path $outputRoot 'READY-I06.txt'
$sourceExe = Join-Path $outputRoot 'nodes\v91-i06-isolated-a\emule.exe'
$firewallCreated = $false
$sourceProcessId = 0

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Este kit debe ejecutarse como administrador.'
    }
}

function Assert-FileSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Falta el archivo requerido: $Path"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedSha256) {
        throw (
            "SHA-256 incorrecto para '$Path'. " +
            "Esperado=$ExpectedSha256; actual=$actual"
        )
    }
}

function Assert-PortAvailable {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('TCP', 'UDP')]
        [string]$Protocol,
        [Parameter(Mandatory = $true)][int]$Port
    )

    if ($Protocol -eq 'TCP') {
        $endpoint = Get-NetTCPConnection -State Listen -LocalPort $Port `
            -ErrorAction SilentlyContinue | Select-Object -First 1
    } else {
        $endpoint = Get-NetUDPEndpoint -LocalPort $Port `
            -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if ($null -ne $endpoint) {
        throw "El puerto $Protocol/$Port ya esta en uso."
    }
}

function Stop-OwnedSourceOnFailure {
    if ($sourceProcessId -le 0) { return }
    $process = Get-Process -Id $sourceProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) { return }
    try {
        if ([IO.Path]::GetFullPath($process.Path) -ne
            [IO.Path]::GetFullPath($sourceExe)) {
            Write-Warning (
                "No se detiene PID $sourceProcessId porque su ruta no coincide " +
                'con el Source aislado.'
            )
            return
        }
        Stop-Process -Id $sourceProcessId -Force -ErrorAction Stop
        $null = $process.WaitForExit(10000)
    } catch {
        Write-Warning "No se pudo detener el Source tras el error: $($_.Exception.Message)"
    }
}

try {
    Assert-Administrator

    foreach ($requiredScript in $commonPath, $preparePath, $starterPath) {
        if (-not (Test-Path -LiteralPath $requiredScript -PathType Leaf)) {
            throw "El kit no contiene el script requerido: $requiredScript"
        }
    }
    if (-not (Test-Path -LiteralPath $packagePath -PathType Container)) {
        throw "El kit no contiene el paquete extraido: $packagePath"
    }
    if (Test-Path -LiteralPath $outputRoot) {
        throw "La salida timestamped ya existe: $outputRoot"
    }

    Assert-FileSha256 -Path (Join-Path $packagePath 'emule.exe') `
        -ExpectedSha256 $expectedEmuleSha256
    Assert-FileSha256 -Path (Join-Path $packagePath 'ese-server.exe') `
        -ExpectedSha256 $expectedEseServerSha256
    Assert-FileSha256 -Path (Join-Path $packagePath 'BUILD_INFO.txt') `
        -ExpectedSha256 $expectedBuildInfoSha256

    $tailscaleAdapter = Get-NetAdapter -Name 'Tailscale' `
        -ErrorAction SilentlyContinue
    if ($null -eq $tailscaleAdapter -or
        [string]$tailscaleAdapter.Status -ne 'Up') {
        throw 'La interfaz Tailscale no existe o no esta activa.'
    }
    $sourceTailscaleIPv6 = @(
        Get-NetIPAddress -InterfaceAlias 'Tailscale' -AddressFamily IPv6 `
            -ErrorAction Stop |
            Where-Object {
                $_.AddressState -eq 'Preferred' -and
                $_.IPAddress -notlike 'fe80:*'
            }
    ) | Select-Object -First 1
    if ($null -eq $sourceTailscaleIPv6) {
        throw 'Maria no tiene una IPv6 Tailscale preferida.'
    }

    Assert-PortAvailable -Protocol TCP -Port $tcpPort
    Assert-PortAvailable -Protocol UDP -Port $udpPort
    Assert-PortAvailable -Protocol TCP -Port $webPort

    Write-Host 'Identidad RC2 verificada. Arrancando Source I06...' `
        -ForegroundColor Cyan
    & $starterPath -PackagePath $packagePath -OutputRoot $outputRoot `
        -TcpPort $tcpPort -UdpPort $udpPort -WebPort $webPort `
        -BitrateKbps $bitrateKbps -Commit $candidateCommit

    if (-not (Test-Path -LiteralPath $sessionPath -PathType Leaf)) {
        throw "El iniciador no escribio la sesion esperada: $sessionPath"
    }
    $session = Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json
    $sourceProcessId = [int]$session.process_id
    if ($sourceProcessId -le 0 -or
        [string]::IsNullOrWhiteSpace([string]$session.stream_key)) {
        throw 'La sesion I06 no contiene PID o stream key validos.'
    }

    $sourceProcess = Get-Process -Id $sourceProcessId -ErrorAction Stop
    if ([IO.Path]::GetFullPath($sourceProcess.Path) -ne
        [IO.Path]::GetFullPath($sourceExe)) {
        throw 'El PID de la sesion no pertenece al Source aislado esperado.'
    }

    New-NetFirewallRule -Name $firewallRuleName `
        -DisplayName "eSE V91 I06 RC2 $runStamp" `
        -Direction Inbound -Action Allow -Profile Any -Protocol TCP `
        -LocalPort $tcpPort -Program $sourceExe `
        -InterfaceAlias 'Tailscale' -RemoteAddress $viewerTailscaleIPv6 |
        Out-Null
    $firewallCreated = $true

    $listener = Get-NetTCPConnection -State Listen -LocalPort $tcpPort `
        -ErrorAction SilentlyContinue |
        Where-Object OwningProcess -eq $sourceProcessId |
        Select-Object -First 1
    if ($null -eq $listener) {
        throw "El Source no escucha en TCP/$tcpPort con su PID."
    }

    $readyLines = @(
        'V91-I06 SOURCE READY'
        "candidate_commit=$candidateCommit"
        "candidate_emule_sha256=$expectedEmuleSha256"
        "candidate_ese_server_sha256=$expectedEseServerSha256"
        "candidate_build_info_sha256=$expectedBuildInfoSha256"
        "source_process_id=$sourceProcessId"
        "source_tailscale_ipv6=$($sourceTailscaleIPv6.IPAddress)"
        "viewer_tailscale_ipv6=$viewerTailscaleIPv6"
        "source_tcp_port=$tcpPort"
        "source_udp_port=$udpPort"
        "source_web_port=$webPort"
        "stream_key=$($session.stream_key)"
        "session_json=$sessionPath"
        "source_executable=$sourceExe"
        "firewall_rule=$firewallRuleName"
        ''
        'No cierre el proceso Source hasta terminar la prueba.'
        'La API 7011 permanece local; el firewall solo admite TCP/6962'
        'desde la IPv6 Tailscale exacta del viewer.'
    )
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllLines($readyPath, $readyLines, $encoding)

    Write-Host ''
    Write-Host 'SOURCE I06 LISTO' -ForegroundColor Green
    Write-Host "PID:        $sourceProcessId"
    Write-Host "IPv6:       $($sourceTailscaleIPv6.IPAddress)"
    Write-Host "Puerto TCP: $tcpPort"
    Write-Host "Stream key: $($session.stream_key)"
    Write-Host "READY:      $readyPath"
    Start-Process -FilePath 'notepad.exe' -ArgumentList @($readyPath) | Out-Null
} catch {
    $message = $_.Exception.Message
    Write-Host ''
    Write-Host 'ERROR AL PREPARAR V91-I06 SOURCE' `
        -ForegroundColor White -BackgroundColor DarkRed
    Write-Host $message -ForegroundColor Red

    if ($firewallCreated) {
        try {
            Remove-NetFirewallRule -Name $firewallRuleName -ErrorAction Stop
        } catch {
            Write-Warning "No se pudo retirar la regla firewall: $($_.Exception.Message)"
        }
    }
    Stop-OwnedSourceOnFailure

    try {
        $errorRoot = Join-Path $kitRoot 'runs'
        if (-not (Test-Path -LiteralPath $errorRoot)) {
            $null = New-Item -ItemType Directory -Path $errorRoot -Force
        }
        $errorPath = Join-Path $errorRoot "ERROR-I06-$runStamp.txt"
        [IO.File]::WriteAllText(
            $errorPath,
            ("V91-I06 SOURCE ERROR`r`n{0}`r`n" -f $message),
            (New-Object Text.UTF8Encoding($false))
        )
        Write-Host "Detalle: $errorPath" -ForegroundColor Yellow
    } catch {
        Write-Warning "No se pudo escribir el parte de error: $($_.Exception.Message)"
    }

    if ($Host.Name -eq 'ConsoleHost') {
        $null = Read-Host 'Pulse INTRO para cerrar'
    }
    exit 1
}
