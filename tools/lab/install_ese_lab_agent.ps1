# Installs the reusable eSE lab agent as a SYSTEM scheduled task.
[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\ProgramData\eSE-Lab-Agent',
    [string]$TaskName = 'eSE Lab Agent',
    [ValidatePattern('^$|^[0-9A-Fa-f]{64}$')]
    [string]$Token = $env:ESE_LAB_AGENT_TOKEN,
    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
if ($Token -notmatch '^[0-9A-Fa-f]{64}$') {
    throw (
        'La instalacion requiere ESE_LAB_AGENT_TOKEN o -Token con una ' +
        'credencial aleatoria de 256 bits.'
    )
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $PreflightOnly -and -not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'La instalacion del agente requiere elevacion.'
}

$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$installRoot = [IO.Path]::GetFullPath($InstallRoot)
$agentRelative = 'tools\lab\run_ese_lab_agent.ps1'
$required = @(
    $agentRelative,
    'run_v91_i05_downloader_kit.ps1',
    'cleanup_v91_i05_downloader.ps1',
    'payload\eSE-LiveTV-v0.70b-eSE9.1.0-rc.2-x64.zip'
)
foreach ($relative in $required) {
    if (-not (Test-Path -LiteralPath (
                Join-Path $sourceRoot $relative) -PathType Leaf)) {
        throw "El kit standalone esta incompleto: $relative"
    }
}
$expectedSha256 = [ordered]@{
    'tools\lab\run_ese_lab_agent.ps1' =
        '4fd7ed1c3418d98be11aab99fefb6ab811659af7e1c5510494cb01609d40de83'
    'run_v91_i05_downloader_kit.ps1' =
        '3ebbc495b62e134fbe05baaf420c51037544046180e21f0c00b9053d59abe1b1'
    'cleanup_v91_i05_downloader.ps1' =
        'e5f90abd7bb564ce532e93f9b9b1c097a3ca598cbe833a69f38a5b8dc538542c'
    'payload\eSE-LiveTV-v0.70b-eSE9.1.0-rc.2-x64.zip' =
        '5f17af0edbdda9e1fcc165d2e2f8a33910b40f856343934b970db24259cf3590'
}
foreach ($relative in $expectedSha256.Keys) {
    $actual = (Get-FileHash -LiteralPath (
            Join-Path $sourceRoot $relative) -Algorithm SHA256).
        Hash.ToLowerInvariant()
    if ($actual -cne [string]$expectedSha256[$relative]) {
        throw "SHA-256 del kit incorrecto: $relative"
    }
}
if ($PreflightOnly) {
    [pscustomobject]@{
        status = 'PASS'
        source_root = $sourceRoot
        required_files = $required.Count
        verified_hashes = $expectedSha256.Count
    }
    return
}

$existingTask = Get-ScheduledTask -TaskName $TaskName `
    -ErrorAction SilentlyContinue
if ($null -ne $existingTask) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
$robocopyArguments = @(
    $sourceRoot, $installRoot, '/E', '/COPY:DAT', '/DCOPY:DAT',
    '/R:2', '/W:1', '/NFL', '/NDL', '/NJH', '/NJS', '/NP',
    '/XD', 'runs', 'agent-logs', 'jobs', 'injected',
    '/XF',
    'ACTIVE-V91-I05-T1.json',
    'READY-V91-I05-T1.json',
    'LAST-ERROR-V91-I05-T1.txt',
    'LAST-FAILURE-V91-I05-T1.json',
    'AGENT-STATUS.json',
    'STOP-ESE-LAB-AGENT.flag'
)
& robocopy.exe @robocopyArguments | Out-Null
if ($LASTEXITCODE -gt 7) {
    throw "No se pudo instalar el kit (robocopy=$LASTEXITCODE)."
}

foreach ($relative in $required) {
    $source = Join-Path $sourceRoot $relative
    $installed = Join-Path $installRoot $relative
    if (-not (Test-Path -LiteralPath $installed -PathType Leaf) -or
        (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash) {
        throw "La copia instalada no coincide: $relative"
    }
}

$agentPath = Join-Path $installRoot $agentRelative
$taskArguments = ((
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" ' +
        '-TaskName "{1}" -Token "{2}"'
    ) -f $agentPath, $TaskName, $Token)
$action = New-ScheduledTaskAction -Execute (
    Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\powershell.exe'
) -Argument $taskArguments -WorkingDirectory $installRoot
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
    -LogonType ServiceAccount -RunLevel Highest
$task = New-ScheduledTask -Action $action -Trigger $trigger `
    -Settings $settings -Principal $taskPrincipal `
    -Description (
        'Agente unattended eSE limitado al laboratorio V91 y controlado ' +
        'desde el H1 autorizado.'
    )
Register-ScheduledTask -TaskName $TaskName -InputObject $task `
    -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

$receipt = [ordered]@{
    schema = 'ese.lab.agent-installation/v1'
    status = 'INSTALLED'
    task_name = $TaskName
    install_root = $installRoot
    installed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    agent_sha256 = (
        Get-FileHash -LiteralPath $agentPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    candidate_sha256 = (
        Get-FileHash -LiteralPath (
            Join-Path $installRoot (
                'payload\eSE-LiveTV-v0.70b-eSE9.1.0-rc.2-x64.zip'
            )) -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}
$receipt | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (
        Join-Path $installRoot 'INSTALLATION-RECEIPT.json') -Encoding UTF8

Write-Host ''
Write-Host 'eSE LAB AGENT: INSTALADO' -ForegroundColor Green
Write-Host "Ruta: $installRoot"
Write-Host "Tarea: $TaskName"
Write-Host 'Ya puede cerrar esta ventana; el agente queda en segundo plano.'
