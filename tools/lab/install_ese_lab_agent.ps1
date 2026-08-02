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
    'payload\candidates\eSE-LiveTV-v0.70b-eSE9.1.0-rc.3-x64.zip'
)
foreach ($relative in $required) {
    if (-not (Test-Path -LiteralPath (
                Join-Path $sourceRoot $relative) -PathType Leaf)) {
        throw "El kit standalone esta incompleto: $relative"
    }
}
$expectedSha256 = [ordered]@{
    'tools\lab\run_ese_lab_agent.ps1' =
        '0cddb94e37f4810b9243cdaee5741da68c74569b012549bbbb803b57a38e0b7d'
    'run_v91_i05_downloader_kit.ps1' =
        'e89fb4e86a4bb3d1a508dc46477b63037b2f95a408b259aef92683c8eddd93b1'
    'cleanup_v91_i05_downloader.ps1' =
        '226bb82d17177a4217268239ba5f66df1068cfab58297ef8a366b2c1da6ea02f'
    'payload\candidates\eSE-LiveTV-v0.70b-eSE9.1.0-rc.3-x64.zip' =
        '359272c764c532c32cfd97eeb92e2db4feaa620c5d3f6318a82a7453dbf1b56f'
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
                'payload\candidates\' +
                'eSE-LiveTV-v0.70b-eSE9.1.0-rc.3-x64.zip'
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
