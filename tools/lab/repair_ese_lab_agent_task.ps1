[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\ProgramData\eSE-Lab-Agent',
    [string]$TaskName = 'eSE Lab Agent',
    [ValidatePattern('^$|^[0-9A-Fa-f]{64}$')]
    [string]$Token = $env:ESE_LAB_AGENT_TOKEN
)

$ErrorActionPreference = 'Stop'
if ($Token -notmatch '^[0-9A-Fa-f]{64}$') {
    throw (
        'La reparacion requiere ESE_LAB_AGENT_TOKEN o -Token con la ' +
        'credencial emparejada.'
    )
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'La reparacion requiere elevacion.'
}

$agentPath = Join-Path $InstallRoot `
    'tools\lab\run_ese_lab_agent.ps1'
if (-not (Test-Path -LiteralPath $agentPath -PathType Leaf)) {
    throw "No existe el agente instalado: $agentPath"
}
$expectedAgentSha256 =
    '4fd7ed1c3418d98be11aab99fefb6ab811659af7e1c5510494cb01609d40de83'
$actualAgentSha256 = (Get-FileHash -LiteralPath $agentPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualAgentSha256 -cne $expectedAgentSha256) {
    throw 'El agente instalado no coincide con el kit standalone 1.0.0.'
}

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$taskArguments = ((
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" ' +
        '-TaskName "{1}" -Token "{2}"'
    ) -f $agentPath, $TaskName, $Token)
$action = New-ScheduledTaskAction -Execute (
    Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\powershell.exe'
) -Argument $taskArguments -WorkingDirectory $InstallRoot
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
        'Agente unattended reutilizable para pruebas eSE/eMule.'
    )
Register-ScheduledTask -TaskName $TaskName -InputObject $task `
    -Force | Out-Null

$statusPath = Join-Path $InstallRoot 'AGENT-STATUS.json'
$repairStarted = [DateTimeOffset]::UtcNow
Start-ScheduledTask -TaskName $TaskName
$ready = $false
foreach ($attempt in 1..30) {
    Start-Sleep -Seconds 1
    if (Test-Path -LiteralPath $statusPath -PathType Leaf) {
        $statusItem = Get-Item -LiteralPath $statusPath
        if ($statusItem.LastWriteTimeUtc -ge $repairStarted.UtcDateTime) {
            $status = Get-Content -LiteralPath $statusPath -Raw |
                ConvertFrom-Json
            if ([string]$status.schema -ceq 'ese.lab.agent-status/v1' -and
                [string]$status.status -notin @(
                    'STOPPED', 'SHUTTING_DOWN'
                )) {
                $ready = $true
                break
            }
        }
    }
}
if (-not $ready) {
    $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
    $fatalPath = Join-Path $InstallRoot 'AGENT-FATAL.json'
    $fatal = if (Test-Path -LiteralPath $fatalPath -PathType Leaf) {
        Get-Content -LiteralPath $fatalPath -Raw
    } else {
        ''
    }
    throw (
        "El agente no publico estado. LastTaskResult=" +
        "$($taskInfo.LastTaskResult). $fatal"
    )
}

[ordered]@{
    schema = 'ese.lab.agent-task-repair/v1'
    status = 'REPAIRED_AND_READY'
    repaired_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    task_name = $TaskName
    task_arguments = $taskArguments
    agent_pid = [int]$status.agent_pid
    agent_status = [string]$status.status
} | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (
        Join-Path $InstallRoot 'TASK-REPAIR-RECEIPT.json') -Encoding UTF8

Write-Host ''
Write-Host 'eSE LAB AGENT: REPARADO Y ACTIVO' -ForegroundColor Green
Write-Host "PID del agente: $($status.agent_pid)"
Write-Host 'No necesita dejar ninguna ventana abierta.'
