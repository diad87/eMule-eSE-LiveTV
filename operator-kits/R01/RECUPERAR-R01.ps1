$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Este recuperador debe ejecutarse como administrador.'
}

$taskNames = @(
    'eSE Lab Agent',
    'eSE Lab SmallFrame Agent',
    'eSE Lab R01 Disposable Agent'
)
Remove-Item 'C:\ProgramData\eSE-Lab-Agent\STOP-ESE-LAB-AGENT.flag' `
    -Force -ErrorAction SilentlyContinue

$started = [Collections.Generic.List[string]]::new()
$missing = [Collections.Generic.List[string]]::new()
foreach ($name in $taskNames) {
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        $missing.Add($name)
        continue
    }
    Start-ScheduledTask -TaskName $name
    $started.Add($name)
}
Start-Sleep -Seconds 5

$tasks = @(
    foreach ($name in $taskNames) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($null -eq $task) { continue }
        $info = Get-ScheduledTaskInfo -TaskName $name
        [pscustomobject][ordered]@{
            name = $name
            state = [string]$task.State
            last_result = [int]$info.LastTaskResult
            last_run_utc = if ($info.LastRunTime.Year -gt 2000) {
                $info.LastRunTime.ToUniversalTime().ToString('o')
            } else { $null }
        }
    }
)
$listeners = @(
    foreach ($port in @(8013, 8015, 8016)) {
        $connections = @(Get-NetTCPConnection -State Listen -LocalPort $port `
                -ErrorAction SilentlyContinue)
        [pscustomobject][ordered]@{
            port = $port
            listening = $connections.Count -gt 0
            pid = if ($connections.Count -eq 1) {
                [int]$connections[0].OwningProcess
            } else { $null }
        }
    }
)
$ready = @($listeners | Where-Object {
        [bool]$_.listening -and [int]$_.port -in @(8015, 8016)
    }).Count -gt 0
$result = [pscustomobject][ordered]@{
    schema = 'ese.v91.r01-agent-recovery/v1'
    created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    status = if ($ready) { 'READY' } else { 'NOT_READY' }
    started_tasks = @($started.ToArray())
    missing_tasks = @($missing.ToArray())
    tasks = $tasks
    listeners = $listeners
}
$outputPath = Join-Path $PSScriptRoot 'RECUPERAR-R01-RESULTADO.json'
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $outputPath `
    -Encoding UTF8
$result | ConvertTo-Json -Depth 6
Write-Host "`nResultado: $outputPath"
if (-not $ready) {
    Write-Host 'El agente R01 no ha abierto todavía 8015/8016.' `
        -ForegroundColor Red
    exit 2
}
Write-Host 'Agente R01 recuperado.' -ForegroundColor Green
exit 0
