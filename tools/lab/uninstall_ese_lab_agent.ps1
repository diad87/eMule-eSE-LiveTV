# Removes the reusable eSE lab agent task while preserving evidence.
[CmdletBinding()]
param([string]$TaskName = 'eSE Lab Agent')

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'La desinstalacion requiere elevacion.'
}

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false `
    -ErrorAction SilentlyContinue
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object {
        [string]$_.Name -like 'eSE-Lab-Agent-*'
    } | Remove-NetFirewallRule -ErrorAction SilentlyContinue

Write-Host 'Agente eSE detenido y tarea eliminada.' -ForegroundColor Green
Write-Host (
    'Los resultados conservados en C:\ProgramData\eSE-Lab-Agent no ' +
    'se han borrado.'
)
