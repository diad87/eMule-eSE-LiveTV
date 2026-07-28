[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$CoordinatorProcessId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RunRoot
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'El reset de V91-I05 requiere elevacion.'
}

$allowedRoot = [IO.Path]::GetFullPath('D:\eSE-Lab\V91-I05\runs') +
    [IO.Path]::DirectorySeparatorChar
$resolvedRun = [IO.Path]::GetFullPath($RunRoot)
if (-not $resolvedRun.StartsWith(
        $allowedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'RunRoot queda fuera de D:\eSE-Lab\V91-I05\runs.'
}
if (-not (Test-Path -LiteralPath $resolvedRun -PathType Container)) {
    throw "No existe la campana indicada: $resolvedRun"
}

$process = Get-Process -Id $CoordinatorProcessId -ErrorAction SilentlyContinue
if ($null -ne $process) {
    if ([string]$process.ProcessName -cne 'powershell') {
        throw 'El PID indicado no pertenece al coordinador PowerShell esperado.'
    }
    Stop-Process -Id $CoordinatorProcessId -Force
    $process.WaitForExit(10000) | Out-Null
}

$cleanup = Join-Path $PSScriptRoot 'cleanup_v91_i05_t1_source.ps1'
& $cleanup -RunRoot $resolvedRun -NoOpen
if ($LASTEXITCODE -ne 0) {
    throw 'La limpieza del coordinador V91-I05 no termino correctamente.'
}

[pscustomobject]@{
    status = 'RESET_COMPLETE'
    coordinator_pid = $CoordinatorProcessId
    run_root = $resolvedRun
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
} | ConvertTo-Json | Set-Content -LiteralPath (
    Join-Path $resolvedRun 'OPERATOR-RESET.json') -Encoding UTF8
