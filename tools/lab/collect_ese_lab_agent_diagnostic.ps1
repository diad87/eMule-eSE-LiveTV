[CmdletBinding()]
param(
    [string]$TaskName = 'eSE Lab Agent',
    [string]$InstallRoot = 'C:\ProgramData\eSE-Lab-Agent',
    [string]$ReturnNode = 'iaki-casa-1'
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'El diagnostico requiere elevacion.'
}

$stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss')
$root = Join-Path $env:TEMP "eSE-Agent-Diagnostic-$stamp"
New-Item -ItemType Directory -Path $root -Force | Out-Null

function Write-DiagnosticText {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )
    try {
        & $Command 2>&1 | Out-String -Width 4096 |
            Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8
    } catch {
        ($_ | Out-String -Width 4096) |
            Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8
    }
}

Write-DiagnosticText -Name 'identity.txt' -Command {
    whoami.exe /all
}
Write-DiagnosticText -Name 'network.txt' -Command {
    Get-NetIPAddress | Sort-Object InterfaceIndex, AddressFamily |
        Format-List *
    Get-NetTCPConnection -LocalPort 8013 -ErrorAction SilentlyContinue |
        Format-List *
    tailscale.exe status
}
Write-DiagnosticText -Name 'task.txt' -Command {
    Get-ScheduledTask -TaskName $TaskName | Format-List *
    Get-ScheduledTaskInfo -TaskName $TaskName | Format-List *
    Export-ScheduledTask -TaskName $TaskName
}
Write-DiagnosticText -Name 'processes.txt' -Command {
    Get-CimInstance Win32_Process |
        Where-Object {
            [string]$_.CommandLine -match 'run_ese_lab_agent|eSE-Lab-Agent'
        } | Format-List *
}
Write-DiagnosticText -Name 'firewall.txt' -Command {
    Get-NetFirewallRule |
        Where-Object Name -Like 'eSE-Lab-Agent-*' |
        ForEach-Object {
            $_ | Format-List *
            Get-NetFirewallAddressFilter `
                -AssociatedNetFirewallRule $_ | Format-List *
            Get-NetFirewallPortFilter `
                -AssociatedNetFirewallRule $_ | Format-List *
            Get-NetFirewallApplicationFilter `
                -AssociatedNetFirewallRule $_ | Format-List *
        }
}
Write-DiagnosticText -Name 'installed-files.txt' -Command {
    Get-ChildItem -LiteralPath $InstallRoot -Recurse -File |
        Select-Object FullName, Length, LastWriteTimeUtc |
        Format-Table -AutoSize
    Get-FileHash -LiteralPath (
        Join-Path $InstallRoot 'tools\lab\run_ese_lab_agent.ps1'
    ) -Algorithm SHA256 | Format-List *
}
Write-DiagnosticText -Name 'task-events.txt' -Command {
    Get-WinEvent -LogName `
        'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 200 |
        Where-Object Message -Match ([regex]::Escape($TaskName)) |
        Select-Object -First 50 TimeCreated, Id, LevelDisplayName, Message |
        Format-List *
}

foreach ($name in @(
    'AGENT-FATAL.json',
    'AGENT-STATUS.json',
    'INSTALLATION-RECEIPT.json',
    'LAST-AGENT-DEPLOYMENT.json'
)) {
    $source = Join-Path $InstallRoot $name
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-Item -LiteralPath $source -Destination (
            Join-Path $root $name) -Force
    }
}

try {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 5
} catch {
}
Write-DiagnosticText -Name 'task-after-retry.txt' -Command {
    Get-ScheduledTask -TaskName $TaskName | Format-List *
    Get-ScheduledTaskInfo -TaskName $TaskName | Format-List *
    Get-CimInstance Win32_Process |
        Where-Object {
            [string]$_.CommandLine -match 'run_ese_lab_agent|eSE-Lab-Agent'
        } | Format-List *
    Get-NetTCPConnection -LocalPort 8013 -ErrorAction SilentlyContinue |
        Format-List *
}
foreach ($name in @('AGENT-FATAL.json', 'AGENT-STATUS.json')) {
    $source = Join-Path $InstallRoot $name
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-Item -LiteralPath $source -Destination (
            Join-Path $root ("after-$name")) -Force
    }
}

$zip = "$root.zip"
Compress-Archive -LiteralPath $root -DestinationPath $zip `
    -CompressionLevel Optimal
$tailscale = (Get-Command tailscale.exe -ErrorAction Stop).Source
& $tailscale file cp $zip "$ReturnNode`:"
if ($LASTEXITCODE -ne 0) {
    throw "No se pudo devolver el diagnostico (tailscale=$LASTEXITCODE)."
}

Write-Host ''
Write-Host 'DIAGNOSTICO ENVIADO CORRECTAMENTE' -ForegroundColor Green
Write-Host 'Puede cerrar esta ventana.'
