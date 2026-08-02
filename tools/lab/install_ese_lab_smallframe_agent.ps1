[CmdletBinding()]
param(
    [string]$SourcePath = '',
    [string]$ControllerTaildropName = '',
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AllowedSourceIPv4,
    [ValidateRange(1024, 65535)][int]$Port = 8015,
    [string]$TaskName = 'eSE Lab SmallFrame Agent',
    [string]$FirewallName = 'eSE-Lab-SmallFrame-Agent',
    [string]$TokenDpapiPath = ''
)

$ErrorActionPreference = 'Stop'
$parsedAllowedSourceIPv4 = $null
if (-not [Net.IPAddress]::TryParse(
        $AllowedSourceIPv4, [ref]$parsedAllowedSourceIPv4) -or
    $parsedAllowedSourceIPv4.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork -or
    $parsedAllowedSourceIPv4.Equals([Net.IPAddress]::Any)) {
    throw 'AllowedSourceIPv4 must be an explicit, usable IPv4 literal.'
}
$AllowedSourceIPv4 = $parsedAllowedSourceIPv4.ToString()
if ([string]::IsNullOrWhiteSpace($SourcePath)) {
    $SourcePath = Join-Path $PSScriptRoot 'run_ese_lab_smallframe_agent.ps1'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator rights are required.'
}
if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
    throw "Missing agent source: $SourcePath"
}

$root = 'C:\ProgramData\eSE-Lab-Agent'
$agentPath = Join-Path $root 'run_ese_lab_smallframe_agent.ps1'
$tokenFileName = (
    ($TaskName -replace '[^A-Za-z0-9_.-]', '-').Trim('-') +
    '-token.txt'
)
$tokenPath = Join-Path $root $tokenFileName
New-Item -ItemType Directory -Path $root -Force | Out-Null
Copy-Item -LiteralPath $SourcePath -Destination $agentPath -Force

$bytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$token = (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
[IO.File]::WriteAllText(
    $tokenPath, $token, (New-Object Text.ASCIIEncoding))

$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sidText in 'S-1-5-18', 'S-1-5-32-544') {
    $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $tokenPath -AclObject $acl

if (-not [string]::IsNullOrWhiteSpace($TokenDpapiPath)) {
    $dpapiFullPath = [IO.Path]::GetFullPath($TokenDpapiPath)
    New-Item -ItemType Directory -Path (Split-Path -Parent $dpapiFullPath) `
        -Force | Out-Null
    ConvertTo-SecureString $token -AsPlainText -Force |
        ConvertFrom-SecureString |
        Set-Content -LiteralPath $dpapiFullPath -Encoding ASCII
}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false `
    -ErrorAction SilentlyContinue
$powershell = Join-Path $env:SystemRoot (
    'System32\WindowsPowerShell\v1.0\powershell.exe')
$arguments = (
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
    '-File "{0}" -TokenFile "{1}" -AllowedSourceIPv4 "{2}" -Port {3}'
) -f $agentPath, $tokenPath, $AllowedSourceIPv4, $Port
$action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments `
    -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$task = New-ScheduledTask -Action $action -Trigger $trigger `
    -Settings $settings -Principal (
        New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
            -LogonType ServiceAccount -RunLevel Highest
    ) -Description 'Small-frame authenticated eSE lab control for mobile links.'
Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force |
    Out-Null

Remove-NetFirewallRule -Name $FirewallName -ErrorAction SilentlyContinue
New-NetFirewallRule -Name $FirewallName `
    -DisplayName 'eSE lab small-frame control' -Direction Inbound `
    -Action Allow -Protocol TCP -LocalPort $Port `
    -RemoteAddress $AllowedSourceIPv4 -Profile Any -Program $powershell |
    Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3

if (-not [string]::IsNullOrWhiteSpace($ControllerTaildropName)) {
    $tailscale = (Get-Command tailscale.exe -ErrorAction Stop).Source
    & $tailscale file cp $tokenPath "$ControllerTaildropName`:"
    if ($LASTEXITCODE -ne 0) {
        throw (
            'The agent started, but its token could not be returned by ' +
            'Taildrop.'
        )
    }
}

$state = (Get-ScheduledTask -TaskName $TaskName).State
[pscustomobject]@{
    status = 'INSTALLED'
    task = $TaskName
    state = [string]$state
    listen = "0.0.0.0:$Port"
    allowed_source = $AllowedSourceIPv4
    token_sent_to = $ControllerTaildropName
    token_saved_dpapi = -not [string]::IsNullOrWhiteSpace($TokenDpapiPath)
} | Format-List
