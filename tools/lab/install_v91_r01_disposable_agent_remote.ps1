[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [Alias('JobRequestPath')]
    [string]$RequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$request = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
if ([string]$request.schema -cne
        'ese.v91.r01-disposable-agent-install-request/v1') {
    throw 'Invalid R01 disposable-agent install request schema.'
}
$expectedRunnerSha256 = [string]$request.expected_runner_sha256
$candidateSourcePath = [IO.Path]::GetFullPath(
    [string]$request.candidate_source_path)
$expectedCandidateSha256 = [string]$request.expected_candidate_sha256
[Int64]$expectedCandidateBytes = [Int64]$request.expected_candidate_bytes
$allowedSourceIPv4 = [string]$request.allowed_source_ipv4
[int]$port = [int]$request.port
$planOnly = $false
$planProperty = $request.PSObject.Properties['plan_only']
if ($null -ne $planProperty) {
    if (-not ($planProperty.Value -is [bool])) {
        throw 'plan_only must be a JSON boolean.'
    }
    $planOnly = [bool]$planProperty.Value
}
if ($expectedRunnerSha256 -notmatch '^[0-9a-f]{64}$' -or
    $expectedCandidateSha256 -notmatch '^[0-9a-f]{64}$' -or
    $expectedCandidateBytes -le 0 -or $port -lt 1024 -or $port -gt 65535) {
    throw 'Invalid R01 disposable-agent immutable binding.'
}
$parsedAllowedSource = $null
if (-not [Net.IPAddress]::TryParse(
        $allowedSourceIPv4, [ref]$parsedAllowedSource) -or
    $parsedAllowedSource.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork -or
    $parsedAllowedSource.Equals([Net.IPAddress]::Any)) {
    throw 'Invalid allowed controller IPv4.'
}
$allowedSourceIPv4 = $parsedAllowedSource.ToString()

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ([string]$identity.User.Value -cne 'S-1-5-18' -or
    -not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Installer must run as elevated SYSTEM through the recovery agent.'
}

function Assert-R01NoReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved)) {
        throw "Required path is missing: $resolved"
    }
    $cursorPath = $resolved
    while (-not [string]::IsNullOrWhiteSpace($cursorPath)) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Path crosses a reparse point: $($cursor.FullName)"
        }
        $parentPath = Split-Path -Parent $cursor.FullName
        if ([string]::IsNullOrWhiteSpace($parentPath) -or
            [string]::Equals($parentPath, $cursor.FullName,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $cursorPath = $parentPath
    }
    return $resolved
}

function Get-R01Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).
        Hash.ToLowerInvariant()
}

function Get-R01StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) |
                    ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

$accountName = 'eSER01Lab'
$accountDescription = 'eSE v9.1 R01 disposable physical-lab account'
$taskName = 'eSE Lab R01 Disposable Agent'
$firewallName = 'eSE-Lab-R01-Disposable-Agent'
$root = 'C:\ProgramData\eSE-Lab-R01-Agent'
$dataRoot = Join-Path $root 'smallframe-data'
$candidateRoot = Join-Path $root 'candidate'
$candidatePath = Join-Path $candidateRoot 'candidate.zip'
$runnerPath = Join-Path $root 'run_ese_lab_smallframe_agent.ps1'
$tokenPath = Join-Path $root 'smallframe-token.txt'

$systemTask = Get-ScheduledTask -TaskName 'eSE Lab SmallFrame Agent' `
    -ErrorAction Stop
if (@($systemTask.Actions).Count -ne 1) {
    throw 'Recovery agent task action is ambiguous.'
}
$systemArguments = [string]$systemTask.Actions[0].Arguments
$runnerMatch = [regex]::Match(
    $systemArguments, '(?i)-File\s+"([^"]+)"')
$tokenMatch = [regex]::Match(
    $systemArguments, '(?i)-TokenFile\s+"([^"]+)"')
if (-not $runnerMatch.Success -or -not $tokenMatch.Success) {
    throw 'Recovery agent task does not expose runner/token paths.'
}
$systemRunnerPath = Assert-R01NoReparsePath -Path $runnerMatch.Groups[1].Value
$systemTokenPath = Assert-R01NoReparsePath -Path $tokenMatch.Groups[1].Value
if ((Get-R01Sha256 -Path $systemRunnerPath) -cne
        $expectedRunnerSha256) {
    throw 'Recovery agent runner hash mismatch.'
}
$token = (Get-Content -LiteralPath $systemTokenPath -Raw).Trim()
if ($token -notmatch '^[0-9a-f]{64}$') {
    throw 'Recovery agent token contract is invalid.'
}

$candidateSourcePath = Assert-R01NoReparsePath -Path $candidateSourcePath
$candidateSourceItem = Get-Item -LiteralPath $candidateSourcePath
if ([Int64]$candidateSourceItem.Length -ne $expectedCandidateBytes -or
    (Get-R01Sha256 -Path $candidateSourcePath) -cne
        $expectedCandidateSha256) {
    throw 'Source candidate ZIP immutable binding mismatch.'
}

$existingAccount = Get-LocalUser -Name $accountName `
    -ErrorAction SilentlyContinue
if ($null -ne $existingAccount -and
    [string]$existingAccount.Description -cne $accountDescription) {
    throw 'Refusing to reuse an account not owned by the R01 lab.'
}
$existingTask = Get-ScheduledTask -TaskName $taskName `
    -ErrorAction SilentlyContinue
if ($null -ne $existingTask -and
    [string]$existingTask.Description -cne $accountDescription) {
    throw 'Refusing to replace a task not owned by the R01 lab.'
}
$existingFirewall = @(Get-NetFirewallRule -Name $firewallName `
    -ErrorAction SilentlyContinue)
if ($existingFirewall.Count -gt 1) {
    throw 'Disposable-agent firewall ownership is ambiguous.'
}
$portOwners = @(Get-NetTCPConnection -LocalPort $port `
    -ErrorAction SilentlyContinue)
if ($portOwners.Count -gt 0 -and $null -eq $existingTask) {
    throw 'Disposable-agent port is already owned by another listener.'
}
if ($planOnly) {
    [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-disposable-agent-preflight/v1'
        status = 'PASS'
        mutation_performed = $false
        recovery_task_state = [string]$systemTask.State
        runner_sha256 = Get-R01Sha256 -Path $systemRunnerPath
        source_candidate_sha256 = Get-R01Sha256 -Path $candidateSourcePath
        source_candidate_bytes = [Int64]$candidateSourceItem.Length
        account_owned_or_absent = $true
        existing_owned_account = $null -ne $existingAccount
        existing_owned_task = $null -ne $existingTask
        port_available_or_owned = $true
        requested_port = $port
    } | ConvertTo-Json -Compress
    exit 0
}

$accountCreated = $false
$taskRegistered = $false
$firewallCreated = $false
$passwordPlain = ''
try {
    $passwordBytes = New-Object byte[] 30
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($passwordBytes) } finally { $rng.Dispose() }
    $passwordPlain = 'E!9a' + [Convert]::ToBase64String($passwordBytes)
    $password = ConvertTo-SecureString $passwordPlain -AsPlainText -Force

    $account = $existingAccount
    if ($null -eq $account) {
        $account = New-LocalUser -Name $accountName -Password $password `
            -FullName 'eSE R01 disposable lab' `
            -Description $accountDescription -AccountNeverExpires `
            -PasswordNeverExpires
        $accountCreated = $true
    } else {
        Set-LocalUser -Name $accountName -Password $password `
            -AccountNeverExpires -PasswordNeverExpires $true
        Enable-LocalUser -Name $accountName
        $account = Get-LocalUser -Name $accountName -ErrorAction Stop
    }
    $accountSid = [Security.Principal.SecurityIdentifier]$account.SID
    $administrators = Get-LocalGroup -SID (
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $isAdministrator = @(
        Get-LocalGroupMember -Group $administrators -ErrorAction Stop |
            Where-Object { $_.SID -eq $accountSid }
    ).Count -eq 1
    if (-not $isAdministrator) {
        Add-LocalGroupMember -Group $administrators -Member $accountName
    }

    foreach ($directory in @($root, $dataRoot, $candidateRoot)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $rootAcl = Get-Acl -LiteralPath $root
    $inheritance = [Security.AccessControl.InheritanceFlags](
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit)
    $rootRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $accountSid, [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance, [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    $rootAcl.SetAccessRule($rootRule)
    Set-Acl -LiteralPath $root -AclObject $rootAcl

    Copy-Item -LiteralPath $systemRunnerPath -Destination $runnerPath -Force
    if ((Get-R01Sha256 -Path $runnerPath) -cne $expectedRunnerSha256) {
        throw 'Disposable agent runner copy mismatch.'
    }
    [IO.File]::WriteAllText(
        $tokenPath, $token, (New-Object Text.ASCIIEncoding))
    $tokenAcl = New-Object Security.AccessControl.FileSecurity
    $tokenAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @(
            ([Security.Principal.SecurityIdentifier]::new('S-1-5-18')),
            ([Security.Principal.SecurityIdentifier]::new(
                'S-1-5-32-544')),
            $accountSid)) {
        $tokenAcl.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $tokenPath -AclObject $tokenAcl

    if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf) -or
        [Int64](Get-Item -LiteralPath $candidatePath).Length -ne
            $expectedCandidateBytes -or
        (Get-R01Sha256 -Path $candidatePath) -cne
            $expectedCandidateSha256) {
        $candidateNew = $candidatePath + '.new'
        Copy-Item -LiteralPath $candidateSourcePath `
            -Destination $candidateNew -Force
        if ([Int64](Get-Item -LiteralPath $candidateNew).Length -ne
                $expectedCandidateBytes -or
            (Get-R01Sha256 -Path $candidateNew) -cne
                $expectedCandidateSha256) {
            throw 'Disposable candidate ZIP copy mismatch.'
        }
        Move-Item -LiteralPath $candidateNew -Destination $candidatePath -Force
    }

    $mutexSuffix = (Get-R01StringSha256 -Value (
            "$accountName|$port")).Substring(0, 32)
    $mutexName = "Global\eSE-Lab-SmallFrame-Agent-$mutexSuffix"
    $powershell = Join-Path $env:SystemRoot (
        'System32\WindowsPowerShell\v1.0\powershell.exe')
    $arguments = (
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
        '-File "{0}" -TokenFile "{1}" -Root "{2}" ' +
        '-AllowedSourceIPv4 "{3}" -Port {4} -MutexName "{5}"'
    ) -f $runnerPath, $tokenPath, $dataRoot, $allowedSourceIPv4,
        $port, $mutexName
    $action = New-ScheduledTaskAction -Execute $powershell `
        -Argument $arguments -WorkingDirectory $root
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1)
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false `
        -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $taskName -Action $action `
        -Trigger $trigger -Settings $settings `
        -User "$env:COMPUTERNAME\$accountName" -Password $passwordPlain `
        -RunLevel Highest -Description $accountDescription -Force | Out-Null
    $taskRegistered = $true

    Remove-NetFirewallRule -Name $firewallName -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $firewallName `
        -DisplayName 'eSE R01 disposable small-frame control' `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port `
        -RemoteAddress $allowedSourceIPv4 -Profile Any -Program $powershell |
        Out-Null
    $firewallCreated = $true
    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds 4
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ([string]$task.State -cne 'Running') {
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        throw "Disposable agent task is not running: result=$($info.LastTaskResult)"
    }

    [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-disposable-agent-install/v1'
        status = 'PASS'
        task = $taskName
        task_state = [string]$task.State
        account_sid_sha256 = Get-R01StringSha256 -Value (
            [string]$accountSid.Value)
        account_is_system = [string]$accountSid.Value -ceq 'S-1-5-18'
        port = $port
        allowed_source_ipv4 = $allowedSourceIPv4
        runner_sha256 = Get-R01Sha256 -Path $runnerPath
        candidate_zip_sha256 = Get-R01Sha256 -Path $candidatePath
        candidate_zip_bytes = [Int64](Get-Item $candidatePath).Length
        candidate_zip_path = $candidatePath
        recovery_agent_preserved = [string]$systemTask.State -ceq 'Running'
    } | ConvertTo-Json -Compress
} catch {
    if ($taskRegistered) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    if ($firewallCreated) {
        Remove-NetFirewallRule -Name $firewallName `
            -ErrorAction SilentlyContinue
    }
    if ($accountCreated) {
        Remove-LocalUser -Name $accountName -ErrorAction SilentlyContinue
    }
    throw
} finally {
    if (-not [string]::IsNullOrEmpty($passwordPlain)) {
        $passwordPlain = ('0' * $passwordPlain.Length)
    }
}
