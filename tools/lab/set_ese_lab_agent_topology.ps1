[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$job = Get-Content -LiteralPath $JobRequestPath -Raw |
    ConvertFrom-Json
if ([string]$job.schema -cne 'ese.lab.agent-job-request/v1') {
    throw 'Peticion de trabajo no valida.'
}
$request = $job.request
$taskName = [string]$request.task_name
$listenIPv4 = [string]$request.listen_ipv4
$allowedSourceIPv4 = [string]$request.allowed_source_ipv4
$i05SourceIPv4 = [string]$request.i05_source_ipv4
$i05DownloaderIPv4 = [string]$request.i05_downloader_ipv4

foreach ($value in @(
        $listenIPv4,
        $allowedSourceIPv4,
        $i05SourceIPv4,
        $i05DownloaderIPv4
    )) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($value, [ref]$parsed) -or
        $parsed.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "IPv4 no valida: $value"
    }
}
if ([string]::IsNullOrWhiteSpace($taskName)) {
    throw 'Falta task_name.'
}

function Set-AgentArgument {
    param(
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $pattern = (
        '(?i)(-' + [regex]::Escape($Name) +
        '\s+)(?:"[^"]*"|\S+)'
    )
    if ($Arguments -match (
            '(?i)(?:^|\s)-' + [regex]::Escape($Name) + '(?:\s+|=)'
        )) {
        return [regex]::Replace(
            $Arguments,
            $pattern,
            { param($match)
                $match.Groups[1].Value + '"' + $Value + '"'
            }
        )
    }
    return $Arguments + ' -' + $Name + ' "' + $Value + '"'
}

$task = Get-ScheduledTask -TaskName $taskName
if (@($task.Actions).Count -ne 1) {
    throw 'La tarea debe tener exactamente una accion.'
}
$action = $task.Actions[0]
$taskArguments = [string]$action.Arguments
if ($taskArguments -notmatch
        '(?i)-Token\s+(?:"[0-9a-f]{64}"|[0-9a-f]{64})(?:\s|$)' -or
    $taskArguments -notmatch
        '(?i)-File\s+"?[^"]*run_ese_lab_agent\.ps1"?') {
    throw 'La accion existente no es un agente eSE emparejado.'
}

$taskArguments = Set-AgentArgument -Arguments $taskArguments `
    -Name 'ListenIPv4' -Value $listenIPv4
$taskArguments = Set-AgentArgument -Arguments $taskArguments `
    -Name 'AllowedSourceIPv4' -Value $allowedSourceIPv4
$taskArguments = Set-AgentArgument -Arguments $taskArguments `
    -Name 'I05SourceIPv4' -Value $i05SourceIPv4
$taskArguments = Set-AgentArgument -Arguments $taskArguments `
    -Name 'I05DownloaderIPv4' -Value $i05DownloaderIPv4

$newAction = New-ScheduledTaskAction -Execute ([string]$action.Execute) `
    -Argument $taskArguments `
    -WorkingDirectory ([string]$action.WorkingDirectory)
Set-ScheduledTask -TaskName $taskName -Action $newAction | Out-Null

[pscustomobject][ordered]@{
    schema = 'ese.lab.agent-topology-update/v1'
    status = 'UPDATED'
    task_name = $taskName
    listen_ipv4 = $listenIPv4
    allowed_source_ipv4 = $allowedSourceIPv4
    i05_source_ipv4 = $i05SourceIPv4
    i05_downloader_ipv4 = $i05DownloaderIPv4
}
