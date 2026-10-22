[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$taskName = 'eSE Lab SmallFrame Agent'
$taskPath = '\'
$taskDescription =
    'Small-frame authenticated eSE lab control for mobile links.'
$firewallName = 'eSE-Lab-SmallFrame-Agent'
$firewallDisplayName = 'eSE lab small-frame control'
$root = 'C:\ProgramData\eSE-Lab-Agent'
$dataRoot = Join-Path $root 'smallframe-data'
$runnerPath = Join-Path $root 'run_ese_lab_smallframe_agent.ps1'
$bundledRunnerPath = Join-Path $PSScriptRoot (
    'run_ese_lab_smallframe_agent.ps1')
$allowedSourceIPv4 = '100.69.24.30'
$port = 8015
$expectedRunnerSha256 =
    '441650d699ad63e971a59cfdea1cb6c0418e1bc20e3c0dd882c4b57b4f441773'
$powershellPath = Join-Path $env:SystemRoot (
    'System32\WindowsPowerShell\v1.0\powershell.exe')
$resultPath = Join-Path $PSScriptRoot (
    'REPARAR-AGENTE-R01-RESULTADO.json')
$runId = (
    [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' +
    [Guid]::NewGuid().ToString('N'))

function Write-Utf8TextAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $temporary = $Path + '.new-' + [Guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText(
            $temporary, $Text, (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force `
            -ErrorAction SilentlyContinue
    }
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    Write-Utf8TextAtomic -Path $Path -Text (
        $Value | ConvertTo-Json -Depth 10)
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).
        Hash.ToLowerInvariant()
}

function Test-EqualPath {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    return [string]::Equals(
        [IO.Path]::GetFullPath(
            [Environment]::ExpandEnvironmentVariables($Left)),
        [IO.Path]::GetFullPath(
            [Environment]::ExpandEnvironmentVariables($Right)),
        [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved)) {
        throw "Falta la ruta requerida: $resolved"
    }
    $cursorPath = $resolved
    while (-not [string]::IsNullOrWhiteSpace($cursorPath)) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force
        if (($cursor.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "La ruta contiene un punto de reparacion: $resolved"
        }
        $parentPath = Split-Path -Parent $cursor.FullName
        if ([string]::IsNullOrWhiteSpace($parentPath) -or
            [string]::Equals(
                $parentPath, $cursor.FullName,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $cursorPath = $parentPath
    }
    return $resolved
}

function Get-TaskArgumentValue {
    param(
        [AllowEmptyString()][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Arguments)) { return $null }
    $pattern = (
        '(?i)(?:^|\s)-' + [regex]::Escape($Name) +
        '(?:\s+|=)(?:"(?<quoted>[^"]+)"|(?<plain>[^\s"]+))')
    $matches = [regex]::Matches($Arguments, $pattern)
    if ($matches.Count -gt 1) {
        throw "El argumento -$Name aparece mas de una vez."
    }
    if ($matches.Count -eq 0) { return $null }
    if ($matches[0].Groups['quoted'].Success) {
        return $matches[0].Groups['quoted'].Value
    }
    return $matches[0].Groups['plain'].Value
}

function Test-SystemTaskPrincipal {
    param([Parameter(Mandatory = $true)]$Task)

    $userId = [string]$Task.Principal.UserId
    return (
        $userId -ieq 'SYSTEM' -or
        $userId -ieq 'NT AUTHORITY\SYSTEM' -or
        $userId -ceq 'S-1-5-18')
}

function Get-ExactTask {
    $tasks = @(Get-ScheduledTask -TaskName $taskName `
            -ErrorAction SilentlyContinue)
    if ($tasks.Count -gt 1) {
        throw 'Hay varias tareas con el nombre del agente; no es seguro repararlas.'
    }
    if ($tasks.Count -eq 0) { return $null }
    if ([string]$tasks[0].TaskPath -cne $taskPath) {
        throw 'La tarea encontrada no esta en la raiz del Programador de tareas.'
    }
    return $tasks[0]
}

function Assert-OwnedTask {
    param([Parameter(Mandatory = $true)]$Task)

    if (-not (Test-SystemTaskPrincipal -Task $Task)) {
        throw 'La tarea existente no pertenece a SYSTEM; no se sustituira.'
    }
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1) {
        throw 'La tarea existente tiene una accion ambigua; no se sustituira.'
    }
    if (-not (Test-EqualPath -Left ([string]$actions[0].Execute) `
            -Right $powershellPath)) {
        throw 'La tarea existente no ejecuta Windows PowerShell; no se sustituira.'
    }

    $fileArgument = Get-TaskArgumentValue `
        -Arguments ([string]$actions[0].Arguments) -Name 'File'
    $ownedAction = $false
    if (-not [string]::IsNullOrWhiteSpace($fileArgument)) {
        try {
            $ownedAction = Test-EqualPath -Left $fileArgument `
                -Right $runnerPath
        } catch {
            $ownedAction = $false
        }
    }
    $ownedDescription =
        [string]$Task.Description -ceq $taskDescription
    if (-not $ownedAction -and -not $ownedDescription) {
        throw (
            'La tarea existente no conserva ni la accion ni la descripcion ' +
            'propias de eSE; no se sustituira.')
    }
}

function Get-ValidatedTokenPath {
    param([AllowNull()]$ExistingTask)

    $hintPath = $null
    if ($null -ne $ExistingTask) {
        $hint = Get-TaskArgumentValue `
            -Arguments ([string]$ExistingTask.Actions[0].Arguments) `
            -Name 'TokenFile'
        if (-not [string]::IsNullOrWhiteSpace($hint)) {
            $hintPath = [IO.Path]::GetFullPath($hint)
            if (-not [string]::Equals(
                    (Split-Path -Parent $hintPath),
                    [IO.Path]::GetFullPath($root),
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw (
                    'La tarea apunta a una credencial fuera del directorio ' +
                    'privado eSE; no se leera.')
            }
        }
    }

    $candidatePaths = [Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($hintPath)) {
        $candidatePaths.Add($hintPath)
    }
    $candidatePaths.Add((Join-Path $root (
                'eSE-Lab-SmallFrame-Agent-token.txt')))
    $candidatePaths.Add((Join-Path $root 'smallframe-token.txt'))

    $seen = @{}
    $valid = [Collections.Generic.List[object]]::new()
    foreach ($candidatePath in $candidatePaths) {
        $fullPath = [IO.Path]::GetFullPath($candidatePath)
        $key = $fullPath.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            continue
        }
        $null = Assert-NoReparsePath -Path $fullPath
        $secret = [IO.File]::ReadAllText($fullPath).Trim()
        if ($secret -notmatch '^[0-9a-fA-F]{64}$') {
            Remove-Variable secret -ErrorAction SilentlyContinue
            continue
        }
        $valid.Add([pscustomobject]@{
                path = $fullPath
                secret = $secret.ToLowerInvariant()
            })
        Remove-Variable secret -ErrorAction SilentlyContinue
    }

    if (-not [string]::IsNullOrWhiteSpace($hintPath)) {
        $hintMatch = @($valid | Where-Object {
                [string]::Equals(
                    [string]$_.path, $hintPath,
                    [StringComparison]::OrdinalIgnoreCase)
            })
        if ($hintMatch.Count -eq 1) {
            $selected = [string]$hintMatch[0].path
            foreach ($item in $valid) { $item.secret = $null }
            return $selected
        }
    }

    if ($valid.Count -eq 0) {
        throw (
            'No existe una credencial small-frame valida. El kit no genera ' +
            'otra para no romper la credencial guardada en H1.')
    }
    if ($valid.Count -eq 1) {
        $selected = [string]$valid[0].path
        $valid[0].secret = $null
        return $selected
    }

    $distinctSecrets = @($valid | ForEach-Object { $_.secret } |
            Select-Object -Unique)
    if ($distinctSecrets.Count -ne 1) {
        foreach ($item in $valid) { $item.secret = $null }
        throw (
            'Hay varias credenciales small-frame distintas y la tarea no ' +
            'identifica una de forma valida. No se elegira una al azar.')
    }
    $preferred = @($valid | Where-Object {
            [IO.Path]::GetFileName([string]$_.path) -ceq
                'eSE-Lab-SmallFrame-Agent-token.txt'
        })
    $selected = if ($preferred.Count -eq 1) {
        [string]$preferred[0].path
    } else {
        [string]$valid[0].path
    }
    foreach ($item in $valid) { $item.secret = $null }
    return $selected
}

function New-RestrictedAcl {
    param([switch]$Directory)

    if ($Directory) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $inheritance = [Security.AccessControl.InheritanceFlags](
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit)
    } else {
        $acl = New-Object Security.AccessControl.FileSecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
    }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule) | Out-Null
    }
    return $acl
}

function Get-FirewallSnapshot {
    $rules = @(Get-NetFirewallRule -Name $firewallName `
            -ErrorAction SilentlyContinue)
    if ($rules.Count -gt 1) {
        throw 'Hay varias reglas firewall con el nombre eSE; no se tocaran.'
    }
    if ($rules.Count -eq 0) { return $null }
    $rule = $rules[0]
    if ([string]$rule.DisplayName -cne $firewallDisplayName) {
        throw (
            'La regla firewall existente no tiene la identidad eSE ' +
            'esperada; no se sustituira.')
    }
    $portFilter = @(Get-NetFirewallPortFilter `
            -AssociatedNetFirewallRule $rule)
    $addressFilter = @(Get-NetFirewallAddressFilter `
            -AssociatedNetFirewallRule $rule)
    $applicationFilter = @(Get-NetFirewallApplicationFilter `
            -AssociatedNetFirewallRule $rule)
    if ($portFilter.Count -ne 1 -or $addressFilter.Count -ne 1 -or
        $applicationFilter.Count -ne 1) {
        throw 'Los filtros de la regla firewall eSE son ambiguos.'
    }
    return [pscustomobject][ordered]@{
        name = [string]$rule.Name
        display_name = [string]$rule.DisplayName
        description = [string]$rule.Description
        enabled = [string]$rule.Enabled
        profile = [string]$rule.Profile
        direction = [string]$rule.Direction
        action = [string]$rule.Action
        edge_traversal_policy = [string]$rule.EdgeTraversalPolicy
        protocol = [string]$portFilter[0].Protocol
        local_port = @($portFilter[0].LocalPort)
        remote_port = @($portFilter[0].RemotePort)
        local_address = @($addressFilter[0].LocalAddress)
        remote_address = @($addressFilter[0].RemoteAddress)
        program = [string]$applicationFilter[0].Program
    }
}

function Restore-FirewallSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)

    Remove-NetFirewallRule -Name $firewallName `
        -ErrorAction SilentlyContinue
    $parameters = @{
        Name = [string]$Snapshot.name
        DisplayName = [string]$Snapshot.display_name
        Direction = [string]$Snapshot.direction
        Action = [string]$Snapshot.action
        Enabled = [string]$Snapshot.enabled
        Profile = [string]$Snapshot.profile
        Protocol = [string]$Snapshot.protocol
        LocalPort = @($Snapshot.local_port)
        RemotePort = @($Snapshot.remote_port)
        LocalAddress = @($Snapshot.local_address)
        RemoteAddress = @($Snapshot.remote_address)
        Program = [string]$Snapshot.program
        EdgeTraversalPolicy = [string]$Snapshot.edge_traversal_policy
    }
    if (-not [string]::IsNullOrWhiteSpace(
            [string]$Snapshot.description)) {
        $parameters.Description = [string]$Snapshot.description
    }
    New-NetFirewallRule @parameters | Out-Null
}

function Get-PortListeners {
    return @(Get-NetTCPConnection -State Listen -LocalPort $port `
            -ErrorAction SilentlyContinue)
}

function Get-ProcessRecord {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    return Get-CimInstance Win32_Process `
        -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
}

function Test-OwnedAgentProcess {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    $process = Get-ProcessRecord -ProcessId $ProcessId
    if ($null -eq $process) { return $false }
    if (-not (Test-EqualPath -Left ([string]$process.ExecutablePath) `
            -Right $powershellPath)) {
        return $false
    }
    return [regex]::IsMatch(
        [string]$process.CommandLine,
        '(?i)-File\s+"?' + [regex]::Escape($runnerPath) + '"?(?:\s|$)')
}

function Assert-NoForeignListener {
    foreach ($listener in (Get-PortListeners)) {
        $processId = [int]$listener.OwningProcess
        if (-not (Test-OwnedAgentProcess -ProcessId $processId)) {
            throw (
                "El puerto $port pertenece al proceso $processId, que no " +
                'es el agente eSE. No se interrumpira.')
        }
    }
}

function Stop-OwnedAgentListener {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(8)
    do {
        $listeners = @(Get-PortListeners)
        if ($listeners.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    foreach ($listener in (Get-PortListeners)) {
        $processId = [int]$listener.OwningProcess
        if (-not (Test-OwnedAgentProcess -ProcessId $processId)) {
            throw "Un proceso ajeno conserva el puerto $port."
        }
        Stop-Process -Id $processId -Force -ErrorAction Stop
    }
    Start-Sleep -Seconds 1
    if (@(Get-PortListeners).Count -ne 0) {
        throw "El puerto $port no se libero de forma segura."
    }
}

function Assert-FirewallReady {
    $rules = @(Get-NetFirewallRule -Name $firewallName `
            -ErrorAction Stop)
    if ($rules.Count -ne 1) {
        throw 'La regla firewall final no es unica.'
    }
    $rule = $rules[0]
    $portFilter = @(Get-NetFirewallPortFilter `
            -AssociatedNetFirewallRule $rule)
    $addressFilter = @(Get-NetFirewallAddressFilter `
            -AssociatedNetFirewallRule $rule)
    $applicationFilter = @(Get-NetFirewallApplicationFilter `
            -AssociatedNetFirewallRule $rule)
    if ($portFilter.Count -ne 1 -or $addressFilter.Count -ne 1 -or
        $applicationFilter.Count -ne 1) {
        throw 'Los filtros de la regla firewall final no son unicos.'
    }
    $localPorts = @($portFilter[0].LocalPort)
    $remotePorts = @($portFilter[0].RemotePort)
    $localAddresses = @($addressFilter[0].LocalAddress)
    $remoteAddresses = @($addressFilter[0].RemoteAddress)
    if ([string]$rule.DisplayName -cne $firewallDisplayName -or
        [string]$rule.Direction -cne 'Inbound' -or
        [string]$rule.Action -cne 'Allow' -or
        [string]$rule.Enabled -cne 'True' -or
        [string]$rule.Profile -cne 'Any' -or
        [string]$rule.EdgeTraversalPolicy -cne 'Block' -or
        [string]$portFilter[0].Protocol -notin @('TCP', '6') -or
        $localPorts.Count -ne 1 -or
        [string]$localPorts[0] -cne [string]$port -or
        $remotePorts.Count -ne 1 -or
        [string]$remotePorts[0] -cne 'Any' -or
        $localAddresses.Count -ne 1 -or
        [string]$localAddresses[0] -cne 'Any' -or
        $remoteAddresses.Count -ne 1 -or
        [string]$remoteAddresses[0] -notin @(
            $allowedSourceIPv4, "$allowedSourceIPv4/32") -or
        -not (Test-EqualPath `
            -Left ([string]$applicationFilter[0].Program) `
            -Right $powershellPath)) {
        throw 'La regla firewall final no cumple el contrato restrictivo.'
    }
}

function Assert-FinalTaskDefinition {
    param(
        [Parameter(Mandatory = $true)]$Task,
        [Parameter(Mandatory = $true)][string]$ExpectedArguments
    )

    $actions = @($Task.Actions)
    $triggers = @($Task.Triggers)
    if (-not (Test-SystemTaskPrincipal -Task $Task) -or
        [string]$Task.Description -cne $taskDescription -or
        $actions.Count -ne 1 -or
        -not (Test-EqualPath -Left ([string]$actions[0].Execute) `
            -Right $powershellPath) -or
        [string]$actions[0].Arguments -cne $ExpectedArguments -or
        -not (Test-EqualPath `
            -Left ([string]$actions[0].WorkingDirectory) -Right $root) -or
        $triggers.Count -ne 1 -or
        [string]$triggers[0].CimClass.CimClassName -cne
            'MSFT_TaskBootTrigger') {
        throw 'La definicion registrada de la tarea no es la congelada.'
    }
}

function Assert-TaskReady {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    do {
        $task = Get-ExactTask
        $listeners = @(Get-PortListeners)
        if ($null -ne $task -and [string]$task.State -ceq 'Running' -and
            $listeners.Count -eq 1) {
            $processId = [int]$listeners[0].OwningProcess
            if (Test-OwnedAgentProcess -ProcessId $processId) {
                return [pscustomobject]@{
                    task = $task
                    process_id = $processId
                }
            }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    $info = Get-ScheduledTaskInfo -TaskName $taskName `
        -TaskPath $taskPath -ErrorAction SilentlyContinue
    $lastResult = if ($null -eq $info) { $null } else {
        [int]$info.LastTaskResult
    }
    throw "La tarea no abrio el puerto $port; resultado=$lastResult"
}

function Write-PublicResult {
    param([Parameter(Mandatory = $true)]$Value)

    try {
        Write-JsonAtomic -Path $resultPath -Value $Value
    } catch {
        Write-Host (
            'No se pudo escribir el resultado junto al kit: ' +
            $_.Exception.Message) -ForegroundColor Yellow
    }
    $Value | ConvertTo-Json -Depth 8
}

trap {
    $failure = [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-recovery-agent-repair/v1'
        created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        status = 'ERROR'
        mutation_performed = $false
        error = $_.Exception.Message
        rollback_performed = $false
        rollback_complete = $true
        token_value_recorded = $false
    }
    Write-PublicResult -Value $failure
    Write-Host ("`nNo se inicio la reparacion: " +
        $_.Exception.Message) -ForegroundColor Red
    exit 1
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Este reparador debe ejecutarse como administrador.'
}
if (-not (Test-Path -LiteralPath $bundledRunnerPath -PathType Leaf)) {
    throw "Falta el runner incluido en el kit: $bundledRunnerPath"
}
if ((Get-Sha256 -Path $bundledRunnerPath) -cne
        $expectedRunnerSha256) {
    throw 'El runner incluido no coincide con la version R01 congelada.'
}

$existingTask = Get-ExactTask
if ($null -ne $existingTask) {
    Assert-OwnedTask -Task $existingTask
}
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw (
        'No existe el directorio privado del agente. Sin el token existente ' +
        'no es seguro generar una instalacion nueva.')
}
$null = Assert-NoReparsePath -Path $root
if (Test-Path -LiteralPath $dataRoot) {
    $null = Assert-NoReparsePath -Path $dataRoot
}
$tokenPath = Get-ValidatedTokenPath -ExistingTask $existingTask
$tokenHashBefore = Get-Sha256 -Path $tokenPath
$tokenAclBefore = (Get-Acl -LiteralPath $tokenPath).Sddl
$firewallBefore = Get-FirewallSnapshot
Assert-NoForeignListener

$evidenceRoot = Join-Path $root 'repair-evidence'
New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null
$null = Assert-NoReparsePath -Path $evidenceRoot
$evidenceDirectory = Join-Path $evidenceRoot $runId
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
Set-Acl -LiteralPath $evidenceDirectory `
    -AclObject (New-RestrictedAcl -Directory)

$oldTaskXml = $null
$oldTaskWasRunning = $false
if ($null -ne $existingTask) {
    $oldTaskWasRunning = [string]$existingTask.State -ceq 'Running'
    $oldTaskXml = Export-ScheduledTask -TaskName $taskName `
        -TaskPath $taskPath
    Write-Utf8TextAtomic -Path (
        Join-Path $evidenceDirectory 'task-before.xml') `
        -Text $oldTaskXml
}
$runnerExisted = Test-Path -LiteralPath $runnerPath -PathType Leaf
$runnerBackupPath = Join-Path $evidenceDirectory 'runner-before.ps1'
$runnerAclBefore = $null
if ($runnerExisted) {
    $runnerAclBefore = (Get-Acl -LiteralPath $runnerPath).Sddl
    Copy-Item -LiteralPath $runnerPath -Destination $runnerBackupPath
}
if ($null -ne $firewallBefore) {
    Write-JsonAtomic -Path (
        Join-Path $evidenceDirectory 'firewall-before.json') `
        -Value $firewallBefore
}
$preflight = [pscustomobject][ordered]@{
    schema = 'ese.v91.r01-recovery-agent-repair-preflight/v1'
    created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    mutation_performed = $false
    task_present = $null -ne $existingTask
    task_state = if ($null -eq $existingTask) {
        $null
    } else { [string]$existingTask.State }
    runner_present = $runnerExisted
    bundled_runner_sha256 = Get-Sha256 -Path $bundledRunnerPath
    token_file_name = [IO.Path]::GetFileName($tokenPath)
    token_contract_valid = $true
    token_value_recorded = $false
    firewall_present = $null -ne $firewallBefore
    port = $port
    allowed_source_ipv4 = $allowedSourceIPv4
}
Write-JsonAtomic -Path (
    Join-Path $evidenceDirectory 'preflight.json') -Value $preflight

$taskMutated = $false
$runnerMutated = $false
$tokenAclMutated = $false
$firewallMutated = $false
$rollbackErrors = [Collections.Generic.List[string]]::new()
try {
    if ($null -ne $existingTask) {
        $taskMutated = $true
        Stop-ScheduledTask -TaskName $taskName -TaskPath $taskPath `
            -ErrorAction SilentlyContinue
    }
    Stop-OwnedAgentListener

    $newRunnerPath = $runnerPath + '.new-' +
        [Guid]::NewGuid().ToString('N')
    try {
        Copy-Item -LiteralPath $bundledRunnerPath `
            -Destination $newRunnerPath
        if ((Get-Sha256 -Path $newRunnerPath) -cne
                $expectedRunnerSha256) {
            throw 'La copia local del runner no conserva su hash.'
        }
        $runnerMutated = $true
        Move-Item -LiteralPath $newRunnerPath -Destination $runnerPath `
            -Force
        Set-Acl -LiteralPath $runnerPath `
            -AclObject (New-RestrictedAcl)
        if ((Get-Sha256 -Path $runnerPath) -cne
                $expectedRunnerSha256) {
            throw 'Proteger el runner altero su contenido.'
        }
    } finally {
        Remove-Item -LiteralPath $newRunnerPath -Force `
            -ErrorAction SilentlyContinue
    }

    $tokenAclMutated = $true
    Set-Acl -LiteralPath $tokenPath `
        -AclObject (New-RestrictedAcl)
    if ((Get-Sha256 -Path $tokenPath) -cne $tokenHashBefore) {
        throw 'La credencial cambio al proteger sus permisos.'
    }

    if ($null -eq $existingTask -and $null -ne (Get-ExactTask)) {
        throw 'La tarea aparecio durante la reparacion; no se sobrescribira.'
    }
    $taskMutated = $true
    if ($null -ne $existingTask) {
        Unregister-ScheduledTask -TaskName $taskName `
            -TaskPath $taskPath -Confirm:$false
    }
    $arguments = (
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
        '-File "{0}" -TokenFile "{1}" -Root "{2}" ' +
        '-AllowedSourceIPv4 "{3}" -Port {4} ' +
        '-MutexName "Global\eSE-Lab-SmallFrame-Agent"'
    ) -f $runnerPath, $tokenPath, $dataRoot,
        $allowedSourceIPv4, $port
    $action = New-ScheduledTaskAction -Execute $powershellPath `
        -Argument $arguments -WorkingDirectory $root
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
        -LogonType ServiceAccount -RunLevel Highest
    $taskDefinition = New-ScheduledTask -Action $action `
        -Trigger $trigger -Settings $settings -Principal $principal `
        -Description $taskDescription
    Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath `
        -InputObject $taskDefinition -Force | Out-Null
    $registeredTask = Get-ExactTask
    Assert-FinalTaskDefinition -Task $registeredTask `
        -ExpectedArguments $arguments
    Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    $ready = Assert-TaskReady

    $firewallMutated = $true
    Remove-NetFirewallRule -Name $firewallName `
        -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $firewallName `
        -DisplayName $firewallDisplayName -Direction Inbound `
        -Action Allow -Enabled True -Protocol TCP -LocalPort $port `
        -RemoteAddress $allowedSourceIPv4 -Profile Any `
        -Program $powershellPath -EdgeTraversalPolicy Block | Out-Null
    Assert-FirewallReady

    if ((Get-Sha256 -Path $runnerPath) -cne
            $expectedRunnerSha256) {
        throw 'El runner instalado no conserva el hash congelado.'
    }
    if ((Get-Sha256 -Path $tokenPath) -cne $tokenHashBefore) {
        throw 'La credencial existente no se preservo byte por byte.'
    }

    $finalTask = Get-ExactTask
    $finalInfo = Get-ScheduledTaskInfo -TaskName $taskName `
        -TaskPath $taskPath
    $result = [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-recovery-agent-repair/v1'
        created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        status = 'READY'
        mutation_performed = $true
        rollback_performed = $false
        task = $taskName
        task_state = [string]$finalTask.State
        last_task_result = [int]$finalInfo.LastTaskResult
        listen = "0.0.0.0:$port"
        listener_pid = [int]$ready.process_id
        allowed_source_ipv4 = $allowedSourceIPv4
        runner_sha256 = Get-Sha256 -Path $runnerPath
        runner_acl_restricted = $true
        token_preserved_byte_for_byte = $true
        token_value_recorded = $false
        firewall_verified = $true
        evidence_directory = $evidenceDirectory
    }
    Write-JsonAtomic -Path (
        Join-Path $evidenceDirectory 'result.json') -Value $result
    Write-PublicResult -Value $result
    Write-Host (
        "`nAgente listo. H1 puede conectar a $allowedSourceIPv4 -> " +
        "este equipo:$port.") -ForegroundColor Green
    exit 0
} catch {
    $failureMessage = $_.Exception.Message

    if ($taskMutated) {
        try {
            Stop-ScheduledTask -TaskName $taskName -TaskPath $taskPath `
                -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName `
                -TaskPath $taskPath -Confirm:$false `
                -ErrorAction SilentlyContinue
        } catch {
            $rollbackErrors.Add('task_remove: ' + $_.Exception.Message)
        }
    }

    if ($runnerMutated) {
        try {
            if ($runnerExisted) {
                Copy-Item -LiteralPath $runnerBackupPath `
                    -Destination $runnerPath -Force
                $runnerAcl = Get-Acl -LiteralPath $runnerPath
                $runnerAcl.SetSecurityDescriptorSddlForm($runnerAclBefore)
                Set-Acl -LiteralPath $runnerPath `
                    -AclObject $runnerAcl
            } else {
                Remove-Item -LiteralPath $runnerPath -Force `
                    -ErrorAction SilentlyContinue
            }
        } catch {
            $rollbackErrors.Add('runner: ' + $_.Exception.Message)
        }
    }

    if ($tokenAclMutated) {
        try {
            $acl = Get-Acl -LiteralPath $tokenPath
            $acl.SetSecurityDescriptorSddlForm($tokenAclBefore)
            Set-Acl -LiteralPath $tokenPath -AclObject $acl
        } catch {
            $rollbackErrors.Add('token_acl: ' + $_.Exception.Message)
        }
    }

    if ($taskMutated -and $null -ne $oldTaskXml) {
        try {
            Register-ScheduledTask -TaskName $taskName `
                -TaskPath $taskPath -Xml $oldTaskXml -Force |
                Out-Null
            if ($oldTaskWasRunning) {
                Start-ScheduledTask -TaskName $taskName `
                    -TaskPath $taskPath
            }
        } catch {
            $rollbackErrors.Add('task_restore: ' + $_.Exception.Message)
        }
    }

    if ($firewallMutated) {
        try {
            Remove-NetFirewallRule -Name $firewallName `
                -ErrorAction SilentlyContinue
            if ($null -ne $firewallBefore) {
                Restore-FirewallSnapshot -Snapshot $firewallBefore
            }
        } catch {
            $rollbackErrors.Add(
                'firewall: ' + $_.Exception.Message)
        }
    }

    $tokenStillPreserved = $false
    try {
        $tokenStillPreserved =
            (Get-Sha256 -Path $tokenPath) -ceq $tokenHashBefore
    } catch {
        $rollbackErrors.Add('token_verify: ' + $_.Exception.Message)
    }
    $failure = [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-recovery-agent-repair/v1'
        created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        status = 'ERROR'
        mutation_performed = (
            $taskMutated -or $runnerMutated -or
            $tokenAclMutated -or $firewallMutated)
        error = $failureMessage
        rollback_performed = (
            $taskMutated -or $runnerMutated -or
            $tokenAclMutated -or $firewallMutated)
        rollback_complete = $rollbackErrors.Count -eq 0
        rollback_errors = @($rollbackErrors.ToArray())
        token_preserved_byte_for_byte = $tokenStillPreserved
        token_value_recorded = $false
        evidence_directory = $evidenceDirectory
    }
    try {
        Write-JsonAtomic -Path (
            Join-Path $evidenceDirectory 'result.json') -Value $failure
    } catch {}
    Write-PublicResult -Value $failure
    Write-Host "`nNo se completo la reparacion: $failureMessage" `
        -ForegroundColor Red
    exit 1
}
