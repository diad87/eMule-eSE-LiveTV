[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$expectedEmuleSha256 =
    '94620cf502c954cda29fa7f40f834ef1eebacb753f1fe277865d1d173e0b9b41'
$expectedZipSha256 =
    '359272c764c532c32cfd97eeb92e2db4feaa620c5d3f6318a82a7453dbf1b56f'
$expectedZipBytes = 212040831L
$peerPort = 7962
$controlPort = 8012

$layoutRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$activeAtLayout = Join-Path $layoutRoot 'ACTIVE-V91-I05-T1.json'
$activeAtScripts = Join-Path $PSScriptRoot 'ACTIVE-V91-I05-T1.json'
$kitRoot = if (Test-Path -LiteralPath $activeAtScripts -PathType Leaf) {
    [IO.Path]::GetFullPath($PSScriptRoot)
} else {
    $layoutRoot
}
$activePath = Join-Path $kitRoot 'ACTIVE-V91-I05-T1.json'
$latestReadyPath = Join-Path $kitRoot 'READY-V91-I05-T1.json'
$latestCleanupPath = Join-Path $kitRoot 'CLEANUP-V91-I05-T1.json'
$commonPath = Join-Path $PSScriptRoot 'common.ps1'
$contractPath = Join-Path $PSScriptRoot 'v91_i05_t1_contract.ps1'

foreach ($required in @($commonPath, $contractPath, $activePath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Falta el archivo de cleanup requerido: $required"
    }
}
. $commonPath
. $contractPath

function Assert-I05CleanupAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'El cleanup V91-I05 H3 requiere administrador.'
    }
}

function Test-I05CleanupContained {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + '\'
    $pathFull = [IO.Path]::GetFullPath($Path)
    return $pathFull.StartsWith(
        $rootFull, [StringComparison]::OrdinalIgnoreCase)
}

function Get-I05CleanupProcessExact {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ProcessId
    )
    $cimMatches = @(Get-CimInstance Win32_Process `
        -Filter ("ProcessId={0}" -f $ProcessId) -ErrorAction Stop)
    if ($cimMatches.Count -gt 1) {
        throw "Win32_Process devolvio mas de una fila para PID $ProcessId."
    }
    if ($cimMatches.Count -eq 0) {
        return $null
    }

    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
    } catch {
        $processError = $_
        $confirmation = @(Get-CimInstance Win32_Process `
            -Filter ("ProcessId={0}" -f $ProcessId) -ErrorAction Stop)
        if ($confirmation.Count -gt 1) {
            throw "Win32_Process devolvio mas de una fila para PID $ProcessId."
        }
        if ($confirmation.Count -eq 0) {
            return $null
        }
        throw $processError
    }

    return [pscustomobject][ordered]@{
        process = $process
        cim = $cimMatches[0]
    }
}

function Get-I05CleanupIniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key
    )
    $current = ''
    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*\[(.+?)\]\s*$') {
            $current = $Matches[1]
            continue
        }
        if ($current -ieq $Section -and
            $line -match '^\s*([^;#][^=]*?)\s*=(.*)$' -and
            $Matches[1].Trim() -ieq $Key) {
            $values.Add($Matches[2].Trim())
        }
    }
    if ($values.Count -ne 1) {
        throw "INI [$Section] $Key no es unico."
    }
    return $values[0]
}

function Assert-I05CleanupFirewall {
    param(
        [Parameter(Mandatory = $true)][object]$Rule,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string]$InterfaceAlias,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$LocalPort
    )
    if ([string]$Rule.DisplayName -cne $DisplayName -or
        [string]$Rule.Direction -ne 'Inbound' -or
        [string]$Rule.Action -ne 'Allow' -or
        [string]$Rule.Enabled -ne 'True') {
        throw 'La identidad base de firewall ya no coincide.'
    }
    $ports = @(Get-NetFirewallPortFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $apps = @(Get-NetFirewallApplicationFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $addresses = @(Get-NetFirewallAddressFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $interfaces = @(Get-NetFirewallInterfaceFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    if ($ports.Count -ne 1 -or $apps.Count -ne 1 -or
        $addresses.Count -ne 1 -or $interfaces.Count -ne 1 -or
        [string]$ports[0].Protocol -notin @('TCP', '6') -or
        [int]$ports[0].LocalPort -ne $LocalPort -or
        [IO.Path]::GetFullPath([string]$apps[0].Program) -ne
            [IO.Path]::GetFullPath($Program) -or
        [string]$addresses[0].LocalAddress -ne $LocalAddress -or
        [string]$addresses[0].RemoteAddress -ne $RemoteAddress -or
        [string]$interfaces[0].InterfaceAlias -ne $InterfaceAlias) {
        throw 'Los filtros firewall propios ya no coinciden exactamente.'
    }
}

function Convert-I05CleanupFirewallValues {
    param([AllowNull()][object]$Value)
    $values = @($Value | ForEach-Object { [string]$_ } |
        Sort-Object -Unique)
    if ($values.Count -eq 0) { return @('Any') }
    return $values
}

function Get-I05CleanupContainmentRuleLine {
    param([Parameter(Mandatory = $true)][object]$Rule)
    return (
        'role={0}|name_sha256={1}|direction={2}|action={3}|' +
        'enabled={4}|profile={5}|protocol={6}|local_ports={7}|' +
        'remote_ports={8}|remote_addresses_sha256={9}|' +
        'remote_address_count={10}|program_sha256={11}|' +
        'all_interfaces={12}'
    ) -f [string]$Rule.role, [string]$Rule.name_sha256,
        [string]$Rule.direction, [string]$Rule.action,
        ([string]$Rule.enabled).ToLowerInvariant(),
        [string]$Rule.profile, [string]$Rule.protocol,
        (@($Rule.local_ports | Sort-Object -Unique) -join ','),
        (@($Rule.remote_ports | Sort-Object -Unique) -join ','),
        [string]$Rule.remote_addresses_sha256,
        [int]$Rule.remote_address_count,
        [string]$Rule.program_sha256,
        ([string]$Rule.all_interfaces).ToLowerInvariant()
}

function Assert-I05CleanupContainmentRule {
    param(
        [Parameter(Mandatory = $true)][object]$Rule,
        [Parameter(Mandatory = $true)][object]$Spec
    )
    if ([string]$Rule.Name -cne [string]$Spec.name -or
        [string]$Rule.DisplayName -cne [string]$Spec.display_name -or
        [string]$Rule.Direction -cne [string]$Spec.direction -or
        [string]$Rule.Action -cne 'Block' -or
        [string]$Rule.Enabled -cne 'True' -or
        [string]$Rule.Profile -cne 'Any' -or
        [string]$Rule.EdgeTraversalPolicy -cne 'Block') {
        throw "Identidad containment alterada: $($Spec.role)."
    }
    $ports = @(Get-NetFirewallPortFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $apps = @(Get-NetFirewallApplicationFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $addresses = @(Get-NetFirewallAddressFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $interfaces = @(Get-NetFirewallInterfaceFilter `
        -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    if ($ports.Count -ne 1 -or $apps.Count -ne 1 -or
        $addresses.Count -ne 1 -or $interfaces.Count -ne 1) {
        throw "Cardinalidad containment alterada: $($Spec.role)."
    }
    $protocolExpected = if ([string]$Spec.protocol -ceq 'TCP') {
        @('TCP', '6')
    } else {
        @('UDP', '17')
    }
    $actualLocalPorts =
        Convert-I05CleanupFirewallValues -Value $ports[0].LocalPort
    $actualRemotePorts =
        Convert-I05CleanupFirewallValues -Value $ports[0].RemotePort
    $actualRemoteAddresses =
        Convert-I05CleanupFirewallValues -Value $addresses[0].RemoteAddress
    $actualLocalAddresses =
        Convert-I05CleanupFirewallValues -Value $addresses[0].LocalAddress
    $actualInterfaces =
        Convert-I05CleanupFirewallValues -Value $interfaces[0].InterfaceAlias
    if ([string]$ports[0].Protocol -notin $protocolExpected -or
        ($actualLocalPorts -join "`n") -cne
            ((@($Spec.local_ports | Sort-Object -Unique)) -join "`n") -or
        ($actualRemotePorts -join "`n") -cne
            ((@($Spec.remote_ports | Sort-Object -Unique)) -join "`n") -or
        ($actualRemoteAddresses -join "`n") -cne
            ((@($Spec.remote_addresses | Sort-Object -Unique)) -join "`n") -or
        ($actualLocalAddresses -join "`n") -cne 'Any' -or
        ($actualInterfaces -join "`n") -cne 'Any' -or
        [IO.Path]::GetFullPath([string]$apps[0].Program) -ne
            [IO.Path]::GetFullPath([string]$Spec.program)) {
        throw "Filtros containment alterados: $($Spec.role)."
    }
}

function Get-I05CleanupFirewallRulesExact {
    param([Parameter(Mandatory = $true)][string[]]$Name)

    $rules = [Collections.Generic.List[object]]::new()
    foreach ($item in $Name) {
        try {
            foreach ($rule in @(Get-NetFirewallRule -Name $item `
                    -PolicyStore ActiveStore -ErrorAction Stop)) {
                $rules.Add($rule)
            }
        } catch {
            $notFound = $_.CategoryInfo.Category -eq 'ObjectNotFound' -or
                $_.FullyQualifiedErrorId -match
                    'NoMatching.*GetNetFirewallRule|ObjectNotFound'
            if (-not $notFound) { throw }
        }
    }
    return $rules.ToArray()
}

function Get-I05CleanupContainmentInventory {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $allRules = @(Get-I05CleanupFirewallRulesExact -Name @(
        $Plan.rules | ForEach-Object { [string]$_.name }
    ))
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($spec in @($Plan.rules | Sort-Object role)) {
        $matches = @($allRules | Where-Object {
            [string]$_.Name -ceq [string]$spec.name
        })
        if ($matches.Count -gt 1) {
            throw "Regla containment ambigua: $($spec.role)."
        }
        $present = $matches.Count -eq 1
        $lineSha = $null
        if ($present) {
            Assert-I05CleanupContainmentRule -Rule $matches[0] -Spec $spec
            $lineSha = Get-LabStringSha256 -Value (
                Get-I05CleanupContainmentRuleLine -Rule $spec.canonical)
        }
        $entries.Add([pscustomobject][ordered]@{
            role = [string]$spec.role
            name_sha256 = [string]$spec.canonical.name_sha256
            present = [bool]$present
            observed_spec_line_sha256 = $lineSha
        })
    }
    $stateMaterial = @($entries | Sort-Object role | ForEach-Object {
        'role={0}|name_sha256={1}|present={2}|spec_line_sha256={3}' -f
            [string]$_.role, [string]$_.name_sha256,
            ([string]$_.present).ToLowerInvariant(),
            [string]$_.observed_spec_line_sha256
    }) -join "`n"
    $document = [ordered]@{
        schema = 'ese.v91.i05.t1-firewall-containment-inventory/v1'
        case_id = 'V91-I05'
        nonce = [string]$Plan.nonce
        stage = $Stage
        created_at_utc = Get-LabUtcTimestamp
        scope = 'exact-ten-nonce-program-rules-only'
        global_inventory_included = $false
        rule_count = [int]$Plan.rule_count
        entries = $entries.ToArray()
        state_sha256 = Get-LabStringSha256 -Value $stateMaterial
    }
    $written = Write-LabJson -Value $document -Path $Path
    return [pscustomobject][ordered]@{
        path = $written
        sha256 = Get-LabSha256 -Path $written
        state_sha256 = [string]$document.state_sha256
        present_count = @($entries | Where-Object present).Count
        absent_count = @($entries | Where-Object { -not $_.present }).Count
        entries = $entries.ToArray()
    }
}

Assert-I05CleanupAdministrator

$activeRaw = Get-Content -LiteralPath $activePath -Raw
$active = $activeRaw | ConvertFrom-Json
if ([string]$active.schema -notin @(
        'ese.v91.i05.t1-active-h3/v1',
        'ese.v91.i05.t1-active-h3/v2'
    ) -or
    [string]$active.case_id -cne 'V91-I05' -or
    [string]$active.nonce -notmatch '^[0-9a-f]{32}$') {
    throw 'ACTIVE H3 no tiene la identidad formal esperada.'
}
$nonce = [string]$active.nonce
$runRoot = [IO.Path]::GetFullPath([string]$active.run_root)
if (-not (Test-Path -LiteralPath $runRoot -PathType Container) -or
    -not (Test-I05CleanupContained -Root $kitRoot -Path $runRoot)) {
    throw 'ACTIVE.run_root no es una ejecucion contenida en el kit.'
}
$sessionPath = [IO.Path]::GetFullPath([string]$active.session_path)
if (-not (Test-I05CleanupContained -Root $runRoot -Path $sessionPath) -or
    -not (Test-Path -LiteralPath $sessionPath -PathType Leaf)) {
    throw 'La sesion privada H3 no esta contenida en RunRoot.'
}
$session = (Get-Content -LiteralPath $sessionPath -Raw) |
    ConvertFrom-Json
if ([string]$session.schema -cne
        'ese.v91.i05.t1-h3-private-session/v1' -or
    [string]$session.nonce -cne $nonce -or
    [string]$session.candidate.emule_sha256 -cne
        $expectedEmuleSha256 -or
    [string]$session.candidate.zip_sha256 -cne
        $expectedZipSha256 -or
    [Int64]$session.candidate.zip_bytes -ne $expectedZipBytes) {
    throw 'La sesion privada no fija el candidato RC3 exacto.'
}
$containment = $session.containment
if ($null -eq $containment -or
    [string]$containment.schema -cne
        'ese.v91.i05.t1-firewall-containment-plan/v1' -or
    [string]$containment.case_id -cne 'V91-I05' -or
    [string]$containment.nonce -cne $nonce -or
    [int]$containment.rule_count -ne 10 -or
    @($containment.rules).Count -ne 10 -or
    @($containment.canonical_rules).Count -ne 10) {
    throw 'El plan containment privado no es exacto.'
}
$containmentRoles = @($containment.rules |
    ForEach-Object { [string]$_.role } | Sort-Object)
$expectedContainmentRoles = @(
    'in_tcp_v4_not_h1', 'in_tcp_v6_all',
    'in_udp_v4_all', 'in_udp_v6_all',
    'out_tcp_v4_not_h1_loopback', 'out_tcp_v4_h1_wrong_ports',
    'out_tcp_v4_loopback_non_api_local_ports',
    'out_tcp_v6_all', 'out_udp_v4_all', 'out_udp_v6_all'
) | Sort-Object
if (($containmentRoles -join "`n") -cne
    ($expectedContainmentRoles -join "`n")) {
    throw 'Los roles containment privados no coinciden.'
}
$canonicalMaterial = @($containment.canonical_rules |
    Sort-Object role | ForEach-Object {
        Get-I05CleanupContainmentRuleLine -Rule $_
    }) -join "`n"
if ((Get-LabStringSha256 -Value $canonicalMaterial) -cne
        [string]$containment.spec_sha256) {
    throw 'El SHA logico del plan containment no coincide.'
}
$containmentNamesMaterial = @($containment.rules |
    ForEach-Object { [string]$_.name } | Sort-Object) -join "`n"
if ((Get-LabStringSha256 -Value $containmentNamesMaterial) -cne
        [string]$containment.rule_names_sha256) {
    throw 'El SHA de nombres containment no coincide.'
}
foreach ($spec in @($containment.rules)) {
    if ([string]$spec.profile -cne 'Any' -or
        [string]$spec.action -cne 'Block' -or
        -not [bool]$spec.enabled -or
        [IO.Path]::GetFullPath([string]$spec.program) -ne
            [IO.Path]::GetFullPath([string]$session.emule_path)) {
        throw "Plan containment no es Block/Enabled/Any: $($spec.role)."
    }
}
$containmentSpecPath =
    [IO.Path]::GetFullPath([string]$containment.spec_path)
$containmentBeforePath =
    [IO.Path]::GetFullPath([string]$containment.inventory_before_path)
$containmentAfterPath =
    [IO.Path]::GetFullPath([string]$containment.inventory_after_path)
foreach ($path in @($containmentSpecPath, $containmentBeforePath,
        $containmentAfterPath)) {
    if (-not (Test-I05CleanupContained -Root $runRoot -Path $path)) {
        throw 'Una ruta containment escapa de RunRoot.'
    }
}
if (-not (Test-Path -LiteralPath $containmentSpecPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $containmentBeforePath -PathType Leaf) -or
    (Get-LabSha256 -Path $containmentSpecPath) -cne
        [string]$containment.spec_document_sha256 -or
    (Get-LabSha256 -Path $containmentBeforePath) -cne
        [string]$containment.inventory_before_sha256) {
    throw 'La evidencia pre containment fue alterada.'
}
$emulePath = [IO.Path]::GetFullPath([string]$session.emule_path)
$nodePath = [IO.Path]::GetFullPath([string]$session.node_path)
$preferencesPath =
    [IO.Path]::GetFullPath([string]$session.preferences_path)
if (-not (Test-I05CleanupContained -Root $runRoot -Path $emulePath) -or
    -not (Test-I05CleanupContained -Root $runRoot -Path $nodePath) -or
    -not (Test-I05CleanupContained -Root $runRoot `
        -Path $preferencesPath) -or
    (Get-LabSha256 -Path $emulePath) -cne $expectedEmuleSha256) {
    throw 'Las rutas/hash del proceso registrado no son propias.'
}

$processId = [int]$session.process_id
$processState = if ($null -ne $session.PSObject.Properties['mutations']) {
    [string]$session.mutations.candidate_process
} else { 'OWNED' }
$ownedProcessRecord = $null
if ($processId -gt 0) {
    $ownedProcessRecord = Get-I05CleanupProcessExact -ProcessId $processId
} elseif ($processState -eq 'PENDING') {
    $notBefore = [DateTimeOffset]::Parse(
        [string]$session.process_not_before_utc).UtcDateTime.AddSeconds(-2)
    $arguments = @($session.process_arguments)
    $pendingCandidates = @(Get-CimInstance Win32_Process `
        -ErrorAction Stop | Where-Object {
            if (-not $_.ExecutablePath -or -not $_.CommandLine) {
                return $false
            }
            if ([IO.Path]::GetFullPath([string]$_.ExecutablePath) -ne
                $emulePath) {
                return $false
            }
            $createdAt = if ($_.CreationDate -is [DateTime]) {
                ([DateTime]$_.CreationDate).ToUniversalTime()
            } else {
                [Management.ManagementDateTimeConverter]::
                    ToDateTime([string]$_.CreationDate).ToUniversalTime()
            }
            if ($createdAt -lt $notBefore) { return $false }
            foreach ($argument in $arguments) {
                if ([string]$_.CommandLine -notmatch (
                        '(?i)(?:^|\s)' + [regex]::Escape(
                            [string]$argument) + '(?:\s|$)')) {
                    return $false
                }
            }
            return $true
        })
    if ($pendingCandidates.Count -gt 1) {
        throw 'El proceso PENDING coincide con mas de un PID; cleanup aborta.'
    }
    if ($pendingCandidates.Count -eq 1) {
        $processId = [int]$pendingCandidates[0].ProcessId
        $ownedProcessRecord =
            Get-I05CleanupProcessExact -ProcessId $processId
        if ($null -eq $ownedProcessRecord) {
            throw 'El proceso PENDING desaparecio durante su adquisicion.'
        }
    }
}
if ($null -ne $ownedProcessRecord) {
    $ownedProcess = $ownedProcessRecord.process
    $cim = $ownedProcessRecord.cim
    $ownedProcess.Refresh()
    $registeredStart = $null
    if ([string]$session.process_started_at_utc) {
        $registeredStart = [DateTimeOffset]::Parse(
            [string]$session.process_started_at_utc)
    }
    if ([IO.Path]::GetFullPath([string]$ownedProcess.Path) -ne $emulePath -or
        ($null -ne $registeredStart -and
            [Math]::Abs((
                $ownedProcess.StartTime.ToUniversalTime() -
                $registeredStart.UtcDateTime).TotalSeconds) -gt 2)) {
        throw 'El PID registrado ya no pertenece al downloader H3.'
    }
    foreach ($argument in @(
        '--portable', '--ignoreinstances', '--headless',
        '--metrics-port=8011', '--tcp-port=7962', '--udp-port=7972'
    )) {
        if ([string]$cim.CommandLine -notmatch (
                '(?i)(?:^|\s)' + [regex]::Escape($argument) +
                '(?:\s|$)')) {
            throw 'El PID registrado no conserva sus argumentos aislados.'
        }
    }
    Stop-Process -Id $processId -Force -ErrorAction Stop
    $null = $ownedProcess.WaitForExit(15000)
}
if ($processId -gt 0) {
    $processAfterStop = Get-I05CleanupProcessExact -ProcessId $processId
    if ($null -ne $processAfterStop) {
        throw 'El downloader registrado sigue activo.'
    }
}

$containmentState = if (
    $null -ne $session.mutations.PSObject.Properties[
        'containment_firewall']
) {
    [string]$session.mutations.containment_firewall
} else {
    throw 'La sesion no registra containment_firewall.'
}
$containmentCleanupBeforePath = Join-Path $runRoot `
    'evidence\firewall-containment-inventory-cleanup-before.json'
$containmentCurrent = Get-I05CleanupContainmentInventory `
    -Plan $containment -Stage 'cleanup-before' `
    -Path $containmentCleanupBeforePath
if ($containmentState -eq 'OWNED' -and
        [int]$containmentCurrent.present_count -notin @(0, 10)) {
    throw 'Containment OWNED conserva solo parte de sus diez reglas.'
}
if ($containmentState -eq 'NOT_STARTED' -and
        [int]$containmentCurrent.present_count -ne 0) {
    throw 'Containment NOT_STARTED tiene reglas inesperadas.'
}
if ($containmentState -notin @(
        'NOT_STARTED', 'PENDING', 'OWNED', 'COMPLETED', 'REMOVED'
    )) {
    throw 'Estado containment_firewall no reconocido.'
}
$allContainmentRules = @(Get-I05CleanupFirewallRulesExact -Name @(
    $containment.rules | ForEach-Object { [string]$_.name }
))
foreach ($spec in @($containment.rules | Sort-Object role)) {
    $matches = @($allContainmentRules | Where-Object {
        [string]$_.Name -ceq [string]$spec.name
    })
    if ($matches.Count -gt 1) {
        throw "Regla containment ambigua al retirar: $($spec.role)."
    }
    if ($matches.Count -eq 1) {
        Assert-I05CleanupContainmentRule -Rule $matches[0] -Spec $spec
        Remove-NetFirewallRule -Name ([string]$spec.name) `
            -ErrorAction Stop
    }
}
$containmentAfter = Get-I05CleanupContainmentInventory `
    -Plan $containment -Stage after -Path $containmentAfterPath
$containmentRulesAbsent =
    [int]$containmentAfter.absent_count -eq 10 -and
    [int]$containmentAfter.present_count -eq 0
$containmentInventoryRestored =
    $containmentRulesAbsent -and
    [string]$containmentAfter.state_sha256 -ceq
        [string]$containment.state_before_sha256
if (-not $containmentRulesAbsent -or
    -not $containmentInventoryRestored) {
    throw 'El containment firewall no quedo ausente/restaurado.'
}

$peerName = [string]$session.firewall_rule_name
$peerRules = @(Get-I05CleanupFirewallRulesExact -Name @($peerName))
if ($peerRules.Count -gt 1) {
    throw 'La regla peer registrada es ambigua.'
}
if ($peerRules.Count -eq 1) {
    Assert-I05CleanupFirewall -Rule $peerRules[0] `
        -DisplayName ([string]$session.firewall_display_name) `
        -Program $emulePath `
        -InterfaceAlias ([string]$session.interface_alias) `
        -LocalAddress ([string]$session.downloader_ipv4_address) `
        -RemoteAddress ([string]$session.source_ipv4_address) `
        -LocalPort $peerPort
    Remove-NetFirewallRule -Name $peerName -ErrorAction Stop
}

$controlName = [string]$session.control_firewall_rule_name
$controlRules = @(Get-I05CleanupFirewallRulesExact -Name @($controlName))
if ($controlRules.Count -gt 1) {
    throw 'La regla de control registrada es ambigua.'
}
if ($controlRules.Count -eq 1) {
    Assert-I05CleanupFirewall -Rule $controlRules[0] `
        -DisplayName ([string]$session.control_firewall_display_name) `
        -Program ([string]$session.control_program) `
        -InterfaceAlias ([string]$session.interface_alias) `
        -LocalAddress ([string]$session.downloader_ipv4_address) `
        -RemoteAddress ([string]$session.source_ipv4_address) `
        -LocalPort $controlPort
    Remove-NetFirewallRule -Name $controlName -ErrorAction Stop
}
$peerAbsent = @(Get-I05CleanupFirewallRulesExact `
    -Name @($peerName)).Count -eq 0
$controlAbsent = @(Get-I05CleanupFirewallRulesExact `
    -Name @($controlName)).Count -eq 0
if (-not $peerAbsent -or -not $controlAbsent) {
    throw 'Alguna regla firewall propia sigue presente.'
}

$capture = $session.capture
$sessionProbe = @(& logman.exe query -ets PktMon 2>&1)
if ($LASTEXITCODE -eq 0) {
    if ([string]$active.capture_state -ceq 'COMPLETED') {
        throw (
            'Aparecio una sesion PktMon despues de completar la propia; ' +
            'se rechaza detener una sesion ajena.'
        )
    }
    $sessionText = $sessionProbe -join "`n"
    $expectedEtlPath =
        [IO.Path]::GetFullPath([string]$capture.etl_path)
    if ($sessionText.IndexOf(
            $expectedEtlPath,
            [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw 'La sesion PktMon activa no demuestra pertenecer a H3.'
    }
    & pktmon.exe stop 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo detener la sesion PktMon propia.'
    }
} elseif ([bool]$capture.started -and [bool]$capture.session_owned -and
    [string]$active.capture_state -cne 'COMPLETED') {
    # ControlTrace STOP may already have removed the ETW session before a
    # later proof failed. PktMon still retains an internal "started" state;
    # the persisted owned capture and nonce-scoped filters prove authority to
    # reset that state even though logman can no longer enumerate the session.
    # A non-zero exit is also valid here when ControlTrace already reset the
    # internal monitor. The exact owned filters and absent ETW session are
    # verified below before cleanup can be committed.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & pktmon.exe stop 2>$null | Out-Null
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}
$filterList = @(& pktmon.exe filter list 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw 'No se pudo inventariar PktMon durante cleanup.'
}
$filterText = $filterList -join "`n"
$ownedListed = $false
foreach ($filterName in @($capture.filters)) {
    if ([string]$filterName -notmatch
            ('^ese-i05-' + [regex]::Escape($nonce.Substring(0, 8)) +
                '-v(?:4|6)-')) {
        throw 'La sesion contiene un filtro PktMon no atribuible.'
    }
    if ($filterText.IndexOf(
            [string]$filterName,
            [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $ownedListed = $true
    }
}
if ($ownedListed) {
    if ([string]$active.capture_state -ceq 'COMPLETED') {
        throw 'Hay filtros propios pese a capture_state=COMPLETED.'
    }
    $foreignText = $filterText
    foreach ($filterName in @($capture.filters)) {
        $foreignText = $foreignText -replace
            [regex]::Escape([string]$filterName), ''
    }
    if ($foreignText -match
            '(?im)^\s*(?:filter\s+name|name|nombre(?:\s+de(?:l)?\s+filtro)?)\s*:\s*\S+') {
        throw 'El inventario contiene filtros ajenos; no se altera globalmente.'
    }
    & pktmon.exe filter remove 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo retirar el conjunto de filtros propios.'
    }
}
$filtersAfterPath =
    Join-Path $runRoot 'evidence\pktmon-filters-after-cleanup.txt'
@(& pktmon.exe filter list 2>&1) |
    Set-Content -LiteralPath $filtersAfterPath -Encoding utf8
if ($LASTEXITCODE -ne 0) {
    throw 'No se pudo verificar los filtros PktMon finales.'
}
$afterText = Get-Content -LiteralPath $filtersAfterPath -Raw
$ownedFiltersAbsent = @($capture.filters | Where-Object {
    $afterText.IndexOf(
        [string]$_, [StringComparison]::OrdinalIgnoreCase) -ge 0
}).Count -eq 0
$beforeInventoryPath = [string]$capture.filters_before
$inventoryRestored = $false
if (Test-Path -LiteralPath $beforeInventoryPath -PathType Leaf) {
    $beforeText = (Get-Content -LiteralPath `
        $beforeInventoryPath -Raw).Trim()
    $inventoryRestored = $beforeText -ceq $afterText.Trim()
} elseif (-not $ownedListed) {
    # A crash may occur after ACTIVE=PENDING but before the first read-only
    # inventory. With no owned filter present, cleanup has changed nothing.
    $inventoryRestored = $true
}
$etwAfter = @(& logman.exe query -ets PktMon 2>&1)
$etwSessionAbsent = $LASTEXITCODE -ne 0
if (-not $ownedFiltersAbsent -or -not $inventoryRestored -or
    -not $etwSessionAbsent) {
    throw 'PktMon no quedo exactamente restaurado.'
}

$binding = Get-NetAdapterBinding `
    -Name ([string]$session.interface_alias) `
    -ComponentID ms_tcpip6 -ErrorAction Stop
$bindingEnabled = [bool]$binding.Enabled
$ipv6Mode = [string](Get-I05CleanupIniValue -Path $preferencesPath `
    -Section 'Connection' -Key 'IPv6Mode')
$kadMask = [string](Get-I05CleanupIniValue -Path $preferencesPath `
    -Section 'Connection' -Key 'KadNetworkMask')
$kadEnabled = [string](Get-I05CleanupIniValue -Path $preferencesPath `
    -Section 'eMule' -Key 'NetworkKademlia')
if (-not $bindingEnabled -or $ipv6Mode -cne '0' -or
    $kadMask -cne '0' -or $kadEnabled -cne '0') {
    throw 'La restauracion altero IPv6 Windows o el perfil IPv4-only.'
}

$cleanup = [ordered]@{
    schema = 'ese.v91.i05.t1-cleanup/v1'
    case_id = 'V91-I05'
    status = 'CLEANUP_COMPLETE'
    nonce = $nonce
    created_at_utc = Get-LabUtcTimestamp
    candidate = [ordered]@{
        version = '9.1.0-rc.3'
        commit = '815b45ca7a1415bd3e06ff043d53794bc340b346'
        dirty = $false
        emule_sha256 = $expectedEmuleSha256
        ese_server_sha256 =
            'c12e71a1602bb7b55077b82a72000a6980790fdf75d90bdbcba8d2843f7a0ba2'
        build_info_sha256 =
            '48445ff0231908aa1edbb21970bcb38b91397c643c7012b65b62686bc8a63428'
        zip_sha256 = $expectedZipSha256
        zip_bytes = $expectedZipBytes
    }
    process = [ordered]@{
        registered_process_id = $processId
        executable_sha256 = $expectedEmuleSha256
        absent = $true
    }
    firewall = [ordered]@{
        peer_rule_name_sha256 = Get-LabStringSha256 -Value $peerName
        control_rule_name_sha256 =
            Get-LabStringSha256 -Value $controlName
        peer_rule_absent = $peerAbsent
        control_rule_absent = $controlAbsent
        isolation_rule_count = [int]$containment.rule_count
        isolation_rule_names_sha256 =
            [string]$containment.rule_names_sha256
        isolation_spec_sha256 = [string]$containment.spec_sha256
        isolation_spec_document_sha256 =
            [string]$containment.spec_document_sha256
        isolation_rules_absent = $containmentRulesAbsent
        isolation_inventory_after_sha256 =
            [string]$containmentAfter.sha256
        isolation_state_before_sha256 =
            [string]$containment.state_before_sha256
        isolation_state_after_sha256 =
            [string]$containmentAfter.state_sha256
        inventory_restored = $containmentInventoryRestored
    }
    capture = [ordered]@{
        stopped = $true
        owned_filters_absent = $ownedFiltersAbsent
        etw_session_absent = $etwSessionAbsent
        filter_inventory_restored = $inventoryRestored
        pcap_sha256 = if (Test-Path -LiteralPath `
                ([string]$capture.pcapng_path) -PathType Leaf) {
            Get-LabSha256 -Path ([string]$capture.pcapng_path)
        } else { $null }
        etl_sha256 = if (Test-Path -LiteralPath `
                ([string]$capture.etl_path) -PathType Leaf) {
            Get-LabSha256 -Path ([string]$capture.etl_path)
        } else { $null }
    }
    restoration = [ordered]@{
        ipv6_binding_enabled = $bindingEnabled
        ipv6_mode = [int]$ipv6Mode
        kad_network_mask = [int]$kadMask
        network_kademlia = [int]$kadEnabled
        evidence_preserved = $true
    }
    cleanup_complete = $true
}
$cleanupPath = Write-LabJson -Value $cleanup -Path (
    Join-Path $runRoot 'CLEANUP-V91-I05-T1.json')
Copy-Item -LiteralPath $cleanupPath -Destination (
    Join-Path $runRoot 'evidence\CLEANUP-V91-I05-T1.json') -Force
Copy-Item -LiteralPath $cleanupPath -Destination $latestCleanupPath -Force

if (Test-Path -LiteralPath $latestReadyPath -PathType Leaf) {
    Remove-Item -LiteralPath $latestReadyPath -Force -ErrorAction Stop
}
Remove-Item -LiteralPath $activePath -Force -ErrorAction Stop

Write-Host "V91-I05 H3 CLEANUP COMPLETE: $cleanupPath" `
    -ForegroundColor Green
[pscustomobject]@{
    status = 'CLEANUP_COMPLETE'
    path = $cleanupPath
    sha256 = Get-LabSha256 -Path $cleanupPath
}
