[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$expectedEmuleSha256 =
    '1FD7EEB62E9A93914644DC4FBD11E0C7AC37EE0A416EDF90F415EED7D9A7C105'
$payloadName = 'V91-C01-VANILLA-PAYLOAD.zip'
$layoutRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$kitRoot = if (
    (Test-Path -LiteralPath (Join-Path $PSScriptRoot $payloadName) `
        -PathType Leaf) -or
    (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'ACTIVE-C01.json') `
        -PathType Leaf)
) {
    [IO.Path]::GetFullPath($PSScriptRoot)
} else {
    $layoutRoot
}
$nodeRoot = Join-Path $kitRoot 'node'
$activePath = Join-Path $kitRoot 'ACTIVE-C01.json'
$readyPath = Join-Path $kitRoot 'READY-C01.json'

function Write-JsonUtf8 {
    param($Value, [string]$Path)
    [IO.File]::WriteAllText(
        $Path, ($Value | ConvertTo-Json -Depth 10),
        (New-Object Text.UTF8Encoding($false)))
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'El cleanup V91-C01 debe ejecutarse como administrador.'
    }
}

function Get-FullContainedPath {
    param([string]$Path, [string]$Root, [string]$Label)
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if (-not $full.StartsWith(
            $rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label queda fuera del kit."
    }
    return $full
}

Assert-Admin
if (-not (Test-Path -LiteralPath $activePath -PathType Leaf)) {
    throw 'No existe ACTIVE-C01.json; no hay Source C01 propio que limpiar.'
}
$active = Get-Content -LiteralPath $activePath -Raw | ConvertFrom-Json
if ($active.schema -ne 'ese.v91.c01-active-source/v1' -or
    $active.case_id -ne 'V91-C01' -or
    [string]$active.kit_nonce -notmatch '^[0-9a-f]{32}$') {
    throw 'ACTIVE-C01.json no es valido.'
}
$runRoot = Get-FullContainedPath -Path ([string]$active.run_root) `
    -Root (Join-Path $kitRoot 'runs') -Label 'RunRoot'
$sessionPath = Get-FullContainedPath -Path ([string]$active.session_path) `
    -Root $runRoot -Label 'Session'
if (-not (Test-Path -LiteralPath $sessionPath -PathType Leaf)) {
    throw 'Falta source-session-private.json.'
}
$session = Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json
if ($session.schema -ne 'ese.v91.c01-vanilla-source-session/v1' -or
    $session.case_id -ne 'V91-C01' -or
    $session.kit_nonce -ne $active.kit_nonce) {
    throw 'La sesion C01 no coincide con el marcador activo.'
}
$exe = Get-FullContainedPath -Path ([string]$session.source_executable) `
    -Root $nodeRoot -Label 'Vanilla executable'
if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne
    $expectedEmuleSha256) {
    throw 'El emule.exe remoto ya no coincide con el vanilla fijado.'
}

$stopped = $false
$alreadyStopped = $false
$process = Get-Process -Id ([int]$session.source_process_id) `
    -ErrorAction SilentlyContinue
if ($null -eq $process) {
    $alreadyStopped = $true
} else {
    if ([IO.Path]::GetFullPath($process.Path) -ne $exe) {
        throw 'El PID registrado ya no pertenece al emule.exe vanilla propio.'
    }
    Stop-Process -Id $process.Id -Force -ErrorAction Stop
    $null = $process.WaitForExit(10000)
    $stopped = $true
}

$ruleName = [string]$session.firewall_rule_name
if ($ruleName -ne [string]$active.firewall_rule_name -or
    $ruleName -ne "eSE-V91-C01-$($active.kit_nonce)") {
    throw 'La regla firewall no coincide con el nonce del kit.'
}
$rules = @(Get-NetFirewallRule -Name $ruleName `
    -ErrorAction SilentlyContinue)
if ($rules.Count -gt 1) {
    throw 'Hay mas de una regla firewall con el nonce C01.'
}
$firewallRemoved = $false
if ($rules.Count -eq 1) {
    $rule = $rules[0]
    if ([string]$rule.Direction -ne 'Inbound' -or
        [string]$rule.Action -ne 'Allow') {
        throw 'La regla firewall C01 no conserva Direction/Action esperados.'
    }
    $port = @(Get-NetFirewallPortFilter `
        -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $app = @(Get-NetFirewallApplicationFilter `
        -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $address = @(Get-NetFirewallAddressFilter `
        -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    if ($port.Count -ne 1 -or [string]$port[0].Protocol -ne 'TCP' -or
        [int]$port[0].LocalPort -ne 48712 -or
        $app.Count -ne 1 -or
        [IO.Path]::GetFullPath([string]$app[0].Program) -ne $exe -or
        $address.Count -ne 1 -or
        [string]$address[0].RemoteAddress -ne
            [string]$session.coordinator_tailscale_ipv4) {
        throw 'Los filtros firewall C01 no coinciden con la sesion propia.'
    }
    Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
    $firewallRemoved = $true
}

$cleanup = [ordered]@{
    schema = 'ese.v91.c01-source-cleanup/v1'
    case_id = 'V91-C01'
    kit_nonce = [string]$active.kit_nonce
    cleaned_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    verdict = 'PASS'
    process_stopped = $stopped
    process_already_stopped = $alreadyStopped
    firewall_removed = $firewallRemoved
    firewall_already_absent = -not $firewallRemoved
}
$cleanupPath = Join-Path $runRoot 'evidence\source-cleanup.json'
Write-JsonUtf8 -Value $cleanup -Path $cleanupPath

$evidenceZip = Join-Path $runRoot (
    "V91-C01-SOURCE-EVIDENCE-$($active.kit_nonce).zip")
$evidenceFiles = @(
    $sessionPath,
    (Join-Path $runRoot 'READY-C01.json'),
    (Join-Path $runRoot 'evidence\source-start-result.json'),
    $cleanupPath
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
if ($evidenceFiles.Count -lt 3) {
    throw 'No hay evidencia remota suficiente para empaquetar el cleanup.'
}
Compress-Archive -LiteralPath $evidenceFiles -DestinationPath $evidenceZip `
    -CompressionLevel Optimal
try {
    $tailscaleCommand = Get-Command tailscale.exe -ErrorAction Stop
    foreach ($artifact in $cleanupPath, $evidenceZip) {
        & $tailscaleCommand.Source file cp $artifact 'iaki-casa-1:' |
            Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Taildrop fallo para '$artifact'."
        }
    }
} catch {
    Write-Warning (
        'Cleanup local correcto, pero Taildrop de evidencia fallo: ' +
        $_.Exception.Message
    )
}

foreach ($relative in 'config', 'Temp', 'logs') {
    $target = Get-FullContainedPath -Path (Join-Path $nodeRoot $relative) `
        -Root $nodeRoot -Label "Generated $relative"
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
    }
}
Remove-Item -LiteralPath $activePath -Force -ErrorAction Stop
if (Test-Path -LiteralPath $readyPath) {
    Remove-Item -LiteralPath $readyPath -Force -ErrorAction Stop
}
$textPath = Join-Path $runRoot 'CLEANUP-C01-PASS.txt'
[IO.File]::WriteAllText(
    $textPath,
    "V91-C01 SOURCE CLEANUP PASS`r`nEvidence: $cleanupPath`r`n",
    (New-Object Text.UTF8Encoding($false)))
Write-Host "V91-C01 cleanup PASS: $cleanupPath" -ForegroundColor Green
Start-Process -FilePath notepad.exe -ArgumentList @($textPath) | Out-Null
