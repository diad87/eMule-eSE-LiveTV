[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EvidenceRoot
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptRoot 'common.ps1')
. (Join-Path $scriptRoot 't8_hyperv_common.ps1')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'T8 live Hyper-V test requires an elevated PowerShell session'
}

$evidencePath = [IO.Path]::GetFullPath($EvidenceRoot)
$evidenceLeaf = Split-Path -Leaf $evidencePath
if ($evidenceLeaf -notmatch '^eSE-v9\.2-f04-live-[0-9a-f]{12}$' -or
    (Test-Path -LiteralPath $evidencePath)) {
    throw (
        'EvidenceRoot must be a new directory named ' +
        'eSE-v9.2-f04-live-<12 hex>')
}
$null = New-Item -ItemType Directory -Path $evidencePath

$planPath = Join-Path $evidencePath 'plan.json'
$statePath = Join-Path $evidencePath 'state.json'
$resultPath = Join-Path $evidencePath 'live-result.json'
$orchestrator = Join-Path $scriptRoot 't8_hyperv.ps1'

function Get-T8LiveBaseline {
    $routes = @(Get-NetRoute -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric, InterfaceMetric)
    if ($routes.Count -ne 1) {
        throw 'T8 live test requires one unambiguous IPv4 default route'
    }
    $managementAdapter = Get-NetAdapter -InterfaceIndex `
        ([int]$routes[0].InterfaceIndex) -ErrorAction Stop
    return [pscustomobject][ordered]@{
        management_interface_index = [int]$routes[0].InterfaceIndex
        management_interface_guid = ConvertTo-T8GuidText `
            -Value ([string]$managementAdapter.InterfaceGuid)
        switches = @(Get-VMSwitch -ErrorAction Stop | ForEach-Object {
            '{0}|{1}|{2}' -f $_.Name, $_.Id, $_.SwitchType
        } | Sort-Object)
        nats = @(Get-NetNat -ErrorAction Stop | ForEach-Object {
            '{0}|{1}' -f $_.Name, $_.InternalIPInterfaceAddressPrefix
        } | Sort-Object)
    }
}

function Assert-T8BaselineEquivalent {
    param(
        [Parameter(Mandatory = $true)][object]$Before,
        [Parameter(Mandatory = $true)][object]$After
    )
    if ($Before.management_interface_index -ne
            $After.management_interface_index -or
        $Before.management_interface_guid -ne
            $After.management_interface_guid -or
        (@($Before.switches) -join "`n") -cne
            (@($After.switches) -join "`n") -or
        (@($Before.nats) -join "`n") -cne
            (@($After.nats) -join "`n")) {
        throw 'T8 live teardown did not restore the captured baseline'
    }
}

$before = Get-T8LiveBaseline
$planResult = $null
$applyResult = $null
$teardownResult = $null
$liveFailure = $null

try {
    $planText = @(& $orchestrator -RunLabel 'v92-f04-live' `
        -PlanPath $planPath) -join [Environment]::NewLine
    $planResult = $planText | ConvertFrom-Json
    if ([string]$planResult.verdict -ne 'PASS' -or
        [bool]$planResult.mutation_performed) {
        throw 'T8 live planning did not remain read-only'
    }
    $plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
    $null = Assert-T8PlanShape -Plan $plan
    if ([int]$plan.baseline.management_interface_index -ne
            $before.management_interface_index -or
        [string]$plan.baseline.management_interface_guid -ne
            $before.management_interface_guid) {
        throw 'T8 live plan captured the wrong management route'
    }

    $applyText = @(& $orchestrator -Apply `
        -ExistingPlanPath $planPath `
        -ExpectedPlanHash ([string]$planResult.plan_hash) `
        -StatePath $statePath) -join [Environment]::NewLine
    $applyResult = $applyText | ConvertFrom-Json
    if ([string]$applyResult.verdict -ne 'PASS') {
        throw 'T8 live apply did not return PASS'
    }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $null = Assert-T8StateShape -State $state
    if ([string]$state.phase -ne 'APPLIED') {
        throw 'T8 live state is not APPLIED'
    }
    $switch = @(Get-VMSwitch -Name `
        ([string]$plan.resources.switch_name) -ErrorAction Stop)
    $nat = @(Get-NetNat -Name ([string]$plan.resources.nat_name) `
        -ErrorAction Stop)
    $address = @(Get-NetIPAddress -InterfaceIndex `
        ([int]$state.resources.interface_index) -AddressFamily IPv4 `
        -IPAddress ([string]$plan.resources.gateway_address) `
        -ErrorAction Stop)
    if ($switch.Count -ne 1 -or $nat.Count -ne 1 -or
        $address.Count -ne 1 -or
        [string]$switch[0].Id -ne [string]$state.resources.switch_id -or
        [string]$nat[0].InternalIPInterfaceAddressPrefix -ne
            [string]$plan.resources.prefix) {
        throw 'T8 live resources do not match the immutable plan/state'
    }
} catch {
    $liveFailure = $_
} finally {
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        try {
            $planForTeardown = Get-Content -LiteralPath $planPath -Raw |
                ConvertFrom-Json
            $planHash = Get-T8PlanHash -Plan $planForTeardown
            $teardownText = @(& $orchestrator -Teardown `
                -ExistingPlanPath $planPath `
                -ExpectedPlanHash $planHash -StatePath $statePath) -join `
                [Environment]::NewLine
            $teardownResult = $teardownText | ConvertFrom-Json
        } catch {
            if ($null -eq $liveFailure) {
                $liveFailure = $_
            } else {
                $liveFailure = New-Object Management.Automation.ErrorRecord(
                    (New-Object InvalidOperationException(
                        ($liveFailure.Exception.Message +
                         '; teardown: ' + $_.Exception.Message))),
                    'T8LiveAndTeardownFailure',
                    [Management.Automation.ErrorCategory]::InvalidResult,
                    $null)
            }
        }
    }
}

$after = Get-T8LiveBaseline
Assert-T8BaselineEquivalent -Before $before -After $after
if ($null -ne $liveFailure) {
    $failure = [pscustomobject][ordered]@{
        schema = 'ese.v92.t8-hyperv-live-test/v1'
        verdict = 'FAIL'
        tested_at_utc = Get-LabUtcTimestamp
        plan_id = if ($null -eq $planResult) {
            $null
        } else {
            $planResult.plan_id
        }
        plan_hash = if ($null -eq $planResult) {
            $null
        } else {
            $planResult.plan_hash
        }
        state_created = Test-Path -LiteralPath $statePath -PathType Leaf
        baseline_restored = $true
        error = Protect-LabText -Value $liveFailure.Exception.Message `
            -RedactAddresses
    }
    $null = Write-LabJson -Value $failure -Path $resultPath -Depth 8
    throw $liveFailure
}
if ([string]$teardownResult.verdict -ne 'PASS' -or
    [string]$teardownResult.phase -ne 'TORN_DOWN') {
    throw 'T8 live teardown did not return a TORN_DOWN PASS'
}

$result = [pscustomobject][ordered]@{
    schema = 'ese.v92.t8-hyperv-live-test/v1'
    verdict = 'PASS'
    tested_at_utc = Get-LabUtcTimestamp
    plan_id = $planResult.plan_id
    plan_hash = $planResult.plan_hash
    management_route_preserved = $true
    baseline_switches_restored = $true
    baseline_nats_restored = $true
    final_phase = $teardownResult.phase
}
$null = Write-LabJson -Value $result -Path $resultPath -Depth 8
$result | ConvertTo-Json -Depth 8
