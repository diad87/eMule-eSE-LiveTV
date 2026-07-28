[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptRoot 't8_hyperv_common.ps1')

function Assert-T8Test {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) { throw "T8 Hyper-V test failed: $Message" }
}

$nonce = '0123456789ab'
$names = Get-T8UniqueNames -RunLabel 'fixture-a' -Nonce $nonce
Assert-T8Test -Condition (
    $names.switch -match '^ese-v92-t8-sw-[0-9a-f]{6}-[0-9a-f]{12}$') `
    -Message 'switch name is not unique and namespaced'
Assert-T8Test -Condition (
    $names.nat -match '^ese-v92-t8-nat-[0-9a-f]{6}-[0-9a-f]{12}$') `
    -Message 'NAT name is not unique and namespaced'
Assert-T8Test -Condition (
    (Get-T8UniqueNames -RunLabel 'fixture-a' -Nonce $nonce).switch -eq
        $names.switch) -Message 'name derivation is not deterministic'
Assert-T8Test -Condition (
    (Get-T8UniqueNames -RunLabel 'fixture-b' -Nonce $nonce).switch -ne
        $names.switch) -Message 'run label is absent from resource identity'

Assert-T8Test -Condition (
    Test-T8PrefixOverlap -Left '172.20.4.0/24' -Right '172.20.0.0/16') `
    -Message 'contained prefix overlap was missed'
Assert-T8Test -Condition (
    -not (Test-T8PrefixOverlap -Left '172.20.4.0/24' `
        -Right '172.21.4.0/24')) `
    -Message 'disjoint prefixes were reported as overlapping'

$firstPrefix = Select-T8PrivatePrefix -Nonce $nonce
$secondPrefix = Select-T8PrivatePrefix -Nonce $nonce `
    -UsedPrefixes @($firstPrefix)
Assert-T8Test -Condition ($firstPrefix -ne $secondPrefix) `
    -Message 'prefix collision was not avoided'
Assert-T8Test -Condition (
    -not (Test-T8PrefixOverlap -Left $firstPrefix -Right $secondPrefix)) `
    -Message 'selected prefixes overlap'

$plan = New-T8HyperVPlan -RunLabel 'fixture-a' -Nonce $nonce `
    -ManagementInterfaceIndex 7 `
    -ManagementInterfaceGuid '01234567-89ab-cdef-0123-456789abcdef' `
    -UsedPrefixes @('10.0.0.0/8') `
    -ExistingSwitchNames @('Default Switch') -ExistingNatNames @() `
    -AdapterInventory @([pscustomobject]@{
        interface_index = 7
        interface_guid = '01234567-89ab-cdef-0123-456789abcdef'
    }) `
    -RouteInventory @([pscustomobject]@{
        destination_prefix = '0.0.0.0/0'
        interface_index = 7
    }) `
    -HostFingerprint 'host-fixture'
Assert-T8Test -Condition (Assert-T8PlanShape -Plan $plan) `
    -Message 'valid plan was rejected'
Assert-T8Test -Condition (
    $plan.safety.mutation_model -eq 'additive-only') `
    -Message 'plan is not additive-only'
Assert-T8Test -Condition (
    $plan.baseline.management_interface_index -eq 7) `
    -Message 'management route was not pinned'
Assert-T8Test -Condition (
    $plan.resources.switch_type -eq 'Internal') `
    -Message 'plan does not use an Internal switch'
Assert-T8Test -Condition (
    $plan.resources.gateway_address -eq
        (Get-T8GatewayAddress -Prefix $plan.resources.prefix)) `
    -Message 'gateway/prefix mismatch'
Assert-T8Test -Condition (
    (Get-T8PlanHash -Plan $plan) -match '^[0-9a-f]{64}$') `
    -Message 'plan hash is invalid'
$roundTrippedPlan = $plan | ConvertTo-Json -Depth 16 | ConvertFrom-Json
Assert-T8Test -Condition (
    (Get-T8PlanHash -Plan $roundTrippedPlan) -ceq
        (Get-T8PlanHash -Plan $plan)) `
    -Message 'plan hash is not stable across JSON persistence'

$collisionRefused = $false
try {
    $null = New-T8HyperVPlan -RunLabel 'fixture-a' -Nonce $nonce `
        -ManagementInterfaceIndex 7 `
        -ManagementInterfaceGuid '01234567-89ab-cdef-0123-456789abcdef' `
        -UsedPrefixes @() `
        -ExistingSwitchNames @($names.switch) -ExistingNatNames @() `
        -HostFingerprint 'host-fixture'
} catch {
    $collisionRefused = $true
}
Assert-T8Test -Condition $collisionRefused `
    -Message 'existing resource name collision was accepted'

$tampered = $plan | ConvertTo-Json -Depth 16 | ConvertFrom-Json
$tampered.resources.switch_name = 'Default Switch'
$tamperRefused = $false
try {
    $null = Assert-T8PlanShape -Plan $tampered
} catch {
    $tamperRefused = $true
}
Assert-T8Test -Condition $tamperRefused `
    -Message 'tampered generic switch name was accepted'

$unsafe = $plan | ConvertTo-Json -Depth 16 | ConvertFrom-Json
$unsafe.safety.management_route_preserved = $false
$unsafeRefused = $false
try {
    $null = Assert-T8PlanShape -Plan $unsafe
} catch {
    $unsafeRefused = $true
}
Assert-T8Test -Condition $unsafeRefused `
    -Message 'unsafe management-route plan was accepted'

$stringGate = $plan | ConvertTo-Json -Depth 16 | ConvertFrom-Json
$stringGate.safety.teardown_prepared = 'false'
$stringGateRefused = $false
try {
    $null = Assert-T8PlanShape -Plan $stringGate
} catch {
    $stringGateRefused = $true
}
Assert-T8Test -Condition $stringGateRefused `
    -Message 'string-valued safety gate was accepted as true'

$validState = [pscustomobject][ordered]@{
    schema = 'ese.v92.t8-hyperv-state/v1'
    plan_id = $plan.plan_id
    plan_hash = Get-T8PlanHash -Plan $plan
    phase = 'ADDRESS_CREATED'
    prepared_at_utc = '2026-07-28T00:00:00.000Z'
    baseline_management_interface_index = 7
    created = [pscustomobject][ordered]@{
        switch = $true
        gateway_address = $true
        nat = $false
    }
    resources = [pscustomobject][ordered]@{
        switch_id = '12345678-1234-1234-1234-123456789abc'
        interface_index = 42
        interface_guid = 'abcdef01-2345-6789-abcd-ef0123456789'
        vm_adapter_device_id = 'abcdef01-2345-6789-abcd-ef0123456789'
    }
}
Assert-T8Test -Condition (Assert-T8StateShape -State $validState) `
    -Message 'valid state shape was rejected'
$tamperedState = $validState | ConvertTo-Json -Depth 16 | ConvertFrom-Json
$tamperedState.resources.vm_adapter_device_id =
    '00000000-1111-2222-3333-444444444444'
$tamperedStateRefused = $false
try {
    $null = Assert-T8StateShape -State $tamperedState
} catch {
    $tamperedStateRefused = $true
}
Assert-T8Test -Condition $tamperedStateRefused `
    -Message 'inconsistent switch adapter binding was accepted'

$badPhaseState = $validState | ConvertTo-Json -Depth 16 | ConvertFrom-Json
$badPhaseState.phase = 'APPLIED'
$badPhaseRefused = $false
try {
    $null = Assert-T8StateShape -State $badPhaseState
} catch {
    $badPhaseRefused = $true
}
Assert-T8Test -Condition $badPhaseRefused `
    -Message 'inconsistent phase/created flags were accepted'

$teardownState = $validState | ConvertTo-Json -Depth 16 | ConvertFrom-Json
$teardownState.phase = 'TEARDOWN_NAT_REMOVED'
Assert-T8Test -Condition (Assert-T8StateShape -State $teardownState) `
    -Message 'valid interrupted-teardown state was rejected'

Write-Host 'T8 Hyper-V pure plan tests PASS' -ForegroundColor Green
