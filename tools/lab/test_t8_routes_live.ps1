[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [string]$NodePath = 'node.exe'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptRoot 'common.ps1')
. (Join-Path $scriptRoot 't8_hyperv_common.ps1')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'T8 route live test requires an elevated PowerShell session'
}

$nodeExecutable = (Get-Command $NodePath -ErrorAction Stop).Source
$evidencePath = [IO.Path]::GetFullPath($EvidenceRoot)
$evidenceLeaf = Split-Path -Leaf $evidencePath
if ($evidenceLeaf -notmatch '^eSE-v9\.2-f05-live-[0-9a-f]{12}$' -or
    (Test-Path -LiteralPath $evidencePath)) {
    throw (
        'EvidenceRoot must be a new directory named ' +
        'eSE-v9.2-f05-live-<12 hex>')
}
$null = New-Item -ItemType Directory -Path $evidencePath

$planPath = Join-Path $evidencePath 'plan.json'
$statePath = Join-Path $evidencePath 'state.json'
$resultPath = Join-Path $evidencePath 'live-result.json'
$orchestrator = Join-Path $scriptRoot 't8_hyperv.ps1'
$routeProbe = Join-Path $scriptRoot 'nat_gateway\t8_route_probe.js'
$routeAssert = Join-Path $scriptRoot 'assert_data_route.ps1'
$proxyNames = @(
    'ALL_PROXY', 'HTTPS_PROXY', 'HTTP_PROXY',
    'all_proxy', 'https_proxy', 'http_proxy'
)

function Get-F05Baseline {
    $routes = @(Get-NetRoute -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric, InterfaceMetric)
    if ($routes.Count -ne 1) {
        throw 'F05 requires one unambiguous IPv4 default route'
    }
    $managementAdapter = Get-NetAdapter -InterfaceIndex `
        ([int]$routes[0].InterfaceIndex) -ErrorAction Stop
    $addresses = @(Get-NetIPAddress -InterfaceIndex `
        ([int]$routes[0].InterfaceIndex) -AddressFamily IPv4 `
        -ErrorAction Stop | Where-Object {
            [string]$_.AddressState -eq 'Preferred' -and
            (Get-LabAddressClass -Address ([string]$_.IPAddress)) -in @(
                'private-v4', 'cgnat-v4', 'global-v4'
            )
        })
    if ($addresses.Count -lt 1) {
        throw 'F05 management adapter has no usable preferred IPv4 address'
    }
    return [pscustomobject][ordered]@{
        management_interface_index = [int]$routes[0].InterfaceIndex
        management_interface_guid = ConvertTo-T8GuidText `
            -Value ([string]$managementAdapter.InterfaceGuid)
        management_address = [string]$addresses[0].IPAddress
        switches = @(Get-VMSwitch -ErrorAction Stop | ForEach-Object {
            '{0}|{1}|{2}' -f $_.Name, $_.Id, $_.SwitchType
        } | Sort-Object)
        nats = @(Get-NetNat -ErrorAction Stop | ForEach-Object {
            '{0}|{1}' -f $_.Name, $_.InternalIPInterfaceAddressPrefix
        } | Sort-Object)
    }
}

function Assert-F05BaselineEquivalent {
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
        throw 'F05 teardown did not restore the captured baseline'
    }
}

function Wait-F05PreferredAddress {
    param(
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$Address,
        [ValidateRange(1, 30)][int]$TimeoutSeconds = 15
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $items = @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex `
            -AddressFamily IPv4 -IPAddress $Address `
            -ErrorAction SilentlyContinue)
        if ($items.Count -eq 1 -and
            [string]$items[0].AddressState -eq 'Preferred') {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'F05 T8 address did not reach Preferred state before timeout'
}

function Assert-F05NatPmpPortAvailable {
    $endpoints = @(Get-NetUDPEndpoint -LocalPort 5351 `
        -ErrorAction SilentlyContinue)
    if ($endpoints.Count -gt 0) {
        throw 'F05 NAT-PMP port 5351 is already in use'
    }
}

function Invoke-F05MapperProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$GatewayAddress,
        [Parameter(Mandatory = $true)][string]$ClientAddress,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    $saved = @{}
    foreach ($name in $proxyNames) {
        $saved[$name] = [Environment]::GetEnvironmentVariable(
            $name, 'Process')
        if ($Mode -eq 'baseline') {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        } else {
            [Environment]::SetEnvironmentVariable(
                $name, 'http://127.0.0.1:9', 'Process')
        }
    }
    try {
        $output = @(& $nodeExecutable $routeProbe `
            "--gateway=$GatewayAddress" "--client=$ClientAddress" `
            "--mode=$Mode") -join [Environment]::NewLine
        if ($LASTEXITCODE -ne 0) {
            throw "F05 mapper probe failed in mode $Mode`: $output"
        }
        $result = $output | ConvertFrom-Json
        if ([string]$result.verdict -ne 'PASS') {
            throw "F05 mapper probe returned non-PASS in mode $Mode"
        }
        $null = Write-LabJson -Value $result -Path $OutFile -Depth 12
        return $result
    } finally {
        foreach ($name in $proxyNames) {
            [Environment]::SetEnvironmentVariable(
                $name, $saved[$name], 'Process')
        }
    }
}

function Invoke-F05DataRoute {
    param(
        [Parameter(Mandatory = $true)][string]$GatewayAddress,
        [Parameter(Mandatory = $true)][string]$ClientAddress,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    $listener = $null
    $client = $null
    $accepted = $null
    $saved = @{}
    foreach ($name in $proxyNames) {
        $saved[$name] = [Environment]::GetEnvironmentVariable(
            $name, 'Process')
        [Environment]::SetEnvironmentVariable(
            $name,
            $(if ($Mode -eq 'baseline') {
                $null
            } else {
                'http://127.0.0.1:9'
            }),
            'Process')
    }
    try {
        $gatewayIp = [Net.IPAddress]::Parse($GatewayAddress)
        $clientIp = [Net.IPAddress]::Parse($ClientAddress)
        $listener = New-Object Net.Sockets.TcpListener($gatewayIp, 0)
        $listener.Start()
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $client = New-Object Net.Sockets.TcpClient(
            [Net.Sockets.AddressFamily]::InterNetwork)
        $client.Client.Bind((New-Object Net.IPEndPoint($clientIp, 0)))
        $connect = $client.ConnectAsync($gatewayIp, $port)
        $accepted = $listener.AcceptTcpClient()
        $connect.Wait()
        & $routeAssert -TargetProcessId $PID `
            -ExpectedRemoteAddress $GatewayAddress `
            -ExpectedRemotePort $port `
            -RequiredFamily IPv4 `
            -ForbiddenInterfacePattern '(?i)Tailscale' `
            -OutFile $OutFile
        return Get-Content -LiteralPath $OutFile -Raw | ConvertFrom-Json
    } finally {
        foreach ($name in $proxyNames) {
            [Environment]::SetEnvironmentVariable(
                $name, $saved[$name], 'Process')
        }
        if ($null -ne $accepted) { $accepted.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
        if ($null -ne $listener) { $listener.Stop() }
    }
}

$before = Get-F05Baseline
$planResult = $null
$plan = $null
$state = $null
$probeAddress = $null
$probeAddressCreated = $false
$failure = $null
$baselineMapper = $null
$perturbedMapper = $null
$baselineData = $null
$perturbedData = $null

try {
    Assert-F05NatPmpPortAvailable
    $planText = @(& $orchestrator -RunLabel 'v92-f05-live' `
        -PlanPath $planPath) -join [Environment]::NewLine
    $planResult = $planText | ConvertFrom-Json
    $plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
    $applyText = @(& $orchestrator -Apply `
        -ExistingPlanPath $planPath `
        -ExpectedPlanHash ([string]$planResult.plan_hash) `
        -StatePath $statePath) -join [Environment]::NewLine
    $applyResult = $applyText | ConvertFrom-Json
    if ([string]$applyResult.verdict -ne 'PASS') {
        throw 'F05 Hyper-V apply did not return PASS'
    }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $null = Assert-T8StateShape -State $state
    $gatewayParts = ([string]$plan.resources.gateway_address).Split('.')
    $probeAddress = '{0}.{1}.{2}.2' -f
        $gatewayParts[0], $gatewayParts[1], $gatewayParts[2]
    $existingProbe = @(Get-NetIPAddress -AddressFamily IPv4 `
        -IPAddress $probeAddress -ErrorAction SilentlyContinue)
    if ($existingProbe.Count -gt 0) {
        throw 'F05 probe address unexpectedly exists before creation'
    }
    $null = New-NetIPAddress -InterfaceIndex `
        ([int]$state.resources.interface_index) -IPAddress $probeAddress `
        -PrefixLength 24 -AddressFamily IPv4 -SkipAsSource $false `
        -ErrorAction Stop
    $probeAddressCreated = $true
    Wait-F05PreferredAddress -InterfaceIndex `
        ([int]$state.resources.interface_index) `
        -Address ([string]$plan.resources.gateway_address)
    Wait-F05PreferredAddress -InterfaceIndex `
        ([int]$state.resources.interface_index) -Address $probeAddress
    Assert-F05NatPmpPortAvailable

    $baselineMapper = Invoke-F05MapperProbe -Mode 'baseline' `
        -GatewayAddress ([string]$plan.resources.gateway_address) `
        -ClientAddress $probeAddress `
        -OutFile (Join-Path $evidencePath 'mapper-baseline.json')
    $perturbedMapper = Invoke-F05MapperProbe `
        -Mode 'dns-proxy-perturbed' `
        -GatewayAddress ([string]$plan.resources.gateway_address) `
        -ClientAddress $probeAddress `
        -OutFile (Join-Path $evidencePath 'mapper-perturbed.json')

    $baselineData = Invoke-F05DataRoute `
        -GatewayAddress ([string]$plan.resources.gateway_address) `
        -ClientAddress $probeAddress -Mode 'baseline' `
        -OutFile (Join-Path $evidencePath 'data-baseline.json')
    $perturbedData = Invoke-F05DataRoute `
        -GatewayAddress ([string]$plan.resources.gateway_address) `
        -ClientAddress $probeAddress -Mode 'dns-proxy-perturbed' `
        -OutFile (Join-Path $evidencePath 'data-perturbed.json')

    $baselineMapperCore = $baselineMapper.mapper |
        ConvertTo-Json -Depth 8 -Compress
    $perturbedMapperCore = $perturbedMapper.mapper |
        ConvertTo-Json -Depth 8 -Compress
    $baselineConnection = @($baselineData.matching_connections)
    $perturbedConnection = @($perturbedData.matching_connections)
    $fixtureAdapter = Get-NetAdapter -InterfaceIndex `
        ([int]$state.resources.interface_index) -ErrorAction Stop
    $expectedInterfaceId = Get-LabInterfaceId `
        -Id ([string]$fixtureAdapter.InterfaceGuid) `
        -Name ([string]$fixtureAdapter.Name) `
        -Description ([string]$fixtureAdapter.InterfaceDescription)
    if ($baselineMapperCore -cne $perturbedMapperCore -or
        $baselineMapper.environment.dns_hostname_lookup_count -ne 0 -or
        $perturbedMapper.environment.dns_hostname_lookup_count -ne 0 -or
        @($baselineMapper.environment.proxy_environment_names_set).Count `
            -ne 0 -or
        @($perturbedMapper.environment.proxy_environment_names_set).Count `
            -ne 6 -or
        [string]$baselineData.verdict -ne 'PASS' -or
        [string]$perturbedData.verdict -ne 'PASS' -or
        $baselineConnection.Count -ne 1 -or
        $perturbedConnection.Count -ne 1 -or
        [bool]$baselineConnection[0].interface_forbidden -or
        [bool]$perturbedConnection[0].interface_forbidden -or
        [string]$baselineConnection[0].interface_id -ne
            $expectedInterfaceId -or
        [string]$perturbedConnection[0].interface_id -ne
            $expectedInterfaceId -or
        [string]$baselineConnection[0].interface_id -ne
            [string]$perturbedConnection[0].interface_id) {
        throw 'F05 route/DNS/proxy equivalence assertion failed'
    }
} catch {
    $failure = $_
} finally {
    if ($probeAddressCreated -and $null -ne $state) {
        try {
            $adapter = Get-NetAdapter -InterfaceIndex `
                ([int]$state.resources.interface_index) -ErrorAction Stop
            if ((ConvertTo-T8GuidText -Value (
                    [string]$adapter.InterfaceGuid)) -ne
                    [string]$state.resources.interface_guid -or
                [int]$adapter.InterfaceIndex -eq
                    $before.management_interface_index) {
                throw 'F05 probe adapter identity changed before cleanup'
            }
            Remove-NetIPAddress -InterfaceIndex `
                ([int]$state.resources.interface_index) `
                -IPAddress $probeAddress -Confirm:$false -ErrorAction Stop
            $probeAddressCreated = $false
        } catch {
            if ($null -eq $failure) { $failure = $_ }
        }
    }
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        try {
            $planForTeardown = Get-Content -LiteralPath $planPath -Raw |
                ConvertFrom-Json
            $null = & $orchestrator -Teardown `
                -ExistingPlanPath $planPath `
                -ExpectedPlanHash (Get-T8PlanHash -Plan $planForTeardown) `
                -StatePath $statePath
        } catch {
            if ($null -eq $failure) { $failure = $_ }
        }
    }
}

$after = Get-F05Baseline
Assert-F05BaselineEquivalent -Before $before -After $after
if ($probeAddressCreated) {
    throw 'F05 probe address remains after cleanup'
}
if ($null -ne $failure) {
    $failedResult = [pscustomobject][ordered]@{
        schema = 'ese.v92.t8-route-live-test/v1'
        verdict = 'FAIL'
        tested_at_utc = Get-LabUtcTimestamp
        baseline_restored = $true
        error = Protect-LabText -Value $failure.Exception.Message `
            -RedactAddresses
    }
    $null = Write-LabJson -Value $failedResult -Path $resultPath -Depth 8
    throw $failure
}

$finalState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$result = [pscustomobject][ordered]@{
    schema = 'ese.v92.t8-route-live-test/v1'
    verdict = 'PASS'
    tested_at_utc = Get-LabUtcTimestamp
    plan_id = $planResult.plan_id
    mapper_reached_t8_gateway = $true
    data_avoided_tailscale = $true
    dns_proxy_neutral = $true
    mapper_interface_id = $expectedInterfaceId
    data_interface_id =
        $baselineData.matching_connections[0].interface_id
    baseline_restored = $true
    final_phase = $finalState.phase
}
$null = Write-LabJson -Value $result -Path $resultPath -Depth 8
$result | ConvertTo-Json -Depth 8
