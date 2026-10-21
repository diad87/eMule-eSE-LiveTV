<#
.SYNOPSIS
    Drives and evaluates HG07: physical path plus LAN -> hotspot -> LAN.

.DESCRIPTION
    Capture mode records one phase of the network change. Run it three times:

      -Phase baseline    on the original LAN, while data is flowing
      -Phase hotspot     after switching to the alternate path
      -Phase restored    after returning to the LAN

    Summary mode compares the captured phases and decides whether the change
    actually invalidated the previous evidence and produced a new generation.

    The data-route assertion is delegated to ..\assert_data_route.ps1, which
    refuses Tailscale as the measured path. Tailscale may administer the hosts;
    it may not carry the data used as proof.

    Emits 'ese.lab.route-change-phase/v1' and 'ese.lab.route-change/v1'.
#>
[CmdletBinding(DefaultParameterSetName = 'Capture')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Capture')]
    [ValidateSet('baseline', 'hotspot', 'restored')]
    [string]$Phase,

    [Parameter(Mandatory = $true)][string]$RunDirectory,

    [Parameter(ParameterSetName = 'Capture')][int]$TargetProcessId = 0,
    [Parameter(ParameterSetName = 'Capture')][string]$ExpectedRemoteAddress = '',
    [Parameter(ParameterSetName = 'Capture')][ValidateRange(0, 65535)][int]$ExpectedRemotePort = 0,
    [Parameter(ParameterSetName = 'Capture')][ValidateSet('Any', 'IPv4', 'IPv6')][string]$RequiredFamily = 'Any',
    [Parameter(ParameterSetName = 'Capture')][string]$BaseUrl = 'http://127.0.0.1:4711',
    [Parameter(ParameterSetName = 'Capture')][string]$Token = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'Summary')][switch]$Summarize,

    [string]$Commit = '',
    [switch]$IncludeSensitive
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\common.ps1')

$runRoot = Get-LabFullPath -Path $RunDirectory
$phaseDirectory = Join-Path $runRoot 'hg07'
$null = New-LabDirectory -Path $phaseDirectory

function Get-PhaseFilePath {
    param([string]$PhaseName)
    return (Join-Path $phaseDirectory ('phase-{0}.json' -f $PhaseName))
}

if ($PSCmdlet.ParameterSetName -eq 'Capture') {

    $phasePath = Get-PhaseFilePath -PhaseName $Phase
    if (Test-Path -LiteralPath $phasePath) {
        throw "Phase '$Phase' already captured at $phasePath; refusing to overwrite evidence"
    }

    # Route assertion is optional at capture time so the operator can record a
    # phase even when the transfer is momentarily down (which is itself the
    # expected state right after a network switch).
    $routeAssertion = $null
    $routeError = ''
    if ($TargetProcessId -gt 0) {
        $routeOut = Join-Path $phaseDirectory ('route-{0}.json' -f $Phase)
        try {
            & (Join-Path $PSScriptRoot '..\assert_data_route.ps1') `
                -TargetProcessId $TargetProcessId `
                -ExpectedRemoteAddress $ExpectedRemoteAddress `
                -ExpectedRemotePort $ExpectedRemotePort `
                -RequiredFamily $RequiredFamily `
                -OutFile $routeOut `
                -IncludeSensitive:$IncludeSensitive | Out-Null
            $routeAssertion = Get-Content -LiteralPath $routeOut -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            $routeError = $_.Exception.Message
        }
    }

    $reachOut = Join-Path $phaseDirectory ('reach-{0}.json' -f $Phase)
    & (Join-Path $PSScriptRoot 'reach_probe.ps1') `
        -NodeRole A -BaseUrl $BaseUrl -Token $Token -Label ("hg07-$Phase") `
        -Commit $Commit -OutFile $reachOut -IncludeSensitive:$IncludeSensitive | Out-Null
    $reach = Get-Content -LiteralPath $reachOut -Raw -Encoding UTF8 | ConvertFrom-Json

    $capture = [ordered]@{
        schema            = 'ese.lab.route-change-phase/v1'
        captured_at_utc   = Get-LabUtcTimestamp
        phase             = $Phase
        commit            = $Commit
        network_interfaces = @(Get-LabNetworkInventory -IncludeSensitive:$IncludeSensitive)
        routes            = @(Get-LabRouteInventory -IncludeSensitive:$IncludeSensitive)
        route_assertion   = $routeAssertion
        route_error       = $routeError
        reach_probe       = $reach
    }

    $safeCapture = ConvertTo-LabSanitizedValue -InputObject $capture `
        -RedactAddresses:(-not $IncludeSensitive)
    $writtenPath = Write-LabJson -Value $safeCapture -Path $phasePath
    Write-Host "HG07 phase '$Phase' captured: $writtenPath" -ForegroundColor Green
    if ($routeError) {
        Write-Host "  route assertion not recorded: $routeError" -ForegroundColor Yellow
    }
    return
}

# ---- Summary ----------------------------------------------------------------

$phases = @('baseline', 'hotspot', 'restored')
$loaded = [ordered]@{}
$findings = New-Object System.Collections.ArrayList

foreach ($name in $phases) {
    $path = Get-PhaseFilePath -PhaseName $name
    if (-not (Test-Path -LiteralPath $path)) {
        $null = $findings.Add("phase '$name' was never captured")
        continue
    }
    $loaded[$name] = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Get-PhaseGeneration {
    param([object]$PhaseObject)
    if ($null -eq $PhaseObject) { return $null }
    $probe = $PhaseObject.reach_probe
    if ($null -eq $probe) { return $null }
    if ($null -eq $probe.reach) { return $null }
    $names = @($probe.reach.PSObject.Properties.Name)
    foreach ($candidate in @('topology_generation', 'generation')) {
        if ($names -contains $candidate) { return [string]$probe.reach.$candidate }
    }
    return $null
}

$generations = [ordered]@{}
foreach ($name in $phases) {
    if ($loaded.Contains($name)) {
        $generations[$name] = Get-PhaseGeneration -PhaseObject $loaded[$name]
    } else {
        $generations[$name] = $null
    }
}

$generationObservable = $true
foreach ($name in $phases) {
    if ($null -eq $generations[$name]) { $generationObservable = $false }
}

if (-not $generationObservable) {
    $null = $findings.Add(
        'topology generation is not observable; HG07 invalidation cannot be evidenced ' +
        'until the reachability endpoint exists')
} else {
    if ($generations['baseline'] -eq $generations['hotspot']) {
        $null = $findings.Add(
            'generation did not change across the LAN -> hotspot switch; a real ' +
            'topology change must produce exactly one increment')
    }
    if ($generations['hotspot'] -eq $generations['restored']) {
        $null = $findings.Add(
            'generation did not change on returning to the LAN')
    }
}

# The overlay prohibition is the one HG07 half that is fully testable today.
$dataOutsideOverlay = $null
foreach ($name in $phases) {
    if (-not $loaded.Contains($name)) { continue }
    $assertion = $loaded[$name].route_assertion
    if ($null -eq $assertion) { continue }
    $names = @($assertion.PSObject.Properties.Name)
    if ($names -contains 'verdict') {
        if ([string]$assertion.verdict -ne 'PASS') {
            $null = $findings.Add("phase '$name' route assertion verdict is $($assertion.verdict)")
            $dataOutsideOverlay = $false
        } elseif ($null -eq $dataOutsideOverlay) {
            $dataOutsideOverlay = $true
        }
    }
}
if ($null -eq $dataOutsideOverlay) {
    $null = $findings.Add('no route assertion was recorded in any phase; the ' +
        'data-outside-overlay requirement is unproven')
}

$verdict = 'PASS'
if ($findings.Count -gt 0) { $verdict = 'BLOCKED' }

$summary = [ordered]@{
    schema                = 'ese.lab.route-change/v1'
    case                  = 'HG07'
    generated_at_utc      = Get-LabUtcTimestamp
    commit                = $Commit
    verdict               = $verdict
    phases_captured       = @($loaded.Keys)
    generations           = $generations
    generation_observable = $generationObservable
    data_outside_overlay  = $dataOutsideOverlay
    findings              = @($findings)
}

$outPath = Join-Path $phaseDirectory 'hg07-summary.json'
$safeSummary = ConvertTo-LabSanitizedValue -InputObject $summary `
    -RedactAddresses:(-not $IncludeSensitive)
$writtenPath = Write-LabJson -Value $safeSummary -Path $outPath

Write-Host "HG07 summary written: $writtenPath" -ForegroundColor Green
if ($verdict -eq 'PASS') {
    Write-Host 'HG07 verdict: PASS' -ForegroundColor Green
} else {
    Write-Host "HG07 verdict: $verdict" -ForegroundColor Yellow
    foreach ($finding in $findings) {
        Write-Host "  - $finding" -ForegroundColor Yellow
    }
    exit 1
}
