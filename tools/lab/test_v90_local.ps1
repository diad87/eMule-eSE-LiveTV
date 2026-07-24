[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [string]$OutputRoot = '',
    [ValidateRange(1, 86400)][int]$ObservationSeconds = 1800,
    [ValidateRange(10, 300)][int]$StartupTimeoutSeconds = 90,
    [ValidateRange(0, 50000)][int]$DeclinedPortOffset = 12000,
    [ValidateRange(0, 50000)][int]$AcceptedPortOffset = 12200
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not $OutputRoot) {
    $OutputRoot = Join-Path ([IO.Path]::GetTempPath()) `
        ('eSE-v90-local-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
}
$outputPath = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $outputPath) {
    throw "OutputRoot already exists; refusing to mix test runs: $outputPath"
}
$nodesPath = New-LabDirectory -Path (Join-Path $outputPath 'nodes')
$evidencePath = New-LabDirectory -Path (Join-Path $outputPath 'evidence')
$packageFullPath = (Resolve-Path -LiteralPath $PackagePath).Path

$declinedProcess = $null
$acceptedProcess = $null
$cases = @()

function Add-V90Case {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'BLOCKED')]
        [string]$Verdict,
        [Parameter(Mandatory = $true)][string]$Reason,
        [object]$Details = $null
    )
    $script:cases += [pscustomobject][ordered]@{
        id = $Id
        verdict = $Verdict
        reason = $Reason
        details = $Details
    }
}

function Start-V90Node {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][int]$WebPort
    )
    $executable = Join-Path $NodePath 'emule.exe'
    $arguments = @(
        '--portable',
        '--headless',
        "--metrics-port=$WebPort",
        "--tcp-port=$TcpPort",
        "--udp-port=$UdpPort"
    )
    return Start-Process -FilePath $executable -ArgumentList $arguments `
        -WorkingDirectory $NodePath -PassThru -WindowStyle Hidden
}

function Wait-V90Api {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    do {
        if ($Process.HasExited) {
            throw "eMule exited before its API became ready (exit $($Process.ExitCode))"
        }
        try {
            return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/status" `
                -TimeoutSec 2
        } catch {
            Start-Sleep -Milliseconds 500
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "eMule API did not become ready on loopback port $Port"
}

function Get-V90Api {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Path
    )
    return Invoke-RestMethod -Uri ("http://127.0.0.1:{0}{1}" -f $Port, $Path) `
        -TimeoutSec 5
}

function Stop-V90Process {
    param([AllowNull()][Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try { $Process.Refresh() } catch { return }
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $null = $Process.WaitForExit(10000)
    }
}

function Test-AllFalse {
    param([AllowNull()][object]$Object)
    if ($null -eq $Object) { return $false }
    foreach ($property in $Object.PSObject.Properties) {
        if ([bool]$property.Value) { return $false }
    }
    return $true
}

function Get-NonOverlayAddress {
    foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($adapter.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up) { continue }
        $adapterLabel = '{0}|{1}' -f $adapter.Name, $adapter.Description
        if ($adapterLabel -match '(?i)Tailscale|Cloudflare|WARP|Loopback') { continue }
        foreach ($unicast in $adapter.GetIPProperties().UnicastAddresses) {
            if ($unicast.Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { continue }
            $address = $unicast.Address.ToString()
            if ((Get-LabAddressClass -Address $address) -in @('private-v4', 'global-v4')) {
                return $address
            }
        }
    }
    return $null
}

try {
    & (Join-Path $PSScriptRoot 'inventory.ps1') -NodeRole controller `
        -PackagePath $packageFullPath -OutFile (Join-Path $evidencePath 'inventory.json')

    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
        -SourcePackage $packageFullPath -OutputRoot $nodesPath `
        -RunId 'v90-declined' -PortOffset $DeclinedPortOffset
    $declinedNode = Join-Path $nodesPath 'v90-declined-a'
    $declinedPreferences = Join-Path $declinedNode 'config\preferences.ini'
    Set-LabIniValue -Path $declinedPreferences -Section 'eSE' `
        -Key 'EseNetLabConsent' -Value '1'
    Set-LabIniValue -Path $declinedPreferences -Section 'eSE' `
        -Key 'EseNetLabAdvancedConsent' -Value '1'
    Set-LabIniValue -Path $declinedPreferences -Section 'eSE' `
        -Key 'EseNetLabContributionConsent' -Value '1'
    # Deliberately inconsistent input: load must fail closed because consent is declined.
    Set-LabIniValue -Path $declinedPreferences -Section 'eSE' `
        -Key 'EseNetLabEnabled' -Value '1'

    $declinedPorts = [ordered]@{
        tcp = 4662 + $DeclinedPortOffset
        udp = 4672 + $DeclinedPortOffset
        web = 4711 + $DeclinedPortOffset
    }
    $declinedProcess = Start-V90Node -NodePath $declinedNode `
        -TcpPort $declinedPorts.tcp -UdpPort $declinedPorts.udp -WebPort $declinedPorts.web
    $null = Wait-V90Api -Port $declinedPorts.web -Process $declinedProcess
    $declinedBefore = Get-V90Api -Port $declinedPorts.web -Path '/api/status'
    $declinedV9Before = Get-V90Api -Port $declinedPorts.web -Path '/api/ese/v9'
    Write-LabJson -Value (ConvertTo-LabSanitizedValue $declinedBefore -RedactAddresses) `
        -Path (Join-Path $evidencePath 'declined-before.json') | Out-Null

    Start-Sleep -Seconds $ObservationSeconds

    $declinedAfter = Get-V90Api -Port $declinedPorts.web -Path '/api/status'
    $declinedV9After = Get-V90Api -Port $declinedPorts.web -Path '/api/ese/v9'
    Write-LabJson -Value (ConvertTo-LabSanitizedValue $declinedAfter -RedactAddresses) `
        -Path (Join-Path $evidencePath 'declined-after.json') | Out-Null

    $counterNames = @(
        'hole_punch_attempts',
        'hole_punch_success',
        'kad3_rdv_req_sent',
        'kad3_rdv_req_recv',
        'kad3_rdv_fwd',
        'kad3_rdv_success',
        'keepalive_pings_sent',
        'keepalive_pongs_recv'
    )
    $counterDeltas = [ordered]@{}
    $countersStable = $true
    foreach ($counterName in $counterNames) {
        $beforeValue = [Int64]$declinedBefore.$counterName
        $afterValue = [Int64]$declinedAfter.$counterName
        $delta = $afterValue - $beforeValue
        $counterDeltas[$counterName] = $delta
        if ($delta -ne 0) { $countersStable = $false }
    }
    $declinedSafe = $declinedAfter.netlab_consent -eq 'declined' -and
        -not [bool]$declinedAfter.netlab_enabled -and
        -not [bool]$declinedAfter.keepalive_running -and
        -not [bool]$declinedV9After.netlab.capability_advertised -and
        $countersStable
    Add-V90Case -Id 'V90-C01-RUNTIME' `
        -Verdict $(if ($declinedSafe) { 'PASS' } else { 'FAIL' }) `
        -Reason $(if ($declinedSafe) {
            "Declined consent stayed fail-closed for $ObservationSeconds seconds"
        } else {
            'Declined consent allowed state or experimental counters to change'
        }) `
        -Details ([ordered]@{
            observation_seconds = $ObservationSeconds
            counter_deltas = $counterDeltas
            consent = $declinedAfter.netlab_consent
            enabled = [bool]$declinedAfter.netlab_enabled
        })

    $remoteAddress = Get-NonOverlayAddress
    if ($null -eq $remoteAddress) {
        Add-V90Case -Id 'V90-S01' -Verdict 'BLOCKED' `
            -Reason 'No non-overlay LAN address was available for the remote-access negative control'
    } else {
        $remoteBlocked = $true
        $remoteChecks = [ordered]@{}
        foreach ($remotePath in @('/api/status', '/hls/stream.m3u8', '/live')) {
            $remoteResult = 'unknown'
            $pathBlocked = $false
            try {
                $response = Invoke-WebRequest `
                    -Uri ("http://{0}:{1}{2}" -f $remoteAddress, $declinedPorts.web, $remotePath) `
                    -UseBasicParsing -TimeoutSec 5
                $remoteResult = "unexpected_http_$([int]$response.StatusCode)"
            } catch {
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    $pathBlocked = $statusCode -eq 401 -or $statusCode -eq 403
                    $remoteResult = "http_$statusCode"
                } else {
                    $pathBlocked = $true
                    $remoteResult = 'connection_rejected'
                }
            }
            $remoteChecks[$remotePath] = $remoteResult
            if (-not $pathBlocked) { $remoteBlocked = $false }
        }
        Add-V90Case -Id 'V90-S01' `
            -Verdict $(if ($remoteBlocked) { 'PASS' } else { 'FAIL' }) `
            -Reason $(if ($remoteBlocked) {
                'Unauthenticated non-loopback API, HLS and dashboard access were rejected'
            } else {
                'At least one unauthenticated non-loopback API, HLS or dashboard request succeeded'
            }) `
            -Details ([ordered]@{
                address_class = Get-LabAddressClass -Address $remoteAddress
                results = $remoteChecks
            })
    }

    $webMappingSafe = -not [bool]$declinedAfter.web_upnp_active
    Add-V90Case -Id 'V90-S02-LOCAL' `
        -Verdict $(if ($webMappingSafe) { 'PASS' } else { 'FAIL' }) `
        -Reason $(if ($webMappingSafe) {
            'Native status confirms that WebServer UPnP is inactive'
        } else {
            'Native status reports WebServer UPnP active'
        })

    Stop-V90Process -Process $declinedProcess
    $declinedProcess = $null

    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
        -SourcePackage $packageFullPath -OutputRoot $nodesPath `
        -RunId 'v90-accepted' -PortOffset $AcceptedPortOffset
    $acceptedNode = Join-Path $nodesPath 'v90-accepted-b'
    $acceptedPreferences = Join-Path $acceptedNode 'config\preferences.ini'
    Set-LabIniValue -Path $acceptedPreferences -Section 'eSE' `
        -Key 'EseNetLabConsent' -Value '2'
    Set-LabIniValue -Path $acceptedPreferences -Section 'eSE' `
        -Key 'EseNetLabAdvancedConsent' -Value '1'
    Set-LabIniValue -Path $acceptedPreferences -Section 'eSE' `
        -Key 'EseNetLabContributionConsent' -Value '1'
    Set-LabIniValue -Path $acceptedPreferences -Section 'eSE' `
        -Key 'EseNetLabEnabled' -Value '1'
    Set-LabIniValue -Path $acceptedPreferences -Section 'eSE' `
        -Key 'EseAutoKeepalive' -Value '1'

    $acceptedPorts = [ordered]@{
        tcp = 4662 + $AcceptedPortOffset
        udp = 4672 + $AcceptedPortOffset
        web = 4711 + $AcceptedPortOffset
    }
    $acceptedProcess = Start-V90Node -NodePath $acceptedNode `
        -TcpPort $acceptedPorts.tcp -UdpPort $acceptedPorts.udp -WebPort $acceptedPorts.web
    $null = Wait-V90Api -Port $acceptedPorts.web -Process $acceptedProcess
    $acceptedBefore = Get-V90Api -Port $acceptedPorts.web -Path '/api/ese/v9'

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $killResponse = Get-V90Api -Port $acceptedPorts.web -Path '/api/ese/v9?on=0'
    $killState = $null
    do {
        $killState = Get-V90Api -Port $acceptedPorts.web -Path '/api/ese/v9'
        if (-not [bool]$killState.netlab.enabled -and
            -not [bool]$killState.netlab.keepalive_running) {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ($stopwatch.Elapsed.TotalSeconds -lt 5)
    $stopwatch.Stop()

    $advancedOff = Test-AllFalse -Object $killState.netlab.staged
    $independentOff = Test-AllFalse -Object $killState.netlab.independent
    $killSafe = [bool]$acceptedBefore.netlab.enabled -and
        [bool]$killResponse.success -and
        -not [bool]$killState.netlab.enabled -and
        -not [bool]$killState.netlab.capability_advertised -and
        -not [bool]$killState.netlab.keepalive_running -and
        $advancedOff -and $independentOff -and
        $stopwatch.Elapsed.TotalSeconds -lt 5

    Write-LabJson -Value (ConvertTo-LabSanitizedValue $killState -RedactAddresses) `
        -Path (Join-Path $evidencePath 'accepted-after-kill.json') | Out-Null

    Stop-V90Process -Process $acceptedProcess
    $acceptedProcess = $null
    Start-Sleep -Seconds 2
    $acceptedProcess = Start-V90Node -NodePath $acceptedNode `
        -TcpPort $acceptedPorts.tcp -UdpPort $acceptedPorts.udp -WebPort $acceptedPorts.web
    $null = Wait-V90Api -Port $acceptedPorts.web -Process $acceptedProcess
    $restartState = Get-V90Api -Port $acceptedPorts.web -Path '/api/ese/v9'
    $persistedOff = $restartState.netlab.consent -eq 'accepted' -and
        -not [bool]$restartState.netlab.enabled -and
        -not [bool]$restartState.netlab.capability_advertised -and
        -not [bool]$restartState.netlab.keepalive_running
    $c02Pass = $killSafe -and $persistedOff
    Add-V90Case -Id 'V90-C02-RUNTIME' `
        -Verdict $(if ($c02Pass) { 'PASS' } else { 'FAIL' }) `
        -Reason $(if ($c02Pass) {
            'Kill switch stopped NetLab in under five seconds and survived forced restart'
        } else {
            'Kill switch timing, advanced gates or restart persistence failed'
        }) `
        -Details ([ordered]@{
            kill_elapsed_ms = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 1)
            staged_all_off = $advancedOff
            independent_all_off = $independentOff
            persisted_after_forced_restart = $persistedOff
        })

    & (Join-Path $PSScriptRoot 'capture_status.ps1') -NodeRole B `
        -BaseUrl ("http://127.0.0.1:{0}" -f $acceptedPorts.web) `
        -TargetProcessIds @($acceptedProcess.Id) `
        -OutFile (Join-Path $evidencePath 'accepted-restart-status.json')
} catch {
    Add-V90Case -Id 'V90-LOCAL-HARNESS' -Verdict 'FAIL' `
        -Reason $_.Exception.Message
} finally {
    Stop-V90Process -Process $declinedProcess
    Stop-V90Process -Process $acceptedProcess
}

$failedCases = @($cases | Where-Object { $_.verdict -eq 'FAIL' })
$blockedCases = @($cases | Where-Object { $_.verdict -eq 'BLOCKED' })
$overallVerdict = if ($failedCases.Count -gt 0) {
    'FAIL'
} elseif ($blockedCases.Count -gt 0) {
    'BLOCKED'
} else {
    'PASS'
}
$summary = [ordered]@{
    schema = 'ese.lab.v90-local/v1'
    generated_at_utc = Get-LabUtcTimestamp
    package_name = Split-Path -Leaf $packageFullPath
    observation_seconds = $ObservationSeconds
    cases = $cases
    verdict = $overallVerdict
    limitation = 'Runtime profiles exercise fail-closed loading and the kill switch; the visual first-run prompt requires a separate GUI observation.'
}
Write-LabJson -Value (ConvertTo-LabSanitizedValue $summary -RedactAddresses) `
    -Path (Join-Path $evidencePath 'V90-LOCAL.json') | Out-Null

& (Join-Path $PSScriptRoot 'collect_report.ps1') -RunDirectory $evidencePath `
    -CaseId 'V90-LOCAL' -Outcome $overallVerdict -Version '9.0.0-beta.2' `
    -Notes 'Local declined/accepted NetLab runtime, kill-switch persistence and remote-access controls.'

if ($overallVerdict -eq 'FAIL') {
    throw "V90 local runtime gate FAIL: $($failedCases.reason -join '; ')"
}
Write-Host "V90 local runtime gate ${overallVerdict}: $outputPath" `
    -ForegroundColor $(if ($overallVerdict -eq 'PASS') { 'Green' } else { 'Yellow' })
