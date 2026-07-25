[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$Commit = '',
    [ValidateRange(10, 120)][int]$StartupTimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if ([string]::IsNullOrWhiteSpace($Commit)) {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $Commit = ((& git -C $repoRoot rev-parse HEAD) -join '').Trim()
}
if ($Commit -notmatch '^[0-9a-fA-F]{40}$') {
    throw "Commit must be a full 40-character Git object id: $Commit"
}
$candidateCommit = $Commit.ToLowerInvariant()
$packageFullPath = (Resolve-Path -LiteralPath $PackagePath).Path
$outputPath = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $outputPath) {
    throw "OutputRoot already exists; refusing to mix evidence: $outputPath"
}
$nodesPath = New-LabDirectory -Path (Join-Path $outputPath 'nodes')
$evidencePath = New-LabDirectory -Path (Join-Path $outputPath 'evidence')
$caseResults = New-Object Collections.Generic.List[object]

function Test-AllValues {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][bool]$Expected
    )
    if ($null -eq $Object) { return $false }
    foreach ($property in $Object.PSObject.Properties) {
        if ([bool]$property.Value -ne $Expected) { return $false }
    }
    return $true
}

function Test-ContributionSurfacesOff {
    param([Parameter(Mandatory = $true)][object]$Independent)
    return -not [bool]$Independent.relay_accept -and
        -not [bool]$Independent.relay_egress -and
        -not [bool]$Independent.krp -and
        -not [bool]$Independent.kad6_beta_exit
}

function Set-ScenarioPreferences {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$BaseConsent,
        [Parameter(Mandatory = $true)][int]$AdvancedConsent,
        [Parameter(Mandatory = $true)][int]$ContributionConsent
    )
    $values = [ordered]@{
        EseNetLabConsent = $BaseConsent
        EseNetLabAdvancedConsent = $AdvancedConsent
        EseNetLabContributionConsent = $ContributionConsent
        EseNetLabEnabled = 1
        EseV9Experimental = 1
        EseKad3Rendezvous = 1
        EseAutoKeepalive = 1
        EseRelayAccept = 1
        EseRelayEgress = 1
        EseReachSelector = 1
        EseHolePunchPortPredict = 1
        EseEd2kPunch3 = 1
        Kad6PublicExitOptIn = 1
        Kad6BetaExitOptIn = 1
    }
    foreach ($entry in $values.GetEnumerator()) {
        Set-LabIniValue -Path $Path -Section 'eSE' `
            -Key $entry.Key -Value ([string]$entry.Value)
    }

    # Keep the consent test off the public discovery planes.
    Set-LabIniValue -Path $Path -Section 'Connection' `
        -Key 'KadNetworkMask' -Value '0'
    Set-LabIniValue -Path $Path -Section 'eMule' `
        -Key 'AutoConnect' -Value '0'

    # Deliberately request KRP with no endpoint, server name, CA or token.
    Set-LabIniValue -Path $Path -Section 'KRPRelay' `
        -Key 'KrpRelayEnabled' -Value '1'
    Set-LabIniValue -Path $Path -Section 'KRPRelay' `
        -Key 'KrpRelayKillSwitch' -Value '0'
    Set-LabIniValue -Path $Path -Section 'KRPRelay' `
        -Key 'EndpointHost' -Value ''
    Set-LabIniValue -Path $Path -Section 'KRPRelay' `
        -Key 'EndpointPort' -Value '0'
    Set-LabIniValue -Path $Path -Section 'KRPRelay' `
        -Key 'ExpectedServerName' -Value ''
    Set-LabIniValue -Path $Path -Section 'KRPRelay' `
        -Key 'CaBundlePath' -Value ''
    Set-LabIniValue -Path $Path -Section 'KRPRelay' `
        -Key 'AuthTokenPath' -Value ''
    Set-LabIniValue -Path $Path -Section 'KRPRelay' `
        -Key 'ExperimentalTcpDataPlane' -Value '1'
}

function Start-V91Node {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][int]$WebPort
    )
    return Start-Process -FilePath (Join-Path $NodePath 'emule.exe') `
        -ArgumentList @(
            '--portable',
            '--ignoreinstances',
            '--headless',
            "--metrics-port=$WebPort",
            "--tcp-port=$TcpPort",
            "--udp-port=$UdpPort"
        ) -WorkingDirectory $NodePath -PassThru -WindowStyle Hidden
}

function Wait-V91State {
    param(
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before API readiness with code $($Process.ExitCode)"
        }
        try {
            return Invoke-RestMethod `
                -Uri "http://127.0.0.1:$WebPort/api/ese/v9" -TimeoutSec 2
        } catch {
            Start-Sleep -Milliseconds 300
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "eMule API did not become ready on port $WebPort"
}

function Stop-V91Node {
    param([AllowNull()][Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try { $Process.Refresh() } catch { return }
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $null = $Process.WaitForExit(10000)
    }
}

function Get-TcpSnapshot {
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    return @(
        Get-NetTCPConnection -OwningProcess $ProcessId -ErrorAction SilentlyContinue |
            Sort-Object State, LocalPort, RemotePort |
            ForEach-Object {
                $localClass = Get-LabAddressClass -Address $_.LocalAddress
                $remoteClass = Get-LabAddressClass -Address $_.RemoteAddress
                [pscustomobject][ordered]@{
                    state = [string]$_.State
                    family = if ($localClass.EndsWith('-v6')) { 'IPv6' } else { 'IPv4' }
                    local_address_class = $localClass
                    local_port = [int]$_.LocalPort
                    remote_address_class = $remoteClass
                    remote_port = [int]$_.RemotePort
                }
            }
    )
}

function Invoke-RejectionScenario {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Round,
        [Parameter(Mandatory = $true)][int]$PortOffset,
        [Parameter(Mandatory = $true)][int]$BaseConsent,
        [Parameter(Mandatory = $true)][int]$AdvancedConsent,
        [Parameter(Mandatory = $true)][int]$ContributionConsent
    )
    $runId = "v91-$Name-r$Round"
    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
        -SourcePackage $packageFullPath -OutputRoot $nodesPath `
        -RunId $runId -PortOffset $PortOffset
    $node = Join-Path $nodesPath "$runId-a"
    $preferences = Join-Path $node 'config\preferences.ini'
    Set-ScenarioPreferences -Path $preferences `
        -BaseConsent $BaseConsent -AdvancedConsent $AdvancedConsent `
        -ContributionConsent $ContributionConsent

    $ports = [ordered]@{
        tcp = 4662 + $PortOffset
        udp = 4672 + $PortOffset
        web = 4711 + $PortOffset
    }
    $process = $null
    try {
        $process = Start-V91Node -NodePath $node `
            -TcpPort $ports.tcp -UdpPort $ports.udp -WebPort $ports.web
        $state = Wait-V91State -WebPort $ports.web -Process $process
        $baseOn = Test-AllValues -Object $state.netlab.base -Expected $true
        $stagedOn = Test-AllValues -Object $state.netlab.staged -Expected $true
        $contributionOff = Test-ContributionSurfacesOff `
            -Independent $state.netlab.independent
        $stableExitUnaffected = [bool]$state.netlab.independent.kad6_stable_public_exit

        $passed = switch ($Name) {
            'base-rejected' {
                $state.netlab.consent -eq 'declined' -and
                -not [bool]$state.netlab.enabled -and
                -not [bool]$state.netlab.capability_advertised -and
                -not [bool]$state.netlab.keepalive_running -and
                -not [bool]$state.v9.experimental -and
                (Test-AllValues -Object $state.netlab.staged -Expected $false) -and
                $contributionOff -and $stableExitUnaffected
            }
            'advanced-rejected' {
                $state.netlab.consent -eq 'accepted' -and
                $state.netlab.advanced_consent -eq 'declined' -and
                [bool]$state.netlab.enabled -and $baseOn -and
                (Test-AllValues -Object $state.netlab.staged -Expected $false) -and
                $contributionOff -and $stableExitUnaffected
            }
            'contribution-rejected' {
                $state.netlab.consent -eq 'accepted' -and
                $state.netlab.advanced_consent -eq 'accepted' -and
                $state.netlab.contribution_consent -eq 'declined' -and
                [bool]$state.netlab.enabled -and $baseOn -and $stagedOn -and
                $contributionOff -and $stableExitUnaffected
            }
            default { $false }
        }

        $artifact = [ordered]@{
            schema = 'ese.v91.consent-scenario/v1'
            candidate_commit = $candidateCommit
            scenario = $Name
            round = $Round
            captured_at_utc = Get-LabUtcTimestamp
            ports = $ports
            state = ConvertTo-LabSanitizedValue $state -RedactAddresses
            verdict = if ($passed) { 'PASS' } else { 'FAIL' }
        }
        Write-LabJson -Value $artifact `
            -Path (Join-Path $evidencePath "$Name-r$Round.json") | Out-Null
        $caseResults.Add([pscustomobject]@{
            id = 'V91-C02'
            scenario = $Name
            round = $Round
            verdict = if ($passed) { 'PASS' } else { 'FAIL' }
        })
    } finally {
        Stop-V91Node -Process $process
    }
}

function Invoke-AcceptAndRevokeScenario {
    param(
        [Parameter(Mandatory = $true)][int]$Round,
        [Parameter(Mandatory = $true)][int]$PortOffset
    )
    $runId = "v91-all-accepted-r$Round"
    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
        -SourcePackage $packageFullPath -OutputRoot $nodesPath `
        -RunId $runId -PortOffset $PortOffset
    $node = Join-Path $nodesPath "$runId-b"
    $preferences = Join-Path $node 'config\preferences.ini'
    Set-ScenarioPreferences -Path $preferences `
        -BaseConsent 2 -AdvancedConsent 2 -ContributionConsent 2

    $ports = [ordered]@{
        tcp = 4662 + $PortOffset
        udp = 4672 + $PortOffset
        web = 4711 + $PortOffset
    }
    $process = $null
    try {
        $process = Start-V91Node -NodePath $node `
            -TcpPort $ports.tcp -UdpPort $ports.udp -WebPort $ports.web
        $before = Wait-V91State -WebPort $ports.web -Process $process
        $socketsBefore = Get-TcpSnapshot -ProcessId $process.Id
        $unexpectedKrpSocket = @(
            $socketsBefore | Where-Object {
                $_.state -eq 'Established' -or
                ($_.state -eq 'Listen' -and $_.local_port -notin @($ports.tcp, $ports.web))
            }
        ).Count -gt 0

        $accepted = $before.netlab.consent -eq 'accepted' -and
            $before.netlab.advanced_consent -eq 'accepted' -and
            $before.netlab.contribution_consent -eq 'accepted' -and
            [bool]$before.netlab.enabled -and
            (Test-AllValues -Object $before.netlab.base -Expected $true) -and
            (Test-AllValues -Object $before.netlab.staged -Expected $true) -and
            [bool]$before.netlab.independent.relay_accept -and
            [bool]$before.netlab.independent.relay_egress -and
            [bool]$before.netlab.independent.kad6_beta_exit -and
            -not [bool]$before.netlab.independent.krp -and
            [bool]$before.netlab.independent.kad6_stable_public_exit

        $watch = [Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-RestMethod `
            -Uri "http://127.0.0.1:$($ports.web)/api/ese/v9?on=0" -TimeoutSec 15
        do {
            $after = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$($ports.web)/api/ese/v9" -TimeoutSec 5
            if (-not [bool]$after.netlab.enabled -and
                -not [bool]$after.netlab.capability_advertised -and
                -not [bool]$after.netlab.keepalive_running -and
                (Test-AllValues -Object $after.netlab.staged -Expected $false) -and
                (Test-ContributionSurfacesOff `
                    -Independent $after.netlab.independent)) {
                break
            }
            Start-Sleep -Milliseconds 100
        } while ($watch.Elapsed.TotalSeconds -lt 5)
        $watch.Stop()

        $revoked = [bool]$response.success -and
            -not [bool]$after.netlab.enabled -and
            -not [bool]$after.netlab.capability_advertised -and
            -not [bool]$after.netlab.keepalive_running -and
            (Test-AllValues -Object $after.netlab.staged -Expected $false) -and
            (Test-ContributionSurfacesOff `
                -Independent $after.netlab.independent) -and
            [bool]$after.netlab.independent.kad6_stable_public_exit -and
            $watch.Elapsed.TotalSeconds -lt 5

        Stop-V91Node -Process $process
        $process = $null
        Start-Sleep -Seconds 1
        $process = Start-V91Node -NodePath $node `
            -TcpPort $ports.tcp -UdpPort $ports.udp -WebPort $ports.web
        $restart = Wait-V91State -WebPort $ports.web -Process $process
        $persisted = $restart.netlab.consent -eq 'accepted' -and
            -not [bool]$restart.netlab.enabled -and
            -not [bool]$restart.netlab.capability_advertised -and
            -not [bool]$restart.netlab.keepalive_running -and
            (Test-AllValues -Object $restart.netlab.staged -Expected $false) -and
            (Test-ContributionSurfacesOff `
                -Independent $restart.netlab.independent) -and
            [bool]$restart.netlab.independent.kad6_stable_public_exit

        $c03Pass = $accepted -and $revoked -and $persisted
        $c04Pass = $accepted -and
            -not [bool]$before.netlab.independent.krp -and
            -not $unexpectedKrpSocket

        $artifact = [ordered]@{
            schema = 'ese.v91.accept-revoke/v1'
            candidate_commit = $candidateCommit
            round = $Round
            captured_at_utc = Get-LabUtcTimestamp
            accepted_state = ConvertTo-LabSanitizedValue $before -RedactAddresses
            tcp_sockets_before_revoke = $socketsBefore
            kill_response_success = [bool]$response.success
            revoke_elapsed_ms = [Math]::Round($watch.Elapsed.TotalMilliseconds, 1)
            revoked_state = ConvertTo-LabSanitizedValue $after -RedactAddresses
            restart_state = ConvertTo-LabSanitizedValue $restart -RedactAddresses
            verdicts = [ordered]@{
                V91_C03 = if ($c03Pass) { 'PASS' } else { 'FAIL' }
                V91_C04 = if ($c04Pass) { 'PASS' } else { 'FAIL' }
            }
        }
        Write-LabJson -Value $artifact `
            -Path (Join-Path $evidencePath "all-accepted-r$Round.json") | Out-Null
        $caseResults.Add([pscustomobject]@{
            id = 'V91-C03'
            scenario = 'accept-and-revoke'
            round = $Round
            verdict = if ($c03Pass) { 'PASS' } else { 'FAIL' }
        })
        $caseResults.Add([pscustomobject]@{
            id = 'V91-C04'
            scenario = 'incomplete-krp'
            round = $Round
            verdict = if ($c04Pass) { 'PASS' } else { 'FAIL' }
        })
    } finally {
        Stop-V91Node -Process $process
    }
}

for ($round = 1; $round -le 2; ++$round) {
    $baseOffset = 15000 + (($round - 1) * 1000)
    Invoke-RejectionScenario -Name 'base-rejected' -Round $round `
        -PortOffset $baseOffset -BaseConsent 1 -AdvancedConsent 2 `
        -ContributionConsent 2
    Invoke-RejectionScenario -Name 'advanced-rejected' -Round $round `
        -PortOffset ($baseOffset + 200) -BaseConsent 2 -AdvancedConsent 1 `
        -ContributionConsent 0
    Invoke-RejectionScenario -Name 'contribution-rejected' -Round $round `
        -PortOffset ($baseOffset + 400) -BaseConsent 2 -AdvancedConsent 2 `
        -ContributionConsent 1
    Invoke-AcceptAndRevokeScenario -Round $round `
        -PortOffset ($baseOffset + 600)
}

$caseSummary = @(
    foreach ($caseId in 'V91-C02', 'V91-C03', 'V91-C04') {
        $rows = @($caseResults | Where-Object { $_.id -eq $caseId })
        [pscustomobject][ordered]@{
            id = $caseId
            executions = $rows.Count
            passed = @($rows | Where-Object { $_.verdict -eq 'PASS' }).Count
            failed = @($rows | Where-Object { $_.verdict -eq 'FAIL' }).Count
            verdict = if (@($rows | Where-Object { $_.verdict -ne 'PASS' }).Count -eq 0) {
                'PASS'
            } else {
                'FAIL'
            }
        }
    }
)
$overall = if (@($caseSummary | Where-Object { $_.verdict -ne 'PASS' }).Count -eq 0) {
    'PASS'
} else {
    'FAIL'
}
$summary = [ordered]@{
    schema = 'ese.v91.consent-summary/v1'
    candidate_commit = $candidateCommit
    generated_at_utc = Get-LabUtcTimestamp
    package_name = Split-Path -Leaf $packageFullPath
    cases = $caseSummary
    executions = $caseResults
    verdict = $overall
}
Write-LabJson -Value $summary `
    -Path (Join-Path $evidencePath 'V91-CONSENT-SUMMARY.json') | Out-Null

& (Join-Path $PSScriptRoot 'collect_report.ps1') `
    -RunDirectory $evidencePath -CaseId 'V91-CONSENT' `
    -Outcome $overall -Version '9.1.0-beta.3' -Commit $candidateCommit `
    -Notes 'Two rounds of hierarchical consent rejection, full acceptance, global revocation, restart persistence and incomplete-KRP fail-closed checks.'

if ($overall -ne 'PASS') {
    throw 'V91 consent gate failed'
}
Write-Host "V91 consent gate PASS: $outputPath" -ForegroundColor Green
