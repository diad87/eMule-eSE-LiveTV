[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CandidatePackage,
    [Parameter(Mandatory = $true)][string]$PreviousPackage,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPreviousEmuleSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPreviousBuildInfoSha256,
    [ValidateRange(10, 120)][int]$StartupTimeoutSeconds = 60,
    [ValidateRange(30, 180)][int]$PreviousObservationSeconds = 30,
    [string]$Commit = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$candidateInfo = Get-LabCandidateInfo -PackagePath $CandidatePackage -ExpectedCommit $Commit
$candidateCommit = $candidateInfo.commit
$candidate = $candidateInfo.package_path
$previous = (Resolve-Path -LiteralPath $PreviousPackage).Path
$previousExe = Join-Path $previous 'emule.exe'
$previousEseServer = Join-Path $previous 'ese-server.exe'
$previousBuildInfo = Join-Path $previous 'BUILD_INFO.txt'
foreach ($requiredPreviousFile in @(
    $previousExe, $previousEseServer, $previousBuildInfo
)) {
    if (-not (Test-Path -LiteralPath $requiredPreviousFile -PathType Leaf)) {
        throw "The previous package is incomplete: $requiredPreviousFile"
    }
}
$previousRelease = 'v0.70b-eSE8.1.0'
$previousBuildInfoText = Get-Content -LiteralPath $previousBuildInfo -Raw
if ($previousBuildInfoText -notmatch
    ('(?m)^\s*release:\s*' + [regex]::Escape($previousRelease) + '\s*$')) {
    throw "PreviousPackage is not the required exact $previousRelease build"
}
$canonicalPreviousExeHash =
    '3f5f9ad4f305de15bf345e11a5fe1652969b07afcdde136b9277989415ce4187'
$canonicalPreviousEseServerHash =
    '9563da8e16a8ef3ec05cc58479c0bda2cb0655899b0ce7b10fd9f4c44580a76f'
$canonicalPreviousBuildInfoHash =
    '26fc4348044868fc65c04f73e78cafe966d38cb2178c0c093944164c7aafdfce'
$expectedPreviousExeHash =
    $ExpectedPreviousEmuleSha256.ToLowerInvariant()
$expectedPreviousBuildInfoHash =
    $ExpectedPreviousBuildInfoSha256.ToLowerInvariant()
if ($expectedPreviousExeHash -ne $canonicalPreviousExeHash -or
    $expectedPreviousBuildInfoHash -ne $canonicalPreviousBuildInfoHash) {
    throw (
        'The requested eSE 8.1 hashes are not the canonical V91-K03 ' +
        'downgrade baseline'
    )
}
$previousExeHashBefore = Get-LabSha256 -Path $previousExe
$previousEseServerHashBefore = Get-LabSha256 -Path $previousEseServer
$previousBuildInfoHashBefore = Get-LabSha256 -Path $previousBuildInfo
if ($previousExeHashBefore -ne $expectedPreviousExeHash -or
    $previousEseServerHashBefore -ne $canonicalPreviousEseServerHash -or
    $previousBuildInfoHashBefore -ne $expectedPreviousBuildInfoHash) {
    throw 'PreviousPackage does not match the explicitly pinned eSE 8.1 hashes'
}
$output = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $output) {
    throw "OutputRoot already exists; refusing to mix evidence: $output"
}
$nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')

function Wait-Status {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before API readiness with code $($Process.ExitCode)"
        }
        try {
            return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/status" `
                -TimeoutSec 2
        } catch {
            Start-Sleep -Milliseconds 300
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "eMule API did not become ready on port $Port"
}

function Assert-PortFree {
    param([Parameter(Mandatory = $true)][int]$Port)

    $owners = @(
        Get-NetTCPConnection -State Listen -LocalPort $Port `
            -ErrorAction SilentlyContinue
    )
    if ($owners.Count -ne 0) {
        throw "Required API port is already owned before launch: $Port"
    }
}

function Assert-OwnedListener {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )

    $owners = @(
        Get-NetTCPConnection -State Listen -LocalPort $Port `
            -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique
    )
    if ($owners.Count -eq 0 -or
        @($owners | Where-Object { $_ -ne $Process.Id }).Count -ne 0 -or
        $owners -notcontains $Process.Id) {
        throw "API listener on port $Port is not owned exclusively by PID $($Process.Id)"
    }
}

function Stop-OwnedProcess {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    $Process.Refresh()
    if ($Process.HasExited) {
        return [pscustomobject]@{ stopped = $true; graceful = $true }
    }
    $actual = Get-Process -Id $Process.Id -ErrorAction Stop
    if ([IO.Path]::GetFullPath($actual.Path) -ne
        [IO.Path]::GetFullPath($ExpectedPath)) {
        throw "Refusing to stop PID $($Process.Id): executable path changed"
    }
    $closed = $Process.CloseMainWindow()
    if ($closed -and $Process.WaitForExit(15000)) {
        return [pscustomobject]@{ stopped = $true; graceful = $true }
    }
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    $null = $Process.WaitForExit(10000)
    $Process.Refresh()
    return [pscustomobject]@{
        stopped = $Process.HasExited
        graceful = $false
    }
}

function Get-IniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key
    )
    $current = ''
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            $current = $Matches[1]
            continue
        }
        if ($current -eq $Section -and
            $line -match ('^\s*' + [regex]::Escape($Key) + '\s*=(.*)$')) {
            return $Matches[1].Trim()
        }
    }
    return $null
}

$candidateNode = Join-Path $nodes 'v91-k03-candidate-a'
$candidateExe = Join-Path $candidateNode 'emule.exe'
$candidatePreferences = Join-Path $candidateNode 'config\preferences.ini'
$previousNode = Join-Path $nodes 'v91-k03-previous'
$copiedPreviousExe = Join-Path $previousNode 'emule.exe'
$copiedPreviousEseServer = Join-Path $previousNode 'ese-server.exe'
$copiedPreviousBuildInfo = Join-Path $previousNode 'BUILD_INFO.txt'
$previousConfig = Join-Path $previousNode 'config'
$previousPreferences = Join-Path $previousConfig 'preferences.ini'
$previousApiPort = 4711
$candidateProcess = $null
$previousProcess = $null
$candidateStopResult = $null
$previousStopResult = $null
$runtimeFailure = $null
$candidateStatus = $null
$legacyAfterCandidate = $null
$maskAfterCandidate = $null
$previousProfileBefore = $null
$legacyAfterPrevious = $null
$previousStayedRunning = $false
$previousTcp = @()
$previousUdp = @()
$kadSamples = [System.Collections.Generic.List[object]]::new()
$productFailures = New-Object 'Collections.Generic.List[string]'
$blockedReasons = New-Object 'Collections.Generic.List[string]'
$cleanupFailures = New-Object 'Collections.Generic.List[string]'
$apiFullyObservable = $true
$kadConnectedObserved = $false
$candidateCrashObserved = $false
$previousCrashObserved = $false
$observationStarted = $null
$observationFinished = $null

try {
    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
        -SourcePackage $candidate -OutputRoot $nodes `
        -RunId 'v91-k03-candidate' -PortOffset 18000
    if ((Get-LabSha256 -Path $candidateExe) -ne
        $candidateInfo.emule_sha256) {
        throw 'The isolated candidate executable does not match its package'
    }
    Set-LabIniValue -Path $candidatePreferences -Section 'Connection' `
        -Key 'KadNetworkMask' -Value '2'
    # Deliberately leave the old boolean unsafe; the candidate must normalize
    # and save it as OFF for the downgraded build.
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' `
        -Key 'NetworkKademlia' -Value '1'
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' `
        -Key 'AutoConnect' -Value '1'
    Set-LabIniValue -Path $candidatePreferences -Section 'eMule' `
        -Key 'ConfirmExit' -Value '0'
    Set-LabIniValue -Path $candidatePreferences -Section 'eSE' `
        -Key 'EseNetLabConsent' -Value '1'

    Assert-PortFree -Port 22711
    $candidateProcess = Start-Process -FilePath $candidateExe `
        -ArgumentList @(
            '--portable',
            '--ignoreinstances',
            '--metrics-port=22711',
            '--tcp-port=22662',
            '--udp-port=22672'
        ) -WorkingDirectory $candidateNode -WindowStyle Hidden -PassThru
    $candidateStatus = Wait-Status -Port 22711 -Process $candidateProcess
    Assert-OwnedListener -Port 22711 -Process $candidateProcess
    Start-Sleep -Seconds 1
    $candidateProcess.Refresh()
    if ($candidateProcess.HasExited) {
        $candidateCrashObserved = $true
        $productFailures.Add(
            "candidate exited before requested shutdown with code $($candidateProcess.ExitCode)"
        )
    }
    $candidateStopResult = Stop-OwnedProcess `
        -Process $candidateProcess -ExpectedPath $candidateExe
    if (-not $candidateStopResult.stopped) {
        $cleanupFailures.Add('candidate process did not stop')
    }
    $legacyAfterCandidate = Get-IniValue -Path $candidatePreferences `
        -Section 'eMule' -Key 'NetworkKademlia'
    $maskAfterCandidate = Get-IniValue -Path $candidatePreferences `
        -Section 'Connection' -Key 'KadNetworkMask'

    Copy-Item -LiteralPath $previous -Destination $previousNode -Recurse
    if ((Get-LabSha256 -Path $copiedPreviousExe) -ne
            $expectedPreviousExeHash -or
        (Get-LabSha256 -Path $copiedPreviousEseServer) -ne
            $canonicalPreviousEseServerHash -or
        (Get-LabSha256 -Path $copiedPreviousBuildInfo) -ne
            $expectedPreviousBuildInfoHash) {
        throw 'The isolated eSE 8.1 copy does not match the pinned package'
    }
    if (Test-Path -LiteralPath $previousConfig) {
        Move-Item -LiteralPath $previousConfig `
            -Destination (Join-Path $previousNode 'config.previous-original')
    }
    Copy-Item -LiteralPath (Join-Path $candidateNode 'config') `
        -Destination $previousConfig -Recurse
    # eSE 8.1 predates the --metrics-port override and exposes its native
    # localhost status API on the legacy WebServer port.
    Set-LabIniValue -Path $previousPreferences -Section 'WebServer' `
        -Key 'Enabled' -Value '1'
    Set-LabIniValue -Path $previousPreferences -Section 'WebServer' `
        -Key 'Port' -Value ([string]$previousApiPort)
    Set-LabIniValue -Path $previousPreferences -Section 'WebServer' `
        -Key 'WebUseUPnP' -Value '0'
    $previousProfileBefore = Get-IniValue -Path $previousPreferences `
        -Section 'eMule' -Key 'NetworkKademlia'

    Assert-PortFree -Port $previousApiPort
    $previousProcess = Start-Process -FilePath $copiedPreviousExe `
        -ArgumentList @(
            '--portable',
            '--ignoreinstances',
            '--tcp-port=22862',
            '--udp-port=22872'
        ) -WorkingDirectory $previousNode -WindowStyle Hidden -PassThru
    $null = Wait-Status -Port $previousApiPort -Process $previousProcess
    Assert-OwnedListener -Port $previousApiPort -Process $previousProcess
    $observationStarted = [DateTime]::UtcNow
    $observationDeadline =
        $observationStarted.AddSeconds($PreviousObservationSeconds)
    do {
        $captured = [DateTime]::UtcNow
        $previousProcess.Refresh()
        if ($previousProcess.HasExited) {
            $previousCrashObserved = $true
            $productFailures.Add(
                "eSE 8.1 exited during downgrade observation with code $($previousProcess.ExitCode)"
            )
            break
        }
        $available = $false
        $fieldPresent = $false
        $valueValid = $false
        $connected = $null
        $sampleError = $null
        try {
            $status = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$previousApiPort/api/status" `
                -TimeoutSec 2
            $available = $true
            $property = $status.PSObject.Properties['kad_connected']
            $fieldPresent = $null -ne $property
            if ($fieldPresent) {
                if ($property.Value -is [bool]) {
                    $connected = [bool]$property.Value
                    $valueValid = $true
                } else {
                    $parsed = $false
                    $valueValid = [bool]::TryParse(
                        [string]$property.Value, [ref]$parsed
                    )
                    if ($valueValid) { $connected = $parsed }
                }
            }
        } catch {
            $sampleError = $_.Exception.Message
        }
        if (-not $available -or -not $fieldPresent -or -not $valueValid) {
            $apiFullyObservable = $false
        }
        if ($valueValid -and $connected) {
            $kadConnectedObserved = $true
        }
        $kadSamples.Add([pscustomobject][ordered]@{
            captured_at_utc = $captured.ToString('o')
            api_available = $available
            kad_connected_field_present = $fieldPresent
            kad_connected_value_valid = $valueValid
            kad_connected = $connected
            error = $sampleError
        })
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $observationDeadline)
    $observationFinished = [DateTime]::UtcNow
    $previousProcess.Refresh()
    $previousStayedRunning = -not $previousProcess.HasExited
    if ($previousStayedRunning) {
        $previousTcp = @(
            Get-NetTCPConnection -OwningProcess $previousProcess.Id `
                -ErrorAction SilentlyContinue |
                Select-Object State, LocalAddress, LocalPort,
                    RemoteAddress, RemotePort
        )
        $previousUdp = @(
            Get-NetUDPEndpoint -OwningProcess $previousProcess.Id `
                -ErrorAction SilentlyContinue |
                Select-Object LocalAddress, LocalPort
        )
    }
    $previousStopResult = Stop-OwnedProcess -Process $previousProcess `
        -ExpectedPath $copiedPreviousExe
    if (-not $previousStopResult.stopped) {
        $cleanupFailures.Add('eSE 8.1 process did not stop')
    }
    $legacyAfterPrevious = Get-IniValue -Path $previousPreferences `
        -Section 'eMule' -Key 'NetworkKademlia'
} catch {
    $runtimeFailure = $_
} finally {
    if ($null -ne $previousProcess) {
        try {
            $cleanup = Stop-OwnedProcess -Process $previousProcess `
                -ExpectedPath $copiedPreviousExe
            if ($null -eq $previousStopResult) {
                $previousStopResult = $cleanup
            }
            if (-not $cleanup.stopped) {
                $cleanupFailures.Add('eSE 8.1 process remains running')
            }
        } catch {
            $cleanupFailures.Add(
                "eSE 8.1 cleanup failed: $($_.Exception.Message)"
            )
        }
    }
    if ($null -ne $candidateProcess) {
        try {
            $cleanup = Stop-OwnedProcess -Process $candidateProcess `
                -ExpectedPath $candidateExe
            if ($null -eq $candidateStopResult) {
                $candidateStopResult = $cleanup
            }
            if (-not $cleanup.stopped) {
                $cleanupFailures.Add('candidate process remains running')
            }
        } catch {
            $cleanupFailures.Add(
                "candidate cleanup failed: $($_.Exception.Message)"
            )
        }
    }
}

$candidateAfter = $null
$candidateNodeHashAfter = ''
$previousExeHashAfter = ''
$previousEseServerHashAfter = ''
$previousBuildInfoHashAfter = ''
$copiedPreviousExeHashAfter = ''
$copiedPreviousEseServerHashAfter = ''
$copiedPreviousBuildInfoHashAfter = ''
try {
    $candidateAfter = Get-LabCandidateInfo -PackagePath $CandidatePackage `
        -ExpectedCommit $candidateCommit
    if (Test-Path -LiteralPath $candidateExe -PathType Leaf) {
        $candidateNodeHashAfter = Get-LabSha256 -Path $candidateExe
    }
    $previousExeHashAfter = Get-LabSha256 -Path $previousExe
    $previousEseServerHashAfter = Get-LabSha256 -Path $previousEseServer
    $previousBuildInfoHashAfter = Get-LabSha256 -Path $previousBuildInfo
    if (Test-Path -LiteralPath $copiedPreviousExe -PathType Leaf) {
        $copiedPreviousExeHashAfter =
            Get-LabSha256 -Path $copiedPreviousExe
    }
    if (Test-Path -LiteralPath $copiedPreviousEseServer -PathType Leaf) {
        $copiedPreviousEseServerHashAfter =
            Get-LabSha256 -Path $copiedPreviousEseServer
    }
    if (Test-Path -LiteralPath $copiedPreviousBuildInfo -PathType Leaf) {
        $copiedPreviousBuildInfoHashAfter =
            Get-LabSha256 -Path $copiedPreviousBuildInfo
    }
} catch {
    $blockedReasons.Add(
        "candidate/previous identity could not be revalidated: $($_.Exception.Message)"
    )
}
$candidateUnchanged = $null -ne $candidateAfter -and
    $candidateAfter.emule_sha256 -eq $candidateInfo.emule_sha256 -and
    $candidateAfter.ese_server_sha256 -eq $candidateInfo.ese_server_sha256 -and
    $candidateAfter.build_info_sha256 -eq $candidateInfo.build_info_sha256 -and
    $candidateNodeHashAfter -eq $candidateInfo.emule_sha256
$previousUnchanged =
    $previousExeHashAfter -eq $expectedPreviousExeHash -and
    $previousEseServerHashAfter -eq $canonicalPreviousEseServerHash -and
    $previousBuildInfoHashAfter -eq $expectedPreviousBuildInfoHash -and
    $copiedPreviousExeHashAfter -eq $expectedPreviousExeHash -and
    $copiedPreviousEseServerHashAfter -eq $canonicalPreviousEseServerHash -and
    $copiedPreviousBuildInfoHashAfter -eq $expectedPreviousBuildInfoHash
$identitiesUnchanged = $candidateUnchanged -and $previousUnchanged
if (-not $identitiesUnchanged) {
    $blockedReasons.Add('candidate or pinned eSE 8.1 identity changed')
}
if ($null -ne $runtimeFailure) {
    $blockedReasons.Add("runtime/setup error: $($runtimeFailure.Exception.Message)")
}
if ($cleanupFailures.Count -gt 0) {
    $blockedReasons.Add('process cleanup did not complete safely')
}
if ($legacyAfterCandidate -ne '0' -or $maskAfterCandidate -ne '2') {
    $productFailures.Add(
        'candidate did not persist Kad6-only as legacy NetworkKademlia=0'
    )
}
if ($previousProfileBefore -ne '0' -or $legacyAfterPrevious -ne '0') {
    $productFailures.Add(
        'eSE 8.1 did not preserve legacy NetworkKademlia=0'
    )
}
if (-not $previousStayedRunning -and $null -eq $runtimeFailure -and
    -not @($productFailures | Where-Object {
        $_ -like 'eSE 8.1 exited*'
    }).Count) {
    $productFailures.Add('eSE 8.1 did not remain running during observation')
}
if ($kadConnectedObserved) {
    $productFailures.Add('eSE 8.1 reactivated and connected Kad2')
}
$observedSeconds = if ($null -ne $observationStarted -and
    $null -ne $observationFinished) {
    ($observationFinished - $observationStarted).TotalSeconds
} else { 0.0 }
if (-not $previousCrashObserved -and (
    $kadSamples.Count -eq 0 -or -not $apiFullyObservable -or
    $observedSeconds -lt $PreviousObservationSeconds)) {
    $blockedReasons.Add(
        'eSE 8.1 kad_connected state was not continuously observable for the required duration'
    )
}

$outcome = if ($blockedReasons.Count -gt 0) {
    'BLOCKED'
} elseif ($productFailures.Count -gt 0) {
    'FAIL'
} else {
    'PASS'
}
$artifact = [ordered]@{
    schema = 'ese.v91.k03-downgrade/v2'
    case_id = 'V91-K03'
    candidate_commit = $candidateCommit
    captured_at_utc = Get-LabUtcTimestamp
    candidate = [ordered]@{
        version = $candidateInfo.version
        emule_sha256_before = $candidateInfo.emule_sha256
        emule_sha256_after = if ($null -eq $candidateAfter) {
            ''
        } else { $candidateAfter.emule_sha256 }
        ese_server_sha256_before = $candidateInfo.ese_server_sha256
        ese_server_sha256_after = if ($null -eq $candidateAfter) {
            ''
        } else { $candidateAfter.ese_server_sha256 }
        build_info_sha256_before = $candidateInfo.build_info_sha256
        build_info_sha256_after = if ($null -eq $candidateAfter) {
            ''
        } else { $candidateAfter.build_info_sha256 }
        isolated_emule_sha256_after = $candidateNodeHashAfter
        unchanged = $candidateUnchanged
    }
    previous_build = [ordered]@{
        required_release = $previousRelease
        expected_build_info_sha256 = $expectedPreviousBuildInfoHash
        build_info_sha256_before = $previousBuildInfoHashBefore
        build_info_sha256_after = $previousBuildInfoHashAfter
        isolated_build_info_sha256_after =
            $copiedPreviousBuildInfoHashAfter
        expected_emule_sha256 = $expectedPreviousExeHash
        emule_sha256_before = $previousExeHashBefore
        emule_sha256_after = $previousExeHashAfter
        isolated_emule_sha256_after = $copiedPreviousExeHashAfter
        expected_ese_server_sha256 = $canonicalPreviousEseServerHash
        ese_server_sha256_before = $previousEseServerHashBefore
        ese_server_sha256_after = $previousEseServerHashAfter
        isolated_ese_server_sha256_after =
            $copiedPreviousEseServerHashAfter
        unchanged = $previousUnchanged
    }
    candidate_profile_after_save = [ordered]@{
        kad_network_mask = $maskAfterCandidate
        legacy_network_kademlia = $legacyAfterCandidate
        crash_observed = $candidateCrashObserved
        graceful_close = if ($null -eq $candidateStopResult) {
            $false
        } else { [bool]$candidateStopResult.graceful }
    }
    previous_runtime = [ordered]@{
        required_observation_seconds = $PreviousObservationSeconds
        observed_seconds = [Math]::Round($observedSeconds, 3)
        status_sample_count = $kadSamples.Count
        api_fully_observable = $apiFullyObservable
        kad_connected_observed = $kadConnectedObserved
        crash_observed = $previousCrashObserved
        status_samples = @($kadSamples)
        stayed_running = $previousStayedRunning
        legacy_network_kademlia_before_start = $previousProfileBefore
        legacy_network_kademlia_after_close = $legacyAfterPrevious
        graceful_close = if ($null -eq $previousStopResult) {
            $false
        } else { [bool]$previousStopResult.graceful }
        tcp_sockets_diagnostic =
            ConvertTo-LabSanitizedValue $previousTcp -RedactAddresses
        udp_endpoints_diagnostic =
            ConvertTo-LabSanitizedValue $previousUdp -RedactAddresses
        observability_limit = 'eSE 8.1 exposes kad_connected but not a distinct Kad2 running-state field; the gate combines continuous disconnected status with legacy NetworkKademlia=0 before/after and a live process.'
    }
    product_failures = @($productFailures | Select-Object -Unique)
    blocked_reasons = @($blockedReasons | Select-Object -Unique)
    cleanup_failures = @($cleanupFailures)
    verdict = $outcome
}
Write-LabJson -Value $artifact `
    -Path (Join-Path $evidence 'V91-K03-SUMMARY.json') | Out-Null
& (Join-Path $PSScriptRoot 'collect_report.ps1') `
    -RunDirectory $evidence -CaseId 'V91-K03' -Outcome $outcome `
    -Version $candidateInfo.version -Commit $candidateCommit `
    -Notes 'Kad6-only profile saved by the exact candidate, then opened and continuously observed with the explicitly pinned eSE 8.1 package.'

if ($outcome -eq 'FAIL') {
    throw "V91-K03 FAIL: $(@($artifact.product_failures) -join '; ')"
}
if ($outcome -eq 'BLOCKED') {
    throw "V91-K03 BLOCKED: $(@($artifact.blocked_reasons) -join '; ')"
}
Write-Host "V91-K03 PASS: $output" -ForegroundColor Green
