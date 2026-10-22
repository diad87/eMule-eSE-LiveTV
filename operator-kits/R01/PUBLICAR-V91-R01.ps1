[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$statusPath = 'C:\tmp\V91-R01-operator-status.json'
$wrapperPublicPath = 'C:\tmp\V91-R01-wrapper-public.json'
$startedAt = [DateTimeOffset]::UtcNow

function Write-OperatorStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)][int]$Progress,
        [Parameter(Mandatory = $true)][string]$Status,
        [string]$CampaignStatus = '',
        [AllowNull()]$ExitCode = $null,
        [AllowNull()][string]$ErrorSha256 = $null
    )
    $value = [ordered]@{
        schema = 'ese.v91.r01-operator-status/v1'
        phase = $Phase
        progress_percent = $Progress
        status = $Status
        campaign_status = $CampaignStatus
        exit_code = $ExitCode
        error_sha256 = $ErrorSha256
        started_at_utc = $startedAt.ToString('o')
        updated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $temporary = $statusPath + '.new'
    [IO.File]::WriteAllText(
        $temporary,
        (($value | ConvertTo-Json -Depth 5) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $statusPath -Force
}

function Get-TextSha256 {
    param([Parameter(Mandatory = $true)][string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) |
                    ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function Get-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally {
        $identity.Dispose()
    }
}

function Test-ExactWindowRestored {
    $statePath = Join-Path $windowRoot 'state.json'
    $resultPath = Join-Path $windowRoot 'restore-result.json'
    if ((Test-Path -LiteralPath $tailscaleEnvPath) -or
        $null -ne (Get-ScheduledTask -TaskName $rollbackTaskName `
            -ErrorAction SilentlyContinue) -or
        -not (Test-Path -LiteralPath $statePath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        return $false
    }
    try {
        $result = Get-Content -LiteralPath $resultPath -Raw |
            ConvertFrom-Json
        return [string]$result.schema -ceq
                'ese.r01.tailscale-upnp-restore/v1' -and
            [string]$result.status -ceq 'RESTORED' -and
            [bool]$result.original_state_restored -and
            [bool]$result.service_running -and
            [bool]$result.backend_running -and
            [bool]$result.self_online
    } catch {
        return $false
    }
}

function Quote-Argument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value.Contains('"')) { throw 'Unsupported quote in an argument.' }
    return '"' + $Value + '"'
}

if (-not (Get-IsAdministrator)) {
    $powerShell = Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', (Quote-Argument -Value $PSCommandPath)) -join ' '
    $elevated = Start-Process -FilePath $powerShell -ArgumentList $arguments `
        -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    exit [int]$elevated.ExitCode
}

$startWindow = 'C:\tmp\Start-R01TailscaleUpnpWindow.ps1'
$restoreWindow = 'C:\tmp\Restore-R01TailscaleUpnp.ps1'
$wrapper = 'C:\tmp\Invoke-V91R01FailSafe.ps1'
$controller =
    'C:\tmp\v91-ai-i03\tools\lab\control_ese_lab_smallframe_agent.ps1'
$publicAddressProbe = 'C:\tmp\Get-R01PublicAddressRemote.ps1'
$publicAddressRequest = 'C:\tmp\r01-public-ip-request.json'
$publicAddressEvidence = 'C:\tmp\v91-r01-public-ip-remote.json'
$privateOutputRoot =
    'C:\tmp\v91-ai-i03\lab-runs\v91-r01-wrapper'
$powerShell = Join-Path $env:SystemRoot `
    'System32\WindowsPowerShell\v1.0\powershell.exe'
$windowRoot = 'C:\ProgramData\eSE-R01-Tailscale-UPnP'
$windowArchiveRoot =
    'C:\ProgramData\eSE-R01-Tailscale-UPnP-archive'
$tailscaleEnvPath = 'C:\ProgramData\Tailscale\tailscaled-env.txt'
$rollbackTaskName = 'eSE R01 Restore Tailscale UPnP'

$expectedHashes = [ordered]@{
    $startWindow =
        'dd72d59213f0a469f0fc073e7ea98ad536ceb970423242a4e9e969111649a09f'
    $restoreWindow =
        '714a45883e31c305124bc5815a0b8a82c3e5bb9f87545b72ad071e16b5af1bd5'
    $wrapper =
        '08167fcd7bab21281eb52bf408f22829ff367dd6240bb61efb10736cbb144178'
    $controller =
        '027f6374f20a8d81acf40816675ad8631e512f63f25f09d80b9ae95520963213'
    $publicAddressProbe =
        '256c831f2686accf328b223629ad3f7697826cd97c4ebbf1fb63190d99336412'
    $publicAddressRequest =
        '805df9f182648843e8ce5009e27c14a4298d60b9517bba1a377a1883718996c1'
    'C:\tmp\v91-ai-i03\tools\lab\invoke_v91_r01_campaign.ps1' =
        '6a4bac06bec27848de4d7d7313200115138cfdb423c624c9f66eac736b342ead'
    'C:\tmp\v91-ai-i03\tools\lab\common.ps1' =
        '92a95763cd00d0acee96f9e50bdf6022f09e202fb342a8552515931250ea3db3'
    'C:\tmp\v91-ai-i03\tools\lab\v91_r01_upnp.ps1' =
        'ca7d6bb0162699b8fddcffa7af686b05901f6e065d1ffca0aae5c35d41d03e25'
    'C:\tmp\Get-R01FreshSidRemote.ps1' =
        'd2021221afcc8cf4f85a2d107c13f372989499ff345d5af5d053e7e4d2f4ffcb'
    'C:\tmp\v91-ai-i03\tools\lab\run_v91_r01_remote.ps1' =
        'a34d19a94ce20d1d704c18e6aa258efd619124a701e7e25a93e336928d786c19'
    'C:\tmp\v91-ai-i03\tools\lab\run_v91_r01_server.ps1' =
        '6634e274d02cbd2d528e3f722753901a25ff84ba3b6559a44e8434a4f6beece5'
    'C:\tmp\v91-ai-i03\tools\lab\run_v91_r01_wifi_watchdog.ps1' =
        '1d7d2af95ab39d4fc5c806be53a909b7795cad3c389319b737b0e67e5ae1d7fb'
}

$wrapperOwnsRestore = $false
$terminalExitCode = 60
try {
    Write-OperatorStatus -Phase 'VERIFYING' -Progress 5 -Status 'RUNNING'
    foreach ($entry in $expectedHashes.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Key -PathType Leaf)) {
            throw 'A pinned R01 input is missing.'
        }
        $actual = (Get-FileHash -LiteralPath $entry.Key -Algorithm SHA256).
            Hash.ToLowerInvariant()
        if ($actual -cne [string]$entry.Value) {
            throw 'A pinned R01 input changed after audit.'
        }
        $tokens = $null
        $errors = $null
        if ([IO.Path]::GetExtension([string]$entry.Key) -ceq '.ps1') {
            $null = [Management.Automation.Language.Parser]::ParseFile(
                [string]$entry.Key, [ref]$tokens, [ref]$errors)
            if ($errors.Count -ne 0) {
                throw 'A pinned R01 script has parse errors.'
            }
        }
    }

    if (Test-Path -LiteralPath $windowRoot) {
        $statePath = Join-Path $windowRoot 'state.json'
        $restoreResultPath = Join-Path $windowRoot 'restore-result.json'
        if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
            throw 'Previous Tailscale window has no owned rollback state.'
        }
        if (-not (Test-ExactWindowRestored)) {
            & $restoreWindow -Reason r01_terminal | Out-Null
            if (-not (Test-ExactWindowRestored)) {
                throw 'Previous Tailscale window could not be restored exactly.'
            }
        }
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $restore = Get-Content -LiteralPath $restoreResultPath -Raw |
            ConvertFrom-Json
        if ([string]$state.schema -cne
                'ese.r01.tailscale-upnp-window/v1' -or
            [bool]$state.original_exists -or
            [string]$restore.schema -cne
                'ese.r01.tailscale-upnp-restore/v1' -or
            [string]$restore.status -cne 'RESTORED' -or
            -not [bool]$restore.original_state_restored -or
            -not [bool]$restore.service_running -or
            -not [bool]$restore.backend_running -or
            -not [bool]$restore.self_online) {
            throw 'Previous Tailscale window did not prove exact restoration.'
        }
        $archiveBase = [IO.Path]::GetFullPath($windowArchiveRoot).
            TrimEnd('\')
        $sourceFull = [IO.Path]::GetFullPath($windowRoot).TrimEnd('\')
        if ($sourceFull -cne
            [IO.Path]::GetFullPath(
                'C:\ProgramData\eSE-R01-Tailscale-UPnP').TrimEnd('\')) {
            throw 'Unexpected Tailscale window source path.'
        }
        $null = New-Item -ItemType Directory -Path $archiveBase -Force
        $archiveTarget = Join-Path $archiveBase (
            [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
            [Guid]::NewGuid().ToString('N'))
        $targetFull = [IO.Path]::GetFullPath($archiveTarget)
        if (-not $targetFull.StartsWith(
                $archiveBase + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Unexpected Tailscale archive target path.'
        }
        Move-Item -LiteralPath $sourceFull -Destination $targetFull `
            -ErrorAction Stop
    }

    Write-OperatorStatus -Phase 'TAILSCALE_WINDOW' -Progress 15 `
        -Status 'RUNNING'
    & $startWindow -RollbackMinutes 30 | Out-Null

    Write-OperatorStatus -Phase 'REFRESHING_NETWORK_EVIDENCE' `
        -Progress 25 -Status 'RUNNING'
    $agent = @{
        AgentIPv4 = '100.85.133.28'
        Port = 8016
        TimeoutMilliseconds = 15000
    }
    $null = & $controller -Command ping @agent
    $jobId = [Guid]::NewGuid().ToString('N')
    $remoteProbe = "injected/$jobId/Get-R01PublicAddressRemote.ps1"
    $null = & $controller -Command upload @agent `
        -SourcePath $publicAddressProbe -RemotePath $remoteProbe
    $null = & $controller -Command run @agent -JobId $jobId `
        -RemotePath $remoteProbe -JobRequestPath $publicAddressRequest
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 500
        $job = & $controller -Command job @agent -JobId $jobId
    } while ([string]$job.state -cne 'COMPLETE' -and
        [DateTimeOffset]::UtcNow -lt $deadline)
    if ([string]$job.state -cne 'COMPLETE' -or
        [int]$job.exit_code -ne 0) {
        throw 'Fresh network-evidence job did not complete successfully.'
    }
    $null = & $controller -Command download @agent `
        -RemotePath "jobs/$jobId/result.json" `
        -OutputPath $publicAddressEvidence
    $evidence = Get-Content -LiteralPath $publicAddressEvidence -Raw |
        ConvertFrom-Json
    $observed = [DateTimeOffset]::MinValue
    if ([string]$evidence.schema -cne
            'ese.v91.r01-public-address-private/v1' -or
        [string]$evidence.status -cne 'PASS' -or
        -not [DateTimeOffset]::TryParse(
            [string]$evidence.observed_at_utc, [ref]$observed) -or
        ([DateTimeOffset]::UtcNow - $observed).TotalSeconds -gt 60) {
        throw 'Fresh network evidence failed admission before the wrapper.'
    }
    $evidenceHash = (Get-FileHash -LiteralPath $publicAddressEvidence `
            -Algorithm SHA256).Hash

    Remove-Item -LiteralPath $wrapperPublicPath -Force `
        -ErrorAction SilentlyContinue
    Write-OperatorStatus -Phase 'FORMAL_CAMPAIGN' -Progress 40 `
        -Status 'RUNNING'
    $wrapperArguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', (Quote-Argument -Value $wrapper),
        '-PrivatePublicAddressEvidencePath',
            (Quote-Argument -Value $publicAddressEvidence),
        '-ExpectedPublicAddressEvidenceSha256', $evidenceHash,
        '-PrivateOutputRoot', (Quote-Argument -Value $privateOutputRoot),
        '-NoSelfElevation') -join ' '
    $wrapperProcess = Start-Process -FilePath $powerShell `
        -ArgumentList $wrapperArguments -WindowStyle Hidden -PassThru
    $wrapperOwnsRestore = $true
    $wrapperProcess.WaitForExit()

    if (-not (Test-ExactWindowRestored)) {
        $wrapperOwnsRestore = $false
        throw 'The formal wrapper did not leave an exact restored window.'
    }

    if (-not (Test-Path -LiteralPath $wrapperPublicPath -PathType Leaf)) {
        $wrapperOwnsRestore = $false
        throw 'The formal wrapper did not publish its terminal projection.'
    }
    $public = Get-Content -LiteralPath $wrapperPublicPath -Raw |
        ConvertFrom-Json
    if ([string]$public.schema -cne
            'ese.v91.r01-failsafe-wrapper-public/v1' -or
        -not [bool]$public.restore_completed) {
        $wrapperOwnsRestore = $false
        throw 'The formal wrapper did not prove terminal restoration.'
    }
    $terminalExitCode = [int]$wrapperProcess.ExitCode
    if ([int]$public.final_exit_code -ne $terminalExitCode -or
        ([string]$public.status -ceq 'CAMPAIGN_PASS' -and
            ($terminalExitCode -ne 0 -or
                [string]$public.campaign_status -cne 'PASS')) -or
        ([string]$public.status -cne 'CAMPAIGN_PASS' -and
            $terminalExitCode -eq 0)) {
        throw 'The formal wrapper terminal projection is incoherent.'
    }
    Write-OperatorStatus -Phase 'TERMINAL' -Progress 100 `
        -Status ([string]$public.status) `
        -CampaignStatus ([string]$public.campaign_status) `
        -ExitCode $terminalExitCode
} catch {
    $errorText = $_ | Out-String
    $errorHash = Get-TextSha256 -Text $errorText
    if (-not $wrapperOwnsRestore -and
        (Test-Path -LiteralPath (Join-Path $windowRoot 'state.json') `
            -PathType Leaf)) {
        try { & $restoreWindow -Reason apply_failure | Out-Null } catch {}
    }
    Write-OperatorStatus -Phase 'TERMINAL' -Progress 100 `
        -Status 'OPERATOR_BLOCKED' -ExitCode 60 -ErrorSha256 $errorHash
    $terminalExitCode = 60
} finally {
    $stateStillExists = Test-Path -LiteralPath (
        Join-Path $windowRoot 'state.json') -PathType Leaf
    $taskStillArmed = $null -ne (Get-ScheduledTask `
        -TaskName $rollbackTaskName -ErrorAction SilentlyContinue)
    $envStillArmed = Test-Path -LiteralPath $tailscaleEnvPath
    if (($stateStillExists -and -not (Test-ExactWindowRestored)) -or
        $taskStillArmed -or $envStillArmed) {
        try { & $restoreWindow -Reason apply_failure | Out-Null } catch {}
    }
    $finalStateExists = Test-Path -LiteralPath (
        Join-Path $windowRoot 'state.json') -PathType Leaf
    $finalTaskArmed = $null -ne (Get-ScheduledTask `
        -TaskName $rollbackTaskName -ErrorAction SilentlyContinue)
    $finalEnvArmed = Test-Path -LiteralPath $tailscaleEnvPath
    if (($finalStateExists -and -not (Test-ExactWindowRestored)) -or
        $finalTaskArmed -or $finalEnvArmed) {
        $terminalExitCode = 61
        Write-OperatorStatus -Phase 'TERMINAL' -Progress 100 `
            -Status 'RESTORE_BLOCKED' -ExitCode $terminalExitCode
    }
}

exit $terminalExitCode
