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
$targetAddress = '2606:4700:4700::1111'
$targetPort = 42424
$streamKey = '00112233445566778899AABBCCDDEEFF'
$package = (Resolve-Path -LiteralPath $PackagePath).Path
$output = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $output) {
    throw "OutputRoot already exists; refusing to mix evidence: $output"
}
$nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
$results = New-Object Collections.Generic.List[object]

function Stop-TestProcess {
    param([AllowNull()][Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try { $Process.Refresh() } catch { return }
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $null = $Process.WaitForExit(10000)
    }
}

function Wait-Api {
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
            Start-Sleep -Milliseconds 250
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "eMule API did not become ready on port $Port"
}

function Set-ProxyPreferences {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$Type,
        [Parameter(Mandatory = $true)][int]$Port
    )
    foreach ($section in 'eMule', 'Proxy') {
        Set-LabIniValue -Path $Path -Section $section `
            -Key 'ProxyEnablePassword' -Value '0'
        Set-LabIniValue -Path $Path -Section $section `
            -Key 'ProxyEnableProxy' -Value '1'
        Set-LabIniValue -Path $Path -Section $section `
            -Key 'ProxyName' -Value '127.0.0.1'
        Set-LabIniValue -Path $Path -Section $section `
            -Key 'ProxyPort' -Value ([string]$Port)
        Set-LabIniValue -Path $Path -Section $section `
            -Key 'ProxyType' -Value ([string]$Type)
    }
    Set-LabIniValue -Path $Path -Section 'Connection' `
        -Key 'KadNetworkMask' -Value '0'
    Set-LabIniValue -Path $Path -Section 'eMule' `
        -Key 'AutoConnect' -Value '0'
}

function Invoke-ProxyScenario {
    param(
        [Parameter(Mandatory = $true)][string]$CaseId,
        [Parameter(Mandatory = $true)][ValidateSet('socks5', 'http', 'socks4')]
        [string]$Mode,
        [Parameter(Mandatory = $true)][int]$ProxyType,
        [Parameter(Mandatory = $true)][int]$PortOffset
    )
    $runId = $CaseId.ToLowerInvariant()
    & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
        -SourcePackage $package -OutputRoot $nodes -RunId $runId `
        -PortOffset $PortOffset
    $node = Join-Path $nodes "$runId-a"
    $proxyPort = 32000 + $PortOffset
    $tcpPort = 4662 + $PortOffset
    $udpPort = 4672 + $PortOffset
    $webPort = 4711 + $PortOffset
    Set-ProxyPreferences -Path (Join-Path $node 'config\preferences.ini') `
        -Type $ProxyType -Port $proxyPort

    $capture = Join-Path $evidence "$CaseId-proxy-capture.json"
    $proxyStdout = Join-Path $evidence "$CaseId-proxy.stdout.log"
    $proxyStderr = Join-Path $evidence "$CaseId-proxy.stderr.log"
    $proxyProcess = $null
    $emuleProcess = $null
    try {
        $timeoutMs = if ($Mode -eq 'socks4') { 6000 } else { 12000 }
        $proxyProcess = Start-Process -FilePath 'node.exe' `
            -ArgumentList @(
                (Join-Path $PSScriptRoot 'mock_proxy_capture.js'),
                "--mode=$Mode",
                "--port=$proxyPort",
                "--out=$capture",
                "--timeout-ms=$timeoutMs"
            ) -WorkingDirectory $PSScriptRoot -RedirectStandardOutput $proxyStdout `
            -RedirectStandardError $proxyStderr -WindowStyle Hidden -PassThru
        $readyDeadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            if ($proxyProcess.HasExited) {
                throw "Mock proxy exited before readiness with code $($proxyProcess.ExitCode)"
            }
            if ((Test-Path -LiteralPath $proxyStdout) -and
                (Get-Content -LiteralPath $proxyStdout -Raw) -match '^READY ') {
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $readyDeadline)

        $emuleProcess = Start-Process -FilePath (Join-Path $node 'emule.exe') `
            -ArgumentList @(
                '--portable',
                '--ignoreinstances',
                '--headless',
                "--metrics-port=$webPort",
                "--tcp-port=$tcpPort",
                "--udp-port=$udpPort"
            ) -WorkingDirectory $node -WindowStyle Hidden -PassThru
        $null = Wait-Api -Port $webPort -Process $emuleProcess
        $encodedAddress = [Uri]::EscapeDataString($targetAddress)
        $uri = "http://127.0.0.1:$webPort/api/live/direct_join" +
            "?key=$streamKey&ip=$encodedAddress&port=$targetPort&title=ProxyV6"
        $apiStatus = 200
        try {
            $apiResponse = Invoke-RestMethod -Uri $uri -TimeoutSec 10
        } catch {
            if ($null -eq $_.Exception.Response) { throw }
            $apiStatus = [int]$_.Exception.Response.StatusCode
            $responseBody = [string]$_.ErrorDetails.Message
            if ([string]::IsNullOrWhiteSpace($responseBody)) {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object IO.StreamReader($stream)
                try { $responseBody = $reader.ReadToEnd() }
                finally {
                    $reader.Dispose()
                    $stream.Dispose()
                }
            }
            if ([string]::IsNullOrWhiteSpace($responseBody)) { throw }
            $apiResponse = $responseBody | ConvertFrom-Json
        }

        $captureDeadline = [DateTime]::UtcNow.AddSeconds(20)
        do {
            if (Test-Path -LiteralPath $capture) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $captureDeadline)
        if (-not (Test-Path -LiteralPath $capture)) {
            throw "Mock proxy did not produce capture for $CaseId"
        }
        $proxyCapture = Get-Content -LiteralPath $capture -Raw | ConvertFrom-Json
        $expectedAddressHex = ([Net.IPAddress]::Parse($targetAddress).GetAddressBytes() |
            ForEach-Object { $_.ToString('x2') }) -join ''
        $httpAuthorityCorrect = $false
        if ($Mode -eq 'http') {
            $httpMatch = [regex]::Match(
                [string]$proxyCapture.request_line,
                '^CONNECT \[([^\]]+)\]:(\d+) HTTP/1\.1$'
            )
            $httpAuthorityCorrect = $httpMatch.Success -and
                [Net.IPAddress]::Parse($httpMatch.Groups[1].Value).Equals(
                    [Net.IPAddress]::Parse($targetAddress)
                ) -and
                [int]$httpMatch.Groups[2].Value -eq $targetPort
        }

        $pass = switch ($CaseId) {
            'V91-P01' {
                [int]$proxyCapture.version -eq 5 -and
                [int]$proxyCapture.command -eq 1 -and
                [int]$proxyCapture.atyp -eq 4 -and
                [string]$proxyCapture.destination_hex -eq $expectedAddressHex -and
                [int]$proxyCapture.destination_port -eq $targetPort
            }
            'V91-P02' {
                $httpAuthorityCorrect
            }
            'V91-P03' {
                [bool]$proxyCapture.no_connection -and
                $apiStatus -eq 400 -and
                -not [bool]$apiResponse.success -and
                -not [bool]$apiResponse.joined -and
                -not [bool]$apiResponse.dialed -and
                [string]$apiResponse.error -eq 'ipv6_not_supported_by_socks4'
            }
            default { $false }
        }
        $artifact = [ordered]@{
            schema = 'ese.v91.proxy-case/v1'
            case_id = $CaseId
            candidate_commit = $candidateCommit
            captured_at_utc = Get-LabUtcTimestamp
            target = [ordered]@{
                family = 'IPv6'
                address_hex = $expectedAddressHex
                port = $targetPort
            }
            api_status = $apiStatus
            api_response = ConvertTo-LabSanitizedValue $apiResponse -RedactAddresses
            proxy_capture = ConvertTo-LabSanitizedValue $proxyCapture -RedactAddresses
            verdict = if ($pass) { 'PASS' } else { 'FAIL' }
        }
        Write-LabJson -Value $artifact `
            -Path (Join-Path $evidence "$CaseId-summary.json") | Out-Null
        $results.Add([pscustomobject]@{
            id = $CaseId
            verdict = if ($pass) { 'PASS' } else { 'FAIL' }
        })
    } finally {
        Stop-TestProcess -Process $emuleProcess
        Stop-TestProcess -Process $proxyProcess
    }
}

Invoke-ProxyScenario -CaseId 'V91-P01' -Mode 'socks5' `
    -ProxyType 3 -PortOffset 17000
Invoke-ProxyScenario -CaseId 'V91-P02' -Mode 'http' `
    -ProxyType 5 -PortOffset 17200
Invoke-ProxyScenario -CaseId 'V91-P03' -Mode 'socks4' `
    -ProxyType 1 -PortOffset 17400

$overall = if (@($results | Where-Object { $_.verdict -ne 'PASS' }).Count -eq 0) {
    'PASS'
} else {
    'FAIL'
}
$summary = [ordered]@{
    schema = 'ese.v91.proxy-summary/v1'
    candidate_commit = $candidateCommit
    generated_at_utc = Get-LabUtcTimestamp
    target_family = 'IPv6'
    cases = $results
    verdict = $overall
}
Write-LabJson -Value $summary `
    -Path (Join-Path $evidence 'V91-PROXY-SUMMARY.json') | Out-Null
& (Join-Path $PSScriptRoot 'collect_report.ps1') `
    -RunDirectory $evidence -CaseId 'V91-PROXY' -Outcome $overall `
    -Version '9.1.0-beta.3' -Commit $candidateCommit `
    -Notes 'Runtime SOCKS5, HTTP CONNECT and SOCKS4 IPv6 behavior through loopback mock proxies.'

if ($overall -ne 'PASS') {
    throw 'V91 IPv6 proxy gate failed'
}
Write-Host "V91 IPv6 proxy gate PASS: $output" -ForegroundColor Green
