[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$jobEnvelope = Get-Content -LiteralPath $JobRequestPath -Raw |
    ConvertFrom-Json
$jobRoot = Split-Path -Parent $JobRequestPath
if ($null -ne $jobEnvelope.PSObject.Properties['request']) {
    $request = $jobEnvelope.request
    $nonce = [string]$jobEnvelope.job_id
} else {
    $request = $jobEnvelope
    $nonce = Split-Path -Leaf $jobRoot
}
$localAddress = [string]$request.local_ipv6
$peerAddress = [string]$request.peer_ipv6
$interfaceIndex = [int]$request.interface_index
$interfaceAlias = [string]$request.interface_alias
if ([string]::IsNullOrWhiteSpace($interfaceAlias)) {
    $interfaceAlias = (
        Get-NetAdapter -InterfaceIndex $interfaceIndex -ErrorAction Stop
    ).Name
}
$durationSeconds = [Math]::Max(15, [Math]::Min(300,
        [int]$request.duration_seconds))

$parsedLocal = [Net.IPAddress]::Parse($localAddress)
$parsedPeer = [Net.IPAddress]::Parse($peerAddress)
if ($parsedLocal.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetworkV6 -or
    $parsedPeer.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetworkV6 -or
    ($parsedLocal.GetAddressBytes()[0] -band 0xfe) -ne 0xfc -or
    ($parsedPeer.GetAddressBytes()[0] -band 0xfe) -ne 0xfc) {
    throw 'La sonda T5 solo acepta direcciones ULA IPv6.'
}

$readyPath = Join-Path $jobRoot 'ula-ready.json'
$resultPath = Join-Path $jobRoot 'ula-result.json'
$ruleName = "eSE-V91-T5-$nonce"
$addressCreated = $false
$ruleCreated = $false

try {
    $existing = Get-NetIPAddress -InterfaceIndex $interfaceIndex `
        -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object IPAddress -EQ $localAddress
    if ($null -eq $existing) {
        New-NetIPAddress -InterfaceIndex $interfaceIndex `
            -IPAddress $localAddress -PrefixLength 64 `
            -AddressFamily IPv6 -Type Unicast | Out-Null
        $addressCreated = $true
    }

    New-NetFirewallRule -Name $ruleName -DisplayName $ruleName `
        -Direction Inbound -Action Allow -Protocol ICMPv6 `
        -InterfaceAlias $interfaceAlias -LocalAddress "$localAddress/128" `
        -RemoteAddress "$peerAddress/128" | Out-Null
    $ruleCreated = $true

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    do {
        $state = Get-NetIPAddress -InterfaceIndex $interfaceIndex `
            -AddressFamily IPv6 -IPAddress $localAddress `
            -ErrorAction SilentlyContinue
        if ($null -ne $state -and
            [string]$state.AddressState -in @('Preferred', 'Deprecated')) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    $ready = [ordered]@{
        schema = 'ese.v91.t5-ula-ready/v1'
        status = 'READY'
        created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        local_ipv6 = $localAddress
        peer_ipv6 = $peerAddress
        interface_index = $interfaceIndex
        interface_alias = $interfaceAlias
        address_state = [string]$state.AddressState
        expires_at_utc = [DateTimeOffset]::UtcNow.
            AddSeconds($durationSeconds).ToString('o')
    }
    $ready | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $readyPath -Encoding UTF8

    $pingOutput = & "$env:SystemRoot\System32\ping.exe" -6 -n 3 `
        -S $localAddress $peerAddress 2>&1
    $pingExitCode = $LASTEXITCODE
    $result = [ordered]@{
        schema = 'ese.v91.t5-ula-result/v1'
        status = if ($pingExitCode -eq 0) { 'PASS' } else { 'NO_PATH' }
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        local_ipv6 = $localAddress
        peer_ipv6 = $peerAddress
        interface_index = $interfaceIndex
        interface_alias = $interfaceAlias
        ping_exit_code = $pingExitCode
        ping_output = @($pingOutput | ForEach-Object { [string]$_ })
    }
    $result | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    $result | ConvertTo-Json -Depth 5

    Start-Sleep -Seconds $durationSeconds
} finally {
    if ($ruleCreated) {
        Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    }
    if ($addressCreated) {
        Remove-NetIPAddress -InterfaceIndex $interfaceIndex `
            -IPAddress $localAddress -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
}
