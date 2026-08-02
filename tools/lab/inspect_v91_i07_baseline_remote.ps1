[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$request = Get-Content -LiteralPath $JobRequestPath -Raw | ConvertFrom-Json
$wrapper = $request.PSObject.Properties['request']
if ($null -ne $wrapper) { $request = $wrapper.Value }
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$resultPath = Join-Path $jobRoot 'result.json'
$status = 'LAB_BLOCKED'
$errorCode = ''
$emuleCount = -1
$tcpEvidence = @()
$udpEvidence = @()

try {
    $nonce = ([string]$request.nonce).ToLowerInvariant()
    $role = ([string]$request.role).ToLowerInvariant()
    $tcpPorts = @($request.tcp_ports | ForEach-Object { [int]$_ })
    $udpPorts = @($request.udp_ports | ForEach-Object { [int]$_ })
    $allPorts = @($tcpPorts) + @($udpPorts)
    if ([string]$request.schema -cne 'ese.v91.i07-baseline-request/v1' -or
        $nonce -notmatch '^[0-9a-f]{32}$' -or
        $role -notin @('source', 'viewer') -or
        $tcpPorts.Count -lt 2 -or $udpPorts.Count -ne 1 -or
        @($allPorts | Where-Object { $_ -lt 1024 -or $_ -gt 65535 }).
            Count -ne 0 -or
        @($allPorts | Select-Object -Unique).Count -ne $allPorts.Count) {
        throw 'Invalid I07 pre-mutation baseline contract.'
    }
    $allProcesses = @(Get-Process -ErrorAction Stop)
    $allTcp = @(Get-NetTCPConnection -ErrorAction Stop)
    $allUdp = @(Get-NetUDPEndpoint -ErrorAction Stop)
    $emuleCount = @($allProcesses | Where-Object {
            [string]$_.ProcessName -ieq 'emule'
        }).Count
    $tcpEvidence = @($tcpPorts | ForEach-Object {
        $port = [int]$_
        $owners = @($allTcp | Where-Object {
                [int]$_.LocalPort -eq $port
            } | Select-Object -ExpandProperty OwningProcess -Unique)
        [pscustomobject][ordered]@{
            port = $_
            available = $owners.Count -eq 0
            owner_count = $owners.Count
        }
    })
    $udpEvidence = @($udpPorts | ForEach-Object {
        $port = [int]$_
        $owners = @($allUdp | Where-Object {
                [int]$_.LocalPort -eq $port
            } | Select-Object -ExpandProperty OwningProcess -Unique)
        [pscustomobject][ordered]@{
            port = $_
            available = $owners.Count -eq 0
            owner_count = $owners.Count
        }
    })
    if ($emuleCount -ne 0) {
        throw 'A pre-existing eMule process contaminates the I07 baseline.'
    }
    if (@($tcpEvidence | Where-Object { -not [bool]$_.available }).Count -ne
            0 -or
        @($udpEvidence | Where-Object { -not [bool]$_.available }).Count -ne
            0) {
        throw 'One or more nonce-planned I07 ports are already occupied.'
    }
    $status = 'PREFLIGHT_PASS'
} catch {
    $errorCode = 'BASELINE_NOT_CLEAN_OR_UNAVAILABLE'
}

$result = [ordered]@{
    schema = 'ese.v91.i07-baseline-result/v1'
    case_id = 'V91-I07'
    status = $status
    role = if ($null -ne $request.PSObject.Properties['role']) {
        [string]$request.role
    } else { '' }
    nonce = if ($null -ne $request.PSObject.Properties['nonce']) {
        [string]$request.nonce
    } else { '' }
    sampled_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    emule_process_count = $emuleCount
    tcp_ports = $tcpEvidence
    udp_ports = $udpEvidence
    error_code = if ($status -ceq 'PREFLIGHT_PASS') {
        $null
    } else { $errorCode }
}
$temporary = $resultPath + '.new'
$result | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $temporary -Encoding UTF8
Move-Item -LiteralPath $temporary -Destination $resultPath -Force
if ($status -ceq 'PREFLIGHT_PASS') { exit 0 }
exit 2
