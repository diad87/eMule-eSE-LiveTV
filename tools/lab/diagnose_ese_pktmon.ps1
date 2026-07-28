[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Continue'
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$utf8 = New-Object Text.UTF8Encoding($false)

function Invoke-PktMonDiagnostic {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $output = @(& pktmon.exe @Arguments 2>&1 | ForEach-Object {
        [string]$_
    })
    $exitCode = $LASTEXITCODE
    [IO.File]::WriteAllLines(
        (Join-Path $jobRoot "$Name.txt"), $output, $utf8)
    return [pscustomobject][ordered]@{
        name = $Name
        arguments = @($Arguments)
        exit_code = $exitCode
        lines = $output.Count
        bytes = (Get-Item -LiteralPath (
                Join-Path $jobRoot "$Name.txt")).Length
    }
}

$commands = @(
    (Invoke-PktMonDiagnostic -Name 'pktmon-list-json' `
        -Arguments @('list', '--json')),
    (Invoke-PktMonDiagnostic -Name 'pktmon-list-text' `
        -Arguments @('list')),
    (Invoke-PktMonDiagnostic -Name 'pktmon-comp-list-json' `
        -Arguments @('comp', 'list', '--json')),
    (Invoke-PktMonDiagnostic -Name 'pktmon-comp-list-text' `
        -Arguments @('comp', 'list')),
    (Invoke-PktMonDiagnostic -Name 'pktmon-help' `
        -Arguments @('help')),
    (Invoke-PktMonDiagnostic -Name 'pktmon-list-help' `
        -Arguments @('list', 'help'))
)

Get-ComputerInfo |
    Select-Object WindowsProductName, WindowsVersion, OsBuildNumber,
        OsArchitecture |
    ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $jobRoot 'windows.json') `
        -Encoding UTF8
Get-NetAdapter -IncludeHidden |
    Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress,
        LinkSpeed, Virtual |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $jobRoot 'adapters.json') `
        -Encoding UTF8

[pscustomobject][ordered]@{
    status = 'PASS'
    job_id = (Get-Content -LiteralPath $JobRequestPath -Raw |
        ConvertFrom-Json).job_id
    commands = $commands
} | ConvertTo-Json -Depth 6 -Compress
