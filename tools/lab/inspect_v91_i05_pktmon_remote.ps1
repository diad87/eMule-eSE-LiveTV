[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Continue'
$filters = @(& pktmon.exe filter list 2>&1)
$filtersExit = $LASTEXITCODE
$session = @(& logman.exe query -ets PktMon 2>&1)
$sessionExit = $LASTEXITCODE
$counters = @(& pktmon.exe counters 2>&1)
$countersExit = $LASTEXITCODE

[pscustomobject][ordered]@{
    schema = 'ese.v91.i05-pktmon-inspection/v1'
    filter_exit_code = $filtersExit
    filters = $filters
    session_exit_code = $sessionExit
    session = $session
    counters_exit_code = $countersExit
    counters = $counters
} | ConvertTo-Json -Depth 5 -Compress
