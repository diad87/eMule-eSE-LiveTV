[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$request = Get-Content -LiteralPath $JobRequestPath -Raw |
    ConvertFrom-Json
if ([string]$request.schema -cne 'ese.lab.agent-job-request/v1' -or
    [string]$request.request.challenge -cne 'unattended-roundtrip') {
    throw 'Remote job request contract failed.'
}
[pscustomobject][ordered]@{
    status = 'PASS'
    job_id = [string]$request.job_id
    challenge = [string]$request.request.challenge
} | ConvertTo-Json -Compress
