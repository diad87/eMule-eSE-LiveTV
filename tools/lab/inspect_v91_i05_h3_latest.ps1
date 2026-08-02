[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$jobsRoot = Split-Path -Parent $jobRoot
$kitRoot = Split-Path -Parent $jobsRoot
$runsRoot = Join-Path $kitRoot 'runs'

$latest = Get-ChildItem -LiteralPath $runsRoot -Directory -ErrorAction Stop |
    Where-Object { $_.Name -like 'v91-i05-h3-*' } |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1

if ($null -eq $latest) {
    throw 'No se encontro ninguna ejecucion V91-I05 H3.'
}

$files = @(Get-ChildItem -LiteralPath $latest.FullName -File -Recurse |
    Sort-Object FullName |
    ForEach-Object {
        [pscustomobject][ordered]@{
            relative_path = $_.FullName.Substring(
                $kitRoot.Length
            ).TrimStart('\').Replace('\', '/')
            bytes = [Int64]$_.Length
            last_write_utc = $_.LastWriteTimeUtc.ToString('o')
        }
    })

[pscustomobject][ordered]@{
    schema = 'ese.v91.i05-h3-inspection/v1'
    run_relative_path = $latest.FullName.Substring(
        $kitRoot.Length
    ).TrimStart('\').Replace('\', '/')
    last_write_utc = $latest.LastWriteTimeUtc.ToString('o')
    files = $files
} | ConvertTo-Json -Depth 5 -Compress
