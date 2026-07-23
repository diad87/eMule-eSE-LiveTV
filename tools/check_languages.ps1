[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [string]$RuntimeDir = ''
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
$RepoRoot = (Resolve-Path $RepoRoot).Path
$checkRuntime = -not [string]::IsNullOrWhiteSpace($RuntimeDir)

$i18nPath = Join-Path $RepoRoot 'srchybrid\I18n.cpp'
$i18n = Get-Content -LiteralPath $i18nPath -Raw
$declared = @([regex]::Matches($i18n, '_T\("([a-z]{2}_[A-Z]{2}(?:_[A-Z]+)?)"\)') |
    ForEach-Object { $_.Groups[1].Value } |
    Sort-Object -Unique)
$declared = @($declared | Where-Object { $_ -ne 'en_US' })

$projects = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'srchybrid\lang') -Filter '*.vcxproj' -File |
    ForEach-Object { $_.BaseName } |
    Sort-Object -Unique)

$missingProjects = @($declared | Where-Object { $_ -notin $projects })
$unknownProjects = @($projects | Where-Object { $_ -notin $declared })
if ($missingProjects.Count -gt 0) { throw "Languages without project: $($missingProjects -join ', ')" }
if ($unknownProjects.Count -gt 0) { throw "Language projects not declared in I18n.cpp: $($unknownProjects -join ', ')" }

$exePath = if ($checkRuntime) { Join-Path $RuntimeDir 'emule.exe' } else { '' }
$langDir = if ($checkRuntime) { Join-Path $RuntimeDir 'lang' } else { '' }
if ($checkRuntime) {
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "Runtime executable is missing: $exePath"
    }
    if (-not (Test-Path -LiteralPath $langDir -PathType Container)) {
        throw "Runtime language directory is missing: $langDir"
    }

    $exeVersion = (Get-Item -LiteralPath $exePath).VersionInfo
    $dlls = @(Get-ChildItem -LiteralPath $langDir -Filter '*.dll' -File)
    $missingDlls = @($declared | Where-Object { -not (Test-Path -LiteralPath (Join-Path $langDir "$_.dll")) })
    if ($missingDlls.Count -gt 0) { throw "Runtime language DLLs missing: $($missingDlls -join ', ')" }

    foreach ($dll in $dlls) {
        $version = $dll.VersionInfo
        if ($version.ProductMajorPart -ne $exeVersion.ProductMajorPart -or
            $version.ProductMinorPart -ne $exeVersion.ProductMinorPart -or
            $version.ProductBuildPart -ne $exeVersion.ProductBuildPart -or
            $version.ProductPrivatePart -ne $exeVersion.ProductPrivatePart)
        {
            throw "Language DLL version mismatch: $($dll.FullName)"
        }
    }
}

Write-Host ("Language check PASS: {0} translations declared" -f $declared.Count) -ForegroundColor Green
exit 0
