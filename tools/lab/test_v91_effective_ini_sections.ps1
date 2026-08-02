[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$targets = @(
    [pscustomobject]@{
        path = 'test_v91_i03_route_selection.ps1'
        functions = @(
            'Set-I03IsolatedPreferences',
            'Enable-I03ControlledEd2kProfile'
        )
    },
    [pscustomobject]@{
        path = 'test_v91_i04_fallback.ps1'
        functions = @(
            'Set-I04IsolatedPreferences',
            'Enable-I04ControlledEd2kProfile'
        )
    },
    [pscustomobject]@{
        path = 'test_v91_d01_dual_dns.ps1'
        functions = @(
            'Set-D01IsolatedPreferences',
            'Enable-D01ControlledEd2kProfile'
        )
    }
)
$effectiveKeys = @(
    'NetworkED2K',
    'CryptLayerRequested',
    'CryptLayerRequired',
    'CryptLayerSupported'
)
$results = [Collections.Generic.List[object]]::new()

foreach ($target in $targets) {
    $path = Join-Path $PSScriptRoot $target.path
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) {
        throw "$($target.path) has $($parseErrors.Count) parser error(s)."
    }
    foreach ($functionName in $target.functions) {
        $definitions = @(
            $ast.FindAll({
                    param($node)
                    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $functionName
                }, $true)
        )
        if ($definitions.Count -ne 1) {
            throw "Expected one $functionName, found $($definitions.Count)."
        }
        $text = $definitions[0].Extent.Text
        $blocks = @(
            [regex]::Matches(
                $text,
                '(?ms)foreach\s*\(\$entry\s+in\s+\(\[ordered\]@\{' +
                '(?<body>.*?)\}\)\.GetEnumerator\(\)\)\s*\{' +
                '.*?Set-LabIniValue\s+.*?-Section\s+''(?<section>[^'']+)''')
        )
        foreach ($key in $effectiveKeys) {
            $owners = @(
                $blocks | Where-Object {
                    $_.Groups['body'].Value -match
                        ('(?m)^\s*' + [regex]::Escape($key) + '\s*=')
                }
            )
            if ($owners.Count -ne 1 -or
                $owners[0].Groups['section'].Value -cne 'Connection') {
                $sections = @(
                    $owners | ForEach-Object {
                        $_.Groups['section'].Value
                    }
                ) -join ','
                throw (
                    "$functionName must write $key exactly once to " +
                    "[Connection]; found $($owners.Count) in '$sections'."
                )
            }
        }
        $results.Add([pscustomobject][ordered]@{
                file = $target.path
                function = $functionName
                effective_section = 'Connection'
                verified_keys = $effectiveKeys.Count
            })
    }
}

[pscustomobject][ordered]@{
    schema = 'ese.v91.effective-ini-sections-selftest/v1'
    status = 'PASS'
    checked_functions = $results.Count
    checks = @($results)
} | ConvertTo-Json -Depth 6
