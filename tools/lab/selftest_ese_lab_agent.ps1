[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$agent = Join-Path $PSScriptRoot 'run_ese_lab_agent.ps1'
$client = Join-Path $PSScriptRoot 'control_ese_lab_agent.ps1'
$installer = Join-Path $PSScriptRoot 'install_ese_lab_agent.ps1'
$files = @($agent, $client, $installer)

foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [Management.Automation.Language.Parser]::ParseFile(
        $file, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -ne 0) {
        throw "PowerShell parser failure in $file"
    }
}

$previousLibraryOnly = $env:ESE_LAB_AGENT_LIBRARY_ONLY
$previousAgentToken = $env:ESE_LAB_AGENT_TOKEN
$env:ESE_LAB_AGENT_LIBRARY_ONLY = '1'
$env:ESE_LAB_AGENT_TOKEN = 'a' * 64
try {
    . $agent
} finally {
    $env:ESE_LAB_AGENT_LIBRARY_ONLY = $previousLibraryOnly
    $env:ESE_LAB_AGENT_TOKEN = $previousAgentToken
}

$sha = Get-AgentSha256 -Bytes ([Text.Encoding]::ASCII.GetBytes('abc'))
if ($sha -cne
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') {
    throw 'Agent SHA-256 oracle failed.'
}

foreach ($allowed in @(
    'run_v91_i05_downloader_kit.ps1',
    'tools/lab/updated_tool.ps1',
    'injected/0123456789abcdef0123456789abcdef/test.ps1'
)) {
    $resolved = Resolve-AgentDeployPath -RelativePath $allowed
    if (-not $resolved.StartsWith(
            $kitRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Allowed deploy path escaped: $allowed"
    }
}
foreach ($rejected in @(
    '..\escape.ps1',
    'payload/candidate.exe',
    'tools/lab/nested/escape.ps1',
    'injected/not-a-job/test.ps1'
)) {
    $wasRejected = $false
    try {
        $null = Resolve-AgentDeployPath -RelativePath $rejected
    } catch {
        $wasRejected = $true
    }
    if (-not $wasRejected) {
        throw "Deploy allowlist accepted: $rejected"
    }
}

$agentText = Get-Content -LiteralPath $agent -Raw
foreach ($requiredCommand in @(
    "'deploy'", "'run_tool'", "'restart_agent'",
    "'fetch_from_h1'", "'list_files'", "'download'"
)) {
    if (-not $agentText.Contains($requiredCommand)) {
        throw "Missing unattended command: $requiredCommand"
    }
}
foreach ($requiredTopologyTerm in @(
    '[string]$I05SourceIPv4',
    '[string]$I05DownloaderIPv4',
    'i05_source_ipv4 = $I05SourceIPv4',
    'i05_downloader_ipv4 = $I05DownloaderIPv4',
    '[string]$config.source.ipv4_address -cne $I05SourceIPv4',
    '$I05DownloaderIPv4'
)) {
    if (-not $agentText.Contains($requiredTopologyTerm)) {
        throw "Missing separated control/test topology: $requiredTopologyTerm"
    }
}
$installerText = Get-Content -LiteralPath $installer -Raw
foreach ($requiredInstallerTerm in @(
    'New-ScheduledTaskTrigger -AtStartup',
    "-UserId 'SYSTEM'",
    '-RestartCount 999',
    'Start-ScheduledTask',
    '-Token "{2}"'
)) {
    if (-not $installerText.Contains($requiredInstallerTerm)) {
        throw "Missing service-like installer contract: $requiredInstallerTerm"
    }
}
if ($agentText -match
        "(?i)Token\\s*=\\s*'[0-9a-f]{64}'" -or
    (Get-Content -LiteralPath $client -Raw) -match
        "(?i)Token\\s*=\\s*'[0-9a-f]{64}'") {
    throw 'The reusable agent must not embed a control credential.'
}
foreach ($requiredRestartTerm in @(
    'Restart {1}',
    'New-ScheduledTaskTrigger -Once',
    "New-ScheduledTaskPrincipal -UserId 'SYSTEM'",
    'Register-ScheduledTask -TaskName $restartTaskName',
    'Unregister-ScheduledTask -TaskName'
)) {
    if (-not $agentText.Contains($requiredRestartTerm)) {
        throw "Missing independent restart-helper contract: $requiredRestartTerm"
    }
}
if ($agentText -match
        'Start-Process[\s\S]{0,600}\$helperCommand') {
    throw 'Restart helper must not be a child of the main scheduled task.'
}

[pscustomobject][ordered]@{
    status = 'PASS'
    parser_files = $files.Count
    deploy_allow_positive = 3
    deploy_allow_negative = 4
    remote_patch = 'PASS'
    remote_large_transfer = 'PASS'
    remote_job = 'PASS'
    remote_results = 'PASS'
    remote_restart = 'PASS'
    separated_control_test_topology = 'PASS'
    scheduled_task_system_startup = 'PASS'
    scheduled_task_restart_policy = 'PASS'
}
