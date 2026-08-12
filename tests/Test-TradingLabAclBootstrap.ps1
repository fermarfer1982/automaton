$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$helperPath = Join-Path $workspace 'scripts\TradingLabAclBootstrap.ps1'
$templatePath = Join-Path $workspace 'config\trading.bootstrap-observe-only.yaml'
. $helperPath

$helperSource = [System.IO.File]::ReadAllText($helperPath)
$allCompatibleScripts = @(
    (Join-Path $workspace 'scripts\TradingLabAclBootstrap.ps1'),
    (Join-Path $workspace 'scripts\Initialize-TradingLabAcl.ps1'),
    (Join-Path $workspace 'scripts\Apply-TradingLabAclGate.ps1')
)
foreach ($script in $allCompatibleScripts) {
    $source = [System.IO.File]::ReadAllText($script)
    if ($source.Contains('RandomNumberGenerator]::Fill')) {
        throw "Windows PowerShell 5.1-incompatible RNG dependency found: $script"
    }
}
foreach ($required in @(
    '[System.Security.Cryptography.RandomNumberGenerator]::Create()',
    '$rng.GetBytes($bytes)',
    '$rng.Dispose()',
    'New-Object byte[] 32',
    '[System.IO.FileMode]::CreateNew'
)) {
    if (-not $helperSource.Contains($required)) {
        throw "CSPRNG implementation lacks required boundary: $required"
    }
}
foreach ($forbidden in @('Get-Random', 'New-Guid', 'Write-Host $encoded', 'Write-Output $encoded')) {
    if ($helperSource.Contains($forbidden)) {
        throw "Secret generation contains forbidden behavior: $forbidden"
    }
}

function New-TestRoot([string] $CaseName) {
    $base = Join-Path ([System.IO.Path]::GetTempPath()) (
        'automaton-acl-bootstrap-' + $CaseName + '-' + [Guid]::NewGuid().ToString('N')
    )
    New-Item -ItemType Directory -Path $base | Out-Null
    return $base
}

function Remove-TestRoot([string] $Path) {
    if (
        $Path.StartsWith([System.IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path $Path -Leaf).StartsWith('automaton-acl-bootstrap-')
    ) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    } else {
        throw "Refusing unsafe test cleanup target: $Path"
    }
}

$caseA = New-TestRoot 'a'
try {
    $lab = Join-Path $caseA 'lab'
    $state = Join-Path $caseA 'agent\.automaton'
    $result = Initialize-TradingLabBootstrapState $lab $state $templatePath
    if (-not $result.config_created -or -not $result.ipc_secret_created) {
        throw 'Case A did not create a fresh bootstrap.'
    }
    [void](Assert-ExactBootstrapConfig (Join-Path $lab 'control\trading.yaml') $templatePath)
    $caseASecretPath = Join-Path $lab 'ipc\automaton.key'
    [void](Assert-ValidIpcSecret $caseASecretPath)
    $caseASecret = [System.IO.File]::ReadAllText($caseASecretPath, [System.Text.Encoding]::ASCII)
    try {
        if (($result | ConvertTo-Json -Depth 5).Contains($caseASecret)) {
            throw 'Case A exposed the IPC secret through structured output.'
        }
    } finally {
        $caseASecret = $null
    }
} finally {
    Remove-TestRoot $caseA
}

$caseB = New-TestRoot 'b-d'
try {
    $lab = Join-Path $caseB 'lab'
    $state = Join-Path $caseB 'agent\.automaton'
    $first = Initialize-TradingLabBootstrapState $lab $state $templatePath
    $configPath = Join-Path $lab 'control\trading.yaml'
    $secretPath = Join-Path $lab 'ipc\automaton.key'
    $configHashBefore = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    $secretHashBefore = (Get-FileHash -LiteralPath $secretPath -Algorithm SHA256).Hash
    $second = Initialize-TradingLabBootstrapState $lab $state $templatePath
    $configHashAfter = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    $secretHashAfter = (Get-FileHash -LiteralPath $secretPath -Algorithm SHA256).Hash
    if (
        -not $second.config_reused -or -not $second.ipc_secret_reused -or
        $configHashBefore -ne $configHashAfter -or $secretHashBefore -ne $secretHashAfter
    ) { throw 'Cases B/D failed idempotent config or secret reuse.' }
} finally {
    $configHashBefore = $null; $configHashAfter = $null
    $secretHashBefore = $null; $secretHashAfter = $null
    Remove-TestRoot $caseB
}

$caseC = New-TestRoot 'c'
try {
    $lab = Join-Path $caseC 'lab'
    $control = Join-Path $lab 'control'
    New-Item -ItemType Directory -Path $control | Out-Null
    Copy-Item -LiteralPath $templatePath -Destination (Join-Path $control 'trading.yaml')
    Add-Content -LiteralPath (Join-Path $control 'trading.yaml') -Value '# unexpected'
    $failed = $false
    try {
        [void](Initialize-TradingLabBootstrapState $lab (Join-Path $caseC 'agent\.automaton') $templatePath)
    } catch { $failed = $true }
    if (-not $failed -or (Test-Path -LiteralPath (Join-Path $lab 'ipc'))) {
        throw 'Case C did not fail closed before further preparation.'
    }
} finally {
    Remove-TestRoot $caseC
}

$caseE = New-TestRoot 'e'
try {
    $lab = Join-Path $caseE 'lab'
    $control = Join-Path $lab 'control'
    $ipc = Join-Path $lab 'ipc'
    New-Item -ItemType Directory -Path $control | Out-Null
    New-Item -ItemType Directory -Path $ipc | Out-Null
    Copy-Item -LiteralPath $templatePath -Destination (Join-Path $control 'trading.yaml')
    [System.IO.File]::WriteAllText((Join-Path $ipc 'automaton.key'), '')
    $failed = $false
    try {
        [void](Initialize-TradingLabBootstrapState $lab (Join-Path $caseE 'agent\.automaton') $templatePath)
    } catch { $failed = $true }
    if (-not $failed -or (Test-Path -LiteralPath (Join-Path $lab 'operational'))) {
        throw 'Case E did not reject an invalid existing secret before further preparation.'
    }
} finally {
    Remove-TestRoot $caseE
}

if ((Resolve-AclApplyFailureStatus 'NOT_RUN' 0) -ne 'NOT_RUN') {
    throw 'Case F pre-apply failure status is incorrect.'
}
$caseG = New-TestRoot 'g'
try {
    $progress = Join-Path $caseG 'progress.jsonl'
    [System.IO.File]::WriteAllText(
        $progress,
        ('{"path":"C:\\test\\first","applied_at_utc":"2026-08-12T00:00:00Z"}' + [Environment]::NewLine),
        [System.Text.UTF8Encoding]::new($false)
    )
    $applied = @(Read-AclProgressFile $progress)
    if (
        (Resolve-AclApplyFailureStatus 'IN_PROGRESS' $applied.Count) -ne 'PARTIAL' -or
        $applied.Count -ne 1 -or $applied[0].path -ne 'C:\test\first'
    ) { throw 'Case G partial ACL failure status or affected-path journal is incorrect.' }
} finally {
    Remove-TestRoot $caseG
}

[pscustomobject]@{
    WINDOWS_POWERSHELL_5_COMPATIBLE_RNG = 'PASS'
    NO_RANDOMNUMBERGENERATOR_FILL_DEPENDENCY = 'PASS'
    CSPRNG_USED = 'PASS'
    SECRET_NOT_LOGGED = 'PASS'
    CASE_A_FRESH_BOOTSTRAP = 'PASS'
    CASE_B_PARTIAL_CONFIG_RESUME = 'PASS'
    CASE_C_CHANGED_CONFIG_FAIL_CLOSED = 'PASS'
    CASE_D_EXISTING_SECRET_REUSED = 'PASS'
    CASE_E_INVALID_SECRET_FAIL_CLOSED = 'PASS'
    CASE_F_PRE_APPLY_STATUS = 'PASS'
    CASE_G_PARTIAL_APPLY_STATUS = 'PASS'
} | ConvertTo-Json
