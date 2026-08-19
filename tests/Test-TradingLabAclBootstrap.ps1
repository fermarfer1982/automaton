$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$helperPath = Join-Path $workspace 'scripts\TradingLabAclBootstrap.ps1'
$templatePath = Join-Path $workspace 'config\trading.bootstrap-observe-only.yaml'
$aclPolicyPath = Join-Path $workspace 'config\windows-acl-policy.json'
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
    '[System.IO.FileMode]::CreateNew',
    '[System.IO.FileAttributes]::ReparsePoint'
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
$pinnedPrevalidationIndex = $helperSource.IndexOf(
    '[void](Assert-PinnedExistingBootstrapConfig $configPath $normalizedExpectedConfigSha256)'
)
$pinnedImmediateRevalidationIndex = $helperSource.LastIndexOf(
    '$config = Assert-PinnedExistingBootstrapConfig $configPath $normalizedExpectedConfigSha256'
)
$secretCreationIndex = $helperSource.IndexOf('$secretResults = @{}')
if ($pinnedPrevalidationIndex -lt 0 -or
    $pinnedImmediateRevalidationIndex -le $pinnedPrevalidationIndex -or
    $secretCreationIndex -le $pinnedImmediateRevalidationIndex) {
    throw 'Pinned config hash must be validated before bootstrap work and immediately before secret creation.'
}
if (-not $helperSource.Contains("`$pinnedExistingConfig = `$PSBoundParameters.ContainsKey('ExpectedExistingConfigSha256')") -or
    -not $helperSource.Contains('} elseif (Test-Path -LiteralPath $configPath) {')) {
    throw 'Default exact-template behavior is not structurally isolated from explicit pinned mode.'
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
    if (-not $result.config_created -or
        -not $result.automaton_key_created -or
        -not $result.observation_key_created -or
        -not $result.research_key_created) {
        throw 'Case A did not create a fresh bootstrap.'
    }
    if ($result.authorization_artifact_count -ne 0 -or
        $result.authorization_artifacts_created -ne 0 -or
        $result.authorization_artifact_pattern -ne 'mt5-read-only-authorization-<UUID>.json') {
        throw 'Case A bootstrap authorization semantics are not empty and human-created only.'
    }
    [void](Assert-ExactBootstrapConfig (Join-Path $lab 'control\trading.yaml') $templatePath)
    $caseASecrets = [System.Collections.Generic.List[string]]::new()
    try {
        $structuredOutput = $result | ConvertTo-Json -Depth 5
        foreach ($keyName in @('automaton.key', 'observation.key', 'research.key')) {
            $secretPath = Join-Path $lab "ipc\$keyName"
            [void](Assert-ValidIpcSecret $secretPath)
            $secretValue = [System.IO.File]::ReadAllText($secretPath, [System.Text.Encoding]::ASCII)
            $caseASecrets.Add($secretValue)
            if ($structuredOutput.Contains($secretValue)) {
                throw "Case A exposed $keyName through structured output."
            }
        }
        if (@($caseASecrets | Select-Object -Unique).Count -ne 3) {
            throw 'Case A generated duplicate IPC credential values.'
        }
    } finally {
        $caseASecrets.Clear()
    }
} finally {
    Remove-TestRoot $caseA
}

$caseB = New-TestRoot 'b'
try {
    $lab = Join-Path $caseB 'lab'
    $state = Join-Path $caseB 'agent\.automaton'
    $first = Initialize-TradingLabBootstrapState $lab $state $templatePath
    $configPath = Join-Path $lab 'control\trading.yaml'
    $configHashBefore = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    $hashesBefore = @{}
    foreach ($keyName in @('automaton.key', 'observation.key', 'research.key')) {
        $hashesBefore[$keyName] = (Get-FileHash -LiteralPath (Join-Path $lab "ipc\$keyName") -Algorithm SHA256).Hash
    }
    $second = Initialize-TradingLabBootstrapState $lab $state $templatePath
    $configHashAfter = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    if (
        -not $second.config_reused -or
        -not $second.automaton_key_reused -or
        -not $second.observation_key_reused -or
        -not $second.research_key_reused -or
        $configHashBefore -ne $configHashAfter
    ) { throw 'Case B failed idempotent config or credential reuse.' }
    foreach ($keyName in $hashesBefore.Keys) {
        $hashAfter = (Get-FileHash -LiteralPath (Join-Path $lab "ipc\$keyName") -Algorithm SHA256).Hash
        if ($hashAfter -ne $hashesBefore[$keyName]) {
            throw "Case B replaced $keyName."
        }
    }
} finally {
    $configHashBefore = $null; $configHashAfter = $null
    $hashesBefore = $null; $hashAfter = $null
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

$casePinnedValid = New-TestRoot 'pinned-valid'
$pinnedBytes = $null
$afterBytes = $null
$pinnedHash = $null
try {
    $lab = Join-Path $casePinnedValid 'lab'
    $control = Join-Path $lab 'control'
    $configPath = Join-Path $control 'trading.yaml'
    New-Item -ItemType Directory -Path $control -Force | Out-Null
    $pinnedBytes = [System.Text.Encoding]::UTF8.GetBytes(
        ([System.IO.File]::ReadAllText($templatePath, [System.Text.Encoding]::UTF8) +
        "`r`n# reviewed non-template operational fixture`r`n")
    )
    [System.IO.File]::WriteAllBytes($configPath, $pinnedBytes)
    $pinnedHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $result = Initialize-TradingLabBootstrapState `
        $lab `
        (Join-Path $casePinnedValid 'agent\.automaton') `
        $templatePath `
        -ExpectedExistingConfigSha256 $pinnedHash.ToUpperInvariant()
    $afterBytes = [System.IO.File]::ReadAllBytes($configPath)
    if ($result.config_created -or -not $result.config_reused -or
        -not $result.config_valid -or
        $result.config_validation_mode -ne 'PINNED_EXISTING_SHA256' -or
        $result.config_sha256 -cne $pinnedHash -or
        -not (Test-ByteArrayEqual $pinnedBytes $afterBytes)) {
        throw 'Pinned mode did not accept and preserve the exact non-template configuration.'
    }
} finally {
    if ($null -ne $pinnedBytes) { [Array]::Clear($pinnedBytes, 0, $pinnedBytes.Length) }
    if ($null -ne $afterBytes) { [Array]::Clear($afterBytes, 0, $afterBytes.Length) }
    $pinnedHash = $null
    Remove-TestRoot $casePinnedValid
}

$casePinnedWrongHash = New-TestRoot 'pinned-wrong-hash'
$actualHash = $null
$wrongHash = $null
try {
    $lab = Join-Path $casePinnedWrongHash 'lab'
    $control = Join-Path $lab 'control'
    New-Item -ItemType Directory -Path $control -Force | Out-Null
    Copy-Item -LiteralPath $templatePath -Destination (Join-Path $control 'trading.yaml')
    $actualHash = (Get-FileHash -LiteralPath (Join-Path $control 'trading.yaml') -Algorithm SHA256).Hash.ToLowerInvariant()
    $wrongHash = if ($actualHash -eq (('0' * 64) -join '')) {
        ('1' * 64) -join ''
    } else { ('0' * 64) -join '' }
    $failed = $false
    try {
        [void](Initialize-TradingLabBootstrapState `
            $lab `
            (Join-Path $casePinnedWrongHash 'agent\.automaton') `
            $templatePath `
            -ExpectedExistingConfigSha256 $wrongHash)
    } catch { $failed = $true }
    if (-not $failed -or
        (Test-Path -LiteralPath (Join-Path $lab 'ipc')) -or
        (Test-Path -LiteralPath (Join-Path $lab 'operational')) -or
        (Test-Path -LiteralPath (Join-Path $lab 'audit')) -or
        (Test-Path -LiteralPath (Join-Path $lab 'logs'))) {
        throw 'Pinned mode wrong hash did not fail before later bootstrap state.'
    }
} finally {
    $actualHash = $null; $wrongHash = $null
    Remove-TestRoot $casePinnedWrongHash
}

$casePinnedMissing = New-TestRoot 'pinned-missing'
try {
    $lab = Join-Path $casePinnedMissing 'lab'
    $failed = $false
    try {
        [void](Initialize-TradingLabBootstrapState `
            $lab `
            (Join-Path $casePinnedMissing 'agent\.automaton') `
            $templatePath `
            -ExpectedExistingConfigSha256 (('0' * 64) -join ''))
    } catch { $failed = $true }
    if (-not $failed -or (Test-Path -LiteralPath $lab)) {
        throw 'Pinned mode missing config did not fail before filesystem mutation.'
    }
} finally {
    Remove-TestRoot $casePinnedMissing
}

$casePinnedMalformed = New-TestRoot 'pinned-malformed'
try {
    $lab = Join-Path $casePinnedMalformed 'lab'
    $control = Join-Path $lab 'control'
    New-Item -ItemType Directory -Path $control -Force | Out-Null
    Copy-Item -LiteralPath $templatePath -Destination (Join-Path $control 'trading.yaml')
    $failed = $false
    try {
        [void](Initialize-TradingLabBootstrapState `
            $lab `
            (Join-Path $casePinnedMalformed 'agent\.automaton') `
            $templatePath `
            -ExpectedExistingConfigSha256 'not-a-sha256')
    } catch { $failed = $true }
    if (-not $failed -or
        (Test-Path -LiteralPath (Join-Path $lab 'ipc')) -or
        (Test-Path -LiteralPath (Join-Path $lab 'operational'))) {
        throw 'Pinned mode malformed SHA did not fail before later bootstrap state.'
    }
} finally {
    Remove-TestRoot $casePinnedMalformed
}

$caseD = New-TestRoot 'd'
try {
    $lab = Join-Path $caseD 'lab'
    $ipc = Join-Path $lab 'ipc'
    New-Item -ItemType Directory -Path $ipc -Force | Out-Null
    $automatonPath = Join-Path $ipc 'automaton.key'
    [void](New-CryptographicIpcSecret $automatonPath)
    $hashBefore = (Get-FileHash -LiteralPath $automatonPath -Algorithm SHA256).Hash
    $result = Initialize-TradingLabBootstrapState $lab (Join-Path $caseD 'agent\.automaton') $templatePath
    if (-not $result.automaton_key_reused -or
        -not $result.observation_key_created -or
        -not $result.research_key_created -or
        (Get-FileHash -LiteralPath $automatonPath -Algorithm SHA256).Hash -ne $hashBefore) {
        throw 'Case D did not preserve automaton.key while creating only missing credentials.'
    }
} finally {
    $hashBefore = $null
    Remove-TestRoot $caseD
}

$caseE = New-TestRoot 'e'
try {
    $lab = Join-Path $caseE 'lab'
    $ipc = Join-Path $lab 'ipc'
    New-Item -ItemType Directory -Path $ipc -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $ipc 'automaton.key'), '')
    $failed = $false
    try {
        [void](Initialize-TradingLabBootstrapState $lab (Join-Path $caseE 'agent\.automaton') $templatePath)
    } catch { $failed = $true }
    if (-not $failed -or
        (Test-Path -LiteralPath (Join-Path $ipc 'observation.key')) -or
        (Test-Path -LiteralPath (Join-Path $ipc 'research.key')) -or
        (Test-Path -LiteralPath (Join-Path $lab 'operational'))) {
        throw 'Case E did not reject invalid automaton.key before further preparation.'
    }
} finally {
    Remove-TestRoot $caseE
}

$caseF = New-TestRoot 'f'
try {
    $lab = Join-Path $caseF 'lab'
    $ipc = Join-Path $lab 'ipc'
    New-Item -ItemType Directory -Path $ipc -Force | Out-Null
    [void](New-CryptographicIpcSecret (Join-Path $ipc 'automaton.key'))
    [System.IO.File]::WriteAllText((Join-Path $ipc 'observation.key'), 'malformed')
    $failed = $false
    try { [void](Initialize-TradingLabBootstrapState $lab (Join-Path $caseF 'agent\.automaton') $templatePath) } catch { $failed = $true }
    if (-not $failed -or (Test-Path -LiteralPath (Join-Path $ipc 'research.key')) -or
        (Test-Path -LiteralPath (Join-Path $lab 'operational'))) {
        throw 'Case F did not fail before creating research.key or later bootstrap state.'
    }
} finally {
    Remove-TestRoot $caseF
}

$caseG = New-TestRoot 'g'
try {
    $lab = Join-Path $caseG 'lab'
    $ipc = Join-Path $lab 'ipc'
    New-Item -ItemType Directory -Path $ipc -Force | Out-Null
    [void](New-CryptographicIpcSecret (Join-Path $ipc 'automaton.key'))
    [System.IO.File]::WriteAllText((Join-Path $ipc 'research.key'), 'malformed')
    $failed = $false
    try { [void](Initialize-TradingLabBootstrapState $lab (Join-Path $caseG 'agent\.automaton') $templatePath) } catch { $failed = $true }
    if (-not $failed -or (Test-Path -LiteralPath (Join-Path $ipc 'observation.key')) -or
        (Test-Path -LiteralPath (Join-Path $lab 'operational'))) {
        throw 'Case G did not fail before creating observation.key or later bootstrap state.'
    }
} finally {
    Remove-TestRoot $caseG
}

$caseH = New-TestRoot 'h'
try {
    $lab = Join-Path $caseH 'lab'
    $ipc = Join-Path $lab 'ipc'
    New-Item -ItemType Directory -Path $ipc -Force | Out-Null
    $existingHashes = @{}
    foreach ($keyName in @('automaton.key', 'observation.key')) {
        $keyPath = Join-Path $ipc $keyName
        [void](New-CryptographicIpcSecret $keyPath)
        $existingHashes[$keyName] = (Get-FileHash -LiteralPath $keyPath -Algorithm SHA256).Hash
    }
    $result = Initialize-TradingLabBootstrapState $lab (Join-Path $caseH 'agent\.automaton') $templatePath
    if (-not $result.automaton_key_reused -or -not $result.observation_key_reused -or
        -not $result.research_key_created) {
        throw 'Case H mixed partial-state result flags are incorrect.'
    }
    foreach ($keyName in $existingHashes.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $ipc $keyName) -Algorithm SHA256).Hash -ne $existingHashes[$keyName]) {
            throw "Case H replaced valid existing $keyName."
        }
    }
} finally {
    $existingHashes = $null
    Remove-TestRoot $caseH
}

$caseI = New-TestRoot 'i'
try {
    $lab = Join-Path $caseI 'lab'
    $ipc = Join-Path $lab 'ipc'
    New-Item -ItemType Directory -Path (Join-Path $ipc 'observation.key') -Force | Out-Null
    $failed = $false
    try { [void](Initialize-TradingLabBootstrapState $lab (Join-Path $caseI 'agent\.automaton') $templatePath) } catch { $failed = $true }
    if (-not $failed -or
        (Test-Path -LiteralPath (Join-Path $ipc 'automaton.key')) -or
        (Test-Path -LiteralPath (Join-Path $ipc 'research.key')) -or
        (Test-Path -LiteralPath (Join-Path $lab 'operational'))) {
        throw 'Case I accepted a non-file credential path or created later bootstrap state.'
    }
} finally {
    Remove-TestRoot $caseI
}

$caseAuthorization = New-TestRoot 'authorization-names'
try {
    $lab = Join-Path $caseAuthorization 'lab'
    $state = Join-Path $caseAuthorization 'agent\.automaton'
    [void](Initialize-TradingLabBootstrapState $lab $state $templatePath)
    [System.IO.File]::WriteAllText(
        (Join-Path $lab 'control\demo-authorization\authorization.json'),
        '{}',
        [System.Text.UTF8Encoding]::new($false)
    )
    $failed = $false
    try { [void](Initialize-TradingLabBootstrapState $lab $state $templatePath) } catch { $failed = $true }
    if (-not $failed) { throw 'Bootstrap accepted legacy authorization.json.' }
} finally {
    Remove-TestRoot $caseAuthorization
}

if ((Resolve-AclApplyFailureStatus 'NOT_RUN' 0) -ne 'NOT_RUN') {
    throw 'Case F pre-apply failure status is incorrect.'
}

$aclPolicy = Read-TradingLabWindowsAclPolicy $aclPolicyPath
$maintenanceTargets = @($aclPolicy.maintenance_targets.PSObject.Properties.Name | Sort-Object)
if (
    $aclPolicy.maintenance_identity -ne 'DESKTOP-QPK9UQ5\Proyecto IA' -or
    ($maintenanceTargets -join ',') -ne 'automaton_state,gateway_logs,lab_root,logs_root,operational,security_logs'
) {
    throw 'Canonical maintenance identity or per-target ACL policy is invalid.'
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
    CASE_B_IDEMPOTENT_THREE_KEY_REUSE = 'PASS'
    CASE_C_CHANGED_CONFIG_FAIL_CLOSED = 'PASS'
    PINNED_EXISTING_NON_TEMPLATE_ACCEPTED = 'PASS'
    PINNED_EXISTING_BYTES_PRESERVED = 'PASS'
    PINNED_WRONG_HASH_NO_DRIFT = 'PASS'
    PINNED_MISSING_CONFIG_NO_DRIFT = 'PASS'
    PINNED_MALFORMED_SHA_NO_DRIFT = 'PASS'
    CASE_D_AUTOMATON_PRESERVED_MISSING_KEYS_CREATED = 'PASS'
    CASE_E_INVALID_AUTOMATON_FAIL_CLOSED = 'PASS'
    CASE_F_INVALID_OBSERVATION_FAIL_CLOSED = 'PASS'
    CASE_G_INVALID_RESEARCH_FAIL_CLOSED = 'PASS'
    CASE_H_MIXED_VALID_PARTIAL_STATE = 'PASS'
    CASE_I_NON_FILE_KEY_FAIL_CLOSED = 'PASS'
    PRE_APPLY_STATUS = 'PASS'
    PARTIAL_APPLY_STATUS = 'PASS'
    MAINTENANCE_POLICY_CANONICAL = 'PASS'
    MAINTENANCE_TARGET_ALLOWLIST_EXACT = 'PASS'
    AUTHORIZATION_ARTIFACTS_HUMAN_CREATED_ONLY = 'PASS'
    LEGACY_AUTHORIZATION_JSON_REJECTED = 'PASS'
} | ConvertTo-Json
