Set-StrictMode -Version 2.0

function Read-TradingLabWindowsAclPolicy([string] $PolicyPath) {
    if (-not [System.IO.Path]::IsPathRooted($PolicyPath) -or
        -not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) {
        throw 'Windows ACL policy must be an existing absolute file.'
    }
    $item = Get-Item -LiteralPath $PolicyPath -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint -or $item.Length -gt 32768) {
        throw 'Windows ACL policy path is unsafe.'
    }
    $policy = [System.IO.File]::ReadAllText($PolicyPath, [System.Text.Encoding]::UTF8) |
        ConvertFrom-Json
    $topLevel = @($policy.PSObject.Properties.Name | Sort-Object)
    if (($topLevel -join ',') -ne 'maintenance_identity,maintenance_targets,schema_version' -or
        $policy.schema_version -ne 1 -or
        -not ($policy.maintenance_identity -is [string]) -or
        [string]::IsNullOrWhiteSpace($policy.maintenance_identity) -or
        $policy.maintenance_identity -match '^S-' -or
        $policy.maintenance_identity -notmatch '\\') {
        throw 'Windows ACL policy schema or maintenance identity is invalid.'
    }
    $expectedTargets = @(
        'automaton_state', 'gateway_logs', 'lab_root',
        'logs_root', 'operational', 'security_logs'
    )
    $actualTargets = @($policy.maintenance_targets.PSObject.Properties.Name | Sort-Object)
    if (($actualTargets -join ',') -ne (($expectedTargets | Sort-Object) -join ',')) {
        throw 'Windows ACL maintenance target allowlist is invalid.'
    }
    foreach ($target in $actualTargets) {
        $entry = $policy.maintenance_targets.$target
        $entryFields = @($entry.PSObject.Properties.Name | Sort-Object)
        $inheritance = @($entry.inheritance_flags | Sort-Object)
        if (($entryFields -join ',') -ne 'inheritance_flags,propagation_flags,rights' -or
            $entry.rights -ne 'FullControl' -or
            ($inheritance -join ',') -ne 'ContainerInherit,ObjectInherit' -or
            @($entry.propagation_flags).Count -ne 0) {
            throw "Windows ACL maintenance policy is malformed for $target."
        }
    }
    return $policy
}

function Resolve-TradingLabAclIdentitySid([string] $Identity) {
    if ($Identity -match '^S-\d(-\d+)+$') {
        return [System.Security.Principal.SecurityIdentifier]::new($Identity)
    }
    return ([System.Security.Principal.NTAccount]::new($Identity)).Translate(
        [System.Security.Principal.SecurityIdentifier]
    )
}

function Test-ByteArrayEqual([byte[]] $First, [byte[]] $Second) {
    if ($First.Length -ne $Second.Length) { return $false }
    for ($index = 0; $index -lt $First.Length; $index++) {
        if ($First[$index] -ne $Second[$index]) { return $false }
    }
    return $true
}

function Assert-ExactBootstrapConfig([string] $ConfigPath, [string] $TemplatePath) {
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw 'Bootstrap trading.yaml is absent.'
    }
    if (-not (Test-Path -LiteralPath $TemplatePath -PathType Leaf)) {
        throw 'Reviewed bootstrap template is absent.'
    }
    foreach ($path in @($ConfigPath, $TemplatePath)) {
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'Bootstrap configuration paths must be regular non-reparse files.'
        }
    }
    $configuredBytes = [System.IO.File]::ReadAllBytes($ConfigPath)
    $templateBytes = [System.IO.File]::ReadAllBytes($TemplatePath)
    if (-not (Test-ByteArrayEqual $configuredBytes $templateBytes)) {
        throw 'Existing trading.yaml differs from the reviewed OBSERVE_ONLY bootstrap template.'
    }
    $text = [System.Text.Encoding]::UTF8.GetString($configuredBytes)
    if (
        $text -notmatch '(?m)^trading_mode:\s*OBSERVE_ONLY\s*$' -or
        $text -notmatch '(?m)^mt5_access_enabled:\s*false\s*$' -or
        $text -notmatch '(?m)^authorized_account:\s*0\s*$' -or
        $text -notmatch '(?m)^authorized_server:\s*CHANGE_ME\s*$'
    ) {
        throw 'Bootstrap trading.yaml is not explicitly fail-closed.'
    }
    if ($text -match '(?im)^\s*(password|passwd|credential|credentials|api_key|apikey|token|secret|private_key)\s*:') {
        throw 'Bootstrap trading.yaml contains a forbidden credential field.'
    }
    return [pscustomobject]@{
        exact_template = $true
        trading_mode = 'OBSERVE_ONLY'
        mt5_access_enabled = $false
        account_configured = $false
        credentials_present = $false
    }
}

function ConvertTo-Base64Url([byte[]] $Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url([string] $Value) {
    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        0 { break }
        2 { $base64 += '==' }
        3 { $base64 += '=' }
        default { throw 'IPC secret encoding is invalid.' }
    }
    try {
        return [Convert]::FromBase64String($base64)
    } catch {
        throw 'IPC secret encoding is invalid.'
    }
}

function Assert-ValidIpcSecret([string] $SecretPath) {
    if (-not (Test-Path -LiteralPath $SecretPath -PathType Leaf)) {
        throw 'IPC secret is absent.'
    }
    $item = Get-Item -LiteralPath $SecretPath -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'IPC secret cannot be a reparse point.'
    }
    if ($item.Length -le 0 -or $item.Length -gt 128) {
        throw 'IPC secret length is invalid.'
    }
    $value = [System.IO.File]::ReadAllText($SecretPath, [System.Text.Encoding]::ASCII)
    $decoded = $null
    try {
        if ($value -notmatch '^[A-Za-z0-9_-]{43}$') {
            throw 'IPC secret format is invalid.'
        }
        $decoded = ConvertFrom-Base64Url $value
        try {
            if ($decoded.Length -ne 32) {
                throw 'IPC secret entropy length is invalid.'
            }
        } finally {
            if ($null -ne $decoded) { [Array]::Clear($decoded, 0, $decoded.Length) }
        }
    } finally {
        $value = $null
    }
    return [pscustomobject]@{ valid = $true; encoded_length = [int]$item.Length }
}

function New-CryptographicIpcSecret([string] $SecretPath) {
    if (Test-Path -LiteralPath $SecretPath) {
        throw 'Refusing to replace an existing IPC secret.'
    }
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $encoded = $null
    try {
        $rng.GetBytes($bytes)
        $encoded = ConvertTo-Base64Url $bytes
        $ascii = [System.Text.Encoding]::ASCII.GetBytes($encoded)
        $stream = [System.IO.FileStream]::new(
            $SecretPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        try {
            $stream.Write($ascii, 0, $ascii.Length)
            $stream.Flush()
        } finally {
            $stream.Dispose()
            [Array]::Clear($ascii, 0, $ascii.Length)
        }
    } finally {
        $rng.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
        $encoded = $null
    }
    return Assert-ValidIpcSecret $SecretPath
}

function Initialize-IdempotentIpcSecret([string] $SecretPath) {
    if (Test-Path -LiteralPath $SecretPath) {
        $validation = Assert-ValidIpcSecret $SecretPath
        return [pscustomobject]@{
            created = $false
            reused = $true
            encoded_length = $validation.encoded_length
        }
    }
    $created = New-CryptographicIpcSecret $SecretPath
    return [pscustomobject]@{
        created = $true
        reused = $false
        encoded_length = $created.encoded_length
    }
}

function Initialize-TradingLabBootstrapState(
    [string] $LabRoot,
    [string] $AutomatonStateDir,
    [string] $TemplatePath
) {
    $createdPaths = [System.Collections.Generic.List[string]]::new()
    $configPath = Join-Path $LabRoot 'control\trading.yaml'
    $secretDefinitions = @(
        [pscustomobject]@{ name = 'automaton'; path = (Join-Path $LabRoot 'ipc\automaton.key') },
        [pscustomobject]@{ name = 'observation'; path = (Join-Path $LabRoot 'ipc\observation.key') },
        [pscustomobject]@{ name = 'research'; path = (Join-Path $LabRoot 'ipc\research.key') }
    )
    $appendTargets = @(
        (Join-Path $LabRoot 'audit\journal\audit.jsonl'),
        (Join-Path $LabRoot 'logs\security\security.log')
    )
    # Validate every pre-existing security-sensitive file before creating any
    # additional path.  A corrupt partial state therefore fails without drift.
    if (Test-Path -LiteralPath $configPath) {
        [void](Assert-ExactBootstrapConfig $configPath $TemplatePath)
    }
    foreach ($secretDefinition in $secretDefinitions) {
        if (Test-Path -LiteralPath $secretDefinition.path) {
            [void](Assert-ValidIpcSecret $secretDefinition.path)
        }
    }
    $authorizationRoot = Join-Path $LabRoot 'control\demo-authorization'
    $authorizationArtifacts = @()
    if (Test-Path -LiteralPath $authorizationRoot) {
        $authorizationRootItem = Get-Item -LiteralPath $authorizationRoot -Force
        if (-not $authorizationRootItem.PSIsContainer -or
            ($authorizationRootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'Bootstrap authorization root must be a regular non-reparse directory.'
        }
        $authorizationArtifacts = @(Get-ChildItem -LiteralPath $authorizationRoot -Force)
        foreach ($artifact in $authorizationArtifacts) {
            if ($artifact.PSIsContainer -or
                $artifact.Name -cnotmatch '^mt5-read-only-authorization-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$' -or
                ($artifact.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                throw "Unexpected authorization artifact in bootstrap state: $($artifact.FullName)"
            }
        }
    }
    foreach ($appendTarget in $appendTargets) {
        if (Test-Path -LiteralPath $appendTarget) {
            if (-not (Test-Path -LiteralPath $appendTarget -PathType Leaf)) {
                throw "Prepared append target is not a regular file: $appendTarget"
            }
            $appendTargetItem = Get-Item -LiteralPath $appendTarget -Force
            if ($appendTargetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Prepared append target cannot be a reparse point: $appendTarget"
            }
        }
    }
    $directories = @(
        $LabRoot,
        (Join-Path $LabRoot 'control'),
        (Join-Path $LabRoot 'control\demo-authorization'),
        (Join-Path $LabRoot 'ipc'),
        (Join-Path $LabRoot 'operational'),
        (Join-Path $LabRoot 'research'),
        (Join-Path $LabRoot 'audit'),
        (Join-Path $LabRoot 'audit\sqlite'),
        (Join-Path $LabRoot 'audit\journal'),
        (Join-Path $LabRoot 'logs'),
        (Join-Path $LabRoot 'logs\gateway'),
        (Join-Path $LabRoot 'logs\security'),
        $AutomatonStateDir
    )
    foreach ($directory in $directories) {
        if (Test-Path -LiteralPath $directory) {
            $directoryItem = Get-Item -LiteralPath $directory -Force
            if (-not $directoryItem.PSIsContainer -or
                ($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                throw "Bootstrap directory must be a regular non-reparse directory: $directory"
            }
        }
    }
    foreach ($directory in $directories) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -ItemType Directory -Path $directory | Out-Null
            $createdPaths.Add($directory)
        }
    }

    $configCreated = $false
    if (-not (Test-Path -LiteralPath $configPath)) {
        Copy-Item -LiteralPath $TemplatePath -Destination $configPath
        $createdPaths.Add($configPath)
        $configCreated = $true
    }
    $config = Assert-ExactBootstrapConfig $configPath $TemplatePath

    $secretResults = @{}
    $createdSecretPaths = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($secretDefinition in $secretDefinitions) {
            $secretResult = Initialize-IdempotentIpcSecret $secretDefinition.path
            $secretResults[$secretDefinition.name] = $secretResult
            if ($secretResult.created) {
                $createdPaths.Add($secretDefinition.path)
                $createdSecretPaths.Add($secretDefinition.path)
            }
        }

        foreach ($file in $appendTargets) {
            if (-not (Test-Path -LiteralPath $file)) {
                $stream = [System.IO.FileStream]::new(
                    $file,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None
                )
                $stream.Dispose()
                $createdPaths.Add($file)
            } elseif (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
                throw "Prepared append target is not a regular file: $file"
            }
        }
    } catch {
        $primaryError = $_.Exception.Message
        $cleanupErrors = [System.Collections.Generic.List[string]]::new()
        foreach ($createdSecretPath in $createdSecretPaths) {
            try {
                $createdSecretItem = Get-Item -LiteralPath $createdSecretPath -Force -ErrorAction Stop
                if ($createdSecretItem.PSIsContainer -or
                    ($createdSecretItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    throw 'Created credential path changed type during rollback.'
                }
                [System.IO.File]::Delete($createdSecretPath)
                if (Test-Path -LiteralPath $createdSecretPath) {
                    throw 'Created credential remained after rollback.'
                }
            } catch {
                $cleanupErrors.Add("$createdSecretPath`: $($_.Exception.Message)")
            }
        }
        if ($cleanupErrors.Count -ne 0) {
            throw "Bootstrap failed: $primaryError Credential rollback failed: $($cleanupErrors -join '; ')"
        }
        throw
    }

    return [pscustomobject]@{
        created_paths = @($createdPaths)
        config_created = $configCreated
        config_reused = -not $configCreated
        config_valid = $config.exact_template
        automaton_key_created = $secretResults.automaton.created
        automaton_key_reused = $secretResults.automaton.reused
        automaton_key_length = $secretResults.automaton.encoded_length
        observation_key_created = $secretResults.observation.created
        observation_key_reused = $secretResults.observation.reused
        observation_key_length = $secretResults.observation.encoded_length
        research_key_created = $secretResults.research.created
        research_key_reused = $secretResults.research.reused
        research_key_length = $secretResults.research.encoded_length
        trading_mode = 'OBSERVE_ONLY'
        account_configured = $false
        authorization_artifact_pattern = 'mt5-read-only-authorization-<UUID>.json'
        authorization_artifact_count = $authorizationArtifacts.Count
        authorization_artifacts_created = 0
    }
}

function Resolve-AclApplyFailureStatus([string] $CurrentStatus, [int] $AppliedCount) {
    if ($CurrentStatus -ne 'IN_PROGRESS') { return $CurrentStatus }
    if ($AppliedCount -gt 0) { return 'PARTIAL' }
    return 'FAIL'
}

function Read-AclProgressFile([string] $ProgressPath) {
    if (-not (Test-Path -LiteralPath $ProgressPath -PathType Leaf)) { return @() }
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($line in [System.IO.File]::ReadAllLines($ProgressPath)) {
        if ($line.Trim()) { $items.Add(($line | ConvertFrom-Json)) }
    }
    return @($items)
}
