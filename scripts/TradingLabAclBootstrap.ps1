Set-StrictMode -Version 2.0

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
    $configuredBytes = [System.IO.File]::ReadAllBytes($ConfigPath)
    $templateBytes = [System.IO.File]::ReadAllBytes($TemplatePath)
    if (-not (Test-ByteArrayEqual $configuredBytes $templateBytes)) {
        throw 'Existing trading.yaml differs from the reviewed OBSERVE_ONLY bootstrap template.'
    }
    $text = [System.Text.Encoding]::UTF8.GetString($configuredBytes)
    if (
        $text -notmatch '(?m)^trading_mode:\s*OBSERVE_ONLY\s*$' -or
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
    $secretPath = Join-Path $LabRoot 'ipc\automaton.key'
    # Validate every pre-existing security-sensitive file before creating any
    # additional path.  A corrupt partial state therefore fails without drift.
    if (Test-Path -LiteralPath $configPath) {
        [void](Assert-ExactBootstrapConfig $configPath $TemplatePath)
    }
    if (Test-Path -LiteralPath $secretPath) {
        [void](Assert-ValidIpcSecret $secretPath)
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

    $secret = Initialize-IdempotentIpcSecret $secretPath
    if ($secret.created) { $createdPaths.Add($secretPath) }

    foreach ($file in @(
        (Join-Path $LabRoot 'audit\journal\audit.jsonl'),
        (Join-Path $LabRoot 'logs\security\security.log')
    )) {
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

    return [pscustomobject]@{
        created_paths = @($createdPaths)
        config_created = $configCreated
        config_reused = -not $configCreated
        config_valid = $config.exact_template
        ipc_secret_created = $secret.created
        ipc_secret_reused = $secret.reused
        ipc_secret_length = $secret.encoded_length
        trading_mode = 'OBSERVE_ONLY'
        account_configured = $false
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
