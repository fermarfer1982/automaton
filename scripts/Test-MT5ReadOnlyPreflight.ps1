[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId,
    [ValidateRange(15, 180)]
    [int] $TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$normalizedRunId = $RunId.ToLowerInvariant()
$expectedGatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$workspace = 'C:\automaton'
$finalRoot = 'C:\automaton\.venv'
$pythonExecutable = 'C:\automaton\.venv\Scripts\python.exe'
$configPath = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml'
$operationalRoot = 'C:\ProgramData\AutomatonMT5Lab\operational'
$runtimeTemp = Join-Path $operationalRoot 'runtime-tmp'
$reportRoot = Join-Path $operationalRoot 'mt5-read-only-results'
$reportPath = Join-Path $reportRoot "mt5-read-only-preflight-$normalizedRunId.json"

# Durable failure envelope exists before identity, config, Python, or MT5 work.
$report = [ordered]@{
    schema_version = 1
    mode = 'MT5_READ_ONLY_PREFLIGHT'
    run_id = $normalizedRunId
    effective_sid = $null
    status = 'FAIL_INITIALIZING'
    completed_at_utc = $null
    failure_code = $null
    failure_stage = 'INITIALIZING'
    runtime_error = $null
    python_executable = $pythonExecutable
    trading_mode = 'OBSERVE_ONLY'
    mt5_package_version = $null
    mt5_terminal_version = $null
    mt5_imported = $false
    mt5_initialize_called = $false
    mt5_initialize_result = $false
    mt5_accessed = $false
    mt5_shutdown_called = $false
    terminal_connected = $false
    terminal_trade_allowed = $false
    terminal_path_match = $false
    account_info_read = $false
    account_login_match = $false
    account_server_match = $false
    account_name_match = $null
    account_trade_mode = $null
    account_demo_verified = $false
    symbol = 'XAUUSD'
    symbol_info_read = $false
    symbol_exists = $false
    symbol_digits = $null
    symbol_trade_tick_size = $null
    symbol_trade_mode = $null
    tick_read = $false
    tick_time = $null
    bid = $null
    ask = $null
    spread = $null
    kill_switch_present = $false
    audit_chain_valid = $false
    audit_events_recorded = @()
    unexpected_capability_called = $false
    order_check_called = $false
    order_send_called = $false
    login_called = $false
    symbol_select_called = $false
    market_book_add_called = $false
    market_book_release_called = $false
    copy_ticks_from_called = $false
    automaton_started = $false
    gateway_started = $false
    acl_verified = $false
    acl_modified = $false
    filesystem_runtime_modified = $false
    preflight_process_started = $false
    preflight_process_exit_observed = $false
    preflight_process_exit_code = $null
    preflight_stdout_captured = $false
    preflight_stderr_captured = $false
    preflight_stdout_sanitized = $null
    preflight_stderr_sanitized = $null
    preflight_stream_capture_error = $null
    timeout_seconds = $TimeoutSeconds
    timeout_observed = $false
    forced_termination_used = $false
    process_stopped_cleanly = $false
    orphan_processes = 0
    runtime_fingerprint_verified = $false
    final_runtime_item_count = 0
}

$effectiveSid = $null
$process = $null
$stdoutReadTask = $null
$stderrReadTask = $null
$processStarted = $false
$processExitObserved = $false
$processExitCode = $null
$stdoutCaptured = $false
$stderrCaptured = $false
$stdoutSanitized = $null
$stderrSanitized = $null
$streamCaptureError = $null
$timeoutObserved = $false
$forcedTerminationUsed = $false
$processStoppedCleanly = $false
$orphanProcesses = 0
$beforeFingerprint = $null
$afterFingerprint = $null
$runtimeFingerprintVerified = $false
$filesystemRuntimeModified = $false
$aclModified = $false
$runtimeSucceeded = $false
$runtimeError = $null
$failureCode = $null
$failureStage = 'INITIALIZING'
$stage = 'INITIALIZING'
$reportWritten = $false
$reportWriteError = $null
$childReport = $null

function Get-CanonicalPath([string] $Path) {
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-ExactPath([string] $Path, [string] $Expected) {
    try {
        return (Get-CanonicalPath $Path).Equals(
            (Get-CanonicalPath $Expected),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    } catch { return $false }
}

function Assert-NoReparsePoint([string] $Path, [bool] $Directory) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($Directory -and -not $item.PSIsContainer) { throw "Expected directory: $Path" }
    if (-not $Directory -and $item.PSIsContainer) { throw "Expected file: $Path" }
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Reparse point rejected: $Path"
    }
}

function Assert-PathConfined([string] $Path, [string] $Root) {
    $candidate = Get-CanonicalPath $Path
    $canonicalRoot = Get-CanonicalPath $Root
    if (-not (
        $candidate.Equals($canonicalRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($canonicalRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)
    )) { throw "Path escapes authorized root: $candidate" }
}

function Get-TextSha256([string] $Text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($hash.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $hash.Dispose() }
}

function Get-FinalRuntimeFingerprint {
    if (-not (Test-ExactPath $finalRoot 'C:\automaton\.venv')) {
        throw 'FINAL_PATH_EXACT=FAIL'
    }
    Assert-NoReparsePoint $finalRoot $true
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue((Get-CanonicalPath $finalRoot))
    $contentRecords = [System.Collections.Generic.List[string]]::new()
    $aclRecords = [System.Collections.Generic.List[string]]::new()
    $itemCount = 0
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        Assert-PathConfined $current $finalRoot
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        Assert-NoReparsePoint $item.FullName $item.PSIsContainer
        $canonicalItem = Get-CanonicalPath $item.FullName
        $relative = if ($canonicalItem.Equals(
            (Get-CanonicalPath $finalRoot),
            [System.StringComparison]::OrdinalIgnoreCase
        )) { '.' } else { $canonicalItem.Substring((Get-CanonicalPath $finalRoot).Length + 1) }
        $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor
            [System.Security.AccessControl.AccessControlSections]::Owner -bor
            [System.Security.AccessControl.AccessControlSections]::Group
        $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $aclRecords.Add("$relative|$($security.GetSecurityDescriptorSddlForm($sections))")
        $itemCount++
        if ($item.PSIsContainer) {
            foreach ($child in [System.IO.Directory]::EnumerateFileSystemEntries($item.FullName)) {
                Assert-PathConfined $child $finalRoot
                $pending.Enqueue($child)
            }
        } else {
            $fileHash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $contentRecords.Add("$relative|$($item.Length)|$fileHash")
        }
    }
    $contentRecords.Sort([System.StringComparer]::OrdinalIgnoreCase)
    $aclRecords.Sort([System.StringComparer]::OrdinalIgnoreCase)
    return [pscustomobject]@{
        item_count = $itemCount
        content_sha256 = Get-TextSha256 ($contentRecords -join "`n")
        acl_sha256 = Get-TextSha256 ($aclRecords -join "`n")
    }
}

function Write-ExclusiveJson([string] $Path, [object] $Value) {
    $json = $Value | ConvertTo-Json -Depth 10
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    try {
        $writer = [System.IO.StreamWriter]::new(
            $stream,
            [System.Text.UTF8Encoding]::new($false)
        )
        try { $writer.Write($json); $writer.Flush() } finally { $writer.Dispose() }
    } finally { $stream.Dispose() }
}

function Get-SanitizedRuntimeError([object] $ErrorRecord) {
    $message = $null
    try { $message = [string]$ErrorRecord.Exception.Message } catch {}
    if ([string]::IsNullOrWhiteSpace($message)) { $message = 'Unspecified preflight failure.' }
    $message = $message -replace '(?i)\b(password|passwd|api[_-]?key|ipc[_-]?key|credential|credentials|login|server|account|token|secret)\b\s*[:=]\s*[^\s;,]+', '${1}=[REDACTED]'
    $message = ($message -replace '[\r\n\t]+', ' ').Trim()
    if ($message.Length -gt 512) { $message = $message.Substring(0, 512) }
    return $message
}

function Get-SanitizedBoundedProcessText(
    [AllowNull()][string] $Text,
    [int] $MaximumUtf8Bytes = 8192
) {
    if ($MaximumUtf8Bytes -lt 64) { throw 'Process stream byte limit is too small.' }
    if ($null -eq $Text) { return '' }
    $secretPattern = @'
(?im)["']?(api[\s_-]?key|ipc[\s_-]?key|mt5[\s_-]?password|password|passwd|credential|credentials|client[\s_-]?secret|private[\s_-]?key|secret|access[\s_-]?token|refresh[\s_-]?token|token|mt5[\s_-]?login|login|authorized[\s_-]?account|account|server)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;}\r\n]+)
'@.Trim()
    $sanitized = [regex]::Replace($Text, $secretPattern, '$1=[REDACTED]')
    $encoding = [System.Text.UTF8Encoding]::new($false)
    if ($encoding.GetByteCount($sanitized) -le $MaximumUtf8Bytes) { return $sanitized }
    $marker = '...[TRUNCATED]'
    $payloadLimit = $MaximumUtf8Bytes - $encoding.GetByteCount($marker)
    $low = 0
    $high = [Math]::Min($sanitized.Length, $payloadLimit)
    while ($low -lt $high) {
        $middle = [int][Math]::Ceiling(($low + $high) / 2.0)
        if ($encoding.GetByteCount($sanitized.Substring(0, $middle)) -le $payloadLimit) {
            $low = $middle
        } else { $high = $middle - 1 }
    }
    if ($low -gt 0 -and [char]::IsHighSurrogate($sanitized[$low - 1])) { $low-- }
    return $sanitized.Substring(0, $low) + $marker
}

function Receive-PreflightStreamCapture(
    [AllowNull()][object] $ReadTask,
    [int] $TimeoutMilliseconds = 5000
) {
    if ($null -eq $ReadTask) {
        return [pscustomobject]@{ captured = $false; raw = $null; sanitized = $null; error = 'Asynchronous stream reader was not initialized.' }
    }
    try {
        if (-not $ReadTask.Wait($TimeoutMilliseconds)) {
            return [pscustomobject]@{ captured = $false; raw = $null; sanitized = $null; error = 'Asynchronous stream capture timed out.' }
        }
        $raw = [string]$ReadTask.Result
        return [pscustomobject]@{
            captured = $true
            raw = $raw
            sanitized = Get-SanitizedBoundedProcessText $raw 8192
            error = $null
        }
    } catch {
        return [pscustomobject]@{ captured = $false; raw = $null; sanitized = $null; error = Get-SanitizedRuntimeError $_ }
    }
}

function Copy-PreflightEvidence([object] $Child, [System.Collections.IDictionary] $Destination) {
    $fields = @(
        'effective_sid', 'status', 'failure_code', 'failure_stage', 'runtime_error',
        'python_executable', 'trading_mode', 'mt5_package_version', 'mt5_terminal_version',
        'mt5_imported', 'mt5_initialize_called', 'mt5_initialize_result', 'mt5_accessed',
        'mt5_shutdown_called', 'terminal_connected', 'terminal_trade_allowed',
        'terminal_path_match', 'account_info_read', 'account_login_match',
        'account_server_match', 'account_name_match', 'account_trade_mode',
        'account_demo_verified', 'symbol', 'symbol_info_read', 'symbol_exists',
        'symbol_digits', 'symbol_trade_tick_size', 'symbol_trade_mode', 'tick_read',
        'tick_time', 'bid', 'ask', 'spread', 'kill_switch_present', 'audit_chain_valid',
        'audit_events_recorded', 'unexpected_capability_called', 'order_check_called',
        'order_send_called', 'login_called', 'symbol_select_called',
        'market_book_add_called', 'market_book_release_called', 'copy_ticks_from_called',
        'automaton_started', 'gateway_started', 'acl_verified', 'acl_modified',
        'filesystem_runtime_modified', 'process_stopped_cleanly', 'orphan_processes'
    )
    foreach ($field in $fields) {
        $property = $Child.PSObject.Properties[$field]
        if ($null -eq $property) { throw "Child report missing required field: $field" }
        $Destination[$field] = $property.Value
    }
}

function Test-PreflightChildBoundary([object] $Child) {
    if ($null -eq $Child) { return $false }
    try {
        return (
            $Child.schema_version -eq 1 -and
            $Child.mode -eq 'MT5_READ_ONLY_PREFLIGHT' -and
            $Child.run_id -eq $normalizedRunId -and
            $Child.effective_sid -eq $expectedGatewaySid -and
            $Child.status -eq 'PASS' -and
            $Child.python_executable -eq $pythonExecutable -and
            $Child.trading_mode -eq 'OBSERVE_ONLY' -and
            $Child.mt5_package_version -eq '5.0.6090' -and
            [bool]$Child.mt5_imported -and
            [bool]$Child.mt5_initialize_called -and
            [bool]$Child.mt5_initialize_result -and
            [bool]$Child.mt5_accessed -and
            [bool]$Child.mt5_shutdown_called -and
            [bool]$Child.terminal_connected -and
            [bool]$Child.terminal_path_match -and
            [bool]$Child.account_info_read -and
            [bool]$Child.account_login_match -and
            [bool]$Child.account_server_match -and
            [bool]$Child.account_demo_verified -and
            $Child.symbol -eq 'XAUUSD' -and
            [bool]$Child.symbol_info_read -and [bool]$Child.symbol_exists -and
            [bool]$Child.tick_read -and [bool]$Child.audit_chain_valid -and
            -not [bool]$Child.unexpected_capability_called -and
            -not [bool]$Child.order_check_called -and
            -not [bool]$Child.order_send_called -and
            -not [bool]$Child.login_called -and
            -not [bool]$Child.symbol_select_called -and
            -not [bool]$Child.market_book_add_called -and
            -not [bool]$Child.market_book_release_called -and
            -not [bool]$Child.copy_ticks_from_called -and
            -not [bool]$Child.automaton_started -and
            -not [bool]$Child.gateway_started -and
            [bool]$Child.acl_verified -and
            -not [bool]$Child.acl_modified -and
            -not [bool]$Child.filesystem_runtime_modified -and
            [bool]$Child.process_stopped_cleanly -and
            [int]$Child.orphan_processes -eq 0
        )
    } catch { return $false }
}

# BEGIN_RUNTIME_GUARD
try {
    $stage = 'IDENTITY'
    $effectiveIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $effectiveSid = $effectiveIdentity.User.Value
    $report.effective_sid = $effectiveSid
    if ($effectiveSid -ne $expectedGatewaySid) {
        throw "Wrong Gateway token SID. Expected $expectedGatewaySid; received $effectiveSid."
    }
    $principal = [System.Security.Principal.WindowsPrincipal]::new($effectiveIdentity)
    if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'MT5 read-only preflight refuses an administrative token.'
    }

    $stage = 'PATH_PREFLIGHT'
    if (-not (Test-ExactPath $pythonExecutable 'C:\automaton\.venv\Scripts\python.exe')) {
        throw 'FINAL_PYTHON_EXACT=FAIL'
    }
    foreach ($requiredDirectory in @($workspace, $finalRoot, $operationalRoot, $runtimeTemp)) {
        Assert-NoReparsePoint $requiredDirectory $true
    }
    foreach ($requiredFile in @($pythonExecutable, $configPath)) {
        Assert-NoReparsePoint $requiredFile $false
    }
    if (-not [System.IO.Directory]::Exists($reportRoot)) {
        [void][System.IO.Directory]::CreateDirectory($reportRoot)
    }
    Assert-NoReparsePoint $reportRoot $true
    Assert-PathConfined $reportPath $reportRoot
    if ([System.IO.File]::Exists($reportPath) -or [System.IO.Directory]::Exists($reportPath)) {
        throw 'MT5 read-only report RunId collision. Use a new UUID.'
    }

    $stage = 'CONFIG_PREFLIGHT'
    $configText = [System.IO.File]::ReadAllText($configPath, [System.Text.Encoding]::UTF8)
    if ($configText -notmatch '(?m)^\s*trading_mode\s*:\s*OBSERVE_ONLY\s*$') {
        throw 'TRADING_MODE_OBSERVE_ONLY=FAIL'
    }
    if ($configText -notmatch '(?m)^\s*mt5_access_enabled\s*:\s*false\s*$') {
        throw 'MT5_GATEWAY_ACCESS_MUST_REMAIN_DISABLED=FAIL'
    }
    if ($configText -notmatch '(?m)^\s*allowed_symbol\s*:\s*["'']?XAUUSD["'']?\s*$') {
        throw 'EXACT_XAUUSD_CONFIG=FAIL'
    }
    if ($configText -match '(?im)^\s*(password|passwd|credential|credentials|token|secret|private_key)\s*:') {
        throw 'Forbidden secret field exists in the protected trading config.'
    }

    $stage = 'RUNTIME_FINGERPRINT_BEFORE'
    $beforeFingerprint = Get-FinalRuntimeFingerprint

    $stage = 'PREFLIGHT_PROCESS_START'
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pythonExecutable
    $startInfo.Arguments = "-B -m trading_lab.mt5_read_only_entrypoint --config `"$configPath`" --run-id $normalizedRunId"
    $startInfo.WorkingDirectory = $workspace
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables['TRADING_MODE'] = 'OBSERVE_ONLY'
    $startInfo.EnvironmentVariables['MT5_ACCESS_ENABLED'] = 'false'
    $startInfo.EnvironmentVariables['MT5_READ_ONLY_PREFLIGHT'] = 'true'
    $startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $startInfo.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
    $startInfo.EnvironmentVariables['TEMP'] = $runtimeTemp
    $startInfo.EnvironmentVariables['TMP'] = $runtimeTemp
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw 'MT5 read-only preflight process did not start.' }
    $processStarted = $true
    $stdoutReadTask = $process.StandardOutput.ReadToEndAsync()
    $stderrReadTask = $process.StandardError.ReadToEndAsync()

    $stage = 'PREFLIGHT_PROCESS_WAIT'
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not $process.HasExited) {
        $timeoutObserved = $true
        $failureCode = 'MT5_READ_ONLY_PROCESS_TIMEOUT'
        throw 'MT5 read-only preflight process exceeded its bounded timeout.'
    }
    $processExitObserved = $true
    $processExitCode = $process.ExitCode

    $stage = 'PROCESS_STREAM_CAPTURE'
    $stdoutCapture = Receive-PreflightStreamCapture $stdoutReadTask 5000
    $stderrCapture = Receive-PreflightStreamCapture $stderrReadTask 5000
    $stdoutCaptured = [bool]$stdoutCapture.captured
    $stderrCaptured = [bool]$stderrCapture.captured
    $stdoutSanitized = $stdoutCapture.sanitized
    $stderrSanitized = $stderrCapture.sanitized
    $streamErrors = @(
        @($stdoutCapture.error, $stderrCapture.error) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    )
    if ($streamErrors.Count -gt 0) { $streamCaptureError = $streamErrors -join '; ' }
    if (-not $stdoutCaptured -or -not $stderrCaptured) {
        throw 'MT5 read-only child stdout/stderr capture did not complete.'
    }

    $stage = 'CHILD_REPORT'
    try { $childReport = $stdoutCapture.raw | ConvertFrom-Json -ErrorAction Stop } catch {
        throw 'MT5 read-only child did not emit one valid JSON report.'
    }
    Copy-PreflightEvidence $childReport $report
    $processStoppedCleanly = [bool]$childReport.process_stopped_cleanly
    if (-not (Test-PreflightChildBoundary $childReport)) {
        $failureCode = if ([string]::IsNullOrWhiteSpace([string]$childReport.failure_code)) {
            'MT5_READ_ONLY_CHILD_BOUNDARY_FAILED'
        } else { [string]$childReport.failure_code }
        $stage = if ([string]::IsNullOrWhiteSpace([string]$childReport.failure_stage)) {
            'CHILD_BOUNDARY'
        } else { [string]$childReport.failure_stage }
        throw 'MT5 read-only child report did not pass every boundary.'
    }
    if ($processExitCode -ne 0) {
        throw "MT5 read-only child exited with code $processExitCode despite a PASS report."
    }
    $runtimeSucceeded = $true
} catch {
    $failureStage = $stage
    if ([string]::IsNullOrWhiteSpace($failureCode)) {
        $failureCode = "MT5_READ_ONLY_$($stage)_FAILED"
    }
    if ($null -ne $childReport -and -not [string]::IsNullOrWhiteSpace([string]$childReport.runtime_error)) {
        $runtimeError = Get-SanitizedRuntimeError ([pscustomobject]@{
            Exception = [pscustomobject]@{ Message = [string]$childReport.runtime_error }
        })
    } else { $runtimeError = Get-SanitizedRuntimeError $_ }
} finally {
    # BEGIN_DURABLE_REPORT_FINALLY: only the exact child process object is controlled.
    if ($null -ne $process -and $processStarted) {
        try {
            $knownPid = $process.Id
            if (-not $process.HasExited) {
                $forcedTerminationUsed = $true
                $process.Kill()
                [void]$process.WaitForExit(5000)
            }
            if ($process.HasExited) {
                $processExitObserved = $true
                $processExitCode = $process.ExitCode
            }
            if (-not $stdoutCaptured) {
                $stdoutCapture = Receive-PreflightStreamCapture $stdoutReadTask 5000
                $stdoutCaptured = [bool]$stdoutCapture.captured
                $stdoutSanitized = $stdoutCapture.sanitized
                if (-not [string]::IsNullOrWhiteSpace([string]$stdoutCapture.error)) {
                    $streamCaptureError = [string]$stdoutCapture.error
                }
            }
            if (-not $stderrCaptured) {
                $stderrCapture = Receive-PreflightStreamCapture $stderrReadTask 5000
                $stderrCaptured = [bool]$stderrCapture.captured
                $stderrSanitized = $stderrCapture.sanitized
                if (-not [string]::IsNullOrWhiteSpace([string]$stderrCapture.error)) {
                    $streamCaptureError = if ([string]::IsNullOrWhiteSpace($streamCaptureError)) {
                        [string]$stderrCapture.error
                    } else { "$streamCaptureError; $($stderrCapture.error)" }
                }
            }
            $orphanProcesses = if (Get-Process -Id $knownPid -ErrorAction SilentlyContinue) { 1 } else { 0 }
        } catch {
            $processStoppedCleanly = $false
            $orphanProcesses = 1
            if ([string]::IsNullOrWhiteSpace($runtimeError)) {
                $failureStage = 'PROCESS_CLEANUP'
                $failureCode = 'MT5_READ_ONLY_PROCESS_CLEANUP_FAILED'
                $runtimeError = Get-SanitizedRuntimeError $_
            }
        } finally {
            try { $process.Dispose() } catch {}
        }
    }

    if ($null -ne $beforeFingerprint) {
        try {
            $afterFingerprint = Get-FinalRuntimeFingerprint
            $runtimeFingerprintVerified = $true
            $filesystemRuntimeModified =
                $beforeFingerprint.content_sha256 -ne $afterFingerprint.content_sha256
            $aclModified = $beforeFingerprint.acl_sha256 -ne $afterFingerprint.acl_sha256
        } catch {
            if ([string]::IsNullOrWhiteSpace($runtimeError)) {
                $failureStage = 'RUNTIME_FINGERPRINT_AFTER'
                $failureCode = 'MT5_READ_ONLY_RUNTIME_FINGERPRINT_AFTER_FAILED'
                $runtimeError = Get-SanitizedRuntimeError $_
            }
        }
    }

    $passed =
        $runtimeSucceeded -and $processStarted -and $processExitObserved -and
        $processExitCode -eq 0 -and $stdoutCaptured -and $stderrCaptured -and
        -not $timeoutObserved -and -not $forcedTerminationUsed -and
        $processStoppedCleanly -and $orphanProcesses -eq 0 -and
        $runtimeFingerprintVerified -and -not $filesystemRuntimeModified -and
        -not $aclModified -and (Test-PreflightChildBoundary $childReport)
    if (-not $passed -and [string]::IsNullOrWhiteSpace($failureCode)) {
        $failureStage = 'BOUNDARY_VALIDATION'
        $failureCode = 'MT5_READ_ONLY_BOUNDARY_FAILED'
        $runtimeError = 'One or more MT5 read-only boundaries did not pass.'
    }

    $report.effective_sid = $effectiveSid
    $report.status = if ($passed) { 'PASS' } else { 'FAIL' }
    $report.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    $report.failure_code = if ($passed) { $null } else { $failureCode }
    $report.failure_stage = if ($passed) { $null } else { $failureStage }
    $report.runtime_error = if ($passed) { $null } else { $runtimeError }
    $report.preflight_process_started = $processStarted
    $report.preflight_process_exit_observed = $processExitObserved
    $report.preflight_process_exit_code = $processExitCode
    $report.preflight_stdout_captured = $stdoutCaptured
    $report.preflight_stderr_captured = $stderrCaptured
    $report.preflight_stdout_sanitized = $stdoutSanitized
    $report.preflight_stderr_sanitized = $stderrSanitized
    $report.preflight_stream_capture_error = $streamCaptureError
    $report.timeout_observed = $timeoutObserved
    $report.forced_termination_used = $forcedTerminationUsed
    $report.process_stopped_cleanly = $processStoppedCleanly
    $report.orphan_processes = $orphanProcesses
    $report.runtime_fingerprint_verified = $runtimeFingerprintVerified
    $report.filesystem_runtime_modified = $filesystemRuntimeModified
    $report.acl_modified = $aclModified
    $report.final_runtime_item_count = if ($null -eq $afterFingerprint) { 0 } else { $afterFingerprint.item_count }

    try {
        if (-not [System.IO.Directory]::Exists($reportRoot)) {
            [void][System.IO.Directory]::CreateDirectory($reportRoot)
        }
        Assert-NoReparsePoint $reportRoot $true
        Assert-PathConfined $reportPath $reportRoot
        Write-ExclusiveJson $reportPath $report
        $reportWritten = $true
    } catch {
        $reportWriteError = Get-SanitizedRuntimeError $_
        $report.status = 'FAIL'
        $passed = $false
    }
}

if (-not [string]::IsNullOrWhiteSpace($reportWriteError)) {
    Write-Error "REPORT_WRITE_FAILED: $reportWriteError" -ErrorAction Continue
    if (-not [string]::IsNullOrWhiteSpace($runtimeError)) {
        Write-Error "ORIGINAL_RUNTIME_ERROR: $runtimeError" -ErrorAction Continue
    }
}

Write-Output 'MODE=MT5_READ_ONLY_PREFLIGHT'
Write-Output "STATUS=$($report.status)"
Write-Output 'TRADING_MODE=OBSERVE_ONLY'
Write-Output "MT5_IMPORTED=$($report.mt5_imported.ToString().ToLowerInvariant())"
Write-Output "MT5_ACCESSED=$($report.mt5_accessed.ToString().ToLowerInvariant())"
Write-Output "ORDER_CHECK=$($report.order_check_called.ToString().ToLowerInvariant())"
Write-Output "ORDER_SEND=$($report.order_send_called.ToString().ToLowerInvariant())"
Write-Output "PROCESS_STOPPED_CLEANLY=$($processStoppedCleanly.ToString().ToLowerInvariant())"
Write-Output "ORPHAN_PROCESSES=$orphanProcesses"
Write-Output "REPORT=$reportPath"
if (-not $passed -or -not $reportWritten) { exit 1 }
